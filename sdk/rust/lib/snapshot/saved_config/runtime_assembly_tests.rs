//! Composition tests exercise selection, binding preparation and native sparse precedence.

use std::collections::BTreeMap;

use microsandbox_types::snapshot::saved_config::SavedRuntimeConfig;
use microsandbox_types::{
    EnvVar, HandoffInit, SandboxRuntimeOptionsPatch, SandboxSpec, SandboxSpecPatch,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    RuntimeBindingInput, RuntimeDefaultClear, RuntimeSelectionContext, SnapshotConfigMode,
    prepare_runtime_configuration,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn record(value: Value) -> Value {
    json!({"state":"value","origin":"configured","value":value})
}
fn literal(value: &str) -> Value {
    json!({"kind":"literal","value":value})
}
fn binding(id: &str) -> Value {
    json!({"kind":"binding","id":id})
}
fn source(value: Value) -> SavedRuntimeConfig {
    SavedRuntimeConfig::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap()
}
fn context(full: bool, run: bool) -> RuntimeSelectionContext {
    RuntimeSelectionContext {
        config_mode: SnapshotConfigMode::Saved,
        full_resume: full,
        starts_command: run,
    }
}
fn env(key: &str, value: &str) -> EnvVar {
    EnvVar {
        key: key.into(),
        value: value.into(),
    }
}
fn lower() -> SandboxSpec {
    let mut spec = SandboxSpec::default();
    spec.runtime.entrypoint = Some(vec!["image-entrypoint".into()]);
    spec.runtime.cmd = Some(vec!["image-cmd".into()]);
    spec.runtime.hostname = Some("image-hostname".into());
    spec.runtime
        .scripts
        .insert("old-script".into(), "old-body".into());
    spec.env = vec![env("IMAGE", "lower"), env("TOKEN", "image-token")];
    spec.init = Some(HandoffInit {
        cmd: "/old-init".into(),
        args: vec!["old-arg".into()],
        env: vec![("OLD".into(), "old".into())],
    });
    spec
}
fn script(content: &str, mode: u16) -> Value {
    json!({"kind":"inline","content":content,"mode":mode,"digest":format!("sha256:{}",hex::encode(Sha256::digest(content.as_bytes())))})
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn changed_entrypoint_suppresses_both_saved_and_image_cmd_but_equal_keeps_saved() {
    let saved = source(
        json!({"entrypoint":record(json!([literal("saved-entrypoint")])), "cmd":record(json!([literal("saved-cmd")]))}),
    );
    for (entrypoint, cmd, expected) in [
        ("new-entrypoint", None, Vec::<String>::new()),
        ("saved-entrypoint", None, vec!["saved-cmd".into()]),
        (
            "new-entrypoint",
            Some(vec!["explicit".into()]),
            vec!["explicit".into()],
        ),
        ("new-entrypoint", Some(Vec::new()), Vec::new()),
    ] {
        let mut patch = SandboxSpecPatch::new()
            .runtime(SandboxRuntimeOptionsPatch::new().entrypoint(vec![entrypoint.into()]));
        patch.runtime.cmd = cmd;
        let plan = prepare_runtime_configuration(
            &saved,
            &lower(),
            &patch,
            &[],
            context(false, true),
            &BTreeMap::new(),
        )
        .unwrap();
        let ready = plan.command_defaults().unwrap();
        assert_eq!(ready.runtime.entrypoint, Some(vec![entrypoint.into()]));
        assert_eq!(ready.runtime.cmd, Some(expected));
    }
}

#[test]
fn env_known_map_replaces_lower_then_explicit_merge_retains_other_saved_keys() {
    let saved = source(
        json!({"env":record(json!({"TOKEN":binding("token"), "KEEP":literal("saved"), "A.B":literal("dot")}))}),
    );
    let patch = SandboxSpecPatch::new().env(vec![env("TOKEN", "explicit"), env("NEW", "new")]);
    let plan = prepare_runtime_configuration(
        &saved,
        &lower(),
        &patch,
        &[],
        context(false, true),
        &BTreeMap::new(),
    )
    .unwrap();
    let ready = plan.command_defaults().unwrap();
    let values: BTreeMap<_, _> = ready.env.into_iter().map(|v| (v.key, v.value)).collect();
    assert_eq!(
        values,
        BTreeMap::from([
            ("TOKEN".into(), "explicit".into()),
            ("KEEP".into(), "saved".into()),
            ("A.B".into(), "dot".into()),
            ("NEW".into(), "new".into())
        ])
    );
    assert!(
        plan.inputs()
            .retained
            .env
            .as_ref()
            .unwrap()
            .value()
            .unwrap()
            .get("TOKEN")
            .is_none()
    );
    for patch in [
        SandboxSpecPatch::new().replace_env(Vec::new()),
        SandboxSpecPatch::new().replace_env(vec![env("ONLY", "one")]),
    ] {
        let plan = prepare_runtime_configuration(
            &saved,
            &lower(),
            &patch,
            &[],
            context(false, true),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            plan.command_defaults().unwrap().env,
            patch.get_env().unwrap().clone()
        );
    }
}

#[test]
fn unavailable_future_command_never_returns_lower_or_partial_defaults() {
    let saved = source(
        json!({"cmd":record(json!([literal("before"),binding("token"),literal("after")])),"env":record(json!({"TOKEN":binding("token")}))}),
    );
    let plan = prepare_runtime_configuration(
        &saved,
        &lower(),
        &SandboxSpecPatch::new(),
        &[],
        context(false, false),
        &BTreeMap::new(),
    )
    .unwrap();
    assert!(plan.command_defaults().is_err());
    let supplied = BTreeMap::from([(
        "token".into(),
        RuntimeBindingInput {
            text: Zeroizing::new("PRIVATE_SENTINEL a b".into()),
            script_mode: None,
        },
    )]);
    let plan = prepare_runtime_configuration(
        &saved,
        &lower(),
        &SandboxSpecPatch::new(),
        &[],
        context(false, true),
        &supplied,
    )
    .unwrap();
    let ready = plan.command_defaults().unwrap();
    assert_eq!(
        ready.runtime.cmd,
        Some(vec![
            "before".into(),
            "PRIVATE_SENTINEL a b".into(),
            "after".into()
        ])
    );
    assert_eq!(ready.env, vec![env("TOKEN", "PRIVATE_SENTINEL a b")]);
    assert!(!format!("{plan:?} {ready:?}").contains("PRIVATE_SENTINEL"));
    assert!(
        !serde_json::to_string(&plan.inputs().retained)
            .unwrap()
            .contains("PRIVATE_SENTINEL")
    );
}

#[test]
fn default_empty_and_omitted_commands_env_and_init_remain_distinct() {
    let omitted = prepare_runtime_configuration(
        &SavedRuntimeConfig::default(),
        &lower(),
        &SandboxSpecPatch::new(),
        &[],
        context(false, true),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(
        omitted.command_defaults().unwrap().runtime.cmd,
        lower().runtime.cmd
    );
    assert_eq!(omitted.command_defaults().unwrap().env, lower().env);
    assert_eq!(omitted.cold_boot_init().unwrap().unwrap().cmd, "/old-init");
    for state in [json!({"state":"default"}), record(json!([]))] {
        let saved = source(json!({"cmd":state}));
        let plan = prepare_runtime_configuration(
            &saved,
            &lower(),
            &SandboxSpecPatch::new(),
            &[],
            context(false, true),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            plan.command_defaults().unwrap().runtime.cmd,
            Some(Vec::new())
        );
    }
    let saved = source(json!({"env":{"state":"default"},"init":{"state":"default"}}));
    let plan = prepare_runtime_configuration(
        &saved,
        &lower(),
        &SandboxSpecPatch::new(),
        &[],
        context(false, true),
        &BTreeMap::new(),
    )
    .unwrap();
    assert!(plan.command_defaults().unwrap().env.is_empty());
    assert!(plan.cold_boot_init().unwrap().is_none());
}

#[test]
fn cold_init_uses_resolved_path_and_replacement_drops_saved_args_and_environment() {
    let saved = source(
        json!({"init":record(json!({"kind":"handoff","selection":"auto","resolved_path":"/sbin/chosen","args":[literal("--saved")],"env":{"SAVED":literal("yes")}}))}),
    );
    let plan = prepare_runtime_configuration(
        &saved,
        &lower(),
        &SandboxSpecPatch::new(),
        &[],
        context(false, false),
        &BTreeMap::new(),
    )
    .unwrap();
    let init = plan.cold_boot_init().unwrap().unwrap();
    assert_eq!(init.cmd, "/sbin/chosen");
    assert_eq!(init.args, vec!["--saved"]);
    assert_eq!(init.env, vec![("SAVED".into(), "yes".into())]);
    let patch = SandboxSpecPatch::new().init(HandoffInit {
        cmd: "auto".into(),
        args: vec![],
        env: vec![],
    });
    let plan = prepare_runtime_configuration(
        &saved,
        &lower(),
        &patch,
        &[],
        context(false, false),
        &BTreeMap::new(),
    )
    .unwrap();
    let init = plan.cold_boot_init().unwrap().unwrap();
    assert_eq!(init.cmd, "auto");
    assert!(init.args.is_empty());
    assert!(init.env.is_empty());
    assert!(
        prepare_runtime_configuration(
            &saved,
            &lower(),
            &patch,
            &[],
            context(true, false),
            &BTreeMap::new()
        )
        .is_err()
    );
}

#[test]
fn scripts_keep_exact_saved_modes_and_native_explicit_replacement_semantics() {
    let saved = source(
        json!({"scripts":record(json!({"saved":script("#!/bin/sh\nexit 0\n",0o640),"override":script("old",0o700)}))}),
    );
    let patch = SandboxSpecPatch::new().runtime(
        SandboxRuntimeOptionsPatch::new()
            .scripts(BTreeMap::from([("override".into(), "new".into())])),
    );
    let plan = prepare_runtime_configuration(
        &saved,
        &lower(),
        &patch,
        &[],
        context(false, false),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(
        plan.scripts()["saved"].content.as_str(),
        "#!/bin/sh\nexit 0\n"
    );
    assert_eq!(plan.scripts()["saved"].mode, 0o640);
    assert_eq!(plan.scripts()["override"].content.as_str(), "new");
    assert_eq!(plan.scripts()["override"].mode, 0o755);
    assert!(!plan.scripts().contains_key("old-script"));
    assert!(plan.command_defaults().unwrap().runtime.scripts.is_empty());
    let patch = SandboxSpecPatch::new()
        .runtime(SandboxRuntimeOptionsPatch::new().replace_scripts(BTreeMap::new()));
    let plan = prepare_runtime_configuration(
        &saved,
        &lower(),
        &patch,
        &[],
        context(true, false),
        &BTreeMap::new(),
    )
    .unwrap();
    assert!(plan.scripts().is_empty());
    assert!(plan.inputs().script_replacement_requires_identity_check);
    assert!(plan.inputs().requires_full_identity);
}

#[test]
fn generated_hostname_is_regenerated_for_disk_but_remains_full_identity_evidence() {
    let saved =
        source(json!({"hostname":record(json!({"kind":"generated","value":"source-generated"}))}));
    for full in [false, true] {
        let plan = prepare_runtime_configuration(
            &saved,
            &lower(),
            &SandboxSpecPatch::new(),
            &[],
            context(full, false),
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            plan.command_defaults().unwrap().runtime.hostname,
            if full {
                Some("source-generated".into())
            } else {
                None
            }
        );
        assert_eq!(plan.inputs().requires_full_identity, full);
    }
}

#[test]
fn structural_clears_suppress_lower_values_and_explicit_inputs_still_win() {
    let saved = source(
        json!({"cmd":record(json!([literal("saved")])),"env":record(json!({"TOKEN":literal("saved-token")})),"scripts":record(json!({"old-script":script("saved",0o700)}))}),
    );
    let clears = [
        RuntimeDefaultClear::Cmd,
        RuntimeDefaultClear::Env,
        RuntimeDefaultClear::Scripts,
        RuntimeDefaultClear::Init,
    ];
    let plan = prepare_runtime_configuration(
        &saved,
        &lower(),
        &SandboxSpecPatch::new(),
        &clears,
        context(false, true),
        &BTreeMap::new(),
    )
    .unwrap();
    let ready = plan.command_defaults().unwrap();
    assert_eq!(ready.runtime.cmd, Some(Vec::new()));
    assert!(ready.env.is_empty());
    assert!(plan.scripts().is_empty());
    assert!(plan.cold_boot_init().unwrap().is_none());
    let patch = SandboxSpecPatch::new()
        .env(vec![env("TOKEN", "explicit")])
        .runtime(SandboxRuntimeOptionsPatch::new().cmd(vec!["explicit".into()]));
    let plan = prepare_runtime_configuration(
        &saved,
        &lower(),
        &patch,
        &clears,
        context(false, true),
        &BTreeMap::new(),
    )
    .unwrap();
    let ready = plan.command_defaults().unwrap();
    assert_eq!(ready.env, vec![env("TOKEN", "explicit")]);
    assert_eq!(ready.runtime.cmd, Some(vec!["explicit".into()]));
}

#[test]
fn unknown_fields_remain_guarded_until_whole_field_replaced() {
    let saved = source(json!({"env":{"state":"unknown","reason":"not_recorded"}}));
    let partial = SandboxSpecPatch::new().env(vec![env("ONE", "known")]);
    let plan = prepare_runtime_configuration(
        &saved,
        &lower(),
        &partial,
        &[],
        context(false, false),
        &BTreeMap::new(),
    )
    .unwrap();
    assert!(plan.command_defaults().is_err());
    let complete = SandboxSpecPatch::new().replace_env(vec![env("ONE", "known")]);
    let plan = prepare_runtime_configuration(
        &saved,
        &lower(),
        &complete,
        &[],
        context(false, true),
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(
        plan.command_defaults().unwrap().env,
        vec![env("ONE", "known")]
    );
}

#[test]
fn fresh_mode_uses_destination_defaults_but_full_resume_retains_captured_obligations() {
    let saved = source(json!({
        "cmd":record(json!([literal("saved-cmd")])),
        "hostname":record(json!({"kind":"generated","value":"source-host"})),
        "init":record(json!({"kind":"handoff","selection":"path","resolved_path":"/saved-init","args":[binding("init-token")],"env":{}}))
    }));
    for full in [false, true] {
        let mut ctx = context(full, false);
        ctx.config_mode = SnapshotConfigMode::Fresh;
        let plan = prepare_runtime_configuration(
            &saved,
            &lower(),
            &SandboxSpecPatch::new(),
            &[],
            ctx,
            &BTreeMap::new(),
        )
        .unwrap();
        assert_eq!(
            plan.command_defaults().unwrap().runtime.cmd,
            lower().runtime.cmd
        );
        if full {
            assert!(plan.cold_boot_init().is_err());
            assert!(plan.inputs().requires_full_identity);
            assert_eq!(
                plan.command_defaults().unwrap().runtime.hostname,
                Some("source-host".into())
            );
        } else {
            assert_eq!(plan.cold_boot_init().unwrap().unwrap().cmd, "/old-init");
            assert_eq!(
                plan.command_defaults().unwrap().runtime.hostname,
                lower().runtime.hostname
            );
        }
    }
}

#[test]
fn nullable_overrides_and_literal_key_clears_do_not_touch_other_destination_settings() {
    let saved = source(json!({
        "workdir":record(json!("/saved")), "shell":record(json!("/bin/source-shell")),
        "env":record(json!({"A.B":literal("removed"),"A":literal("keep")}))
    }));
    let mut base = lower();
    base.runtime.disable_metrics_sample = true;
    base.runtime.metrics_sample_interval_ms = Some(4321);
    let mut patch = SandboxSpecPatch::new();
    patch.runtime.workdir = Some(None);
    patch.runtime.shell = Some(None);
    let plan = prepare_runtime_configuration(
        &saved,
        &base,
        &patch,
        &[RuntimeDefaultClear::EnvKey("A.B".into())],
        context(false, true),
        &BTreeMap::new(),
    )
    .unwrap();
    let ready = plan.command_defaults().unwrap();
    assert!(ready.runtime.workdir.is_none());
    assert!(ready.runtime.shell.is_none());
    assert_eq!(ready.env, vec![env("A", "keep")]);
    assert!(ready.runtime.disable_metrics_sample);
    assert_eq!(ready.runtime.metrics_sample_interval_ms, Some(4321));
    assert_eq!(base.env, lower().env);
    assert!(serde_json::to_string(&saved).unwrap().contains("removed"));
}
