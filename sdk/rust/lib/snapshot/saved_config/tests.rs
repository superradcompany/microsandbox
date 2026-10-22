//! Pure runtime-selection behavior through the existing sparse destination patch API.

use std::collections::BTreeMap;

use microsandbox_types::snapshot::saved_config::{
    RuntimeBindingConsumer, SavedRuntimeConfig, SavedValue,
};
use microsandbox_types::{EnvVar, HandoffInit, SandboxRuntimeOptionsPatch, SandboxSpecPatch};
use serde_json::{Value, json};

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn explicit_env_merges_by_key_and_does_not_copy_destination_secrets_into_saved_metadata() {
    let saved = source();
    let before = serde_json::to_vec(&saved).unwrap();
    let patch = SandboxSpecPatch::new().env(vec![
        EnvVar::new("TOKEN", "SENTINEL_DEST_SECRET"),
        EnvVar::new("NEW", "value"),
    ]);
    let selected = select(&saved, &patch, &[], disk());
    let env = selected
        .defaults
        .env
        .as_ref()
        .and_then(SavedValue::value)
        .unwrap();
    assert!(!env.contains_key("TOKEN"));
    assert!(!env.contains_key("NEW"));
    assert!(env.contains_key("KEEP"));
    assert!(!selected.binding_requirements.contains_key("token"));
    assert!(
        !serde_json::to_string(&selected.defaults)
            .unwrap()
            .contains("SENTINEL_DEST_SECRET")
    );
    assert_eq!(patch.get_env().unwrap()[0].value, "SENTINEL_DEST_SECRET");
    assert_eq!(serde_json::to_vec(&saved).unwrap(), before);
}

#[test]
fn native_empty_merge_and_explicit_collection_replacement_remain_distinct() {
    let source = source();
    for patch in [SandboxSpecPatch::new(), SandboxSpecPatch::new().env(vec![])] {
        assert!(
            select(&source, &patch, &[], disk())
                .binding_requirements
                .contains_key("token")
        );
    }
    let replaced = select(
        &source,
        &SandboxSpecPatch::new().replace_env(vec![]),
        &[],
        disk(),
    );
    assert!(replaced.defaults.env.is_none());
    assert!(!replaced.binding_requirements.contains_key("token"));
}

#[test]
fn script_merge_masks_only_replaced_names_but_map_replacement_discards_all_optional_defaults() {
    let patch = SandboxSpecPatch::new().runtime(SandboxRuntimeOptionsPatch::new().scripts(
        BTreeMap::from([("health.check".into(), "SENTINEL_NEW_SCRIPT".into())]),
    ));
    let selected = select(&source(), &patch, &[], disk());
    let scripts = selected
        .defaults
        .scripts
        .as_ref()
        .and_then(SavedValue::value)
        .unwrap();
    assert!(!scripts.contains_key("health.check"));
    assert!(scripts.contains_key("other"));
    assert!(
        !serde_json::to_string(&selected.defaults)
            .unwrap()
            .contains("SENTINEL_NEW_SCRIPT")
    );
    let selected = select(
        &source(),
        &SandboxSpecPatch::new()
            .runtime(SandboxRuntimeOptionsPatch::new().replace_scripts(Default::default())),
        &[],
        disk(),
    );
    assert!(selected.defaults.scripts.is_none());
}

#[test]
fn explicit_null_scalars_and_empty_argv_mask_saved_defaults_using_existing_presence() {
    let patch = SandboxSpecPatch::new().runtime(
        SandboxRuntimeOptionsPatch::new()
            .set_workdir(None)
            .set_shell(None)
            .entrypoint(vec![])
            .cmd(vec![])
            .user("1001".into()),
    );
    let selected = select(&source(), &patch, &[], disk());
    assert!(selected.defaults.workdir.is_none());
    assert!(selected.defaults.shell.is_none());
    assert!(selected.defaults.entrypoint.is_none());
    assert!(selected.defaults.cmd.is_none());
    assert!(selected.defaults.user.is_none());
    assert!(!selected.reset_inherited_cmd);
    assert_eq!(patch.runtime.workdir, Some(None));
    assert_eq!(patch.runtime.entrypoint, Some(vec![]));
}

#[test]
fn explicit_init_selection_discards_all_inherited_init_args_and_environment() {
    let patch = SandboxSpecPatch::new().init(HandoffInit {
        cmd: "auto".into(),
        args: vec!["--new".into()],
        env: vec![("NEW".into(), "value".into())],
    });
    let selected = select(&source(), &patch, &[], disk());
    assert!(selected.defaults.init.is_none());
    assert!(!selected.binding_requirements.contains_key("boot"));
    assert_eq!(patch.init.as_ref().unwrap().args, ["--new"]);
    assert_eq!(patch.init.as_ref().unwrap().env[0].0, "NEW");
}

#[test]
fn structural_clear_keys_do_not_interpret_dots_and_redundant_clears_are_order_independent() {
    let source = source();
    let selected = select(
        &source,
        &SandboxSpecPatch::new(),
        &[
            RuntimeDefaultClear::EnvKey("A.B".into()),
            RuntimeDefaultClear::ScriptKey("health.check".into()),
        ],
        disk(),
    );
    let env = selected
        .defaults
        .env
        .as_ref()
        .and_then(SavedValue::value)
        .unwrap();
    assert!(!env.contains_key("A.B"));
    assert!(env.contains_key("A"));
    for clears in [
        vec![
            RuntimeDefaultClear::Env,
            RuntimeDefaultClear::EnvKey("TOKEN".into()),
        ],
        vec![
            RuntimeDefaultClear::EnvKey("TOKEN".into()),
            RuntimeDefaultClear::EnvKey("TOKEN".into()),
            RuntimeDefaultClear::Env,
        ],
    ] {
        assert!(
            select(&source, &SandboxSpecPatch::new(), &clears, disk())
                .defaults
                .env
                .is_none()
        );
    }
}

#[test]
fn missing_or_unknown_map_key_refuses_without_echoing_key_or_mutating_source() {
    let source = source();
    let before = serde_json::to_vec(&source).unwrap();
    let error = select_runtime_defaults(
        &source,
        &SandboxSpecPatch::new(),
        &[RuntimeDefaultClear::EnvKey("SENTINEL_MISSING".into())],
        disk(),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("SCFG_CLEAR"));
    assert!(!error.contains("SENTINEL"));
    assert_eq!(serde_json::to_vec(&source).unwrap(), before);
    let unknown = parse(json!({"env":{"state":"unknown","reason":"not_recorded"}}));
    assert!(
        select_runtime_defaults(
            &unknown,
            &SandboxSpecPatch::new(),
            &[RuntimeDefaultClear::EnvKey("TOKEN".into())],
            disk()
        )
        .is_err()
    );
    assert!(
        select(
            &unknown,
            &SandboxSpecPatch::new(),
            &[RuntimeDefaultClear::Env],
            disk()
        )
        .unknown_fields
        .is_empty()
    );
}

#[test]
fn saved_fresh_and_full_fresh_have_distinct_captured_state_requirements() {
    let saved = source();
    let explicit = SandboxSpecPatch::new();
    let cold_fresh = select(
        &saved,
        &explicit,
        &[],
        RuntimeSelectionContext {
            config_mode: SnapshotConfigMode::Fresh,
            ..disk()
        },
    );
    assert_eq!(cold_fresh.defaults, SavedRuntimeConfig::default());
    assert!(cold_fresh.binding_requirements.is_empty());
    let full_fresh = select(
        &saved,
        &explicit,
        &[],
        RuntimeSelectionContext {
            config_mode: SnapshotConfigMode::Fresh,
            full_resume: true,
            ..disk()
        },
    );
    assert!(full_fresh.defaults.env.is_none());
    assert!(full_fresh.defaults.cmd.is_none());
    assert!(full_fresh.defaults.init.is_some());
    assert!(full_fresh.defaults.hostname.is_some());
    assert!(full_fresh.defaults.guest_clock.is_some());
    assert!(full_fresh.defaults.scripts.is_some());
    assert!(
        full_fresh.binding_requirements["script"].contains(&RuntimeBindingConsumer::ScriptBacking)
    );
    // Consumers are potential uses, not timing: full resume will not rerun init.
    assert!(full_fresh.binding_requirements["boot"].contains(&RuntimeBindingConsumer::BootInit));
}

#[test]
fn full_resume_never_approves_initial_commands_init_hostname_or_captured_clears() {
    let context = RuntimeSelectionContext {
        full_resume: true,
        ..disk()
    };
    assert!(
        select_runtime_defaults(
            &source(),
            &SandboxSpecPatch::new(),
            &[],
            RuntimeSelectionContext {
                starts_command: true,
                ..context
            }
        )
        .is_err()
    );
    for patch in [
        SandboxSpecPatch::new().init(HandoffInit {
            cmd: "auto".into(),
            args: vec![],
            env: vec![],
        }),
        SandboxSpecPatch::new().runtime(SandboxRuntimeOptionsPatch::new().hostname("same".into())),
    ] {
        assert!(
            select_runtime_defaults(&source(), &patch, &[], context)
                .unwrap_err()
                .to_string()
                .contains("SCFG_FULL_STATE")
        );
    }
    for clear in [
        RuntimeDefaultClear::Init,
        RuntimeDefaultClear::Hostname,
        RuntimeDefaultClear::Scripts,
        RuntimeDefaultClear::ScriptKey("other".into()),
        RuntimeDefaultClear::GuestClock,
    ] {
        assert!(
            select_runtime_defaults(&source(), &SandboxSpecPatch::new(), &[clear], context)
                .is_err()
        );
    }
}

#[test]
fn full_script_registration_and_empty_replacement_carry_identity_obligations() {
    let context = RuntimeSelectionContext {
        full_resume: true,
        ..disk()
    };
    let selected = select(
        &source(),
        &SandboxSpecPatch::new().runtime(
            SandboxRuntimeOptionsPatch::new()
                .scripts(BTreeMap::from([("new".into(), "body".into())])),
        ),
        &[],
        context,
    );
    assert_eq!(
        selected
            .scripts_requiring_identity_check
            .into_iter()
            .collect::<Vec<_>>(),
        ["new"]
    );
    assert!(selected.defaults.scripts.is_some());
    let selected = select(
        &source(),
        &SandboxSpecPatch::new()
            .runtime(SandboxRuntimeOptionsPatch::new().replace_scripts(Default::default())),
        &[],
        context,
    );
    assert!(selected.script_replacement_requires_identity_check);
    assert!(selected.scripts_requiring_identity_check.is_empty());
    assert!(selected.defaults.scripts.is_some());
}

#[test]
fn changed_entrypoint_clears_saved_cmd_unless_destination_cmd_is_explicit() {
    let patch = SandboxSpecPatch::new()
        .runtime(SandboxRuntimeOptionsPatch::new().entrypoint(vec!["/new".into()]));
    let reset = select(&source(), &patch, &[], disk());
    assert!(reset.defaults.cmd.is_none());
    assert!(reset.reset_inherited_cmd);
    let same = SandboxSpecPatch::new()
        .runtime(SandboxRuntimeOptionsPatch::new().entrypoint(vec!["/old".into()]));
    let retained = select(&source(), &same, &[], disk());
    assert!(!retained.reset_inherited_cmd);
    assert!(retained.defaults.cmd.is_some());
    for cmd in [vec!["explicit".into()], vec![]] {
        let explicit = patch.clone().overlay(
            SandboxSpecPatch::new().runtime(SandboxRuntimeOptionsPatch::new().cmd(cmd.clone())),
        );
        let selected = select(&source(), &explicit, &[], disk());
        assert!(!selected.reset_inherited_cmd);
        assert!(selected.defaults.cmd.is_none());
        assert_eq!(explicit.runtime.cmd, Some(cmd));
    }
}

#[test]
fn unknown_or_bound_entrypoint_cannot_prove_saved_cmd_compatibility() {
    for entrypoint in [
        json!({"state":"unknown","reason":"not_recorded"}),
        json!({"state":"default"}),
        value(json!([{"kind":"binding","id":"entrypoint"}])),
    ] {
        let saved =
            parse(json!({"entrypoint":entrypoint,"cmd":value(json!([literal("old-cmd")]))}));
        for argv in [vec!["/new".into()], vec![]] {
            let explicit =
                SandboxSpecPatch::new().runtime(SandboxRuntimeOptionsPatch::new().entrypoint(argv));
            let selected = select(&saved, &explicit, &[], disk());
            assert!(selected.reset_inherited_cmd);
            assert!(selected.defaults.cmd.is_none());
        }
    }
}

#[test]
fn resetting_cmd_removes_only_its_binding_demand_and_fresh_discards_optional_defaults() {
    let saved = parse(json!({
        "entrypoint":value(json!([literal("/old")])),
        "cmd":value(json!([{"kind":"binding","id":"command"}])),
        "env":value(json!({"REQUIRED":{"kind":"binding","id":"env"}}))
    }));
    let explicit = SandboxSpecPatch::new()
        .runtime(SandboxRuntimeOptionsPatch::new().entrypoint(vec!["/new".into()]));
    let selected = select(&saved, &explicit, &[], disk());
    assert!(selected.reset_inherited_cmd);
    assert!(!selected.binding_requirements.contains_key("command"));
    assert!(selected.binding_requirements.contains_key("env"));
    let fresh = select(
        &saved,
        &explicit,
        &[],
        RuntimeSelectionContext {
            config_mode: SnapshotConfigMode::Fresh,
            ..disk()
        },
    );
    assert!(fresh.defaults.cmd.is_none());
    assert!(!fresh.reset_inherited_cmd);
    assert!(fresh.binding_requirements.is_empty());
}

#[test]
fn unknown_values_remain_explicit_until_wholly_overridden_or_ignored() {
    let source = parse(
        json!({"workdir":{"state":"unknown","reason":"not_recorded"},"env":{"state":"unknown","reason":"not_observed"}}),
    );
    let selected = select(
        &source,
        &SandboxSpecPatch::new().env(vec![EnvVar::new("ONE", "value")]),
        &[],
        disk(),
    );
    assert!(selected.unknown_fields.contains("runtime.env"));
    assert!(selected.unknown_fields.contains("runtime.workdir"));
    let selected = select(
        &source,
        &SandboxSpecPatch::new()
            .replace_env(vec![])
            .runtime(SandboxRuntimeOptionsPatch::new().set_workdir(None)),
        &[],
        disk(),
    );
    assert!(selected.unknown_fields.is_empty());
}

#[test]
fn debug_and_errors_do_not_echo_destination_or_source_sensitive_values() {
    let mut saved = source();
    saved.cmd = Some(SavedValue::Value {
        value: vec![
            microsandbox_types::snapshot::saved_config::SavedText::Literal {
                value: "SENTINEL_SOURCE".into(),
            },
        ],
        origin: microsandbox_types::snapshot::saved_config::SavedOrigin::Configured,
    });
    let selected = select(&saved, &SandboxSpecPatch::new(), &[], disk());
    assert!(!format!("{selected:?}").contains("SENTINEL"));
    let clears = vec![RuntimeDefaultClear::Env; 257];
    assert!(
        select_runtime_defaults(&saved, &SandboxSpecPatch::new(), &clears, disk())
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn disk() -> RuntimeSelectionContext {
    RuntimeSelectionContext {
        config_mode: SnapshotConfigMode::Saved,
        full_resume: false,
        starts_command: false,
    }
}

fn select(
    saved: &SavedRuntimeConfig,
    explicit: &SandboxSpecPatch,
    clears: &[RuntimeDefaultClear],
    context: RuntimeSelectionContext,
) -> RuntimeDefaultSelection {
    select_runtime_defaults(saved, explicit, clears, context).unwrap()
}

fn parse(value: Value) -> SavedRuntimeConfig {
    SavedRuntimeConfig::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn value(value: Value) -> Value {
    json!({"state":"value","origin":"configured","value":value})
}

fn literal(text: &str) -> Value {
    json!({"kind":"literal","value":text})
}

fn source() -> SavedRuntimeConfig {
    parse(json!({
        "workdir":value(json!("/saved")),"shell":value(json!("bash")),"entrypoint":value(json!([literal("/old")])),"cmd":value(json!([literal("saved-cmd")])),"user":value(json!("1000")),
        "env":value(json!({"TOKEN":{"kind":"binding","id":"token"},"KEEP":literal("source"),"A.B":literal("dot"),"A":literal("other")})),
        "scripts":value(json!({"health.check":{"kind":"binding","id":"script"},"other":{"kind":"binding","id":"other-script"}})),
        "init":value(json!({"kind":"handoff","selection":"path","resolved_path":"/sbin/init","args":[{"kind":"binding","id":"boot"}],"env":{"INIT":literal("original")}})),
        "hostname":value(json!({"kind":"explicit","value":"source"})),"guest_clock":value(json!("off"))
    }))
}
