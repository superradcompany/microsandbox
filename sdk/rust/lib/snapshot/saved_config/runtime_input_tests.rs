//! Consumer preparation must preserve unresolved fields and exact script backing semantics.

use std::collections::BTreeMap;

use microsandbox_types::SandboxSpecPatch;
use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_TEXT_BYTES, SavedRuntimeConfig, SavedUnknownReason,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    PreparedRuntimeInit, PreparedRuntimeValue, RuntimeBindingInput, RuntimeSelectionContext,
    SnapshotConfigMode, prepare_runtime_inputs, select_runtime_defaults,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn record(value: Value) -> Value {
    json!({"state":"value","origin":"configured","value":value})
}

fn literal(text: &str) -> Value {
    json!({"kind":"literal","value":text})
}

fn binding(id: &str) -> Value {
    json!({"kind":"binding","id":id})
}

fn runtime(value: Value) -> SavedRuntimeConfig {
    SavedRuntimeConfig::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn context(full_resume: bool, starts_command: bool) -> RuntimeSelectionContext {
    RuntimeSelectionContext {
        config_mode: SnapshotConfigMode::Saved,
        full_resume,
        starts_command,
    }
}

fn input(text: &str, mode: Option<u16>) -> RuntimeBindingInput {
    RuntimeBindingInput {
        text: Zeroizing::new(text.into()),
        script_mode: mode,
    }
}

fn inline(text: &str, mode: u16) -> Value {
    json!({"kind":"inline","content":text,"mode":mode,"digest":format!("sha256:{}",hex::encode(Sha256::digest(text.as_bytes())))})
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn bound_arguments_and_environment_preserve_exact_values_without_changing_retained_metadata() {
    let source = runtime(json!({
        "entrypoint":record(json!([literal("/bin/tool"),binding("shared")])),
        "cmd":record(json!([literal(""),literal("a b"),binding("shared")])),
        "env":record(json!({"TOKEN.WITH.DOTS":binding("shared"),"EMPTY":literal("")}))
    }));
    let selected =
        select_runtime_defaults(&source, &SandboxSpecPatch::new(), &[], context(false, true))
            .unwrap();
    let inputs = BTreeMap::from([("shared".into(), input("PRIVATE_SENTINEL\nvalue", None))]);
    let prepared = prepare_runtime_inputs(&selected, &inputs, context(false, true)).unwrap();
    let PreparedRuntimeValue::Ready(argv) = &prepared.cmd else {
        panic!("expected resolved argv")
    };
    assert_eq!(argv.as_slice(), ["", "a b", "PRIVATE_SENTINEL\nvalue"]);
    let PreparedRuntimeValue::Ready(env) = &prepared.env else {
        panic!("expected resolved environment")
    };
    assert_eq!(env["TOKEN.WITH.DOTS"].as_str(), "PRIVATE_SENTINEL\nvalue");
    assert_eq!(env["EMPTY"].as_str(), "");
    assert_eq!(prepared.retained, source);
    assert!(
        !serde_json::to_string(&prepared.retained)
            .unwrap()
            .contains("PRIVATE_SENTINEL")
    );
    assert!(!format!("{prepared:?} {:?}", inputs["shared"]).contains("PRIVATE_SENTINEL"));
}

#[test]
fn future_command_defers_whole_fields_and_reprepares_before_execution() {
    let source = runtime(json!({
        "cmd":record(json!([literal("before"),binding("missing"),literal("after")])),
        "env":record(json!({"READY":literal("present"),"REQUIRED":binding("missing")}))
    }));
    let selected = select_runtime_defaults(
        &source,
        &SandboxSpecPatch::new(),
        &[],
        context(false, false),
    )
    .unwrap();
    let prepared =
        prepare_runtime_inputs(&selected, &BTreeMap::new(), context(false, false)).unwrap();
    assert!(matches!(prepared.cmd, PreparedRuntimeValue::Deferred(_)));
    assert!(matches!(prepared.env, PreparedRuntimeValue::Deferred(_)));
    assert!(prepared.cmd.require_available("runtime.cmd").is_err());
    assert!(prepare_runtime_inputs(&selected, &BTreeMap::new(), context(false, true)).is_err());
    let inputs = BTreeMap::from([("missing".into(), input("middle", None))]);
    let prepared = prepare_runtime_inputs(&selected, &inputs, context(false, true)).unwrap();
    let PreparedRuntimeValue::Ready(argv) = prepared.cmd else {
        panic!("expected complete argv")
    };
    assert_eq!(argv.as_slice(), ["before", "middle", "after"]);
}

#[test]
fn shared_init_input_is_immediate_for_cold_boot_but_deferred_after_full_resume() {
    let source = runtime(json!({
        "init":record(json!({"kind":"handoff","selection":"auto","resolved_path":"/sbin/source-init",
            "args":[literal("--mode"),binding("shared")],"env":{"TOKEN":binding("shared")}})),
        "env":record(json!({"TOKEN":binding("shared")}))
    }));
    let selected = select_runtime_defaults(
        &source,
        &SandboxSpecPatch::new(),
        &[],
        context(false, false),
    )
    .unwrap();
    assert!(prepare_runtime_inputs(&selected, &BTreeMap::new(), context(false, false)).is_err());
    let selected =
        select_runtime_defaults(&source, &SandboxSpecPatch::new(), &[], context(true, false))
            .unwrap();
    let deferred =
        prepare_runtime_inputs(&selected, &BTreeMap::new(), context(true, false)).unwrap();
    assert!(matches!(deferred.init, PreparedRuntimeValue::Deferred(_)));
    assert!(deferred.requires_full_identity);
    let inputs = BTreeMap::from([("shared".into(), input("exact argument", None))]);
    let ready = prepare_runtime_inputs(&selected, &inputs, context(true, false)).unwrap();
    let PreparedRuntimeValue::Ready(PreparedRuntimeInit::Handoff { path, args, env }) = ready.init
    else {
        panic!("expected handoff")
    };
    assert_eq!(path, "/sbin/source-init");
    assert_eq!(args.as_slice(), ["--mode", "exact argument"]);
    assert_eq!(env["TOKEN"].as_str(), "exact argument");
}

#[test]
fn scripts_keep_exact_bytes_and_modes_without_rewrapping_or_guessing_bindings() {
    let content = "#!/custom/interpreter\n\n  exact body  \n";
    let source = runtime(
        json!({"scripts":record(json!({"inline":inline(content,0o640),"bound":binding("script-body")}))}),
    );
    let selected = select_runtime_defaults(
        &source,
        &SandboxSpecPatch::new(),
        &[],
        context(false, false),
    )
    .unwrap();
    assert!(prepare_runtime_inputs(&selected, &BTreeMap::new(), context(false, false)).is_err());
    assert!(
        prepare_runtime_inputs(
            &selected,
            &BTreeMap::from([("script-body".into(), input(content, None))]),
            context(false, false)
        )
        .is_err()
    );
    let inputs = BTreeMap::from([("script-body".into(), input(content, Some(0o751)))]);
    let prepared = prepare_runtime_inputs(&selected, &inputs, context(false, false)).unwrap();
    let PreparedRuntimeValue::Ready(scripts) = prepared.scripts else {
        panic!("expected script backing")
    };
    assert_eq!(scripts["inline"].content.as_str(), content);
    assert_eq!(scripts["inline"].mode, 0o640);
    assert_eq!(scripts["bound"].content.as_str(), content);
    assert_eq!(scripts["bound"].mode, 0o751);
}

#[test]
fn full_script_override_and_empty_replacement_obligations_survive_preparation() {
    let source =
        runtime(json!({"scripts":record(json!({"check":inline("#!/bin/sh\nexit 0\n",0o755)}))}));
    for patch in [
        SandboxSpecPatch::new().runtime(
            microsandbox_types::SandboxRuntimeOptionsPatch::new()
                .scripts(BTreeMap::from([("check".into(), "replacement".into())])),
        ),
        SandboxSpecPatch::new().runtime(
            microsandbox_types::SandboxRuntimeOptionsPatch::new().replace_scripts(BTreeMap::new()),
        ),
    ] {
        let selected = select_runtime_defaults(&source, &patch, &[], context(true, false)).unwrap();
        let prepared =
            prepare_runtime_inputs(&selected, &BTreeMap::new(), context(true, false)).unwrap();
        assert_eq!(
            prepared.scripts_requiring_identity_check,
            selected.scripts_requiring_identity_check
        );
        assert_eq!(
            prepared.script_replacement_requires_identity_check,
            selected.script_replacement_requires_identity_check
        );
        assert!(prepared.requires_full_identity);
    }
}

#[test]
fn default_unknown_omitted_and_empty_are_not_collapsed() {
    let source = runtime(
        json!({"entrypoint":{"state":"default"},"cmd":record(json!([])),
        "env":{"state":"unknown","reason":"not_recorded"},"init":record(json!({"kind":"builtin"}))}),
    );
    let selected = select_runtime_defaults(
        &source,
        &SandboxSpecPatch::new(),
        &[],
        context(false, false),
    )
    .unwrap();
    let prepared =
        prepare_runtime_inputs(&selected, &BTreeMap::new(), context(false, false)).unwrap();
    assert!(matches!(prepared.entrypoint, PreparedRuntimeValue::Default));
    assert!(matches!(prepared.workdir, PreparedRuntimeValue::Omitted));
    assert!(matches!(
        prepared.env,
        PreparedRuntimeValue::Unknown(SavedUnknownReason::NotRecorded)
    ));
    assert!(matches!(
        prepared.init,
        PreparedRuntimeValue::Ready(PreparedRuntimeInit::Builtin)
    ));
    let PreparedRuntimeValue::Ready(cmd) = prepared.cmd else {
        panic!("expected explicit empty CMD")
    };
    assert!(cmd.is_empty());
    assert!(prepare_runtime_inputs(&selected, &BTreeMap::new(), context(false, true)).is_err());
}

#[test]
fn invalid_destination_text_unknown_ids_and_unused_script_mode_are_redacted() {
    let source = runtime(json!({"env":record(json!({"TOKEN":binding("known")}))}));
    let selected =
        select_runtime_defaults(&source, &SandboxSpecPatch::new(), &[], context(false, true))
            .unwrap();
    for inputs in [
        BTreeMap::from([(
            "PRIVATE_UNKNOWN_SENTINEL".into(),
            input("PRIVATE_VALUE_SENTINEL", None),
        )]),
        BTreeMap::from([("known".into(), input("PRIVATE_NUL_SENTINEL\0", None))]),
        BTreeMap::from([("known".into(), input("PRIVATE_MODE_SENTINEL", Some(0o755)))]),
        BTreeMap::from([(
            "known".into(),
            input(&"x".repeat(MAX_SAVED_TEXT_BYTES + 1), None),
        )]),
    ] {
        let err = prepare_runtime_inputs(&selected, &inputs, context(false, true)).unwrap_err();
        assert!(!err.to_string().contains("SENTINEL"));
    }
}

#[test]
fn shared_script_and_environment_input_obeys_both_consumers_constraints() {
    let source = runtime(
        json!({"scripts":record(json!({"script":binding("shared")})),"env":record(json!({"TOKEN":binding("shared")}))}),
    );
    let selected = select_runtime_defaults(
        &source,
        &SandboxSpecPatch::new(),
        &[],
        context(false, false),
    )
    .unwrap();
    for input in [input("nul\0", Some(0o755)), input("plain", Some(0o4755))] {
        assert!(
            prepare_runtime_inputs(
                &selected,
                &BTreeMap::from([("shared".into(), input)]),
                context(false, false)
            )
            .is_err()
        );
    }
    assert!(
        prepare_runtime_inputs(
            &selected,
            &BTreeMap::from([("shared".into(), input("same", Some(0o700)))]),
            context(false, false)
        )
        .is_ok()
    );
}

#[test]
fn repeated_binding_expansion_and_combined_scripts_are_bounded_before_returning() {
    let source =
        runtime(json!({"cmd":record(Value::Array((0..9).map(|_|binding("large")).collect()))}));
    let selected =
        select_runtime_defaults(&source, &SandboxSpecPatch::new(), &[], context(false, true))
            .unwrap();
    let inputs = BTreeMap::from([(
        "large".into(),
        input(&"x".repeat(MAX_SAVED_TEXT_BYTES), None),
    )]);
    assert!(
        prepare_runtime_inputs(&selected, &inputs, context(false, true))
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
    let scripts = (0..5)
        .map(|i| (format!("s{i}"), binding("large")))
        .collect::<serde_json::Map<_, _>>();
    let source = runtime(json!({"scripts":record(Value::Object(scripts))}));
    let selected = select_runtime_defaults(
        &source,
        &SandboxSpecPatch::new(),
        &[],
        context(false, false),
    )
    .unwrap();
    let inputs = BTreeMap::from([(
        "large".into(),
        input(&"x".repeat(MAX_SAVED_TEXT_BYTES), Some(0o755)),
    )]);
    assert!(
        prepare_runtime_inputs(&selected, &inputs, context(false, false))
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
}

#[test]
fn changed_entrypoint_cmd_reset_and_full_mode_refusal_are_preserved() {
    let source = runtime(
        json!({"entrypoint":record(json!([literal("old")])),"cmd":record(json!([literal("old-cmd")]))}),
    );
    let explicit = SandboxSpecPatch::new().runtime(
        microsandbox_types::SandboxRuntimeOptionsPatch::new().entrypoint(vec!["new".into()]),
    );
    let selected = select_runtime_defaults(&source, &explicit, &[], context(false, true)).unwrap();
    let prepared =
        prepare_runtime_inputs(&selected, &BTreeMap::new(), context(false, true)).unwrap();
    assert!(prepared.reset_inherited_cmd);
    assert!(matches!(prepared.cmd, PreparedRuntimeValue::Omitted));
    assert!(prepare_runtime_inputs(&selected, &BTreeMap::new(), context(true, true)).is_err());
}
