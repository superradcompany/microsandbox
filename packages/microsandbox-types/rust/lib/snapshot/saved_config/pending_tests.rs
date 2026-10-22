//! Pending declarations are portable intent, never evidence for active restore.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use super::document_tests::document;
use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn configured(value: Value) -> Value {
    json!({"state":"value","origin":"configured","value":value})
}

fn pending_runtime() -> Value {
    json!({
        "init":configured(json!({"kind":"requested_handoff","cmd":"auto","args":[{"kind":"binding","id":"init-input"}],"env":{}})),
        "scripts":configured(json!({"task":{"kind":"declaration","content":"echo next-start"}}))
    })
}

fn parse(value: &Value) -> SavedSandboxConfig {
    SavedSandboxConfig::from_bytes(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn declarations(content: &str) -> RuntimeCaptureInput<'_> {
    RuntimeCaptureInput {
        init: Some(SavedValue::Value {
            value: RuntimeCaptureInit::RequestedHandoff {
                cmd: "auto",
                args: vec![],
                env: BTreeMap::new(),
            },
            origin: SavedOrigin::Configured,
        }),
        scripts: Some(SavedValue::Value {
            value: BTreeMap::from([("task", RuntimeCaptureScript::Declaration(content))]),
            origin: SavedOrigin::Configured,
        }),
        ..Default::default()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn pending_declarations_round_trip_without_active_binding_demand() {
    let mut doc = document();
    doc["pending"] = json!({"runtime":pending_runtime()});
    doc["bindings"] = json!({"init-input":"text"});
    let parsed = parse(&doc);
    assert!(parsed.active_binding_uses().unwrap().is_empty());
    assert_eq!(
        serde_json::to_value(&parsed).unwrap()["pending"]["runtime"],
        pending_runtime()
    );
    // Moving the exact same declaration into active is invalid, even with a valid inventory.
    for field in ["init", "scripts"] {
        let mut invalid = doc.clone();
        invalid["active"]["runtime"][field] = pending_runtime()[field].clone();
        let error = SavedSandboxConfig::from_bytes(&serde_json::to_vec(&invalid).unwrap())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("SCFG_IDENTITY"), "{error}");
    }
}

#[test]
fn pending_init_requires_bounded_guest_command_and_configured_origin() {
    for cmd in ["auto", "/sbin/init"] {
        let mut runtime = pending_runtime();
        runtime["init"]["value"]["cmd"] = json!(cmd);
        assert!(SavedRuntimeConfig::from_bytes(&serde_json::to_vec(&runtime).unwrap()).is_ok());
    }
    for cmd in ["", "relative", "AUTO", "/init\0PRIVATE"] {
        let mut runtime = pending_runtime();
        runtime["init"]["value"]["cmd"] = json!(cmd);
        let error = SavedRuntimeConfig::from_bytes(&serde_json::to_vec(&runtime).unwrap())
            .unwrap_err()
            .to_string();
        assert!(!error.contains("PRIVATE"));
    }
    for field in ["init", "scripts"] {
        for origin in ["observed", "image", "platform"] {
            let mut runtime = pending_runtime();
            runtime[field]["origin"] = json!(origin);
            assert!(
                SavedRuntimeConfig::from_bytes(&serde_json::to_vec(&runtime).unwrap()).is_err()
            );
        }
    }
    for (field, extra) in [
        ("init", "resolved_path"),
        ("scripts", "mode"),
        ("scripts", "digest"),
    ] {
        let mut runtime = pending_runtime();
        let value = if field == "scripts" {
            &mut runtime[field]["value"]["task"]
        } else {
            &mut runtime[field]["value"]
        };
        value[extra] = json!("PRIVATE");
        assert!(SavedRuntimeConfig::from_bytes(&serde_json::to_vec(&runtime).unwrap()).is_err());
    }
}

#[test]
fn declarations_cannot_be_projected_as_active_even_when_excluded() {
    let controls = BTreeMap::from([
        (RuntimeCaptureTarget::Init, RuntimeCaptureAction::Omit),
        (RuntimeCaptureTarget::Scripts, RuntimeCaptureAction::Omit),
    ]);
    for controls in [&BTreeMap::new(), &controls] {
        assert!(project_runtime_capture(declarations("declared"), None, controls, false).is_err());
    }
}

#[test]
fn pending_exclusions_precede_validation_and_leave_no_backing_digest() {
    let content = "PRIVATE".repeat(MAX_SAVED_SCRIPT_BYTES);
    let controls = BTreeMap::from([(
        RuntimeCaptureTarget::ScriptKey("task".into()),
        RuntimeCaptureAction::Bind("script-input".into()),
    )]);
    let projected = project_runtime_capture(
        RuntimeCaptureInput::default(),
        Some(declarations(&content)),
        &controls,
        true,
    )
    .unwrap();
    let pending = projected.pending.unwrap();
    let encoded = serde_json::to_string(&pending).unwrap();
    assert!(!encoded.contains("PRIVATE"));
    assert!(!encoded.contains("digest"));
    assert!(!encoded.contains("mode"));
    assert_eq!(projected.bindings["script-input"], SavedBindingKind::Text);
    assert!(pending.validate_active().is_err());
}

#[test]
fn declaration_scripts_share_the_document_payload_budget() {
    let content = "x".repeat(MAX_SAVED_SCRIPT_BYTES);
    let script = json!({"kind":"declaration","content":content});
    let mut doc = document();
    let count = MAX_SAVED_SCRIPTS_BYTES / MAX_SAVED_SCRIPT_BYTES;
    let scripts: BTreeMap<_, _> = (0..count)
        .map(|i| (format!("task-{i}"), script.clone()))
        .collect();
    doc["pending"] = json!({"runtime":{"scripts":configured(json!(scripts))}});
    parse(&doc);
    // A separate active payload must count toward the same total.
    doc["active"]["runtime"]["scripts"] = configured(json!({"active":{
        "kind":"inline","content":"x","mode":493,
        "digest":"sha256:2d711642b726b04401627ca9fbac32f5c8530fb1903cc4db02258717921a4881"
    }}));
    let error = SavedSandboxConfig::from_bytes(&serde_json::to_vec(&doc).unwrap())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("combined active and pending"), "{error}");
}

#[test]
fn pending_init_bindings_obey_inventory_and_capture_controls() {
    let mut doc = document();
    doc["pending"] = json!({"runtime":pending_runtime()});
    doc["bindings"] = json!({"init-input":"text"});
    let controls = BTreeMap::from([(
        RuntimeCaptureTarget::InitArg(0),
        RuntimeCaptureAction::Bind("replacement".into()),
    )]);
    let result = apply_runtime_capture_controls(parse(&doc), &controls, true).unwrap();
    assert_eq!(
        result.bindings,
        BTreeMap::from([("replacement".into(), SavedBindingKind::Text)])
    );
    assert!(result.active_binding_uses().unwrap().is_empty());
    doc["bindings"] = json!({"init-input":"certificate"});
    assert!(SavedSandboxConfig::from_bytes(&serde_json::to_vec(&doc).unwrap()).is_err());
}
