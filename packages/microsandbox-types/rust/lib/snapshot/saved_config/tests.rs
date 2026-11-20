//! Behavioral and hostile-input checks for the portable runtime section.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn field_presence_preserves_omitted_unknown_default_and_empty() {
    let forms = [
        json!({}),
        json!({"cmd": {"state": "unknown", "reason": "not_recorded"}}),
        json!({"cmd": {"state": "default"}}),
        json!({"cmd": recorded(json!([]))}),
    ];
    let parsed: Vec<_> = forms.iter().map(parse).collect();
    for (index, config) in parsed.iter().enumerate() {
        assert_eq!(serde_json::to_value(config).unwrap(), forms[index]);
        for other in parsed.iter().skip(index + 1) {
            assert_ne!(config, other);
        }
    }
}

#[test]
fn present_null_is_not_silently_dropped_for_any_runtime_field() {
    for field in [
        "workdir",
        "shell",
        "entrypoint",
        "cmd",
        "env",
        "scripts",
        "init",
        "hostname",
        "user",
        "guest_clock",
    ] {
        let value = json!({field: null});
        reject(&value, "SCFG_SCHEMA");
    }
}

#[test]
fn init_keeps_builtin_unknown_and_resolved_auto_distinct() {
    let builtin = parse(&json!({"init": recorded(json!({"kind": "builtin"}))}));
    let unknown = parse(&json!({"init": {"state": "unknown", "reason": "not_observed"}}));
    let auto = parse(&json!({"init": recorded(json!({
        "kind": "handoff", "selection": "auto", "resolved_path": "/sbin/init",
        "args": [literal("--unit=multi-user.target")],
        "env": {"BOOT_TOKEN": {"kind": "binding", "id": "init.boot-token"}}
    }))}));
    assert_ne!(builtin, unknown);
    assert_ne!(auto, builtin);
    assert!(
        matches!(auto.init.as_ref().and_then(SavedValue::value), Some(SavedInit::Handoff { selection: SavedInitSelection::Auto, resolved_path, .. }) if resolved_path == "/sbin/init")
    );

    for path in ["auto", "sbin/init", "C:\\host\\init", "/sbin/\0init"] {
        reject(
            &json!({"init": recorded(json!({
                "kind": "handoff", "selection": "auto", "resolved_path": path, "args": [], "env": {}
            }))}),
            "active.runtime.init.resolved_path",
        );
    }
}

#[test]
fn command_defaults_keep_exact_argv_and_do_not_reinterpret_literals() {
    let value = json!({
        "shell": recorded(json!("bash")),
        "workdir": recorded(json!("app")),
        "entrypoint": recorded(json!([literal("/bin/echo")])),
        "cmd": recorded(json!([literal(""), literal("$(touch /tmp/not-a-hook)"), literal("a\nb")])),
        "env": recorded(json!({"TOKEN": literal("ordinary explicitly declared text"), "A.B": literal("")}))
    });
    let config = parse(&value);
    assert_eq!(serde_json::to_value(config).unwrap(), value);
}

#[test]
fn unknown_operational_fields_and_injected_host_objects_refuse() {
    for value in [
        json!({"post_restore_hook": "SENTINEL"}),
        json!({"registry_auth": {"password": "SENTINEL"}}),
        json!({"env": recorded(json!({"TOKEN": {"kind": "binding", "id": "token", "value": "SENTINEL"}}))}),
        json!({"init": recorded(json!({"kind": "builtin", "host_path": "SENTINEL"}))}),
        json!({"scripts": recorded(json!({"boot": {"kind": "binding", "id": "script.boot", "content": "SENTINEL"}}))}),
        json!({"cmd": {"state": "value", "origin": "configured", "value": [], "safe_to_apply": true}}),
        json!({"hostname": recorded(json!({"kind": "source_lookup", "value": "SENTINEL"}))}),
    ] {
        let error = reject(&value, "SCFG_SCHEMA");
        assert!(!error.contains("SENTINEL"));
    }
}

#[test]
fn malformed_input_errors_never_echo_values_or_unrecognized_keys() {
    for input in [
        r#"{"SENTINEL":null,"SENTINEL":1}"#,
        r#"{"cmd":{"state":"SENTINEL"}}"#,
        r#"{"cmd":{"state":"value","value":"SENTINEL","origin":"configured"}}"#,
        r#"{"cmd":{"state":"value","value":[],"origin":"SENTINEL"}}"#,
        r#"{"SENTINEL":#}"#,
    ] {
        let error = SavedRuntimeConfig::from_bytes(input.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(!error.contains("SENTINEL"));
        assert!(error.contains("active.runtime"));
    }
}

#[test]
fn duplicate_keys_refuse_at_every_nested_level() {
    for input in [
        r#"{"env":{"state":"default"},"env":{"state":"default"}}"#,
        r#"{"env":{"state":"value","origin":"configured","value":{"A":{"kind":"literal","value":"x"},"A":{"kind":"literal","value":"y"}}}}"#,
        r#"{"cmd":{"state":"value","origin":"configured","value":[{"kind":"literal","value":"x","value":"y"}]}}"#,
    ] {
        let error = SavedRuntimeConfig::from_bytes(input.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(error.contains("SCFG_JSON"));
    }
}

#[test]
fn script_bytes_are_exact_and_digest_detects_alteration() {
    let body = "#!/bin/custom-shell\r\necho 'café\\n'\n";
    let mut value = json!({"scripts": recorded(json!({"health": script(body, 0o755)}))});
    let config = parse(&value);
    assert_eq!(serde_json::to_value(&config).unwrap(), value);
    assert!(!format!("{config:?}").contains("custom-shell"));

    value["scripts"]["value"]["health"]["content"] = json!(format!("{body}tampered"));
    reject(&value, "SCFG_INTEGRITY");
}

#[test]
fn script_names_cannot_escape_or_be_repaired_into_a_different_name() {
    for name in [
        "",
        ".",
        "..",
        "../escape",
        "/absolute",
        "a/b",
        "a\\b",
        "a\0b",
    ] {
        reject(
            &json!({"scripts": recorded(json!({name: script("echo ok", 0o755)}))}),
            "active.runtime.scripts",
        );
    }
    parse(&json!({"scripts": recorded(json!({"check.v2": script("echo ok", 0o755)}))}));
}

#[test]
fn script_permissions_do_not_smuggle_privilege_or_object_types() {
    for mode in [0o1755, 0o2755, 0o4755, 0o100755] {
        reject(
            &json!({"scripts": recorded(json!({"check": script("echo ok", mode)}))}),
            "SCFG_",
        );
    }
    for mode in [0o444, 0o555, 0o755] {
        parse(&json!({"scripts": recorded(json!({"check": script("echo ok", mode)}))}));
    }
}

#[test]
fn binding_identifier_is_not_a_url_path_or_secret_value() {
    for id in [
        "",
        "../file/key",
        "https://host/key",
        "token secret",
        "a\0b",
    ] {
        let error = reject(
            &json!({"env": recorded(json!({"TOKEN": {"kind": "binding", "id": id}}))}),
            "SCFG_BINDING",
        );
        assert!(!error.contains("TOKEN"));
    }
    parse(
        &json!({"scripts": recorded(json!({"health": {"kind": "binding", "id": "script.health-v2"}}))}),
    );
}

#[test]
fn environment_and_argv_boundaries_match_process_inputs() {
    for name in ["", "a=b", "a\0b"] {
        reject(
            &json!({"env": recorded(json!({name: literal("v")}))}),
            "active.runtime.env",
        );
    }
    reject(
        &json!({"cmd": recorded(json!([literal("SENTINEL\0")]))}),
        "active.runtime.cmd",
    );
    reject(
        &json!({"init": recorded(json!({"kind":"handoff", "selection":"path", "resolved_path":"/bin/init", "args":[], "env":{"A":literal("v\0")}}))}),
        "active.runtime.init.env",
    );
}

#[test]
fn map_list_depth_and_encoded_size_limits_refuse_without_truncation() {
    parse(&json!({"cmd": recorded(json!(vec![literal(""); MAX_SAVED_CONFIG_ENTRIES]))}));
    reject(
        &json!({"cmd": recorded(json!(vec![literal(""); MAX_SAVED_CONFIG_ENTRIES + 1]))}),
        "SCFG_LIMIT",
    );
    let entries: BTreeMap<_, _> = (0..=MAX_SAVED_CONFIG_ENTRIES)
        .map(|i| (format!("E{i}"), literal("")))
        .collect();
    reject(&json!({"env": recorded(json!(entries))}), "SCFG_LIMIT");

    let mut nested = json!(0);
    for _ in 0..26 {
        nested = json!([nested]);
    }
    reject(&json!({"unknown": nested}), "SCFG_LIMIT");
    let oversized = vec![b' '; MAX_SAVED_CONFIG_BYTES + 1];
    assert!(
        SavedRuntimeConfig::from_bytes(&oversized)
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
}

#[test]
fn script_size_limits_apply_individually_and_in_aggregate() {
    let body = "x".repeat(MAX_SAVED_SCRIPT_BYTES);
    parse(&json!({"scripts": recorded(json!({"check": script(&body, 0o755)}))}));
    reject(
        &json!({"scripts": recorded(json!({"check": script(&(body.clone() + "x"), 0o755)}))}),
        "script payload is too large",
    );

    let mut scripts: BTreeMap<_, _> = (0..4)
        .map(|i| (format!("check{i}"), script(&body, 0o755)))
        .collect();
    parse(&json!({"scripts": recorded(json!(scripts))}));
    scripts.insert("extra".into(), script("x", 0o755));
    reject(
        &json!({"scripts": recorded(json!(scripts))}),
        "combined script payload is too large",
    );
}

#[test]
fn typed_construction_cannot_bypass_semantic_validation() {
    let config = SavedRuntimeConfig {
        env: Some(SavedValue::Value {
            value: BTreeMap::from([(
                "TOKEN".into(),
                SavedText::Literal {
                    value: "SENTINEL\0".into(),
                },
            )]),
            origin: SavedOrigin::Configured,
        }),
        ..Default::default()
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("active.runtime.env"));
    assert!(!error.contains("SENTINEL"));
}

#[test]
fn draft_types_do_not_enable_saved_config_descriptor_support() {
    assert!(!crate::snapshot::SUPPORTED_REQUIRES.contains(&"microsandbox.sandbox-config"));
}

fn recorded(value: Value) -> Value {
    json!({"state": "value", "value": value, "origin": "configured"})
}

fn literal(value: &str) -> Value {
    json!({"kind": "literal", "value": value})
}

fn script(content: &str, mode: u32) -> Value {
    json!({"kind": "inline", "content": content, "mode": mode, "digest": format!("sha256:{}", hex::encode(Sha256::digest(content.as_bytes())))})
}

fn parse(value: &Value) -> SavedRuntimeConfig {
    SavedRuntimeConfig::from_bytes(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn reject(value: &Value, expected: &str) -> String {
    let error = SavedRuntimeConfig::from_bytes(&serde_json::to_vec(value).unwrap())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(expected),
        "expected {expected}, received {error}"
    );
    error
}
