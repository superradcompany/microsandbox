//! Raw-source provenance, secret exclusion and observed-backing projection together.

use std::collections::BTreeMap;

use microsandbox_protocol::init_observation::InitObservation;
use microsandbox_runtime::retention::{
    CapturedScriptBacking, CapturedScriptDirectory, ScriptBackingEvidence,
};
use microsandbox_types::snapshot::saved_config::{
    RuntimeCaptureAction, RuntimeCaptureTarget, SavedHostname, SavedInit, SavedInitSelection,
    SavedScript, SavedText, SavedUnknownReason, SavedValue, project_runtime_capture,
};
use serde_json::{Value, json};

use crate::sandbox::SandboxBuilder;

use super::RuntimeCaptureSource;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn source() -> Value {
    let config = SandboxBuilder::new("source")
        .image("alpine")
        .cmd(["reusable-default"])
        .background_command(["PRIVATE_INVOCATION"])
        .env("literal", "declared")
        .host_env("host".into(), "PRIVATE_HOST".into())
        .init_with("/init", |init| {
            init.host_env("init_host".into(), "PRIVATE_INIT_HOST".into())
        })
        .finish(None, None)
        .unwrap();
    serde_json::to_value(config.clone_for_persistence()).unwrap()
}

fn bindings() -> BTreeMap<RuntimeCaptureTarget, RuntimeCaptureAction> {
    BTreeMap::from([
        (
            RuntimeCaptureTarget::EnvKey("host".into()),
            RuntimeCaptureAction::Bind("host-input".into()),
        ),
        (
            RuntimeCaptureTarget::InitEnvKey("init_host".into()),
            RuntimeCaptureAction::Bind("init-input".into()),
        ),
    ])
}

fn observed_scripts() -> ScriptBackingEvidence {
    ScriptBackingEvidence::Observed {
        runtime_directory: CapturedScriptDirectory {
            uid: 0,
            gid: 0,
            mode: 0o755,
        },
        scripts_directory: CapturedScriptDirectory {
            uid: 0,
            gid: 0,
            mode: 0o755,
        },
        files: BTreeMap::from([(
            "task".into(),
            CapturedScriptBacking {
                content: "guest-mutated-backing".into(),
                uid: 42,
                gid: 43,
                mode: 0o640,
            },
        )]),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn runtime_capture_source_uses_reusable_cmd_and_binds_host_inputs() {
    let raw = source();
    let init = InitObservation::Handoff {
        path: "/init".into(),
    };
    let source = RuntimeCaptureSource::from_recorded(&raw, Some(&init), None).unwrap();
    let projected = project_runtime_capture(source.input(), None, &bindings(), false).unwrap();
    let json = serde_json::to_string(&projected.active).unwrap();
    for secret in ["PRIVATE_HOST", "PRIVATE_INIT_HOST", "PRIVATE_INVOCATION"] {
        assert!(!json.contains(secret));
    }
    assert_eq!(
        projected.active.cmd.as_ref().unwrap().value().unwrap(),
        &vec![SavedText::Literal {
            value: "reusable-default".into()
        }]
    );
    assert_eq!(
        projected.active.env.as_ref().unwrap().value().unwrap()["literal"],
        SavedText::Literal {
            value: "declared".into()
        }
    );
    assert!(matches!(
        projected.active.init.as_ref().unwrap().value(),
        Some(SavedInit::Handoff {
            selection: SavedInitSelection::Path,
            ..
        })
    ));
    assert_eq!(projected.bindings.len(), 2);
}

#[test]
fn runtime_capture_missing_fields_do_not_acquire_serde_defaults() {
    let mut raw = source();
    for key in [
        "runtime",
        "env",
        "init",
        "command_provenance",
        "environment_provenance",
        "init_provenance",
    ] {
        raw.as_object_mut().unwrap().remove(key);
    }
    let source = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let projected = project_runtime_capture(source.input(), None, &BTreeMap::new(), false).unwrap();
    let encoded = serde_json::to_value(projected.active).unwrap();
    for field in [
        "workdir",
        "shell",
        "entrypoint",
        "cmd",
        "env",
        "scripts",
        "hostname",
        "user",
        "guest_clock",
    ] {
        assert_eq!(
            encoded[field],
            json!({"state":"unknown","reason":"not_recorded"})
        );
    }
    assert_eq!(
        encoded["init"],
        json!({"state":"unknown","reason":"not_observed"})
    );
}

#[test]
fn runtime_capture_historical_values_require_positive_environment_origin() {
    let mut raw = source();
    raw.as_object_mut().unwrap().remove("command_provenance");
    raw.as_object_mut()
        .unwrap()
        .remove("environment_provenance");
    let source = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let error = project_runtime_capture(source.input(), None, &BTreeMap::new(), false)
        .err()
        .unwrap();
    assert!(error.to_string().contains("SCFG_BINDING"));
    assert!(!error.to_string().contains("PRIVATE"));
    let controls = BTreeMap::from([(RuntimeCaptureTarget::Env, RuntimeCaptureAction::Omit)]);
    let projected = project_runtime_capture(source.input(), None, &controls, false).unwrap();
    assert!(matches!(
        projected.active.cmd,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
    assert!(projected.active.env.is_none());
}

#[test]
fn runtime_capture_typed_secret_key_cannot_be_exported_as_a_declared_literal() {
    let mut raw = source();
    raw["network"]["secrets"] = json!({"secrets":[{
        "env_var":"literal", "value":"PRIVATE_SECRET_VALUE", "placeholder":"placeholder"
    }]});
    let source = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let controls = BTreeMap::from([(
        RuntimeCaptureTarget::EnvKey("host".into()),
        RuntimeCaptureAction::Omit,
    )]);
    assert!(project_runtime_capture(source.input(), None, &controls, false).is_err());
    let controls = BTreeMap::from([
        (
            RuntimeCaptureTarget::EnvKey("host".into()),
            RuntimeCaptureAction::Omit,
        ),
        (
            RuntimeCaptureTarget::EnvKey("literal".into()),
            RuntimeCaptureAction::Bind("gateway-secret".into()),
        ),
    ]);
    let projected = project_runtime_capture(source.input(), None, &controls, false).unwrap();
    let json = serde_json::to_string(&projected.active).unwrap();
    assert!(!json.contains("PRIVATE_SECRET_VALUE"));
    assert!(!json.contains("declared"));
    assert!(matches!(
        projected.active.env.unwrap().value().unwrap()["literal"],
        SavedText::Binding { .. }
    ));
}

#[test]
fn runtime_capture_uses_observed_script_bytes_and_preserves_unknown_backing() {
    let mut raw = source();
    raw["runtime"]["scripts"] = json!({"task":"PRIVATE_STALE_REGISTERED_BODY"});
    let controls = BTreeMap::from([(RuntimeCaptureTarget::Env, RuntimeCaptureAction::Omit)]);
    let missing = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let missing = project_runtime_capture(missing.input(), None, &controls, false).unwrap();
    assert!(matches!(
        missing.active.scripts,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotObserved
        })
    ));
    let backing = observed_scripts();
    let source = RuntimeCaptureSource::from_recorded(&raw, None, Some(&backing)).unwrap();
    let projected = project_runtime_capture(source.input(), None, &controls, false).unwrap();
    let serialized = serde_json::to_string(&projected.active).unwrap();
    assert!(!serialized.contains("PRIVATE_STALE_REGISTERED_BODY"));
    match &projected.active.scripts.unwrap().value().unwrap()["task"] {
        SavedScript::Inline { content, mode, .. } => {
            assert_eq!(content, "guest-mutated-backing");
            assert_eq!(*mode, 0o640);
        }
        _ => panic!("expected observed script"),
    }
}

#[test]
fn runtime_capture_contradictions_refuse_with_redacted_errors() {
    let mut raw = source();
    raw["env"][1]["value"] = json!("PRIVATE_CHANGED_VALUE");
    let error = RuntimeCaptureSource::from_recorded(&raw, None, None)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("SCFG_INTEGRITY"));
    assert!(!error.contains("PRIVATE"));
    let raw = source();
    let wrong_init = InitObservation::Handoff {
        path: "/PRIVATE_OTHER_INIT".into(),
    };
    assert!(RuntimeCaptureSource::from_recorded(&raw, Some(&wrong_init), None).is_err());
    assert!(RuntimeCaptureSource::from_recorded(&raw, None, Some(&observed_scripts())).is_err());
    assert!(
        RuntimeCaptureSource::from_recorded(&json!({"env":"PRIVATE_BAD_TYPE"}), None, None)
            .err()
            .unwrap()
            .to_string()
            .find("PRIVATE")
            .is_none()
    );
}

#[test]
fn runtime_capture_original_auto_selection_survives_guest_resolution() {
    let config = SandboxBuilder::new("auto")
        .image("alpine")
        .init("auto")
        .finish(None, None)
        .unwrap();
    let raw = serde_json::to_value(config.clone_for_persistence()).unwrap();
    let observed = InitObservation::Handoff {
        path: "/sbin/init".into(),
    };
    let source = RuntimeCaptureSource::from_recorded(&raw, Some(&observed), None).unwrap();
    let projected = project_runtime_capture(source.input(), None, &BTreeMap::new(), false).unwrap();
    assert!(
        matches!(projected.active.init.unwrap().value(), Some(SavedInit::Handoff { selection: SavedInitSelection::Auto, resolved_path, .. }) if resolved_path == "/sbin/init")
    );
    let source = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let projected = project_runtime_capture(source.input(), None, &BTreeMap::new(), false).unwrap();
    assert!(matches!(
        projected.active.init,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotObserved
        })
    ));
}

#[test]
fn runtime_capture_default_empty_and_generated_are_not_missing() {
    let config = SandboxBuilder::new("source-name")
        .image("alpine")
        .cmd(Vec::<String>::new())
        .finish(None, None)
        .unwrap();
    let mut raw = serde_json::to_value(config.clone_for_persistence()).unwrap();
    raw["runtime"]["workdir"] = Value::Null;
    let source =
        RuntimeCaptureSource::from_recorded(&raw, Some(&InitObservation::Builtin), None).unwrap();
    let projected = project_runtime_capture(source.input(), None, &BTreeMap::new(), false).unwrap();
    assert!(matches!(
        projected.active.workdir,
        Some(SavedValue::Default {})
    ));
    assert!(projected.active.cmd.unwrap().value().unwrap().is_empty());
    assert!(matches!(
        projected.active.hostname.unwrap().value(),
        Some(SavedHostname::Generated { .. })
    ));
    assert!(matches!(
        projected.active.init.unwrap().value(),
        Some(SavedInit::Builtin {})
    ));
}

#[test]
#[ignore = "requires MSB_RUNTIME_CAPTURE_FIXTURES from the live receipt collector"]
fn runtime_capture_live_records() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("MSB_RUNTIME_CAPTURE_FIXTURES").expect("live fixture directory"),
    );
    for case in ["new-default", "new-detached"] {
        let bytes = std::fs::read(directory.join(format!("{case}-receipt.json"))).unwrap();
        let fixture: Value = serde_json::from_slice(&bytes).unwrap();
        let record = &fixture["record"];
        let raw = &record["source"]["source"];
        assert!(
            raw.is_object(),
            "live capture must contain confirmed source"
        );
        let init: Option<InitObservation> = serde_json::from_value(record["init"].clone()).unwrap();
        let scripts: Option<ScriptBackingEvidence> =
            serde_json::from_value(record["scripts"].clone()).unwrap();
        let source =
            RuntimeCaptureSource::from_recorded(raw, init.as_ref(), scripts.as_ref()).unwrap();
        let controls = BTreeMap::from([(
            RuntimeCaptureTarget::EnvKey("ORIGIN_HOST".into()),
            RuntimeCaptureAction::Bind("host-input".into()),
        )]);
        let projection = project_runtime_capture(source.input(), None, &controls, false).unwrap();
        let encoded = serde_json::to_string(&projection.active).unwrap();
        assert!(!encoded.contains("host-sentinel"));
        assert!(!encoded.contains("invocation-ran"));
        assert!(!encoded.contains("registered-private-body"));
        assert!(encoded.contains("default-ran"));
        let env = projection.active.env.as_ref().unwrap().value().unwrap();
        assert_eq!(
            env["ORIGIN_LITERAL"],
            SavedText::Literal {
                value: "plain".into()
            }
        );
        assert_eq!(
            env["ORIGIN_OVERRIDE"],
            SavedText::Literal {
                value: "explicit".into()
            }
        );
        assert!(matches!(env["ORIGIN_HOST"], SavedText::Binding { .. }));
        match &projection.active.scripts.as_ref().unwrap().value().unwrap()["task"] {
            SavedScript::Inline { content, mode, .. } => {
                assert_eq!(content, "observed-script-body\n");
                assert_eq!(*mode, 0o640);
            }
            _ => panic!("expected observed backing"),
        }
        match &init {
            None => assert!(matches!(
                projection.active.init,
                Some(SavedValue::Unknown {
                    reason: SavedUnknownReason::NotObserved
                })
            )),
            Some(InitObservation::Builtin) => assert!(matches!(
                projection.active.init.as_ref().unwrap().value(),
                Some(SavedInit::Builtin {})
            )),
            Some(InitObservation::Handoff { .. }) => panic!("fixture did not request handoff"),
        }
        let mut controls = controls;
        controls.insert(
            RuntimeCaptureTarget::ScriptKey("task".into()),
            RuntimeCaptureAction::Bind("script-input".into()),
        );
        let excluded = project_runtime_capture(source.input(), None, &controls, false).unwrap();
        let encoded = serde_json::to_string(&excluded.active).unwrap();
        assert!(!encoded.contains("observed-script-body"));
        assert!(!encoded.contains("digest"));
    }
}

#[test]
#[ignore = "requires MSB_RUNTIME_INIT_CAPTURE_FIXTURES from the live init collector"]
fn runtime_capture_live_init_records() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("MSB_RUNTIME_INIT_CAPTURE_FIXTURES").expect("live init fixture directory"),
    );
    for case in ["builtin", "explicit", "auto"] {
        let fixture: Value = serde_json::from_slice(
            &std::fs::read(directory.join(format!("{case}-source.json"))).unwrap(),
        )
        .unwrap();
        let raw = &fixture["source"];
        let init: InitObservation = serde_json::from_value(fixture["init"].clone()).unwrap();
        let source = RuntimeCaptureSource::from_recorded(raw, Some(&init), None).unwrap();
        let projected =
            project_runtime_capture(source.input(), None, &BTreeMap::new(), false).unwrap();
        // Unlike the older-agent fixtures, these captures must positively identify init.
        // Auto intent survives resolution, but restore must use the captured executable.
        let saved = projected.active.init.as_ref().unwrap().value().unwrap();
        match (case, saved) {
            ("builtin", SavedInit::Builtin {}) => {}
            (
                "explicit" | "auto",
                SavedInit::Handoff {
                    selection,
                    resolved_path,
                    args,
                    env,
                },
            ) => {
                assert_eq!(resolved_path, "/sbin/init");
                assert_eq!(
                    *selection,
                    if case == "auto" {
                        SavedInitSelection::Auto
                    } else {
                        SavedInitSelection::Path
                    }
                );
                assert!(args.is_empty());
                // Auto init inherits the image environment; explicit init keeps its
                // existing supplemental-only environment contract.
                let expected = if case == "auto" {
                    BTreeMap::from([(
                        "PATH".into(),
                        SavedText::Literal {
                            value: "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
                                .into(),
                        },
                    )])
                } else {
                    BTreeMap::new()
                };
                assert_eq!(*env, expected);
            }
            _ => panic!("capture did not preserve the selected init"),
        }
        let encoded = serde_json::to_string(&projected.active).unwrap();
        assert!(!encoded.contains("init_provenance"));
        assert!(!encoded.contains("runtime_boot_id"));
    }
}
