//! Pre-serialization sanitization of active and pending runtime capture input.

use std::collections::BTreeMap;

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn value<T>(value: T) -> SavedValue<T> {
    SavedValue::Value {
        value,
        origin: SavedOrigin::Observed,
    }
}

fn ordinary<'a>(secret: &'a str) -> RuntimeCaptureInput<'a> {
    RuntimeCaptureInput {
        workdir: Some(value("/workspace")),
        shell: Some(value("sh")),
        entrypoint: Some(value(vec![RuntimeCaptureText::Literal("sh")])),
        cmd: Some(value(vec![
            RuntimeCaptureText::Literal(secret),
            RuntimeCaptureText::Literal(""),
        ])),
        env: Some(value(BTreeMap::from([
            ("ordinary", RuntimeCaptureText::Literal("")),
            ("KEY.WITH.DOTS", RuntimeCaptureText::Literal(secret)),
        ]))),
        scripts: Some(value(BTreeMap::from([(
            "task",
            RuntimeCaptureScript::Inline {
                content: secret,
                mode: 0o640,
            },
        )]))),
        init: Some(value(RuntimeCaptureInit::Handoff {
            selection: SavedInitSelection::Auto,
            resolved_path: "/sbin/init",
            args: vec![RuntimeCaptureText::Literal(secret)],
            env: BTreeMap::from([("INIT", RuntimeCaptureText::Literal(secret))]),
        })),
        hostname: Some(value(SavedHostname::Generated {
            value: "source".into(),
        })),
        user: Some(value("42:43")),
        guest_clock: Some(value(crate::GuestClockPolicy::Off)),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn ordinary_literals_empty_values_and_original_init_intent_survive() {
    let projected =
        project_runtime_capture(ordinary("declared"), None, &BTreeMap::new(), false).unwrap();
    let encoded = serde_json::to_vec(&projected.active).unwrap();
    assert!(projected.bindings.is_empty());
    let decoded = SavedRuntimeConfig::from_bytes(&encoded).unwrap();
    assert_eq!(decoded, projected.active);
    let cmd = decoded.cmd.unwrap();
    assert_eq!(
        cmd.value().unwrap(),
        &vec![
            SavedText::Literal {
                value: "declared".into()
            },
            SavedText::Literal { value: "".into() }
        ]
    );
    assert!(matches!(
        decoded.init.unwrap().value(),
        Some(SavedInit::Handoff {
            selection: SavedInitSelection::Auto,
            ..
        })
    ));
    assert!(matches!(
        decoded.scripts.unwrap().value().unwrap()["task"],
        SavedScript::Inline { mode: 0o640, .. }
    ));
}

#[test]
fn excluded_text_is_removed_before_validation_for_active_and_pending() {
    // Invalid literal data proves the sanitizer did not validate/serialize its original form
    // first. A bound script must retain neither the body nor its original digest/mode.
    let secret = "SOURCE_PRIVATE\0".repeat(MAX_SAVED_SCRIPT_BYTES);
    let controls = BTreeMap::from([
        (
            RuntimeCaptureTarget::CmdArg(0),
            RuntimeCaptureAction::Bind("command".into()),
        ),
        (
            RuntimeCaptureTarget::EnvKey("KEY.WITH.DOTS".into()),
            RuntimeCaptureAction::Omit,
        ),
        (
            RuntimeCaptureTarget::ScriptKey("task".into()),
            RuntimeCaptureAction::Bind("script".into()),
        ),
        (
            RuntimeCaptureTarget::InitArg(0),
            RuntimeCaptureAction::Bind("init".into()),
        ),
        (
            RuntimeCaptureTarget::InitEnvKey("INIT".into()),
            RuntimeCaptureAction::Bind("init".into()),
        ),
    ]);
    let projected =
        project_runtime_capture(ordinary(&secret), Some(ordinary(&secret)), &controls, true)
            .unwrap();
    assert_eq!(
        projected.bindings,
        BTreeMap::from([
            ("command".into(), SavedBindingKind::Text),
            ("init".into(), SavedBindingKind::Text),
            ("script".into(), SavedBindingKind::Text),
        ])
    );
    for output in [&projected.active, projected.pending.as_ref().unwrap()] {
        let encoded = serde_json::to_string(output).unwrap();
        assert!(!encoded.contains("SOURCE_PRIVATE"));
        assert!(!encoded.contains("digest"));
        assert!(!encoded.contains("mode"));
        assert!(
            !output
                .env
                .as_ref()
                .unwrap()
                .value()
                .unwrap()
                .contains_key("KEY.WITH.DOTS")
        );
        assert!(matches!(
            output.scripts.as_ref().unwrap().value().unwrap()["task"],
            SavedScript::Binding { .. }
        ));
        SavedRuntimeConfig::from_bytes(encoded.as_bytes()).unwrap();
    }
}

#[test]
fn host_or_unknown_text_requires_a_binding_or_permitted_omission() {
    for action in [
        None,
        Some(RuntimeCaptureAction::Bind("replacement".into())),
        Some(RuntimeCaptureAction::Omit),
    ] {
        let input = RuntimeCaptureInput {
            env: Some(value(BTreeMap::from([(
                "private-key-name",
                RuntimeCaptureText::BindingRequired,
            )]))),
            ..Default::default()
        };
        let controls = action
            .map(|action| {
                BTreeMap::from([(
                    RuntimeCaptureTarget::EnvKey("private-key-name".into()),
                    action,
                )])
            })
            .unwrap_or_default();
        let result = project_runtime_capture(input, None, &controls, false);
        if controls.is_empty() {
            let error = result.err().unwrap().to_string();
            assert!(error.contains("SCFG_BINDING: runtime.env"));
            assert!(!error.contains("private-key-name"));
        } else {
            let result = result.unwrap();
            assert!(
                !serde_json::to_string(&result.active)
                    .unwrap()
                    .contains("literal")
            );
        }
    }
}

#[test]
fn omitting_whole_optional_fields_never_visits_unclassified_children() {
    let input = RuntimeCaptureInput {
        cmd: Some(value(vec![RuntimeCaptureText::BindingRequired])),
        init: Some(value(RuntimeCaptureInit::Handoff {
            selection: SavedInitSelection::Path,
            resolved_path: "invalid\0path",
            args: vec![RuntimeCaptureText::BindingRequired],
            env: BTreeMap::new(),
        })),
        scripts: Some(value(BTreeMap::from([(
            "task",
            RuntimeCaptureScript::BindingRequired,
        )]))),
        ..Default::default()
    };
    let controls = [
        RuntimeCaptureTarget::Cmd,
        RuntimeCaptureTarget::Init,
        RuntimeCaptureTarget::Scripts,
    ]
    .into_iter()
    .map(|t| (t, RuntimeCaptureAction::Omit))
    .collect();
    let output = project_runtime_capture(input, None, &controls, false).unwrap();
    assert_eq!(output.active, SavedRuntimeConfig::default());
    assert!(output.bindings.is_empty());
}

#[test]
fn unknown_and_pending_values_cannot_manufacture_active_input() {
    let input = RuntimeCaptureInput {
        env: Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded,
        }),
        cmd: Some(SavedValue::Default {}),
        ..Default::default()
    };
    let pending = RuntimeCaptureInput {
        env: Some(value(BTreeMap::from([(
            "later",
            RuntimeCaptureText::BindingRequired,
        )]))),
        ..Default::default()
    };
    let controls = BTreeMap::from([(
        RuntimeCaptureTarget::EnvKey("later".into()),
        RuntimeCaptureAction::Bind("deferred".into()),
    )]);
    let output = project_runtime_capture(input, Some(pending), &controls, false).unwrap();
    assert!(matches!(
        output.active.env,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
    assert!(matches!(output.active.cmd, Some(SavedValue::Default {})));
    assert!(matches!(
        output.pending.unwrap().env.unwrap().value().unwrap()["later"],
        SavedText::Binding { .. }
    ));
}

#[test]
fn full_capture_rejects_omission_of_active_backing_but_sanitizes_pending_only() {
    for target in [
        RuntimeCaptureTarget::Scripts,
        RuntimeCaptureTarget::ScriptKey("task".into()),
        RuntimeCaptureTarget::Init,
        RuntimeCaptureTarget::Hostname,
        RuntimeCaptureTarget::GuestClock,
    ] {
        let controls = BTreeMap::from([(target, RuntimeCaptureAction::Omit)]);
        let error = project_runtime_capture(ordinary("literal"), None, &controls, true)
            .err()
            .unwrap();
        assert!(error.to_string().contains("SCFG_IDENTITY"));
        project_runtime_capture(
            RuntimeCaptureInput::default(),
            Some(ordinary("literal")),
            &controls,
            true,
        )
        .unwrap();
    }
}

#[test]
fn invalid_unmatched_and_overlapping_controls_refuse_without_echoing_input() {
    for controls in [
        BTreeMap::from([(RuntimeCaptureTarget::CmdArg(0), RuntimeCaptureAction::Omit)]),
        BTreeMap::from([(
            RuntimeCaptureTarget::InitEnvKey("INIT".into()),
            RuntimeCaptureAction::Omit,
        )]),
        BTreeMap::from([(
            RuntimeCaptureTarget::Cmd,
            RuntimeCaptureAction::Bind("id".into()),
        )]),
        BTreeMap::from([(
            RuntimeCaptureTarget::CmdArg(0),
            RuntimeCaptureAction::Bind("PRIVATE_ID/invalid".into()),
        )]),
        BTreeMap::from([(
            RuntimeCaptureTarget::CmdArg(4),
            RuntimeCaptureAction::Bind("id".into()),
        )]),
        BTreeMap::from([(
            RuntimeCaptureTarget::EnvKey("PRIVATE_KEY".into()),
            RuntimeCaptureAction::Omit,
        )]),
        BTreeMap::from([
            (RuntimeCaptureTarget::Env, RuntimeCaptureAction::Omit),
            (
                RuntimeCaptureTarget::EnvKey("ordinary".into()),
                RuntimeCaptureAction::Omit,
            ),
        ]),
    ] {
        let error = project_runtime_capture(ordinary("PRIVATE_VALUE"), None, &controls, false)
            .err()
            .unwrap()
            .to_string();
        for secret in ["PRIVATE_VALUE", "PRIVATE_KEY", "PRIVATE_ID"] {
            assert!(!error.contains(secret));
        }
    }
}

#[test]
fn pending_script_match_cannot_authorize_omission_from_unknown_full_backing() {
    let controls = BTreeMap::from([(
        RuntimeCaptureTarget::ScriptKey("task".into()),
        RuntimeCaptureAction::Omit,
    )]);
    for scripts in [
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded,
        }),
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotObserved,
        }),
        Some(SavedValue::Default {}),
    ] {
        let active = RuntimeCaptureInput {
            scripts,
            ..Default::default()
        };
        let error = project_runtime_capture(
            active,
            Some(ordinary("PRIVATE_PENDING_BODY")),
            &controls,
            true,
        )
        .err()
        .expect("pending intent cannot prove active backing absent")
        .to_string();
        assert!(error.contains("SCFG_IDENTITY"));
        assert!(!error.contains("PRIVATE_PENDING_BODY"));
    }
    // Known absence still permits sanitizing pending-only content, and disk capture
    // does not claim to preserve the active runtime share.
    for (scripts, full) in [
        (Some(value(BTreeMap::new())), true),
        (None, true),
        (
            Some(SavedValue::Unknown {
                reason: SavedUnknownReason::NotObserved,
            }),
            false,
        ),
    ] {
        let output = project_runtime_capture(
            RuntimeCaptureInput {
                scripts,
                ..Default::default()
            },
            Some(ordinary("PRIVATE_PENDING_BODY")),
            &controls,
            full,
        )
        .unwrap();
        assert!(
            output
                .pending
                .unwrap()
                .scripts
                .unwrap()
                .value()
                .unwrap()
                .is_empty()
        );
    }
}

#[test]
fn retained_oversized_text_is_rejected_without_echoing_it() {
    let content = "PRIVATE".repeat(MAX_SAVED_SCRIPT_BYTES);
    let error = project_runtime_capture(ordinary(&content), None, &BTreeMap::new(), false)
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("SCFG_LIMIT"));
    assert!(!error.contains("PRIVATE"));
}
