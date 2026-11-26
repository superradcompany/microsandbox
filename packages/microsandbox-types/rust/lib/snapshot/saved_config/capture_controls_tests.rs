//! Exclusion, binding demand and redaction across active and pending capture metadata.

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn literal(value: &str) -> SavedText {
    SavedText::Literal {
        value: value.into(),
    }
}
fn value<T>(value: T) -> SavedValue<T> {
    SavedValue::Value {
        value,
        origin: SavedOrigin::Observed,
    }
}

fn document() -> SavedSandboxConfig {
    let runtime = SavedRuntimeConfig {
        entrypoint: Some(value(vec![
            literal("first"),
            literal("PRIVATE_ENTRY"),
            literal("last"),
        ])),
        cmd: Some(value(vec![literal("PRIVATE_CMD")])),
        env: Some(value(BTreeMap::from([
            ("KEY.WITH.DOTS".into(), literal("PRIVATE_ENV")),
            ("ordinary".into(), literal("")),
        ]))),
        scripts: Some(value(BTreeMap::from([(
            "task.sh".into(),
            SavedScript::Inline {
                content: "PRIVATE_SCRIPT".into(),
                mode: 0o640,
                digest: format!("sha256:{}", hex::encode(Sha256::digest("PRIVATE_SCRIPT"))),
            },
        )]))),
        init: Some(value(SavedInit::Handoff {
            selection: SavedInitSelection::Path,
            resolved_path: "/sbin/init".into(),
            args: vec![literal("PRIVATE_INIT_ARG")],
            env: BTreeMap::from([("INIT".into(), literal("PRIVATE_INIT_ENV"))]),
        })),
        ..Default::default()
    };
    let active = SavedActiveConfig {
        runtime,
        ..Default::default()
    };
    SavedSandboxConfig {
        schema_version: SAVED_CONFIG_SCHEMA_VERSION,
        pending: Some(active.clone()),
        active,
        bindings: BTreeMap::new(),
        provenance: SavedCaptureProvenance {
            producer_version: "test".into(),
            source_name: None,
            active_generation: value("1".into()),
            construction_resources: None,
        },
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn binding_substitution_removes_active_and_pending_content_without_shifting_arguments() {
    let draft = document();
    let controls = BTreeMap::from([
        (
            RuntimeCaptureTarget::EntrypointArg(1),
            RuntimeCaptureAction::Bind("entry".into()),
        ),
        (
            RuntimeCaptureTarget::CmdArg(0),
            RuntimeCaptureAction::Bind("command".into()),
        ),
        (
            RuntimeCaptureTarget::EnvKey("KEY.WITH.DOTS".into()),
            RuntimeCaptureAction::Bind("environment".into()),
        ),
        (
            RuntimeCaptureTarget::InitArg(0),
            RuntimeCaptureAction::Bind("init-argument".into()),
        ),
        (
            RuntimeCaptureTarget::InitEnvKey("INIT".into()),
            RuntimeCaptureAction::Bind("init-env".into()),
        ),
        (
            RuntimeCaptureTarget::ScriptKey("task.sh".into()),
            RuntimeCaptureAction::Bind("script".into()),
        ),
    ]);
    let original_digest = format!("sha256:{}", hex::encode(Sha256::digest("PRIVATE_SCRIPT")));
    let projected = apply_runtime_capture_controls(draft, &controls, true).unwrap();
    let bytes = serde_json::to_string(&projected).unwrap();
    for secret in [
        "PRIVATE_ENTRY",
        "PRIVATE_CMD",
        "PRIVATE_ENV",
        "PRIVATE_INIT_ARG",
        "PRIVATE_INIT_ENV",
        "PRIVATE_SCRIPT",
        &original_digest,
    ] {
        assert!(!bytes.contains(secret), "excluded value survived capture");
    }
    assert_eq!(
        projected
            .active
            .runtime
            .entrypoint
            .as_ref()
            .unwrap()
            .value()
            .unwrap()
            .len(),
        3
    );
    let uses = projected.active_binding_uses().unwrap();
    assert!(
        uses["entry"]
            .consumers
            .contains(&SavedBindingConsumer::NewCommand)
    );
    assert!(
        uses["init-argument"]
            .consumers
            .contains(&SavedBindingConsumer::BootInit)
    );
    assert!(
        uses["script"]
            .consumers
            .contains(&SavedBindingConsumer::ScriptBacking)
    );
    assert_eq!(projected.bindings.len(), controls.len());
    assert_eq!(
        SavedSandboxConfig::from_bytes(bytes.as_bytes())
            .unwrap()
            .pending,
        projected.pending
    );
}

#[test]
fn omission_removes_optional_defaults_from_both_sections_but_preserves_sibling_keys() {
    let controls = BTreeMap::from([
        (
            RuntimeCaptureTarget::EnvKey("KEY.WITH.DOTS".into()),
            RuntimeCaptureAction::Omit,
        ),
        (
            RuntimeCaptureTarget::ScriptKey("task.sh".into()),
            RuntimeCaptureAction::Omit,
        ),
        (RuntimeCaptureTarget::Entrypoint, RuntimeCaptureAction::Omit),
        (RuntimeCaptureTarget::Cmd, RuntimeCaptureAction::Omit),
        (RuntimeCaptureTarget::Init, RuntimeCaptureAction::Omit),
    ]);
    let projected = apply_runtime_capture_controls(document(), &controls, false).unwrap();
    for section in [&projected.active, projected.pending.as_ref().unwrap()] {
        let env = section.runtime.env.as_ref().unwrap().value().unwrap();
        assert_eq!(env.len(), 1);
        assert_eq!(env["ordinary"], literal(""));
        assert!(section.runtime.entrypoint.is_none());
        assert!(section.runtime.cmd.is_none());
        assert!(section.runtime.init.is_none());
        assert!(
            section
                .runtime
                .scripts
                .as_ref()
                .unwrap()
                .value()
                .unwrap()
                .is_empty()
        );
    }
    assert!(
        !serde_json::to_string(&projected)
            .unwrap()
            .contains("PRIVATE_")
    );
}

#[test]
fn required_full_state_and_positional_or_init_inputs_cannot_be_silently_omitted() {
    for target in [
        RuntimeCaptureTarget::Scripts,
        RuntimeCaptureTarget::ScriptKey("task.sh".into()),
        RuntimeCaptureTarget::Init,
        RuntimeCaptureTarget::Hostname,
        RuntimeCaptureTarget::GuestClock,
    ] {
        assert!(
            apply_runtime_capture_controls(
                document(),
                &BTreeMap::from([(target, RuntimeCaptureAction::Omit)]),
                true
            )
            .is_err()
        );
    }
    for target in [
        RuntimeCaptureTarget::EntrypointArg(1),
        RuntimeCaptureTarget::CmdArg(0),
        RuntimeCaptureTarget::InitArg(0),
        RuntimeCaptureTarget::InitEnvKey("INIT".into()),
    ] {
        for full in [false, true] {
            let error = apply_runtime_capture_controls(
                document(),
                &BTreeMap::from([(target.clone(), RuntimeCaptureAction::Omit)]),
                full,
            )
            .err()
            .unwrap()
            .to_string();
            assert!(error.contains("needs a binding"));
            assert!(!error.contains("PRIVATE_"));
        }
    }
}

#[test]
fn missing_overlapping_and_wrong_shape_controls_refuse_with_value_safe_diagnostics() {
    for controls in [
        BTreeMap::from([(
            RuntimeCaptureTarget::EnvKey("PRIVATE_MISSING_KEY".into()),
            RuntimeCaptureAction::Omit,
        )]),
        BTreeMap::from([(
            RuntimeCaptureTarget::CmdArg(999),
            RuntimeCaptureAction::Bind("replacement".into()),
        )]),
        BTreeMap::from([
            (RuntimeCaptureTarget::Env, RuntimeCaptureAction::Omit),
            (
                RuntimeCaptureTarget::EnvKey("KEY.WITH.DOTS".into()),
                RuntimeCaptureAction::Bind("replacement".into()),
            ),
        ]),
        BTreeMap::from([(
            RuntimeCaptureTarget::Cmd,
            RuntimeCaptureAction::Bind("PRIVATE_BAD_BINDING".into()),
        )]),
        BTreeMap::from([(
            RuntimeCaptureTarget::CmdArg(0),
            RuntimeCaptureAction::Bind("PRIVATE/BAD/BINDING".into()),
        )]),
    ] {
        let error = apply_runtime_capture_controls(document(), &controls, false)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("PRIVATE_"));
    }
    let control = RuntimeCaptureTarget::EnvKey("PRIVATE_KEY".into());
    assert!(!format!("{control:?}").contains("PRIVATE_KEY"));
    assert!(
        !format!("{:?}", RuntimeCaptureAction::Bind("PRIVATE_ID".into())).contains("PRIVATE_ID")
    );
    let mut draft = document();
    draft
        .bindings
        .insert("replacement".into(), SavedBindingKind::TlsIdentity);
    assert!(
        apply_runtime_capture_controls(
            draft,
            &BTreeMap::from([(
                RuntimeCaptureTarget::CmdArg(0),
                RuntimeCaptureAction::Bind("replacement".into())
            )]),
            false
        )
        .is_err()
    );
}

#[test]
fn pending_only_input_is_sanitized_without_inventing_an_active_value_or_demand() {
    let mut draft = document();
    draft.active.runtime.env = Some(SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    });
    let projected = apply_runtime_capture_controls(
        draft,
        &BTreeMap::from([(
            RuntimeCaptureTarget::EnvKey("KEY.WITH.DOTS".into()),
            RuntimeCaptureAction::Bind("pending-only".into()),
        )]),
        false,
    )
    .unwrap();
    assert!(matches!(
        projected.active.runtime.env,
        Some(SavedValue::Unknown { .. })
    ));
    assert!(
        !projected
            .active_binding_uses()
            .unwrap()
            .contains_key("pending-only")
    );
    assert_eq!(projected.bindings["pending-only"], SavedBindingKind::Text);
    assert!(
        !serde_json::to_string(&projected)
            .unwrap()
            .contains("PRIVATE_ENV")
    );
}

#[test]
fn shared_binding_survives_other_consumers_and_displaced_declarations_are_removed() {
    let mut draft = document();
    draft.active.runtime.env = Some(value(BTreeMap::from([(
        "remove".into(),
        SavedText::Binding {
            id: "shared".into(),
        },
    )])));
    draft.pending.as_mut().unwrap().runtime.env = draft.active.runtime.env.clone();
    draft.active.runtime.cmd = Some(value(vec![SavedText::Binding {
        id: "shared".into(),
    }]));
    draft
        .bindings
        .insert("shared".into(), SavedBindingKind::Text);
    let projected = apply_runtime_capture_controls(
        draft,
        &BTreeMap::from([(
            RuntimeCaptureTarget::EnvKey("remove".into()),
            RuntimeCaptureAction::Omit,
        )]),
        false,
    )
    .unwrap();
    assert!(projected.bindings.contains_key("shared"));
    let projected = apply_runtime_capture_controls(
        projected,
        &BTreeMap::from([(
            RuntimeCaptureTarget::CmdArg(0),
            RuntimeCaptureAction::Bind("new".into()),
        )]),
        false,
    )
    .unwrap();
    assert!(!projected.bindings.contains_key("shared"));
    assert!(projected.bindings.contains_key("new"));
}

#[test]
fn exclusions_precede_bounds_and_encoding_but_unrelated_invalid_metadata_still_refuses() {
    let mut draft = document();
    draft.active.runtime.cmd = Some(value(vec![literal(
        &"x".repeat(MAX_SAVED_CONFIG_BYTES + 1),
    )]));
    assert!(draft.validate().is_err());
    let controls = BTreeMap::from([(
        RuntimeCaptureTarget::CmdArg(0),
        RuntimeCaptureAction::Bind("command".into()),
    )]);
    let projected = apply_runtime_capture_controls(draft, &controls, false).unwrap();
    assert!(serde_json::to_vec(&projected).unwrap().len() < MAX_SAVED_CONFIG_BYTES);
    let mut invalid = projected.clone();
    invalid
        .bindings
        .insert("unused".into(), SavedBindingKind::Text);
    assert!(apply_runtime_capture_controls(invalid, &BTreeMap::new(), false).is_err());
    let mut invalid = projected;
    invalid.schema_version = 999;
    assert!(apply_runtime_capture_controls(invalid, &BTreeMap::new(), false).is_err());
}

#[test]
fn omitting_a_command_default_cannot_remove_a_shared_gateway_requirement() {
    let mut draft = document();
    draft.active.runtime.env = Some(value(BTreeMap::from([(
        "TOKEN".into(),
        SavedText::Binding {
            id: "secret".into(),
        },
    )])));
    draft.pending.as_mut().unwrap().runtime.env = draft.active.runtime.env.clone();
    draft.active.network.secrets = Some(value(SavedSecretsConfig {
        passthrough_hosts: None,
        violation_action: crate::SecretViolationAction::BlockAndLog,
        entries: vec![SavedSecret {
            env_var: "TOKEN".into(),
            binding: SavedBindingReference {
                id: "secret".into(),
            },
            placeholder: "$MSB_TOKEN".into(),
            allowed_hosts: vec![crate::HostPattern::Exact("api.example.com".into())],
            substitution: SavedSecretSubstitution {
                headers: true,
                header_fields: vec!["Authorization".into()],
                query: false,
                body: false,
            },
            passthrough_hosts: vec![],
            violation_action: None,
            require_tls_identity: true,
        }],
    }));
    draft
        .bindings
        .insert("secret".into(), SavedBindingKind::Text);
    let projected = apply_runtime_capture_controls(
        draft,
        &BTreeMap::from([(
            RuntimeCaptureTarget::EnvKey("TOKEN".into()),
            RuntimeCaptureAction::Omit,
        )]),
        true,
    )
    .unwrap();
    let uses = projected.active_binding_uses().unwrap();
    assert!(projected.bindings.contains_key("secret"));
    assert_eq!(
        uses["secret"].consumers,
        std::collections::BTreeSet::from([SavedBindingConsumer::Gateway])
    );
}

#[test]
fn full_capture_can_omit_pending_only_script_without_weakening_active_protection() {
    let target = RuntimeCaptureTarget::ScriptKey("task.sh".into());
    let controls = BTreeMap::from([(target, RuntimeCaptureAction::Omit)]);
    let mut draft = document();
    draft.active.runtime.scripts = Some(value(BTreeMap::new()));
    let projected = apply_runtime_capture_controls(draft, &controls, true).unwrap();
    assert!(
        !serde_json::to_string(&projected)
            .unwrap()
            .contains("PRIVATE_SCRIPT")
    );
    assert!(
        projected
            .active
            .runtime
            .scripts
            .unwrap()
            .value()
            .unwrap()
            .is_empty()
    );
    assert!(
        projected
            .pending
            .unwrap()
            .runtime
            .scripts
            .unwrap()
            .value()
            .unwrap()
            .is_empty()
    );
    assert!(apply_runtime_capture_controls(document(), &controls, true).is_err());
    let mut unknown = document();
    unknown.active.runtime.scripts = Some(SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    });
    assert!(apply_runtime_capture_controls(unknown, &controls, true).is_err());
}
