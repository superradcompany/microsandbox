//! Pending declarations must remain distinct through raw capture and active selection.

use std::collections::{BTreeMap, BTreeSet};

use microsandbox_image::ImageConfig;
use microsandbox_protocol::init_observation::InitObservation;
use microsandbox_types::snapshot::saved_config::{
    RuntimeCaptureAction, RuntimeCaptureInput, RuntimeCaptureTarget, SavedOrigin,
    SavedRuntimeConfig, SavedUnknownReason, SavedValue, project_runtime_capture,
};
use microsandbox_types::{HandoffInit, SandboxRuntimeOptionsPatch, SandboxSpecPatch};
use serde_json::{Value, json};

use super::{
    ResourceCaptureObservation, RuntimeCaptureSource, RuntimeDefaultClear, RuntimeDefaultSelection,
    RuntimeSelectionContext, SnapshotConfigMode, prepare_runtime_inputs, select_runtime_defaults,
};
use crate::sandbox::SandboxBuilder;
use crate::{SandboxConfig, SandboxConfigPatch};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn source() -> Value {
    let config = SandboxBuilder::new("source")
        .image("alpine")
        .cmd(["reusable"])
        .background_command(["PRIVATE_INVOCATION"])
        .env("ordinary", "literal")
        .host_env("host".into(), "PRIVATE_HOST".into())
        .script("task", "echo pending")
        .init_with("auto", |init| {
            init.host_env("init_host".into(), "PRIVATE_INIT".into())
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

fn context(mode: SnapshotConfigMode) -> RuntimeSelectionContext {
    RuntimeSelectionContext {
        config_mode: mode,
        full_resume: false,
        starts_command: false,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn pending_source_records_declarations_without_observations_or_invocation() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let result = project_runtime_capture(
        adapter.input(),
        Some(adapter.pending_input()),
        &bindings(),
        false,
    )
    .unwrap();
    assert!(matches!(
        result.active.init,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotObserved
        })
    ));
    assert!(matches!(
        result.active.scripts,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotObserved
        })
    ));
    let pending = serde_json::to_value(result.pending.unwrap()).unwrap();
    assert_eq!(pending["init"]["value"]["kind"], "requested_handoff");
    assert_eq!(pending["init"]["value"]["cmd"], "auto");
    assert!(pending["init"]["value"].get("resolved_path").is_none());
    assert_eq!(
        pending["scripts"]["value"]["task"],
        json!({"kind":"declaration","content":"echo pending"})
    );
    assert_eq!(
        pending["cmd"]["value"],
        json!([{"kind":"literal","value":"reusable"}])
    );
    assert!(!pending.to_string().contains("PRIVATE"));
    assert_eq!(raw, source());
}

#[test]
fn pending_source_does_not_substitute_guest_init_observation() {
    let raw = source();
    let observed = InitObservation::Handoff {
        path: "/sbin/init".into(),
    };
    let adapter = RuntimeCaptureSource::from_recorded(&raw, Some(&observed), None).unwrap();
    let result = project_runtime_capture(
        adapter.input(),
        Some(adapter.pending_input()),
        &bindings(),
        false,
    )
    .unwrap();
    let active = serde_json::to_value(result.active).unwrap();
    let pending = serde_json::to_value(result.pending.unwrap()).unwrap();
    assert_eq!(active["init"]["value"]["resolved_path"], "/sbin/init");
    assert_eq!(pending["init"]["value"]["cmd"], "auto");
    assert_eq!(pending["init"]["origin"], "configured");
}

#[test]
fn pending_init_preserves_image_auto_intent_and_unknown_legacy_selection() {
    let image = ImageConfig {
        entrypoint: Some(vec!["/sbin/init".into()]),
        ..Default::default()
    };
    for (choice, expected) in [("auto", "auto"), ("/sbin/init", "/sbin/init")] {
        let config = SandboxBuilder::new("pending-init")
            .image("alpine")
            .init(choice)
            .finish(None, Some(SandboxConfigPatch::from_image(&image)))
            .unwrap();
        let mut raw = serde_json::to_value(config.clone_for_persistence()).unwrap();
        assert_eq!(raw["init"]["cmd"], "/sbin/init");
        let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
        let result = project_runtime_capture(
            RuntimeCaptureInput::default(),
            Some(adapter.pending_input()),
            &BTreeMap::new(),
            false,
        )
        .unwrap();
        let pending = serde_json::to_value(result.pending.unwrap()).unwrap();
        assert_eq!(pending["init"]["value"]["cmd"], expected);
        assert_eq!(pending["init"]["origin"], "configured");

        // The same resolved path without provenance cannot distinguish these choices.
        raw.as_object_mut().unwrap().remove("init_provenance");
        let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
        assert!(matches!(
            adapter.pending_input().init,
            Some(SavedValue::Unknown {
                reason: SavedUnknownReason::NotRecorded
            })
        ));
    }
}

#[test]
fn pending_source_missing_fields_are_unknown_but_explicit_empty_is_known() {
    let mut raw = source();
    raw.as_object_mut().unwrap().remove("init");
    raw.as_object_mut().unwrap().remove("init_provenance");
    raw.as_object_mut()
        .unwrap()
        .remove("environment_provenance");
    raw.as_object_mut().unwrap().remove("env");
    raw["runtime"].as_object_mut().unwrap().remove("scripts");
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let result = project_runtime_capture(
        RuntimeCaptureInput::default(),
        Some(adapter.pending_input()),
        &BTreeMap::new(),
        false,
    )
    .unwrap();
    let pending = result.pending.unwrap();
    assert!(matches!(
        pending.init,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
    assert!(matches!(
        pending.scripts,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
    raw["init"] = Value::Null;
    raw["runtime"]["scripts"] = json!({});
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let result = project_runtime_capture(
        RuntimeCaptureInput::default(),
        Some(adapter.pending_input()),
        &BTreeMap::new(),
        false,
    )
    .unwrap();
    let pending = result.pending.unwrap();
    assert!(matches!(pending.init, Some(SavedValue::Default {})));
    assert!(pending.scripts.unwrap().value().unwrap().is_empty());
}

#[test]
fn rebuilt_historical_environment_requires_bindings_before_capture() {
    let mut raw = source();
    raw.as_object_mut()
        .unwrap()
        .remove("environment_provenance");
    let historical: SandboxConfig = serde_json::from_value(raw).unwrap();
    let rebuilt = SandboxBuilder::new("rebuilt")
        .overlay(SandboxConfigPatch::from_present_fields(historical))
        .finish(None, None)
        .unwrap();
    let raw = serde_json::to_value(rebuilt.clone_for_persistence()).unwrap();
    let init = InitObservation::Handoff {
        path: "/init".into(),
    };
    let adapter = RuntimeCaptureSource::from_recorded(&raw, Some(&init), None).unwrap();
    let error = project_runtime_capture(
        adapter.input(),
        Some(adapter.pending_input()),
        &BTreeMap::new(),
        false,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("SCFG_BINDING"));
    assert!(!error.to_string().contains("PRIVATE"));

    // All historical values lack evidence, including an originally ordinary literal.
    // Explicit bindings permit capture without copying their source values or digests.
    let mut controls = bindings();
    controls.insert(
        RuntimeCaptureTarget::EnvKey("ordinary".into()),
        RuntimeCaptureAction::Bind("ordinary-input".into()),
    );
    let projected = project_runtime_capture(
        adapter.input(),
        Some(adapter.pending_input()),
        &controls,
        false,
    )
    .unwrap();
    for section in [Some(projected.active), projected.pending] {
        let encoded = serde_json::to_string(&section.unwrap()).unwrap();
        assert!(!encoded.contains("PRIVATE"));
        assert!(!encoded.contains("digest"));
        assert!(encoded.contains("ordinary-input"));
        assert!(encoded.contains("host-input"));
        assert!(encoded.contains("init-input"));
    }
}

#[test]
fn rebuilt_historical_command_and_init_intent_stay_unknown_at_capture() {
    let mut raw = source();
    for key in ["command_provenance", "init_provenance"] {
        raw.as_object_mut().unwrap().remove(key);
    }
    let historical: SandboxConfig = serde_json::from_value(raw).unwrap();
    let rebuilt = SandboxBuilder::new("rebuilt")
        .overlay(SandboxConfigPatch::from_present_fields(historical))
        .finish(None, None)
        .unwrap();
    let raw = serde_json::to_value(rebuilt.clone_for_persistence()).unwrap();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    // Unknown init intent has no reusable init environment to bind. Workload
    // environment remains independently available and still needs its binding.
    let controls = BTreeMap::from([(
        RuntimeCaptureTarget::EnvKey("host".into()),
        RuntimeCaptureAction::Bind("host-input".into()),
    )]);
    let projected = project_runtime_capture(
        adapter.input(),
        Some(adapter.pending_input()),
        &controls,
        false,
    )
    .unwrap();
    let pending = projected.pending.unwrap();
    assert!(matches!(
        pending.init,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
    for section in [projected.active, pending] {
        assert!(matches!(
            section.cmd,
            Some(SavedValue::Unknown {
                reason: SavedUnknownReason::NotRecorded
            })
        ));
        assert!(!serde_json::to_string(&section).unwrap().contains("PRIVATE"));
    }
}

#[test]
fn pending_source_requires_env_provenance_and_does_not_infer_reusable_cmd() {
    let mut raw = source();
    raw.as_object_mut()
        .unwrap()
        .remove("environment_provenance");
    raw.as_object_mut().unwrap().remove("command_provenance");
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    assert!(
        project_runtime_capture(
            RuntimeCaptureInput::default(),
            Some(adapter.pending_input()),
            &bindings(),
            false
        )
        .is_err()
    );
    let mut controls = bindings();
    controls.insert(
        RuntimeCaptureTarget::EnvKey("ordinary".into()),
        RuntimeCaptureAction::Omit,
    );
    let result = project_runtime_capture(
        RuntimeCaptureInput::default(),
        Some(adapter.pending_input()),
        &controls,
        false,
    )
    .unwrap();
    assert!(matches!(
        result.pending.unwrap().cmd,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
}

#[test]
fn pending_resource_targets_remain_separate_from_active_capacity() {
    let mut raw = source();
    raw["resources"]["cpus"] = json!(4);
    raw["resources"]["max_cpus"] = json!(8);
    raw["resources"]["memory_mib"] = json!(1024);
    raw["resources"]["max_memory_mib"] = json!(2048);
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let pending = adapter.project_pending_resources().unwrap();
    assert!(matches!(
        pending.cpus,
        Some(SavedValue::Value {
            value: 4,
            origin: SavedOrigin::Configured
        })
    ));
    assert!(matches!(
        pending.memory_mib,
        Some(SavedValue::Value {
            value: 1024,
            origin: SavedOrigin::Configured
        })
    ));
    let active = adapter
        .project_resources(ResourceCaptureObservation::default())
        .unwrap();
    assert!(matches!(
        active.cpus,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotObserved
        })
    ));
    raw["resources"].as_object_mut().unwrap().remove("cpus");
    raw["resources"]
        .as_object_mut()
        .unwrap()
        .remove("memory_mib");
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let pending = adapter.project_pending_resources().unwrap();
    assert!(matches!(
        pending.cpus,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
    assert!(matches!(
        pending.memory_mib,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
}

#[test]
fn active_selection_and_preparation_reject_pending_even_with_fresh_overrides_or_clears() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let projected = project_runtime_capture(
        RuntimeCaptureInput::default(),
        Some(adapter.pending_input()),
        &bindings(),
        false,
    )
    .unwrap();
    let pending = projected.pending.unwrap();
    // Check each pending-only variant independently so one rejection cannot mask the other.
    for runtime in [
        SavedRuntimeConfig {
            init: pending.init,
            ..Default::default()
        },
        SavedRuntimeConfig {
            scripts: pending.scripts,
            ..Default::default()
        },
    ] {
        for mode in [SnapshotConfigMode::Saved, SnapshotConfigMode::Fresh] {
            let mut explicit = SandboxSpecPatch::new()
                .runtime(SandboxRuntimeOptionsPatch::new().replace_scripts(BTreeMap::new()));
            explicit.init = Some(HandoffInit {
                cmd: "/init".into(),
                args: vec![],
                env: vec![],
            });
            assert!(
                select_runtime_defaults(
                    &runtime,
                    &explicit,
                    &[RuntimeDefaultClear::Init, RuntimeDefaultClear::Scripts],
                    context(mode)
                )
                .is_err()
            );
        }
        // Public typed construction cannot bypass the selection gate.
        let selected = RuntimeDefaultSelection {
            defaults: runtime,
            reset_inherited_cmd: false,
            scripts_requiring_identity_check: BTreeSet::new(),
            script_replacement_requires_identity_check: false,
            binding_requirements: BTreeMap::new(),
            unknown_fields: BTreeSet::new(),
        };
        assert!(
            prepare_runtime_inputs(
                &selected,
                &BTreeMap::new(),
                context(SnapshotConfigMode::Saved)
            )
            .is_err()
        );
    }
}
