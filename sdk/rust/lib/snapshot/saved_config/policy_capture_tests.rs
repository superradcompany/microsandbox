//! Source policy projection must preserve observation gaps and exclude private ownership.

use std::collections::BTreeSet;

use microsandbox_types::snapshot::saved_config::{SavedOrigin, SavedUnknownReason, SavedValue};
use microsandbox_types::{Rlimit, RlimitResource, SecurityProfile, TransparentHugePagePolicy};
use serde_json::{Value, json};

use super::{ExecutionCaptureControls, ResourceCaptureObservation, RuntimeCaptureSource};
use crate::sandbox::SandboxBuilder;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn source() -> Value {
    let mut config = SandboxBuilder::new("source")
        .image("alpine")
        .finish(None, None)
        .unwrap();
    config.spec.resources.cpus = 8;
    config.spec.resources.max_cpus = 8;
    config.spec.resources.memory_mib = 1024;
    config.spec.resources.max_memory_mib = 2048;
    config.spec.resources.placement_profile = Some("PRIVATE_HOST_PROFILE".into());
    config.spec.security_profile = SecurityProfile::Restricted;
    config.spec.labels.insert("team".into(), "".into());
    config
        .spec
        .labels
        .insert("sandbox.id".into(), "PRIVATE_SYSTEM_ID".into());
    config.spec.rlimits = vec![Rlimit {
        resource: RlimitResource::Nofile,
        soft: 0,
        hard: u64::MAX,
    }];
    config.spec.lifecycle.ephemeral = true;
    config.spec.lifecycle.max_duration_secs = Some(0);
    config.spec.lifecycle.idle_timeout_secs = None;
    serde_json::to_value(config.clone_for_persistence()).unwrap()
}

fn adapter(raw: &Value) -> RuntimeCaptureSource<'_> {
    RuntimeCaptureSource::from_recorded(raw, None, None).unwrap()
}

fn observed<T>(value: T) -> SavedValue<T> {
    SavedValue::Value {
        value,
        origin: SavedOrigin::Observed,
    }
}

fn unobserved<T>() -> SavedValue<T> {
    SavedValue::Unknown {
        reason: SavedUnknownReason::NotObserved,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn active_capacity_uses_independent_observations_instead_of_targets() {
    let raw = source();
    let original = raw.clone();
    let saved = adapter(&raw)
        .project_resources(ResourceCaptureObservation {
            cpus: observed(2),
            memory_mib: observed(256),
        })
        .unwrap();
    assert!(matches!(
        saved.cpus,
        Some(SavedValue::Value {
            value: 2,
            origin: SavedOrigin::Observed
        })
    ));
    assert!(matches!(
        saved.memory_mib,
        Some(SavedValue::Value {
            value: 256,
            origin: SavedOrigin::Observed
        })
    ));
    assert_eq!(saved.max_cpus.unwrap().value(), Some(&8));
    assert_eq!(saved.max_memory_mib.unwrap().value(), Some(&2048));
    assert_eq!(raw, original);
    let encoded = serde_json::to_string(
        &adapter(&raw)
            .project_resources(ResourceCaptureObservation::default())
            .unwrap(),
    )
    .unwrap();
    assert!(!encoded.contains("PRIVATE_HOST_PROFILE"));
    assert!(!encoded.contains("placement"));
    assert!(!encoded.contains("1024"));
}

#[test]
fn unknown_allocations_and_absent_static_fields_do_not_become_defaults() {
    let mut raw = source();
    // Model a historical producer with no evidence for serializer-omitted defaults.
    raw.as_object_mut().unwrap().remove("field_presence");
    raw["resources"].as_object_mut().unwrap().remove("max_cpus");
    raw["resources"]
        .as_object_mut()
        .unwrap()
        .remove("max_memory_mib");
    let saved = adapter(&raw)
        .project_resources(ResourceCaptureObservation::default())
        .unwrap();
    assert!(matches!(
        saved.cpus,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotObserved
        })
    ));
    assert!(matches!(
        saved.memory_mib,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotObserved
        })
    ));
    assert!(matches!(
        saved.max_cpus,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
    assert!(matches!(
        saved.max_memory_mib,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
    assert!(matches!(
        saved.thp,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
    raw["resources"]["thp"] = json!("never");
    let saved = adapter(&raw)
        .project_resources(ResourceCaptureObservation::default())
        .unwrap();
    assert_eq!(
        saved.thp.unwrap().value(),
        Some(&TransparentHugePagePolicy::Never)
    );
}

#[test]
fn contradictory_or_invalid_capacity_refuses_with_value_safe_errors() {
    let raw = source();
    for observation in [
        ResourceCaptureObservation {
            cpus: observed(0),
            memory_mib: unobserved(),
        },
        ResourceCaptureObservation {
            cpus: observed(9),
            memory_mib: unobserved(),
        },
        ResourceCaptureObservation {
            cpus: unobserved(),
            memory_mib: observed(0),
        },
        ResourceCaptureObservation {
            cpus: unobserved(),
            memory_mib: observed(2049),
        },
    ] {
        let error = adapter(&raw)
            .project_resources(observation)
            .unwrap_err()
            .to_string();
        assert!(error.contains("SCFG_VALUE"));
        assert!(!error.contains("PRIVATE"));
    }
}

#[test]
fn execution_keeps_empty_zero_unlimited_and_order_without_source_ownership() {
    let raw = source();
    let saved = adapter(&raw)
        .project_execution(&ExecutionCaptureControls::default())
        .unwrap();
    let labels = saved.labels.as_ref().unwrap().value().unwrap();
    assert_eq!(labels.len(), 1);
    assert_eq!(labels["team"], "");
    assert_eq!(
        saved.security_profile.as_ref().unwrap().value(),
        Some(&SecurityProfile::Restricted)
    );
    let limits = saved.rlimits.as_ref().unwrap().value().unwrap();
    assert_eq!(limits[0].soft.get(), 0);
    assert_eq!(limits[0].hard.get(), u64::MAX);
    let lifetime = saved.lifecycle.as_ref().unwrap().value().unwrap();
    assert_eq!(lifetime.max_duration_secs.unwrap().get(), 0);
    assert!(lifetime.idle_timeout_secs.is_none());
    let encoded = serde_json::to_string(&saved).unwrap();
    for excluded in ["PRIVATE", "ephemeral", "placement", "sandbox.id"] {
        assert!(!encoded.contains(excluded));
    }
    assert!(encoded.contains("18446744073709551615"));
}

#[test]
fn label_exclusions_precede_portable_value_validation() {
    let mut raw = source();
    raw["labels"]["private.key"] = json!("PRIVATE\0".repeat(100_000));
    let source = adapter(&raw);
    let error = source
        .project_execution(&ExecutionCaptureControls::default())
        .unwrap_err()
        .to_string();
    assert!(!error.contains("PRIVATE"));
    let keyed = source
        .project_execution(&ExecutionCaptureControls {
            omit_label_keys: BTreeSet::from(["private.key".into()]),
            ..Default::default()
        })
        .unwrap();
    assert_eq!(keyed.labels.unwrap().value().unwrap().len(), 1);
    let whole = source
        .project_execution(&ExecutionCaptureControls {
            omit_labels: true,
            ..Default::default()
        })
        .unwrap();
    assert!(whole.labels.is_none());
    assert!(!serde_json::to_string(&whole).unwrap().contains("PRIVATE"));
}

#[test]
fn missing_execution_fields_and_partial_lifetime_remain_unknown() {
    let mut raw = source();
    for key in ["labels", "security_profile", "rlimits"] {
        raw.as_object_mut().unwrap().remove(key);
    }
    raw["lifecycle"]
        .as_object_mut()
        .unwrap()
        .remove("idle_timeout_secs");
    let saved = adapter(&raw)
        .project_execution(&ExecutionCaptureControls::default())
        .unwrap();
    assert!(matches!(saved.labels, Some(SavedValue::Unknown { .. })));
    assert!(matches!(
        saved.security_profile,
        Some(SavedValue::Unknown { .. })
    ));
    assert!(matches!(saved.rlimits, Some(SavedValue::Unknown { .. })));
    assert!(matches!(saved.lifecycle, Some(SavedValue::Unknown { .. })));
    raw["lifecycle"]["idle_timeout_secs"] = Value::Null;
    let saved = adapter(&raw)
        .project_execution(&ExecutionCaptureControls::default())
        .unwrap();
    assert!(
        saved
            .lifecycle
            .unwrap()
            .value()
            .unwrap()
            .idle_timeout_secs
            .is_none()
    );
}

#[test]
fn unmatched_reserved_and_overlapping_label_controls_refuse_without_key_echo() {
    let raw = source();
    for controls in [
        ExecutionCaptureControls {
            omit_label_keys: BTreeSet::from(["PRIVATE_MISSING".into()]),
            ..Default::default()
        },
        ExecutionCaptureControls {
            omit_label_keys: BTreeSet::from(["sandbox.id".into()]),
            ..Default::default()
        },
        ExecutionCaptureControls {
            omit_labels: true,
            omit_label_keys: BTreeSet::from(["team".into()]),
        },
    ] {
        let error = adapter(&raw)
            .project_execution(&controls)
            .unwrap_err()
            .to_string();
        assert!(!error.contains("PRIVATE"));
        assert!(!error.contains("sandbox.id"));
        assert!(!error.contains("team"));
    }
}

#[test]
fn convergence_is_preserved_and_requested_or_default_values_are_not_observations() {
    let raw = source();
    let saved = adapter(&raw)
        .project_resources(ResourceCaptureObservation {
            cpus: SavedValue::Unknown {
                reason: SavedUnknownReason::Converging,
            },
            memory_mib: SavedValue::Unknown {
                reason: SavedUnknownReason::NotRecorded,
            },
        })
        .unwrap();
    assert!(matches!(
        saved.cpus,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::Converging
        })
    ));
    assert!(matches!(
        saved.memory_mib,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
    for cpus in [
        SavedValue::Default {},
        SavedValue::Value {
            value: 8,
            origin: SavedOrigin::Configured,
        },
        SavedValue::Value {
            value: 8,
            origin: SavedOrigin::Image,
        },
        SavedValue::Value {
            value: 8,
            origin: SavedOrigin::Platform,
        },
    ] {
        let error = adapter(&raw)
            .project_resources(ResourceCaptureObservation {
                cpus,
                ..Default::default()
            })
            .unwrap_err()
            .to_string();
        assert!(error.contains("requires observation"));
    }
}
