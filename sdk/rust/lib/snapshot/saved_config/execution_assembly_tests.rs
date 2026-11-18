//! Execution composition must preserve identity, ownership and unknown observations.

use super::*;
use microsandbox_types::snapshot::saved_config::{
    SavedExecutionConfig, SavedLifetimePolicy, SavedOrigin, SavedRlimit, SavedU64,
    SavedUnknownReason, SavedValue,
};
use microsandbox_types::{
    Rlimit, RlimitResource, SandboxPolicyPatch, SandboxSpec, SandboxSpecPatch, SecurityProfile,
};
use std::collections::BTreeMap;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn known<T>(value: T) -> Option<SavedValue<T>> {
    Some(SavedValue::Value {
        value,
        origin: SavedOrigin::Configured,
    })
}

fn labels(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(key, value)| (key.to_string(), value.to_string()))
        .collect()
}

fn security() -> DestinationGuestSecurity {
    DestinationGuestSecurity {
        baseline: SecurityProfile::Default,
        minimum: SecurityProfile::Default,
    }
}

fn plan(
    saved: &SavedExecutionConfig,
    lower: &SandboxSpec,
    explicit: &SandboxSpecPatch,
    clears: &[ExecutionDefaultClear],
) -> crate::MicrosandboxResult<ExecutionConfigurationPlan> {
    prepare_execution_configuration(
        saved,
        lower,
        explicit,
        clears,
        SnapshotConfigMode::Saved,
        ExecutionRestoreMode::Disk,
        security(),
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn complete_saved_labels_replace_lower_user_metadata_and_preserve_destination_identity() {
    let saved = SavedExecutionConfig {
        labels: known(labels(&[("team.a", "SOURCE_PRIVATE"), ("team", "keep")])),
        ..Default::default()
    };
    let lower = SandboxSpec {
        labels: labels(&[("image-only", "obsolete"), ("sandbox.id", "source-id")]),
        ..Default::default()
    };
    let patch = SandboxSpecPatch::new().labels(labels(&[("team.a", "DEST_PRIVATE")]));
    let plan = plan(&saved, &lower, &patch, &[]).unwrap();
    let mut target = SandboxSpec {
        labels: labels(&[
            ("sandbox.id", "destination-id"),
            ("service.name", "destination-service"),
            ("obsolete", "remove"),
        ]),
        ..Default::default()
    };
    plan.apply_to(&mut target).unwrap();
    assert_eq!(
        target.labels,
        labels(&[
            ("sandbox.id", "destination-id"),
            ("service.name", "destination-service"),
            ("team.a", "DEST_PRIVATE"),
            ("team", "keep")
        ])
    );
    assert!(!format!("{plan:?}").contains("PRIVATE"));
}

#[test]
fn exact_label_clear_and_empty_replacement_do_not_resurrect_lower_labels() {
    let saved = SavedExecutionConfig {
        labels: known(labels(&[("team.a", "remove"), ("team", "keep")])),
        ..Default::default()
    };
    let lower = SandboxSpec {
        labels: labels(&[("team.a", "old"), ("image", "old")]),
        ..Default::default()
    };
    let mut target = SandboxSpec::default();
    plan(
        &saved,
        &lower,
        &SandboxSpecPatch::new(),
        &[ExecutionDefaultClear::LabelKey("team.a".into())],
    )
    .unwrap()
    .apply_to(&mut target)
    .unwrap();
    assert_eq!(target.labels, labels(&[("team", "keep")]));
    plan(
        &saved,
        &lower,
        &SandboxSpecPatch::new().replace_labels(BTreeMap::new()),
        &[],
    )
    .unwrap()
    .apply_to(&mut target)
    .unwrap();
    assert!(target.labels.is_empty());
}

#[test]
fn forged_source_or_explicit_identity_is_rejected_even_when_masked_and_values_are_redacted() {
    for key in ["sandbox.id", "microsandbox.owner", "service.name", ""] {
        let saved = SavedExecutionConfig {
            labels: known(labels(&[(key, "PRIVATE_SENTINEL")])),
            ..Default::default()
        };
        let error = prepare_execution_configuration(
            &saved,
            &SandboxSpec::default(),
            &SandboxSpecPatch::new().replace_labels(BTreeMap::new()),
            &[ExecutionDefaultClear::Labels],
            SnapshotConfigMode::Fresh,
            ExecutionRestoreMode::Disk,
            security(),
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("PRIVATE_SENTINEL"));
        assert!(
            plan(
                &SavedExecutionConfig::default(),
                &SandboxSpec::default(),
                &SandboxSpecPatch::new().labels(labels(&[(key, "PRIVATE_SENTINEL")])),
                &[]
            )
            .is_err()
        );
    }
}

#[test]
fn unknown_defaults_refuse_before_any_destination_mutation() {
    for source in [
        SavedExecutionConfig {
            labels: Some(SavedValue::Unknown {
                reason: SavedUnknownReason::NotRecorded,
            }),
            ..Default::default()
        },
        SavedExecutionConfig {
            rlimits: Some(SavedValue::Unknown {
                reason: SavedUnknownReason::NotRecorded,
            }),
            ..Default::default()
        },
        SavedExecutionConfig {
            lifecycle: Some(SavedValue::Unknown {
                reason: SavedUnknownReason::NotRecorded,
            }),
            ..Default::default()
        },
    ] {
        let mut target = SandboxSpec {
            labels: labels(&[("destination", "unchanged")]),
            ..Default::default()
        };
        let before = serde_json::to_value(&target).unwrap();
        let unresolved = plan(&source, &target, &SandboxSpecPatch::new(), &[]).unwrap();
        assert!(
            unresolved
                .apply_to(&mut target)
                .unwrap_err()
                .to_string()
                .contains("SCFG_UNKNOWN")
        );
        assert_eq!(serde_json::to_value(&target).unwrap(), before);
    }
}

#[test]
fn unlimited_and_zero_lifetimes_are_distinct_and_never_copy_ephemeral_ownership() {
    let saved = SavedExecutionConfig {
        lifecycle: known(SavedLifetimePolicy {
            max_duration_secs: Some(SavedU64::new(0)),
            idle_timeout_secs: None,
        }),
        ..Default::default()
    };
    let mut lower = SandboxSpec::default();
    lower.lifecycle.max_duration_secs = Some(30);
    lower.lifecycle.idle_timeout_secs = Some(20);
    lower.lifecycle.ephemeral = true;
    let patch = SandboxSpecPatch::new().lifecycle(SandboxPolicyPatch::new().ephemeral(true));
    let mut target = SandboxSpec::default();
    plan(&saved, &lower, &patch, &[])
        .unwrap()
        .apply_to(&mut target)
        .unwrap();
    assert_eq!(target.lifecycle.max_duration_secs, Some(0));
    assert_eq!(target.lifecycle.idle_timeout_secs, None);
    assert!(!target.lifecycle.ephemeral);
    target.lifecycle.ephemeral = true;
    let patch = SandboxSpecPatch::new().lifecycle(
        SandboxPolicyPatch::new()
            .ephemeral(false)
            .idle_timeout_secs(8),
    );
    plan(
        &saved,
        &lower,
        &patch,
        &[ExecutionDefaultClear::MaxDuration],
    )
    .unwrap()
    .apply_to(&mut target)
    .unwrap();
    assert_eq!(target.lifecycle.max_duration_secs, None);
    assert_eq!(target.lifecycle.idle_timeout_secs, Some(8));
    assert!(target.lifecycle.ephemeral);
}

#[test]
fn partial_lifetime_override_does_not_hide_another_unknown_field() {
    let saved = SavedExecutionConfig {
        lifecycle: Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded,
        }),
        ..Default::default()
    };
    let patch = SandboxSpecPatch::new().lifecycle(SandboxPolicyPatch::new().max_duration_secs(4));
    let mut target = SandboxSpec::default();
    assert!(
        plan(&saved, &target, &patch, &[])
            .unwrap()
            .apply_to(&mut target)
            .is_err()
    );
    plan(
        &saved,
        &target,
        &patch,
        &[ExecutionDefaultClear::IdleTimeout],
    )
    .unwrap()
    .apply_to(&mut target)
    .unwrap();
    assert_eq!(target.lifecycle.max_duration_secs, Some(4));
    assert_eq!(target.lifecycle.idle_timeout_secs, None);
}

#[test]
fn resource_limits_preserve_u64_sentinels_native_order_and_explicit_empty_lists() {
    let saved = SavedExecutionConfig {
        rlimits: known(vec![SavedRlimit {
            resource: RlimitResource::Nofile,
            soft: SavedU64::new(0),
            hard: SavedU64::new(u64::MAX),
        }]),
        ..Default::default()
    };
    let mut target = SandboxSpec::default();
    plan(&saved, &target, &SandboxSpecPatch::new(), &[])
        .unwrap()
        .apply_to(&mut target)
        .unwrap();
    assert_eq!(
        (target.rlimits[0].soft, target.rlimits[0].hard),
        (0, u64::MAX)
    );
    let limits = vec![
        Rlimit {
            resource: RlimitResource::Nofile,
            soft: 1,
            hard: 2,
        },
        Rlimit {
            resource: RlimitResource::Nofile,
            soft: 3,
            hard: 4,
        },
    ];
    plan(
        &saved,
        &target,
        &SandboxSpecPatch::new().rlimits(limits),
        &[],
    )
    .unwrap()
    .apply_to(&mut target)
    .unwrap();
    assert_eq!(
        target.rlimits.iter().map(|r| r.soft).collect::<Vec<_>>(),
        vec![1, 3]
    );
    plan(
        &saved,
        &target,
        &SandboxSpecPatch::new().rlimits(vec![]),
        &[],
    )
    .unwrap()
    .apply_to(&mut target)
    .unwrap();
    assert!(target.rlimits.is_empty());
    let bad = SandboxSpecPatch::new().rlimits(vec![Rlimit {
        resource: RlimitResource::Nofile,
        soft: 3,
        hard: 2,
    }]);
    assert!(plan(&saved, &target, &bad, &[]).is_err());
}

#[test]
fn composition_preserves_unrelated_destination_fields_and_source_document() {
    let saved = SavedExecutionConfig {
        labels: known(labels(&[("owner", "source")])),
        ..Default::default()
    };
    let before_source = saved.clone();
    let mut target = SandboxSpec::default();
    target.resources.cpus = 7;
    target.resources.placement_profile = Some("destination-profile".into());
    let before = serde_json::to_value(&target).unwrap();
    let plan = plan(
        &saved,
        &SandboxSpec::default(),
        &SandboxSpecPatch::new(),
        &[],
    )
    .unwrap();
    plan.apply_to(&mut target).unwrap();
    target.labels.clear();
    assert_eq!(serde_json::to_value(&target).unwrap(), before);
    assert_eq!(saved, before_source);
}

#[test]
fn full_guest_security_and_mandatory_destination_policy_remain_admission_requirements() {
    let saved = SavedExecutionConfig {
        security_profile: known(SecurityProfile::Restricted),
        ..Default::default()
    };
    let full = ExecutionRestoreMode::Full {
        captured_security: SecurityProfile::Restricted,
    };
    let mut target = SandboxSpec::default();
    prepare_execution_configuration(
        &saved,
        &target,
        &SandboxSpecPatch::new(),
        &[],
        SnapshotConfigMode::Fresh,
        full,
        security(),
    )
    .unwrap()
    .apply_to(&mut target)
    .unwrap();
    assert_eq!(target.security_profile, SecurityProfile::Restricted);
    assert!(
        prepare_execution_configuration(
            &saved,
            &target,
            &SandboxSpecPatch::new().security_profile(SecurityProfile::Restricted),
            &[],
            SnapshotConfigMode::Saved,
            full,
            security()
        )
        .is_err()
    );
    let mandatory = DestinationGuestSecurity {
        baseline: SecurityProfile::Restricted,
        minimum: SecurityProfile::Restricted,
    };
    assert!(
        prepare_execution_configuration(
            &saved,
            &target,
            &SandboxSpecPatch::new().security_profile(SecurityProfile::Default),
            &[],
            SnapshotConfigMode::Saved,
            ExecutionRestoreMode::Disk,
            mandatory
        )
        .is_err()
    );
}
