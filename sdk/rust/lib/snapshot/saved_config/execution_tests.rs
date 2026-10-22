//! Process and timer selection, including mandatory and explicit security admission.

use std::collections::BTreeMap;

use microsandbox_types::snapshot::saved_config::{
    SavedExecutionConfig, SavedLifetimePolicy, SavedOrigin, SavedRlimit, SavedU64,
    SavedUnknownReason, SavedValue,
};
use microsandbox_types::{RlimitResource, SandboxPolicyPatch, SandboxSpecPatch, SecurityProfile};

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn known<T>(value: T) -> Option<SavedValue<T>> {
    Some(SavedValue::Value {
        value,
        origin: SavedOrigin::Configured,
    })
}

fn source() -> SavedExecutionConfig {
    SavedExecutionConfig {
        labels: known(BTreeMap::from([
            ("team.a".into(), "SENTINEL_SOURCE".into()),
            ("team".into(), "keep".into()),
        ])),
        security_profile: known(SecurityProfile::Restricted),
        rlimits: known(vec![SavedRlimit {
            resource: RlimitResource::Nofile,
            soft: SavedU64::new(0),
            hard: SavedU64::new(u64::MAX),
        }]),
        lifecycle: known(SavedLifetimePolicy {
            max_duration_secs: Some(SavedU64::new(0)),
            idle_timeout_secs: None,
        }),
    }
}

fn policy() -> DestinationGuestSecurity {
    DestinationGuestSecurity {
        baseline: SecurityProfile::Default,
        minimum: SecurityProfile::Default,
    }
}

fn select(
    saved: &SavedExecutionConfig,
    explicit: &SandboxSpecPatch,
    clears: &[ExecutionDefaultClear],
) -> ExecutionDefaultSelection {
    select_execution_defaults(
        saved,
        explicit,
        clears,
        SnapshotConfigMode::Saved,
        ExecutionRestoreMode::Disk,
        policy(),
    )
    .unwrap()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn label_merges_and_replacements_use_native_semantics_without_copying_explicit_values() {
    let saved = source();
    let patch = SandboxSpecPatch::new().labels(BTreeMap::from([(
        "team.a".into(),
        "SENTINEL_DESTINATION".into(),
    )]));
    let selected = select(&saved, &patch, &[]);
    let labels = selected
        .labels
        .as_ref()
        .and_then(SavedValue::value)
        .unwrap();
    assert_eq!(labels, &BTreeMap::from([("team".into(), "keep".into())]));
    assert!(!format!("{selected:?}").contains("SENTINEL"));
    assert_eq!(
        patch.get_labels().unwrap()["team.a"],
        "SENTINEL_DESTINATION"
    );
    assert_eq!(
        select(
            &saved,
            &SandboxSpecPatch::new().labels(BTreeMap::new()),
            &[]
        )
        .labels,
        saved.labels
    );
    assert!(
        select(
            &saved,
            &SandboxSpecPatch::new().replace_labels(BTreeMap::new()),
            &[]
        )
        .labels
        .is_none()
    );
}

#[test]
fn label_clears_are_structural_idempotent_and_report_missing_keys_without_values() {
    let saved = source();
    let before = saved.clone();
    let selected = select(
        &saved,
        &SandboxSpecPatch::new(),
        &[ExecutionDefaultClear::LabelKey("team.a".into())],
    );
    assert_eq!(selected.labels.unwrap().value().unwrap().len(), 1);
    for clears in [
        vec![
            ExecutionDefaultClear::Labels,
            ExecutionDefaultClear::LabelKey("team.a".into()),
        ],
        vec![
            ExecutionDefaultClear::LabelKey("team.a".into()),
            ExecutionDefaultClear::LabelKey("team.a".into()),
            ExecutionDefaultClear::Labels,
        ],
    ] {
        assert!(
            select(&saved, &SandboxSpecPatch::new(), &clears)
                .labels
                .is_none()
        );
    }
    let error = select_execution_defaults(
        &saved,
        &SandboxSpecPatch::new(),
        &[ExecutionDefaultClear::LabelKey("SENTINEL_MISSING".into())],
        SnapshotConfigMode::Saved,
        ExecutionRestoreMode::Disk,
        policy(),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("SCFG_CLEAR"));
    assert!(!error.contains("SENTINEL"));
    assert_eq!(saved, before);
}

#[test]
fn lifetime_omitted_zero_and_unlimited_are_distinct_and_fields_override_independently() {
    let selected = select(&source(), &SandboxSpecPatch::new(), &[]);
    assert_eq!(
        selected
            .lifetime
            .max_duration_secs
            .as_ref()
            .and_then(SavedValue::value),
        Some(&Some(SavedU64::new(0)))
    );
    assert_eq!(
        selected
            .lifetime
            .idle_timeout_secs
            .as_ref()
            .and_then(SavedValue::value),
        Some(&None)
    );
    let patch = SandboxSpecPatch::new().lifecycle(
        SandboxPolicyPatch::new()
            .max_duration_secs(10)
            .ephemeral(true),
    );
    let selected = select(&source(), &patch, &[]);
    assert!(selected.lifetime.max_duration_secs.is_none());
    assert_eq!(
        selected
            .lifetime
            .idle_timeout_secs
            .as_ref()
            .and_then(SavedValue::value),
        Some(&None)
    );
    assert_eq!(patch.lifecycle.ephemeral, Some(true));
    let selected = select(
        &source(),
        &SandboxSpecPatch::new().lifecycle(SandboxPolicyPatch::new().idle_timeout_secs(0)),
        &[],
    );
    assert!(selected.lifetime.idle_timeout_secs.is_none());
    assert!(selected.lifetime.max_duration_secs.is_some());
    let cleared = select(
        &source(),
        &SandboxSpecPatch::new(),
        &[ExecutionDefaultClear::MaxDuration],
    );
    assert!(cleared.lifetime.max_duration_secs.is_none());
    assert!(cleared.lifetime.idle_timeout_secs.is_some());
    assert_eq!(
        select(
            &source(),
            &SandboxSpecPatch::new(),
            &[ExecutionDefaultClear::Lifetime]
        )
        .lifetime,
        LifetimeDefaultSelection::default()
    );
}

#[test]
fn unknown_lifetime_components_survive_partial_overrides_and_full_clear_resolves_them() {
    let mut saved = source();
    saved.lifecycle = Some(SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    });
    let patch = SandboxSpecPatch::new().lifecycle(SandboxPolicyPatch::new().max_duration_secs(5));
    let selected = select(&saved, &patch, &[]);
    assert!(
        !selected
            .unknown_fields
            .contains("execution.lifecycle.max_duration_secs")
    );
    assert!(
        selected
            .unknown_fields
            .contains("execution.lifecycle.idle_timeout_secs")
    );
    let selected = select(&saved, &patch, &[ExecutionDefaultClear::IdleTimeout]);
    assert!(selected.unknown_fields.is_empty());
    saved.lifecycle = Some(SavedValue::Default {});
    assert!(matches!(
        select(&saved, &SandboxSpecPatch::new(), &[])
            .lifetime
            .max_duration_secs,
        Some(SavedValue::Default {})
    ));
}

#[test]
fn explicit_rlimits_replace_the_complete_saved_list_including_empty_without_changing_patch() {
    let patch = SandboxSpecPatch::new().rlimits(vec![]);
    let selected = select(&source(), &patch, &[]);
    assert!(selected.rlimits.is_none());
    assert!(patch.rlimits.as_ref().unwrap().is_empty());
    let retained = select(&source(), &SandboxSpecPatch::new(), &[]);
    let limits = retained.rlimits.unwrap();
    let limit = &limits.value().unwrap()[0];
    assert_eq!(limit.soft.get(), 0);
    assert_eq!(limit.hard.get(), u64::MAX);
    assert!(
        select(
            &source(),
            &SandboxSpecPatch::new(),
            &[ExecutionDefaultClear::Rlimits]
        )
        .rlimits
        .is_none()
    );
}

#[test]
fn saved_security_is_not_consent_and_explicit_selection_cannot_defeat_mandatory_policy() {
    let mut saved = source();
    saved.security_profile = known(SecurityProfile::Default);
    let baseline = DestinationGuestSecurity {
        baseline: SecurityProfile::Restricted,
        ..policy()
    };
    let no = SandboxSpecPatch::new();
    let error = select_execution_defaults(
        &saved,
        &no,
        &[],
        SnapshotConfigMode::Saved,
        ExecutionRestoreMode::Disk,
        baseline,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("SCFG_APPROVAL"));
    let explicit = SandboxSpecPatch::new().security_profile(SecurityProfile::Default);
    assert_eq!(
        select_execution_defaults(
            &saved,
            &explicit,
            &[],
            SnapshotConfigMode::Saved,
            ExecutionRestoreMode::Disk,
            baseline
        )
        .unwrap()
        .security_profile,
        SecurityProfile::Default
    );
    let mandatory = DestinationGuestSecurity {
        minimum: SecurityProfile::Restricted,
        ..baseline
    };
    assert!(
        select_execution_defaults(
            &saved,
            &explicit,
            &[],
            SnapshotConfigMode::Saved,
            ExecutionRestoreMode::Disk,
            mandatory
        )
        .unwrap_err()
        .to_string()
        .contains("SCFG_POLICY")
    );
    for (mode, clears) in [
        (SnapshotConfigMode::Fresh, vec![]),
        (
            SnapshotConfigMode::Saved,
            vec![ExecutionDefaultClear::Security],
        ),
    ] {
        assert_eq!(
            select_execution_defaults(
                &saved,
                &no,
                &clears,
                mode,
                ExecutionRestoreMode::Disk,
                mandatory
            )
            .unwrap()
            .security_profile,
            SecurityProfile::Restricted
        );
    }
    saved.security_profile = Some(SavedValue::Default {});
    assert!(
        select_execution_defaults(
            &saved,
            &no,
            &[],
            SnapshotConfigMode::Saved,
            ExecutionRestoreMode::Disk,
            baseline
        )
        .is_err()
    );
}

#[test]
fn unknown_security_requires_explicit_disk_choice_but_verified_full_evidence_is_authoritative() {
    let mut saved = source();
    saved.security_profile = Some(SavedValue::Unknown {
        reason: SavedUnknownReason::NotObserved,
    });
    assert!(
        select_execution_defaults(
            &saved,
            &SandboxSpecPatch::new(),
            &[],
            SnapshotConfigMode::Saved,
            ExecutionRestoreMode::Disk,
            policy()
        )
        .unwrap_err()
        .to_string()
        .contains("SCFG_UNKNOWN")
    );
    assert_eq!(
        select(
            &saved,
            &SandboxSpecPatch::new().security_profile(SecurityProfile::Restricted),
            &[]
        )
        .security_profile,
        SecurityProfile::Restricted
    );
    let selected = select_execution_defaults(
        &saved,
        &SandboxSpecPatch::new(),
        &[],
        SnapshotConfigMode::Fresh,
        ExecutionRestoreMode::Full {
            captured_security: SecurityProfile::Restricted,
        },
        policy(),
    )
    .unwrap();
    assert_eq!(selected.security_profile, SecurityProfile::Restricted);
    assert!(selected.labels.is_none());
    assert!(selected.rlimits.is_none());
    assert_eq!(selected.lifetime, LifetimeDefaultSelection::default());
}

#[test]
fn full_security_preserves_existing_override_refusal_and_does_not_waive_evidence_or_policy() {
    for mode in [SnapshotConfigMode::Saved, SnapshotConfigMode::Fresh] {
        let full = ExecutionRestoreMode::Full {
            captured_security: SecurityProfile::Restricted,
        };
        for (explicit, clears) in [
            (
                SandboxSpecPatch::new().security_profile(SecurityProfile::Restricted),
                vec![],
            ),
            (
                SandboxSpecPatch::new(),
                vec![ExecutionDefaultClear::Security],
            ),
        ] {
            assert!(
                select_execution_defaults(&source(), &explicit, &clears, mode, full, policy())
                    .unwrap_err()
                    .to_string()
                    .contains("SCFG_FULL_STATE")
            );
        }
        let full = ExecutionRestoreMode::Full {
            captured_security: SecurityProfile::Default,
        };
        assert!(
            select_execution_defaults(
                &source(),
                &SandboxSpecPatch::new(),
                &[],
                mode,
                full,
                policy()
            )
            .unwrap_err()
            .to_string()
            .contains("SCFG_INTEGRITY")
        );
        let mut saved = source();
        saved.security_profile = known(SecurityProfile::Default);
        let mandatory = DestinationGuestSecurity {
            minimum: SecurityProfile::Restricted,
            ..policy()
        };
        assert!(
            select_execution_defaults(&saved, &SandboxSpecPatch::new(), &[], mode, full, mandatory)
                .unwrap_err()
                .to_string()
                .contains("SCFG_POLICY")
        );
        let baseline = DestinationGuestSecurity {
            baseline: SecurityProfile::Restricted,
            ..policy()
        };
        assert!(
            select_execution_defaults(&saved, &SandboxSpecPatch::new(), &[], mode, full, baseline)
                .unwrap_err()
                .to_string()
                .contains("SCFG_APPROVAL")
        );
    }
}

#[test]
fn execution_selection_is_bounded_and_unknown_label_maps_require_whole_field_clear() {
    let mut saved = source();
    saved.labels = Some(SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    });
    assert!(
        select(
            &saved,
            &SandboxSpecPatch::new().labels(BTreeMap::new()),
            &[]
        )
        .unknown_fields
        .contains("execution.labels")
    );
    assert!(
        !select(
            &saved,
            &SandboxSpecPatch::new(),
            &[ExecutionDefaultClear::Labels]
        )
        .unknown_fields
        .contains("execution.labels")
    );
    assert!(
        select_execution_defaults(
            &saved,
            &SandboxSpecPatch::new(),
            &[ExecutionDefaultClear::LabelKey("x".into())],
            SnapshotConfigMode::Fresh,
            ExecutionRestoreMode::Disk,
            policy()
        )
        .is_err()
    );
    assert!(
        select_execution_defaults(
            &source(),
            &SandboxSpecPatch::new(),
            &vec![ExecutionDefaultClear::Labels; 257],
            SnapshotConfigMode::Saved,
            ExecutionRestoreMode::Disk,
            policy()
        )
        .unwrap_err()
        .to_string()
        .contains("SCFG_LIMIT")
    );
}
