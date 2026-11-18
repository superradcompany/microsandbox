//! Native resource composition preserves sparse maxima and checked full-state geometry.

use super::*;
use microsandbox_types::snapshot::saved_config::{
    SavedOrigin, SavedResourcesConfig, SavedUnknownReason, SavedValue,
};
use microsandbox_types::{
    CpuPlacement, SandboxResources, SandboxResourcesPatch, TransparentHugePagePolicy,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn known<T>(value: T) -> Option<SavedValue<T>> {
    Some(SavedValue::Value {
        value,
        origin: SavedOrigin::Observed,
    })
}

fn plan(
    saved: &SavedResourcesConfig,
    lower: &SandboxResourcesPatch,
    explicit: &SandboxResourcesPatch,
    clears: &[ResourceDefaultClear],
) -> crate::MicrosandboxResult<ResourceConfigurationPlan> {
    prepare_resource_configuration(
        saved,
        lower,
        explicit,
        clears,
        SnapshotConfigMode::Saved,
        ResourceRestoreMode::Disk,
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn omitted_maxima_follow_final_allocation_without_inventing_old_ceilings() {
    let source = SavedResourcesConfig {
        cpus: known(8),
        memory_mib: known(4096),
        ..Default::default()
    };
    let result = plan(
        &source,
        &SandboxResourcesPatch::new().cpus(2).memory_mib(512),
        &SandboxResourcesPatch::new(),
        &[],
    )
    .unwrap()
    .resources()
    .unwrap();
    assert_eq!((result.cpus, result.max_cpus), (8, 8));
    assert_eq!((result.memory_mib, result.max_memory_mib), (4096, 4096));
}

#[test]
fn saved_builtin_maximum_discards_lower_ceiling_but_explicit_maximum_wins() {
    let source = SavedResourcesConfig {
        cpus: known(8),
        max_cpus: Some(SavedValue::Default {}),
        memory_mib: known(4096),
        max_memory_mib: Some(SavedValue::Default {}),
        ..Default::default()
    };
    let lower = SandboxResourcesPatch::new().max_cpus(2).max_memory_mib(512);
    let result = plan(&source, &lower, &SandboxResourcesPatch::new(), &[])
        .unwrap()
        .resources()
        .unwrap();
    assert_eq!((result.max_cpus, result.max_memory_mib), (8, 4096));
    let result = plan(
        &source,
        &lower,
        &SandboxResourcesPatch::new()
            .max_cpus(16)
            .max_memory_mib(8192),
        &[],
    )
    .unwrap()
    .resources()
    .unwrap();
    assert_eq!((result.max_cpus, result.max_memory_mib), (16, 8192));
}

#[test]
fn configured_lower_ceilings_and_explicit_allocations_are_validated_together() {
    let source = SavedResourcesConfig::default();
    for (lower, explicit) in [
        (
            SandboxResourcesPatch::new().max_cpus(2),
            SandboxResourcesPatch::new().cpus(4),
        ),
        (
            SandboxResourcesPatch::new().max_memory_mib(512),
            SandboxResourcesPatch::new().memory_mib(1024),
        ),
        (
            SandboxResourcesPatch::new().cpus(0),
            SandboxResourcesPatch::new(),
        ),
        (
            SandboxResourcesPatch::new().max_memory_mib(0),
            SandboxResourcesPatch::new(),
        ),
    ] {
        assert!(
            plan(&source, &lower, &explicit, &[])
                .unwrap_err()
                .to_string()
                .contains("SCFG_VALUE")
        );
    }
}

#[test]
fn clears_reset_lower_defaults_before_explicit_destination_values_apply() {
    let source = SavedResourcesConfig {
        cpus: known(2),
        max_cpus: known(2),
        thp: known(TransparentHugePagePolicy::Never),
        ..Default::default()
    };
    let result = plan(
        &source,
        &SandboxResourcesPatch::new()
            .max_cpus(1)
            .thp(TransparentHugePagePolicy::Never),
        &SandboxResourcesPatch::new().cpus(8),
        &[
            ResourceDefaultClear::Cpus,
            ResourceDefaultClear::MaxCpus,
            ResourceDefaultClear::Thp,
        ],
    )
    .unwrap()
    .resources()
    .unwrap();
    assert_eq!((result.cpus, result.max_cpus), (8, 8));
    assert_eq!(result.thp, SandboxResources::default().thp);
}

#[test]
fn unknown_observations_never_borrow_lower_requested_capacity() {
    let source = SavedResourcesConfig {
        cpus: Some(SavedValue::Unknown {
            reason: SavedUnknownReason::Converging,
        }),
        ..Default::default()
    };
    let lower = SandboxResourcesPatch::new().cpus(8).max_cpus(2);
    let unresolved = plan(&source, &lower, &SandboxResourcesPatch::new(), &[]).unwrap();
    assert!(
        unresolved
            .resources()
            .unwrap_err()
            .to_string()
            .contains("SCFG_UNKNOWN")
    );
    let resolved = plan(&source, &lower, &SandboxResourcesPatch::new().cpus(2), &[])
        .unwrap()
        .resources()
        .unwrap();
    assert_eq!(resolved.cpus, 2);
    let resolved = plan(
        &source,
        &SandboxResourcesPatch::new(),
        &SandboxResourcesPatch::new(),
        &[ResourceDefaultClear::Cpus],
    )
    .unwrap()
    .resources()
    .unwrap();
    assert_eq!(resolved.cpus, SandboxResources::default().cpus);
}

#[test]
fn full_resume_uses_checked_geometry_without_source_host_placement() {
    let source = SavedResourcesConfig {
        cpus: known(4),
        memory_mib: known(1024),
        thp: known(TransparentHugePagePolicy::Never),
        ..Default::default()
    };
    let captured = SandboxResources {
        cpus: 2,
        max_cpus: 8,
        memory_mib: 512,
        max_memory_mib: 4096,
        cpu_placement: CpuPlacement::Compact,
        placement_profile: Some("SOURCE_PRIVATE_PROFILE".into()),
        ..Default::default()
    };
    let explicit = SandboxResourcesPatch::new()
        .cpu_placement(CpuPlacement::Spread)
        .set_placement_profile(Some("DEST_PRIVATE_PROFILE".into()));
    for mode in [SnapshotConfigMode::Saved, SnapshotConfigMode::Fresh] {
        let plan = prepare_resource_configuration(
            &source,
            &SandboxResourcesPatch::new(),
            &explicit,
            &[],
            mode,
            ResourceRestoreMode::Full(&captured),
        )
        .unwrap();
        assert!(plan.requires_full_compatibility());
        assert!(!format!("{plan:?}").contains("PRIVATE_PROFILE"));
        let result = plan.resources().unwrap();
        assert_eq!(
            (
                result.cpus,
                result.max_cpus,
                result.memory_mib,
                result.max_memory_mib
            ),
            (2, 8, 512, 4096)
        );
        assert_eq!(result.cpu_placement, CpuPlacement::Spread);
        assert_eq!(
            result.placement_profile.as_deref(),
            Some("DEST_PRIVATE_PROFILE")
        );
        assert_eq!(result.thp, TransparentHugePagePolicy::Never);
    }
}

#[test]
fn full_resume_rejects_geometry_changes_and_keeps_unknown_guest_policy_unresolved() {
    let captured = SandboxResources::default();
    let source = SavedResourcesConfig {
        thp: Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotObserved,
        }),
        ..Default::default()
    };
    let result = prepare_resource_configuration(
        &source,
        &SandboxResourcesPatch::new(),
        &SandboxResourcesPatch::new(),
        &[],
        SnapshotConfigMode::Fresh,
        ResourceRestoreMode::Full(&captured),
    )
    .unwrap();
    assert!(result.resources().is_err());
    for patch in [
        SandboxResourcesPatch::new().cpus(captured.cpus + 1),
        SandboxResourcesPatch::new().thp(captured.thp),
    ] {
        assert!(
            prepare_resource_configuration(
                &source,
                &SandboxResourcesPatch::new(),
                &patch,
                &[],
                SnapshotConfigMode::Saved,
                ResourceRestoreMode::Full(&captured)
            )
            .is_err()
        );
    }
}

#[test]
fn fresh_disk_uses_destination_defaults_and_does_not_mutate_the_source() {
    let source = SavedResourcesConfig {
        cpus: known(8),
        memory_mib: known(4096),
        ..Default::default()
    };
    let before = source.clone();
    let plan = prepare_resource_configuration(
        &source,
        &SandboxResourcesPatch::new().cpus(2).memory_mib(512),
        &SandboxResourcesPatch::new(),
        &[],
        SnapshotConfigMode::Fresh,
        ResourceRestoreMode::Disk,
    )
    .unwrap();
    assert!(!plan.requires_full_compatibility());
    let result = plan.resources().unwrap();
    assert_eq!(
        (
            result.cpus,
            result.max_cpus,
            result.memory_mib,
            result.max_memory_mib
        ),
        (2, 2, 512, 512)
    );
    assert_eq!(source, before);
}
