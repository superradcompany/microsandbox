//! Resource selection against actual sparse SDK inputs and independently captured geometry.

use microsandbox_types::snapshot::saved_config::{
    SavedOrigin, SavedResourcesConfig, SavedUnknownReason, SavedValue,
};
use microsandbox_types::{
    CpuPlacement, SandboxResources, SandboxResourcesPatch, TransparentHugePagePolicy,
};

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn known<T>(value: T) -> Option<SavedValue<T>> {
    Some(SavedValue::Value {
        value,
        origin: SavedOrigin::Observed,
    })
}

fn source() -> SavedResourcesConfig {
    SavedResourcesConfig {
        cpus: known(2),
        memory_mib: known(512),
        max_cpus: known(4),
        max_memory_mib: known(2048),
        thp: known(TransparentHugePagePolicy::Never),
    }
}

fn captured() -> SandboxResources {
    SandboxResources {
        cpus: 1,
        memory_mib: 256,
        max_cpus: 8,
        max_memory_mib: 4096,
        cpu_placement: CpuPlacement::Compact,
        placement_profile: Some("SENTINEL_SOURCE_HOST_PROFILE".into()),
        ..Default::default()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn disk_resources_preserve_saved_defaults_but_never_import_host_placement() {
    let explicit = SandboxResourcesPatch::new()
        .cpus(3)
        .memory_mib(1024)
        .cpu_placement(CpuPlacement::Spread)
        .set_placement_profile(Some("destination".into()));
    let selected = select_resource_defaults(
        &source(),
        &explicit,
        &[],
        SnapshotConfigMode::Saved,
        ResourceRestoreMode::Disk,
    )
    .unwrap();
    assert!(selected.defaults.cpus.is_none());
    assert!(selected.defaults.memory_mib.is_none());
    assert_eq!(selected.defaults.max_cpus, source().max_cpus);
    assert_eq!(selected.defaults.max_memory_mib, source().max_memory_mib);
    assert!(selected.required_geometry.is_none());
    assert!(selected.unknown_fields.is_empty());
    assert_eq!(explicit.cpu_placement, Some(CpuPlacement::Spread));
    assert_eq!(explicit.placement_profile, Some(Some("destination".into())));
}

#[test]
fn disk_resource_cross_layer_limits_are_checked_in_both_directions() {
    for patch in [
        SandboxResourcesPatch::new().cpus(5),
        SandboxResourcesPatch::new().max_cpus(1),
        SandboxResourcesPatch::new().memory_mib(4096),
        SandboxResourcesPatch::new().max_memory_mib(256),
    ] {
        let error = select_resource_defaults(
            &source(),
            &patch,
            &[],
            SnapshotConfigMode::Saved,
            ResourceRestoreMode::Disk,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("SCFG_VALUE"));
    }
    let patch = SandboxResourcesPatch::new()
        .cpus(8)
        .max_cpus(8)
        .memory_mib(4096)
        .max_memory_mib(8192);
    let selected = select_resource_defaults(
        &source(),
        &patch,
        &[],
        SnapshotConfigMode::Saved,
        ResourceRestoreMode::Disk,
    )
    .unwrap();
    assert!(selected.defaults.cpus.is_none());
    assert!(selected.defaults.max_cpus.is_none());
}

#[test]
fn resource_fresh_and_clears_discard_optional_limits_before_explicit_selection() {
    let explicit = SandboxResourcesPatch::new().cpus(8);
    let fresh = select_resource_defaults(
        &source(),
        &explicit,
        &[],
        SnapshotConfigMode::Fresh,
        ResourceRestoreMode::Disk,
    )
    .unwrap();
    assert_eq!(fresh.defaults, SavedResourcesConfig::default());
    let cleared = select_resource_defaults(
        &source(),
        &explicit,
        &[ResourceDefaultClear::MaxCpus, ResourceDefaultClear::MaxCpus],
        SnapshotConfigMode::Saved,
        ResourceRestoreMode::Disk,
    )
    .unwrap();
    assert!(cleared.defaults.max_cpus.is_none());
    assert_eq!(cleared.defaults.memory_mib, source().memory_mib);
    for patch in [
        SandboxResourcesPatch::new().cpus(0),
        SandboxResourcesPatch::new().max_cpus(0),
        SandboxResourcesPatch::new().memory_mib(0),
        SandboxResourcesPatch::new().max_memory_mib(0),
    ] {
        assert!(
            select_resource_defaults(
                &source(),
                &patch,
                &[],
                SnapshotConfigMode::Fresh,
                ResourceRestoreMode::Disk
            )
            .is_err()
        );
    }
}

#[test]
fn unknown_resources_are_not_filled_from_a_requested_target_or_maximum() {
    let mut saved = source();
    saved.cpus = Some(SavedValue::Unknown {
        reason: SavedUnknownReason::Converging,
    });
    saved.memory_mib = Some(SavedValue::Unknown {
        reason: SavedUnknownReason::NotObserved,
    });
    let selected = select_resource_defaults(
        &saved,
        &SandboxResourcesPatch::new().max_cpus(8),
        &[],
        SnapshotConfigMode::Saved,
        ResourceRestoreMode::Disk,
    )
    .unwrap();
    assert!(selected.unknown_fields.contains("resources.cpus"));
    assert!(selected.unknown_fields.contains("resources.memory_mib"));
    let selected = select_resource_defaults(
        &saved,
        &SandboxResourcesPatch::new().cpus(4),
        &[ResourceDefaultClear::Memory],
        SnapshotConfigMode::Saved,
        ResourceRestoreMode::Disk,
    )
    .unwrap();
    assert!(selected.unknown_fields.is_empty());
}

#[test]
fn full_geometry_wins_over_active_allocation_even_in_fresh_mode_without_host_placement() {
    let saved = source();
    let captured = captured(); // Construction geometry deliberately differs from observed active allocation.
    for mode in [SnapshotConfigMode::Saved, SnapshotConfigMode::Fresh] {
        let selected = select_resource_defaults(
            &saved,
            &SandboxResourcesPatch::new(),
            &[],
            mode,
            ResourceRestoreMode::Full(&captured),
        )
        .unwrap();
        assert!(selected.defaults.cpus.is_none());
        assert!(selected.defaults.memory_mib.is_none());
        assert_eq!(selected.defaults.thp, saved.thp);
        let patch = selected.required_geometry.unwrap();
        assert_eq!(patch.cpus, Some(1));
        assert_eq!(patch.max_cpus, Some(8));
        assert_eq!(patch.memory_mib, Some(256));
        assert_eq!(patch.max_memory_mib, Some(4096));
        assert_eq!(patch.thp, None);
        assert_eq!(patch.cpu_placement, None);
        assert_eq!(patch.placement_profile, None);
        assert!(!format!("{patch:?}").contains("SENTINEL"));
    }
}

#[test]
fn full_resources_allow_only_existing_equal_geometry_overrides_and_reject_all_boot_clears() {
    let captured = captured();
    let equal = SandboxResourcesPatch::new()
        .cpus(1)
        .max_cpus(8)
        .memory_mib(256)
        .max_memory_mib(4096);
    assert!(
        select_resource_defaults(
            &source(),
            &equal,
            &[],
            SnapshotConfigMode::Saved,
            ResourceRestoreMode::Full(&captured)
        )
        .is_ok()
    );
    for patch in [
        SandboxResourcesPatch::new().cpus(2),
        SandboxResourcesPatch::new().max_cpus(4),
        SandboxResourcesPatch::new().memory_mib(512),
        SandboxResourcesPatch::new().max_memory_mib(8192),
        SandboxResourcesPatch::new().thp(captured.thp),
    ] {
        let error = select_resource_defaults(
            &source(),
            &patch,
            &[],
            SnapshotConfigMode::Fresh,
            ResourceRestoreMode::Full(&captured),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("SCFG_FULL_STATE"));
    }
    for clear in [
        ResourceDefaultClear::Cpus,
        ResourceDefaultClear::Memory,
        ResourceDefaultClear::MaxCpus,
        ResourceDefaultClear::MaxMemory,
        ResourceDefaultClear::Thp,
    ] {
        assert!(
            select_resource_defaults(
                &source(),
                &SandboxResourcesPatch::new(),
                &[clear],
                SnapshotConfigMode::Fresh,
                ResourceRestoreMode::Full(&captured)
            )
            .is_err()
        );
    }
}

#[test]
fn malformed_resources_cannot_be_hidden_by_fresh_mode_or_overrides() {
    let mut bad = source();
    bad.cpus = known(0);
    assert!(
        select_resource_defaults(
            &bad,
            &SandboxResourcesPatch::new().cpus(2),
            &[],
            SnapshotConfigMode::Fresh,
            ResourceRestoreMode::Disk
        )
        .is_err()
    );
    let mut bad_geometry = captured();
    bad_geometry.max_cpus = 0;
    assert!(
        select_resource_defaults(
            &source(),
            &SandboxResourcesPatch::new(),
            &[],
            SnapshotConfigMode::Fresh,
            ResourceRestoreMode::Full(&bad_geometry)
        )
        .is_err()
    );
    assert!(
        select_resource_defaults(
            &source(),
            &SandboxResourcesPatch::new(),
            &vec![ResourceDefaultClear::Cpus; 257],
            SnapshotConfigMode::Saved,
            ResourceRestoreMode::Disk
        )
        .unwrap_err()
        .to_string()
        .contains("SCFG_LIMIT")
    );
}
