//! Storage plans preserve requirements without opening paths or claiming physical identity.

use std::collections::BTreeMap;
use std::path::PathBuf;

use microsandbox_types::snapshot::saved_config::{
    SavedBindRootKind, SavedBindingReference, SavedMount, SavedMountOptions, SavedOrigin,
    SavedStorageConfig, SavedUnknownReason, SavedValue, SavedVsockRoute,
};
use microsandbox_types::snapshot::{
    CheckpointSnapshotState, Manifest, OwnedDirectoryPayload, OwnedMountSnapshot,
    OwnedVolumeCapture, OwnedVolumeData, SnapshotScope, SnapshotState,
};
use microsandbox_types::{
    DiskImageFormat, HostPermissions, MountOptions, NamedVolumeCreate, NamedVolumeMode,
    OwnedVolumeStorage, SandboxSpecPatch, StatVirtualization, VolumeKind, VolumeMount,
    VsockRouteSpec, VsockSocketType, VsockSpecPatch, owned_volume_mount_id,
};
use serde_json::json;

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

fn source(mut mounts: Vec<SavedMount>, routes: Vec<SavedVsockRoute>) -> SavedStorageConfig {
    mounts.sort_by(|a, b| {
        (a.guest().split('/').count(), a.guest()).cmp(&(b.guest().split('/').count(), b.guest()))
    });
    SavedStorageConfig {
        mounts: known(mounts),
        vsock: known(routes),
    }
}

fn bind(guest: &str, id: &str) -> SavedMount {
    SavedMount::Bind {
        guest: guest.into(),
        root_kind: SavedBindRootKind::Directory,
        binding: SavedBindingReference { id: id.into() },
        options: SavedMountOptions::from(&MountOptions::default()),
        stat_virtualization: StatVirtualization::Strict,
        host_permissions: HostPermissions::Private,
        follow_root_symlinks: false,
        quota_mib: None,
    }
}

fn destination(guest: &str) -> VolumeMount {
    VolumeMount::Bind {
        guest: guest.into(),
        host: PathBuf::from("relative/../SENTINEL_HOST"),
        options: MountOptions::default(),
        stat_virtualization: StatVirtualization::Strict,
        host_permissions: HostPermissions::Private,
        follow_root_symlinks: false,
        quota_mib: None,
    }
}

fn route(port: u32, socket_type: VsockSocketType, id: &str) -> SavedVsockRoute {
    SavedVsockRoute {
        port,
        socket_type,
        binding: SavedBindingReference { id: id.into() },
    }
}

fn destination_route(port: u32, socket_type: VsockSocketType) -> VsockRouteSpec {
    VsockRouteSpec {
        port,
        socket_type,
        host_socket: "relative/SENTINEL_SOCKET".into(),
    }
}

fn patch(mounts: Vec<VolumeMount>, routes: Vec<VsockRouteSpec>) -> SandboxSpecPatch {
    SandboxSpecPatch::new()
        .mounts(mounts)
        .vsock(VsockSpecPatch::new().routes(routes))
}

pub(super) fn manifest(full: bool) -> Manifest {
    let mut manifest: Manifest = serde_json::from_value(json!({
        "schema":"microsandbox.snapshot/1", "snapshot_id":"snap_0123456789abcdef0123456789abcdef", "scope":"file",
        "state":{"kind":"file","disk_format":"raw","filesystem":"ext4","virtual_size":4,"head":"layer_0123456789abcdef0123456789abcdef",
          "layers":[{"layer_id":"layer_0123456789abcdef0123456789abcdef","format":"raw","virtual_size":4,"backing":null,"payload":{"file_kind":"regular","integrity":null}}]},
        "capture":{"created_at":"2026-08-29T00:00:00Z","source_lineage":null,"source_checkpoint":null,"consistency":"crash-consistent"},
        "image":{"reference":"alpine:latest","manifest_digest":format!("sha256:{}","a".repeat(64))},
        "parent":null,"requires":[],"extensions":{}
    })).unwrap();
    if full {
        manifest.scope = SnapshotScope::Full;
        manifest.state = SnapshotState::Checkpoint(CheckpointSnapshotState {
            checkpoint_id: "checkpoint_test".into(),
            checkpoint_root: format!("sha256:{}", "a".repeat(64)),
            restore_intents: vec!["clone".into()],
            requirements_summary: BTreeMap::new(),
        });
    }
    manifest
}

pub(super) fn owned(guest: &str) -> OwnedVolumeCapture {
    OwnedVolumeCapture {
        mount_id: owned_volume_mount_id(guest),
        mount: OwnedMountSnapshot {
            guest: guest.into(),
            storage: OwnedVolumeStorage::Directory { quota_mib: None },
            options: MountOptions::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
        },
        data: OwnedVolumeData::Directory {
            descriptor: OwnedDirectoryPayload {
                digest: "a".repeat(64),
                bytes: 1,
            },
            files: vec![],
        },
    }
}

fn select(
    saved: &SavedStorageConfig,
    inputs: &SandboxSpecPatch,
    full: bool,
) -> StorageInputSelection {
    select_storage_inputs(
        saved,
        &manifest(full),
        inputs,
        SnapshotConfigMode::Saved,
        full,
    )
    .unwrap()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn one_mapping_does_not_discard_other_mounts_or_a_shared_binding_consumer() {
    let saved = source(vec![bind("/a", "shared"), bind("/b", "shared")], vec![]);
    let before = saved.clone();
    let inputs = patch(vec![destination("/a/")], vec![]);
    let selected = select(&saved, &inputs, false);
    assert_eq!(selected.mounts.len(), 2);
    assert_eq!(selected.mounts[0].guest, "/a");
    assert!(selected.mounts[0].destination.is_some());
    assert!(selected.mounts[1].destination.is_none());
    assert!(selected.remaining_bindings.contains_key("shared"));
    assert_eq!(inputs.mounts.as_ref().unwrap()[0].guest(), "/a/");
    let VolumeMount::Bind { host, .. } = selected.mounts[0].destination.as_ref().unwrap() else {
        panic!("bind")
    };
    assert_eq!(host, &PathBuf::from("relative/../SENTINEL_HOST"));
    assert_eq!(saved, before);
    assert!(!format!("{selected:?}").contains("SENTINEL"));
    assert!(!format!("{:?}", selected.mounts[0]).contains("SENTINEL"));
    let both = select(
        &saved,
        &patch(vec![destination("/a"), destination("/b")], vec![]),
        false,
    );
    assert!(both.remaining_bindings.is_empty());
}

#[test]
fn fresh_mode_and_empty_lists_keep_required_mounts_and_routes() {
    let saved = source(
        vec![bind("/a", "data")],
        vec![route(9000, VsockSocketType::Stream, "ipc")],
    );
    for full in [false, true] {
        for mode in [SnapshotConfigMode::Saved, SnapshotConfigMode::Fresh] {
            let selected =
                select_storage_inputs(&saved, &manifest(full), &patch(vec![], vec![]), mode, full)
                    .unwrap();
            assert_eq!(selected.mounts.len(), 1);
            assert_eq!(selected.vsock.len(), 1);
            assert_eq!(selected.remaining_bindings.len(), 2);
            assert_eq!(selected.requires_full_identity, full);
        }
    }
}

#[test]
fn canonical_duplicate_paths_reject_without_echoing_host_values() {
    let saved = source(vec![], vec![]);
    for inputs in [
        patch(vec![destination("/same"), destination("/same/")], vec![]),
        patch(vec![destination("/SENTINEL/../bad")], vec![]),
    ] {
        let error = select_storage_inputs(
            &saved,
            &manifest(false),
            &inputs,
            SnapshotConfigMode::Saved,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("SCFG_IDENTITY"));
        assert!(!error.contains("SENTINEL"));
    }
}

#[test]
fn legacy_external_requirements_survive_absent_or_unknown_saved_inventory() {
    let mut manifest = manifest(false);
    manifest
        .set_external_mounts(vec!["/legacy/".into()])
        .unwrap();
    for saved in [
        SavedStorageConfig::default(),
        SavedStorageConfig {
            mounts: Some(SavedValue::Unknown {
                reason: SavedUnknownReason::NotRecorded,
            }),
            ..Default::default()
        },
    ] {
        let selected = select_storage_inputs(
            &saved,
            &manifest,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Fresh,
            false,
        )
        .unwrap();
        assert_eq!(selected.mounts[0].guest, "/legacy");
        assert!(selected.mounts[0].external_required);
        assert!(selected.mounts[0].destination.is_none());
        assert!(!selected.mount_inventory_complete);
        let mapped = select_storage_inputs(
            &saved,
            &manifest,
            &patch(vec![destination("/legacy")], vec![]),
            SnapshotConfigMode::Saved,
            false,
        )
        .unwrap();
        assert!(mapped.mounts[0].destination.is_some());
    }
    assert!(
        select_storage_inputs(
            &source(vec![], vec![]),
            &manifest,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            false
        )
        .is_err()
    );
}

#[test]
fn owned_backing_cannot_be_replaced_or_erased_by_fresh_or_missing_config() {
    for full in [false, true] {
        let mut manifest = manifest(full);
        manifest.set_owned_volumes(vec![owned("/private")]).unwrap();
        let before = manifest.to_canonical_bytes().unwrap();
        let selected = select_storage_inputs(
            &SavedStorageConfig::default(),
            &manifest,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Fresh,
            full,
        )
        .unwrap();
        assert!(matches!(
            selected.mounts[0].saved,
            Some(SavedMount::Owned { .. })
        ));
        for replacement in [
            destination("/private"),
            VolumeMount::Tmpfs {
                guest: "/private".into(),
                size_mib: None,
                options: MountOptions::default(),
            },
            VolumeMount::Owned {
                guest: "/private".into(),
                storage: OwnedVolumeStorage::Directory { quota_mib: None },
                options: MountOptions::default(),
                stat_virtualization: StatVirtualization::Strict,
                host_permissions: HostPermissions::Private,
            },
        ] {
            assert!(
                select_storage_inputs(
                    &SavedStorageConfig::default(),
                    &manifest,
                    &patch(vec![replacement], vec![]),
                    SnapshotConfigMode::Fresh,
                    full
                )
                .unwrap_err()
                .to_string()
                .contains("SCFG_IDENTITY")
            );
        }
        assert_eq!(manifest.to_canonical_bytes().unwrap(), before);
        manifest
            .set_external_mounts(vec!["/private".into()])
            .unwrap();
        assert!(
            select_storage_inputs(
                &SavedStorageConfig::default(),
                &manifest,
                &SandboxSpecPatch::new(),
                SnapshotConfigMode::Fresh,
                full
            )
            .is_err()
        );
    }
}

#[test]
fn empty_tmpfs_or_owned_state_cannot_satisfy_recorded_external_backing() {
    let saved = source(vec![bind("/data", "data")], vec![]);
    for full in [false, true] {
        let inputs = patch(
            vec![VolumeMount::Tmpfs {
                guest: "/data".into(),
                size_mib: None,
                options: MountOptions::default(),
            }],
            vec![],
        );
        assert!(
            select_storage_inputs(
                &saved,
                &manifest(full),
                &inputs,
                SnapshotConfigMode::Saved,
                full
            )
            .unwrap_err()
            .to_string()
            .contains("SCFG_IDENTITY")
        );
    }
}

#[test]
fn full_mounts_reject_obvious_layout_and_flag_changes_without_claiming_backing_identity() {
    let saved = source(vec![bind("/data", "data")], vec![]);
    let mut readonly = destination("/data");
    let VolumeMount::Bind { options, .. } = &mut readonly else {
        panic!("bind")
    };
    options.readonly = true;
    for mount in [
        readonly,
        VolumeMount::DiskImage {
            host: "SENTINEL.raw".into(),
            guest: "/data".into(),
            format: DiskImageFormat::Raw,
            fstype: None,
            options: MountOptions::default(),
        },
        destination("/new"),
    ] {
        let error = select_storage_inputs(
            &saved,
            &manifest(true),
            &patch(vec![mount], vec![]),
            SnapshotConfigMode::Fresh,
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("SCFG_FULL_STATE"));
        assert!(!error.contains("SENTINEL"));
    }
    let selected = select(&saved, &patch(vec![destination("/data")], vec![]), true);
    assert!(selected.requires_full_identity);
    assert!(selected.mounts[0].saved.is_some());
}

#[test]
fn tmpfs_full_layout_is_retained_and_disk_additions_are_ordered_parent_first() {
    let saved = source(
        vec![SavedMount::Tmpfs {
            guest: "/tmp".into(),
            size_mib: Some(8),
            options: SavedMountOptions::from(&MountOptions::default()),
        }],
        vec![],
    );
    let same = VolumeMount::Tmpfs {
        guest: "/tmp".into(),
        size_mib: Some(8),
        options: MountOptions::default(),
    };
    assert!(select(&saved, &patch(vec![same], vec![]), true).requires_full_identity);
    let changed = VolumeMount::Tmpfs {
        guest: "/tmp".into(),
        size_mib: Some(16),
        options: MountOptions::default(),
    };
    assert!(
        select_storage_inputs(
            &saved,
            &manifest(true),
            &patch(vec![changed], vec![]),
            SnapshotConfigMode::Saved,
            true
        )
        .is_err()
    );
    let saved = source(vec![bind("/a/child", "child")], vec![]);
    let selected = select(
        &saved,
        &patch(vec![destination("/z"), destination("/a")], vec![]),
        false,
    );
    assert_eq!(
        selected
            .mounts
            .iter()
            .map(|m| m.guest.as_str())
            .collect::<Vec<_>>(),
        vec!["/a", "/z", "/a/child"]
    );
}

#[test]
fn ipc_namespaces_are_independent_and_shared_consumers_survive_partial_mapping() {
    let saved = source(
        vec![],
        vec![
            route(9000, VsockSocketType::Stream, "stream"),
            route(9001, VsockSocketType::Stream, "stream"),
            route(9000, VsockSocketType::Dgram, "dgram"),
        ],
    );
    let selected = select(
        &saved,
        &patch(
            vec![],
            vec![destination_route(9000, VsockSocketType::Stream)],
        ),
        true,
    );
    assert_eq!(selected.vsock.len(), 3);
    assert!(selected.remaining_bindings.contains_key("stream"));
    assert!(selected.remaining_bindings.contains_key("dgram"));
    assert!(selected.requires_full_identity);
    assert_eq!(
        selected
            .vsock
            .iter()
            .filter(|r| r.destination.is_some())
            .count(),
        1
    );
    assert!(!format!("{:?}", selected.vsock[0]).contains("SENTINEL"));
    let all = select(
        &saved,
        &patch(
            vec![],
            vec![
                destination_route(9000, VsockSocketType::Stream),
                destination_route(9001, VsockSocketType::Stream),
            ],
        ),
        true,
    );
    assert!(!all.remaining_bindings.contains_key("stream"));
    assert!(all.remaining_bindings.contains_key("dgram"));
}

#[test]
fn duplicate_reserved_and_new_full_ipc_routes_refuse_before_endpoint_access() {
    let saved = source(vec![], vec![]);
    for routes in [
        vec![
            destination_route(1, VsockSocketType::Stream),
            destination_route(1, VsockSocketType::Stream),
        ],
        vec![destination_route(0, VsockSocketType::Stream)],
        vec![destination_route(u32::MAX, VsockSocketType::Stream)],
        vec![destination_route(123, VsockSocketType::Dgram)],
    ] {
        let error = select_storage_inputs(
            &saved,
            &manifest(false),
            &patch(vec![], routes),
            SnapshotConfigMode::Saved,
            false,
        )
        .unwrap_err()
        .to_string();
        assert!(!error.contains("SENTINEL"));
    }
    assert_eq!(
        select(
            &saved,
            &patch(
                vec![],
                vec![destination_route(123, VsockSocketType::Stream)]
            ),
            false
        )
        .vsock
        .len(),
        1
    );
    assert!(
        select_storage_inputs(
            &saved,
            &manifest(true),
            &patch(vec![], vec![destination_route(1, VsockSocketType::Stream)]),
            SnapshotConfigMode::Fresh,
            true
        )
        .unwrap_err()
        .to_string()
        .contains("SCFG_FULL_STATE")
    );
}

#[test]
fn unknown_inventories_are_not_proven_complete_by_partial_destination_inputs() {
    let saved = SavedStorageConfig {
        mounts: Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotObserved,
        }),
        vsock: Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded,
        }),
    };
    let selected = select(
        &saved,
        &patch(
            vec![destination("/data")],
            vec![destination_route(9000, VsockSocketType::Stream)],
        ),
        true,
    );
    assert!(!selected.mount_inventory_complete);
    assert!(!selected.vsock_inventory_complete);
    assert_eq!(selected.unknown_fields.len(), 2);
    assert!(selected.requires_full_identity);
    assert!(
        select_storage_inputs(
            &saved,
            &manifest(false),
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            true
        )
        .unwrap_err()
        .to_string()
        .contains("SCFG_MODE")
    );
}

#[test]
fn saved_relaxations_are_obligations_and_explicit_safe_mounts_do_not_replay_them() {
    let mut mount = bind("/data", "data");
    let SavedMount::Bind {
        stat_virtualization,
        host_permissions,
        follow_root_symlinks,
        ..
    } = &mut mount
    else {
        panic!("bind")
    };
    *stat_virtualization = StatVirtualization::Relaxed;
    *host_permissions = HostPermissions::Mirror;
    *follow_root_symlinks = true;
    let saved = source(vec![mount], vec![]);
    let selected = select(&saved, &SandboxSpecPatch::new(), false);
    assert_eq!(selected.required_approvals.len(), 3);
    assert!(
        selected
            .required_approvals
            .iter()
            .any(|r| r.relaxation == StorageRelaxation::MirrorHostPermissions)
    );
    let mapped = select(&saved, &patch(vec![destination("/data")], vec![]), false);
    assert!(mapped.required_approvals.is_empty());
    assert!(mapped.mounts[0].saved.is_some());
    let mut manifest = manifest(false);
    let mut volume = owned("/private");
    volume.mount.host_permissions = HostPermissions::Mirror;
    manifest.set_owned_volumes(vec![volume]).unwrap();
    let owned = select_storage_inputs(
        &SavedStorageConfig::default(),
        &manifest,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Fresh,
        false,
    )
    .unwrap();
    assert!(
        owned
            .required_approvals
            .iter()
            .any(|r| r.relaxation == StorageRelaxation::MirrorHostPermissions)
    );
}

#[test]
fn full_named_destination_provisioning_is_rejected_while_existing_bindings_require_proof() {
    let saved = source(vec![bind("/data", "data")], vec![]);
    let mut target = VolumeMount::Named {
        name: "SENTINEL_VOLUME".into(),
        guest: "/data".into(),
        create: None,
        options: MountOptions::default(),
        stat_virtualization: StatVirtualization::Strict,
        host_permissions: HostPermissions::Private,
        follow_root_symlinks: false,
    };
    assert!(select(&saved, &patch(vec![target.clone()], vec![]), true).requires_full_identity);
    let VolumeMount::Named { create, .. } = &mut target else {
        panic!("named")
    };
    *create = Some(NamedVolumeCreate {
        mode: NamedVolumeMode::Create,
        name: "SENTINEL_VOLUME".into(),
        kind: VolumeKind::Directory,
        quota_mib: None,
        capacity_mib: None,
        labels: vec![],
    });
    let error = select_storage_inputs(
        &saved,
        &manifest(true),
        &patch(vec![target], vec![]),
        SnapshotConfigMode::Saved,
        true,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("SCFG_FULL_STATE"));
    assert!(!error.contains("SENTINEL"));
}

#[test]
fn new_owned_mounts_cannot_alias_each_other_or_captured_private_backing() {
    let first = "/shared-path/11188";
    let second = "/shared-path/92829";
    assert_eq!(owned_volume_mount_id(first), owned_volume_mount_id(second));
    let new_owned = |guest: &str| VolumeMount::Owned {
        guest: guest.into(),
        storage: OwnedVolumeStorage::Directory { quota_mib: None },
        options: MountOptions::default(),
        stat_virtualization: StatVirtualization::Strict,
        host_permissions: HostPermissions::Private,
    };
    let mut descriptor = manifest(false);
    descriptor.set_owned_volumes(vec![owned(first)]).unwrap();
    let error = select_storage_inputs(
        &SavedStorageConfig::default(),
        &descriptor,
        &patch(vec![new_owned(second)], vec![]),
        SnapshotConfigMode::Fresh,
        false,
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("owned backing namespace"));
    let selected = select_storage_inputs(
        &SavedStorageConfig::default(),
        &descriptor,
        &patch(vec![new_owned("/new")], vec![]),
        SnapshotConfigMode::Fresh,
        false,
    )
    .unwrap();
    assert_eq!(selected.mounts.len(), 2);
    assert!(
        select_storage_inputs(
            &source(vec![], vec![]),
            &manifest(false),
            &patch(vec![new_owned(first), new_owned(second)], vec![]),
            SnapshotConfigMode::Saved,
            false
        )
        .is_err()
    );
}

#[test]
fn full_disk_overrides_cannot_change_known_format_or_filesystem_and_probe_is_not_proof() {
    let saved = source(
        vec![SavedMount::DiskImage {
            guest: "/disk".into(),
            binding: SavedBindingReference { id: "disk".into() },
            format: DiskImageFormat::Raw,
            fstype: Some("ext4".into()),
            options: SavedMountOptions::from(&MountOptions::default()),
        }],
        vec![],
    );
    let disk = |format, fstype: Option<&str>| VolumeMount::DiskImage {
        guest: "/disk".into(),
        host: "SENTINEL_DISK".into(),
        format,
        fstype: fstype.map(str::to_owned),
        options: MountOptions::default(),
    };
    for destination in [
        disk(DiskImageFormat::Qcow2, Some("ext4")),
        disk(DiskImageFormat::Raw, Some("xfs")),
    ] {
        assert!(
            select_storage_inputs(
                &saved,
                &manifest(true),
                &patch(vec![destination], vec![]),
                SnapshotConfigMode::Saved,
                true
            )
            .unwrap_err()
            .to_string()
            .contains("SCFG_FULL_STATE")
        );
    }
    for destination in [
        disk(DiskImageFormat::Raw, Some("ext4")),
        disk(DiskImageFormat::Raw, None),
    ] {
        let selected = select(&saved, &patch(vec![destination], vec![]), true);
        assert!(selected.requires_full_identity);
        assert!(selected.mounts[0].saved.is_some());
    }
}
