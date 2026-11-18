//! Native preparation must retain source identity obligations without touching backing.

use std::collections::BTreeMap;
#[cfg(unix)]
use std::ffi::OsString;
#[cfg(unix)]
use std::os::unix::ffi::OsStringExt;
use std::path::PathBuf;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_BYTES, MAX_SAVED_TEXT_BYTES, SavedBindRootKind, SavedBindingReference,
    SavedMount, SavedMountOptions, SavedNamedStorage, SavedOrigin, SavedStorageConfig,
    SavedUnknownReason, SavedValue, SavedVsockRoute,
};
use microsandbox_types::{
    DiskImageFormat, HostPermissions, MountOptions, SandboxSpec, SandboxSpecPatch,
    StatVirtualization, VolumeMount, VsockRouteSpec, VsockSocketType,
};

use super::storage_tests::{manifest, owned};
use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn binding(id: &str) -> SavedBindingReference {
    SavedBindingReference { id: id.into() }
}

fn known<T>(value: T) -> Option<SavedValue<T>> {
    Some(SavedValue::Value {
        value,
        origin: SavedOrigin::Configured,
    })
}

fn bind(guest: &str, id: &str) -> SavedMount {
    SavedMount::Bind {
        guest: guest.into(),
        root_kind: SavedBindRootKind::Directory,
        binding: binding(id),
        options: SavedMountOptions::from(&MountOptions::default()),
        stat_virtualization: StatVirtualization::Strict,
        host_permissions: HostPermissions::Private,
        follow_root_symlinks: false,
        quota_mib: Some(17),
    }
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

fn prepare(
    saved: &SavedStorageConfig,
    inputs: &BTreeMap<String, StorageBindingInput>,
) -> crate::MicrosandboxResult<StorageConfigurationPlan> {
    prepare_storage_configuration(
        saved,
        &manifest(false),
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        false,
        inputs,
    )
}

fn assert_redacted(error: &crate::MicrosandboxError, code: &str) {
    assert!(error.to_string().contains(code), "{error}");
    assert!(!error.to_string().contains("SENTINEL"), "{error}");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn prepares_shared_backing_each_mount_policy_and_routes_without_source_lookup() {
    let mut child = bind("/data/child", "directory");
    if let SavedMount::Bind {
        options, quota_mib, ..
    } = &mut child
    {
        options.readonly = true;
        *quota_mib = Some(0);
    }
    let saved = source(
        vec![child, bind("/data", "directory")],
        vec![
            SavedVsockRoute {
                port: 1234,
                socket_type: VsockSocketType::Stream,
                binding: binding("ipc"),
            },
            SavedVsockRoute {
                port: 1235,
                socket_type: VsockSocketType::Stream,
                binding: binding("ipc"),
            },
        ],
    );
    let original = serde_json::to_vec(&saved).unwrap();
    let inputs = BTreeMap::from([
        (
            "directory".into(),
            StorageBindingInput::FilesystemDirectory("./symlink/../SENTINEL".into()),
        ),
        (
            "ipc".into(),
            StorageBindingInput::StreamSocket("relative/SENTINEL.sock".into()),
        ),
    ]);
    let plan = prepare(&saved, &inputs).unwrap();
    let mut destination = SandboxSpec::default();
    destination.name = "destination".into();
    plan.apply_to(&mut destination).unwrap();
    assert_eq!(destination.name, "destination");
    assert_eq!(
        destination
            .mounts
            .iter()
            .map(|m| m.guest())
            .collect::<Vec<_>>(),
        ["/data", "/data/child"]
    );
    for mount in &destination.mounts {
        let VolumeMount::Bind {
            host,
            options,
            quota_mib,
            guest,
            ..
        } = mount
        else {
            panic!()
        };
        assert_eq!(host, &PathBuf::from("./symlink/../SENTINEL"));
        assert_eq!(options.readonly, guest == "/data/child");
        assert_eq!(*quota_mib, Some(if guest == "/data" { 17 } else { 0 }));
    }
    assert_eq!(destination.vsock.routes.len(), 2);
    assert_eq!(
        destination.vsock.routes[1].host_socket,
        PathBuf::from("relative/SENTINEL.sock")
    );
    assert_eq!(plan.selection().remaining_bindings.len(), 2);
    assert_eq!(serde_json::to_vec(&saved).unwrap(), original);
    assert!(!format!("{inputs:?} {plan:?}").contains("SENTINEL"));
}

#[test]
fn named_disk_and_external_image_preserve_semantics_without_provisioning() {
    let saved = source(
        vec![
            SavedMount::Named {
                guest: "/named".into(),
                binding: binding("volume"),
                storage: SavedNamedStorage::Disk { capacity_mib: 512 },
                options: SavedMountOptions::from(&MountOptions::default()),
                stat_virtualization: StatVirtualization::Strict,
                host_permissions: HostPermissions::Private,
                follow_root_symlinks: false,
            },
            SavedMount::DiskImage {
                guest: "/disk".into(),
                binding: binding("disk"),
                format: DiskImageFormat::Vmdk,
                fstype: Some("ext4".into()),
                options: SavedMountOptions::from(&MountOptions {
                    readonly: true,
                    ..Default::default()
                }),
            },
            SavedMount::Tmpfs {
                guest: "/memory".into(),
                size_mib: Some(64),
                options: SavedMountOptions::from(&MountOptions::default()),
            },
        ],
        vec![],
    );
    let inputs = BTreeMap::from([
        (
            "volume".into(),
            StorageBindingInput::NamedDisk("destination-volume".into()),
        ),
        (
            "disk".into(),
            StorageBindingInput::DiskImage("missing/SENTINEL.vmdk".into()),
        ),
    ]);
    let plan = prepare(&saved, &inputs).unwrap();
    let mut destination = SandboxSpec::default();
    plan.apply_to(&mut destination).unwrap();
    assert!(
        matches!(&destination.mounts[0], VolumeMount::DiskImage { format: DiskImageFormat::Vmdk, fstype: Some(fs), options, .. } if fs == "ext4" && options.readonly)
    );
    assert!(matches!(
        &destination.mounts[1],
        VolumeMount::Tmpfs {
            size_mib: Some(64),
            ..
        }
    ));
    assert!(
        matches!(&destination.mounts[2], VolumeMount::Named { name, create: None, .. } if name == "destination-volume")
    );
    assert!(matches!(
        &plan.selection().mounts[2].saved,
        Some(SavedMount::Named {
            storage: SavedNamedStorage::Disk { capacity_mib: 512 },
            ..
        })
    ));
}

#[test]
fn explicit_mapping_masks_only_its_consumer_of_a_shared_binding() {
    let saved = source(vec![bind("/a", "shared"), bind("/b", "shared")], vec![]);
    let explicit = SandboxSpecPatch::new().mounts(vec![VolumeMount::Bind {
        host: "explicit/SENTINEL".into(),
        guest: "/a".into(),
        options: MountOptions::default(),
        stat_virtualization: StatVirtualization::Strict,
        host_permissions: HostPermissions::Private,
        follow_root_symlinks: false,
        quota_mib: Some(99),
    }]);
    let inputs = BTreeMap::from([(
        "shared".into(),
        StorageBindingInput::FilesystemDirectory("bound/SENTINEL".into()),
    )]);
    let plan = prepare_storage_configuration(
        &saved,
        &manifest(false),
        &explicit,
        SnapshotConfigMode::Fresh,
        false,
        &inputs,
    )
    .unwrap();
    let mut destination = SandboxSpec::default();
    plan.apply_to(&mut destination).unwrap();
    assert!(
        matches!(&destination.mounts[0], VolumeMount::Bind { host, quota_mib: Some(99), .. } if host == &PathBuf::from("explicit/SENTINEL"))
    );
    assert!(
        matches!(&destination.mounts[1], VolumeMount::Bind { host, quota_mib: Some(17), .. } if host == &PathBuf::from("bound/SENTINEL"))
    );
    assert_eq!(plan.selection().remaining_bindings.len(), 1);
}

#[test]
fn missing_extra_and_wrong_kind_inputs_refuse_with_redacted_errors() {
    let saved = source(vec![bind("/data", "data")], vec![]);
    assert_redacted(
        &prepare(&saved, &BTreeMap::new()).unwrap_err(),
        "SCFG_BINDING",
    );
    for input in [
        StorageBindingInput::FilesystemFile("SENTINEL".into()),
        StorageBindingInput::NamedDirectory("SENTINEL".into()),
        StorageBindingInput::DatagramSocket("SENTINEL".into()),
    ] {
        assert_redacted(
            &prepare(&saved, &BTreeMap::from([("data".into(), input)])).unwrap_err(),
            "SCFG_BINDING",
        );
    }
    let empty = source(vec![], vec![]);
    assert_redacted(
        &prepare(
            &empty,
            &BTreeMap::from([(
                "SENTINEL".into(),
                StorageBindingInput::FilesystemDirectory("SENTINEL".into()),
            )]),
        )
        .unwrap_err(),
        "SCFG_BINDING",
    );
}

#[test]
fn captured_owned_backing_remains_required_in_fresh_mode_and_cannot_be_rebound() {
    let mut manifest = manifest(false);
    let captured = owned("/private");
    let id = captured.mount_id.clone();
    manifest.set_owned_volumes(vec![captured]).unwrap();
    let saved = source(
        vec![SavedMount::Owned {
            guest: "/private".into(),
            mount_id: id.clone(),
        }],
        vec![],
    );
    let plan = prepare_storage_configuration(
        &saved,
        &manifest,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Fresh,
        false,
        &BTreeMap::new(),
    )
    .unwrap();
    assert_eq!(plan.captured_owned_ids(), [id]);
    let mut destination = SandboxSpec::default();
    plan.apply_to(&mut destination).unwrap();
    assert!(
        matches!(&destination.mounts[0], VolumeMount::Owned { guest, .. } if guest == "/private")
    );
    let explicit = SandboxSpecPatch::new().mounts(vec![VolumeMount::Tmpfs {
        guest: "/private".into(),
        size_mib: None,
        options: MountOptions::default(),
    }]);
    assert_redacted(
        &prepare_storage_configuration(
            &saved,
            &manifest,
            &explicit,
            SnapshotConfigMode::Fresh,
            false,
            &BTreeMap::new(),
        )
        .unwrap_err(),
        "SCFG_IDENTITY",
    );
}

#[test]
fn supplied_paths_do_not_grant_saved_relaxations_or_prove_full_identity() {
    let mut mount = bind("/data", "data");
    if let SavedMount::Bind {
        stat_virtualization,
        host_permissions,
        follow_root_symlinks,
        ..
    } = &mut mount
    {
        *stat_virtualization = StatVirtualization::Relaxed;
        *host_permissions = HostPermissions::Mirror;
        *follow_root_symlinks = true;
    }
    let saved = source(vec![mount], vec![]);
    let inputs = BTreeMap::from([(
        "data".into(),
        StorageBindingInput::FilesystemDirectory("missing/SENTINEL".into()),
    )]);
    let plan = prepare_storage_configuration(
        &saved,
        &manifest(true),
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Fresh,
        true,
        &inputs,
    )
    .unwrap();
    assert!(plan.selection().requires_full_identity);
    assert_eq!(plan.selection().required_approvals.len(), 3);
}

#[test]
fn unknown_inventory_cannot_partially_replace_destination_mounts_or_routes() {
    let saved = SavedStorageConfig {
        mounts: Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotObserved,
        }),
        vsock: known(vec![]),
    };
    let plan = prepare(&saved, &BTreeMap::new()).unwrap();
    let mut destination = SandboxSpec::default();
    destination.mounts.push(VolumeMount::Tmpfs {
        guest: "/keep".into(),
        size_mib: Some(1),
        options: MountOptions::default(),
    });
    destination.vsock.routes.push(VsockRouteSpec {
        port: 8080,
        host_socket: "SENTINEL.sock".into(),
        socket_type: VsockSocketType::Stream,
    });
    let before = serde_json::to_vec(&destination).unwrap();
    assert_redacted(
        &plan.apply_to(&mut destination).unwrap_err(),
        "SCFG_UNKNOWN",
    );
    assert_eq!(serde_json::to_vec(&destination).unwrap(), before);
}

#[test]
fn shared_path_expansion_is_bounded_before_cloning_each_consumer() {
    let count = MAX_SAVED_CONFIG_BYTES / MAX_SAVED_TEXT_BYTES + 1;
    let saved = source(
        (0..count)
            .map(|i| bind(&format!("/data-{i}"), "shared"))
            .collect(),
        vec![],
    );
    let inputs = BTreeMap::from([(
        "shared".into(),
        StorageBindingInput::FilesystemDirectory("a".repeat(MAX_SAVED_TEXT_BYTES).into()),
    )]);
    assert_redacted(&prepare(&saved, &inputs).unwrap_err(), "SCFG_LIMIT");
    let saved = source(vec![bind("/data", "data")], vec![]);
    for path in [
        "".to_owned(),
        "SENTINEL\0path".to_owned(),
        "a".repeat(MAX_SAVED_TEXT_BYTES + 1),
    ] {
        assert_redacted(
            &prepare(
                &saved,
                &BTreeMap::from([(
                    "data".into(),
                    StorageBindingInput::FilesystemDirectory(path.into()),
                )]),
            )
            .unwrap_err(),
            "SCFG_VALUE",
        );
    }
}

#[cfg(unix)]
#[test]
fn native_non_utf8_path_spelling_is_not_normalized_or_opened() {
    let path = PathBuf::from(OsString::from_vec(b"./symlink/../SENTINEL-\xff".to_vec()));
    let saved = source(vec![bind("/data", "data")], vec![]);
    let inputs = BTreeMap::from([(
        "data".into(),
        StorageBindingInput::FilesystemDirectory(path.clone()),
    )]);
    let plan = prepare(&saved, &inputs).unwrap();
    let mut destination = SandboxSpec::default();
    plan.apply_to(&mut destination).unwrap();
    assert!(matches!(&destination.mounts[0], VolumeMount::Bind { host, .. } if host == &path));
}

#[test]
fn file_named_directory_and_datagram_inputs_keep_their_distinct_requirements() {
    let mut file = bind("/file", "file");
    if let SavedMount::Bind {
        root_kind,
        quota_mib,
        ..
    } = &mut file
    {
        *root_kind = SavedBindRootKind::File;
        *quota_mib = None;
    }
    let saved = source(
        vec![
            file,
            SavedMount::Named {
                guest: "/named".into(),
                binding: binding("directory"),
                storage: SavedNamedStorage::Directory {
                    quota_mib: Some(23),
                },
                options: SavedMountOptions::from(&MountOptions::default()),
                stat_virtualization: StatVirtualization::Strict,
                host_permissions: HostPermissions::Private,
                follow_root_symlinks: false,
            },
        ],
        vec![SavedVsockRoute {
            port: 9000,
            socket_type: VsockSocketType::Dgram,
            binding: binding("datagram"),
        }],
    );
    let inputs = BTreeMap::from([
        (
            "file".into(),
            StorageBindingInput::FilesystemFile("missing/SENTINEL.file".into()),
        ),
        (
            "directory".into(),
            StorageBindingInput::NamedDirectory("destination-dir".into()),
        ),
        (
            "datagram".into(),
            StorageBindingInput::DatagramSocket("missing/SENTINEL.sock".into()),
        ),
    ]);
    let plan = prepare(&saved, &inputs).unwrap();
    let mut destination = SandboxSpec::default();
    plan.apply_to(&mut destination).unwrap();
    assert!(
        matches!(&destination.mounts[1], VolumeMount::Named { create: None, name, .. } if name == "destination-dir")
    );
    assert!(matches!(
        &plan.selection().mounts[1].saved,
        Some(SavedMount::Named {
            storage: SavedNamedStorage::Directory {
                quota_mib: Some(23)
            },
            ..
        })
    ));
    assert_eq!(
        destination.vsock.routes[0].socket_type,
        VsockSocketType::Dgram
    );
}

#[test]
fn legacy_external_mount_cannot_disappear_when_no_logical_binding_was_recorded() {
    let mut manifest = manifest(false);
    manifest
        .set_external_mounts(vec!["/legacy".into()])
        .unwrap();
    let saved = SavedStorageConfig::default();
    assert_redacted(
        &prepare_storage_configuration(
            &saved,
            &manifest,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Fresh,
            false,
            &BTreeMap::new(),
        )
        .unwrap_err(),
        "SCFG_BINDING",
    );
    let explicit = SandboxSpecPatch::new().mounts(vec![VolumeMount::Bind {
        guest: "/legacy".into(),
        host: "destination/SENTINEL".into(),
        options: MountOptions::default(),
        stat_virtualization: StatVirtualization::Strict,
        host_permissions: HostPermissions::Private,
        follow_root_symlinks: false,
        quota_mib: None,
    }]);
    let plan = prepare_storage_configuration(
        &saved,
        &manifest,
        &explicit,
        SnapshotConfigMode::Fresh,
        false,
        &BTreeMap::new(),
    )
    .unwrap();
    assert!(!plan.selection().mount_inventory_complete);
    let mut destination = SandboxSpec::default();
    plan.apply_to(&mut destination).unwrap();
    assert_eq!(destination.mounts[0].guest(), "/legacy");
}
