//! Admission regressions must fail before replacing any existing sandbox state.

use std::collections::BTreeMap;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox_image::checkpoint::{
    CaptureIntent, CheckpointGeometry, CheckpointManifest, ContentRef, DiskGenerationManifest,
    DiskLayerRef, LocalObjectStore, MemoryCaptureMode, MemoryExtent, MemoryExtentContent,
    MemoryManifest, ObjectId,
};
use microsandbox_image::snapshot::{
    CheckpointSnapshotState, DiskLayer, DiskLayerId, FileSnapshotState, ImageRef, LayerFileKind,
    LayerPayload, Manifest, SCHEMA, SnapshotCapture, SnapshotConsistency, SnapshotFormat,
    SnapshotId, SnapshotRootDisk, SnapshotScope, SnapshotState,
};
use sea_orm::EntityTrait;

use crate::backend::local::database;
use crate::backend::local::snapshot::archive::{
    save_direct_checkpoint_snapshot, save_direct_file_snapshot,
};
use crate::config::{GlobalConfig, PathsConfig};
use crate::sandbox::SandboxBuilder;
use crate::snapshot::SnapshotReference;
use crate::test_support::local_backend;

use super::{LocalBackend, RootfsSource, SandboxConfig, SandboxStatus, SpawnMode, sandbox_entity};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn archive(root: &Path, flat: bool, plain: bool) -> PathBuf {
    let source = root.join("source.raw");
    std::fs::write(&source, vec![0u8; 4096]).unwrap();
    let layer_id = DiskLayerId::new("layer_00000000000000000000000000000001").unwrap();
    let manifest = Manifest {
        schema: SCHEMA.into(),
        snapshot_id: SnapshotId::new("snap_00000000000000000000000000000001").unwrap(),
        scope: SnapshotScope::Disk,
        state: SnapshotState::File(FileSnapshotState {
            disk_format: SnapshotFormat::Raw,
            filesystem: "ext4".into(),
            virtual_size: 4096,
            head: layer_id.clone(),
            layers: vec![DiskLayer {
                layer_id,
                format: SnapshotFormat::Raw,
                virtual_size: 4096,
                backing: None,
                payload: LayerPayload {
                    file_kind: LayerFileKind::Regular,
                    integrity: None,
                },
            }],
        }),
        capture: SnapshotCapture {
            created_at: "2026-09-17T00:00:00Z".into(),
            source_lineage: None,
            source_checkpoint: None,
            consistency: SnapshotConsistency::CrashConsistent,
        },
        image: ImageRef {
            reference: "docker.io/library/alpine:3.21".into(),
            manifest_digest: format!("sha256:{}", "1".repeat(64)),
        },
        root_disk: if flat {
            SnapshotRootDisk::Flat
        } else {
            SnapshotRootDisk::Managed
        },
        parent: None,
        extensions: BTreeMap::new(),
        requires: Vec::new(),
    };
    let out = root.join("source.msnap");
    save_direct_file_snapshot(
        &manifest,
        &BTreeMap::new(),
        "saved",
        &[source],
        None,
        &out,
        plain,
        false,
    )
    .await
    .unwrap();
    out
}

/// Write a minimal full-snapshot archive whose checkpoint is never resumed.
async fn checkpoint_archive(root: &Path) -> PathBuf {
    let source = root.join("checkpoint-source");
    let store = LocalObjectStore::open(&source).unwrap();
    let memory_bytes = b"checkpoint-memory";
    let memory_object = store.put_bytes(memory_bytes).unwrap();
    let memory = MemoryManifest {
        schema: "microsandbox.memory/1".into(),
        architecture: std::env::consts::ARCH.into(),
        guest_page_size: 4096,
        topology_generation: 1,
        generation: 1,
        capture_mode: MemoryCaptureMode::Full,
        pause_generation: 1,
        extents: vec![MemoryExtent {
            start: 0,
            length: memory_bytes.len() as u64,
            content: MemoryExtentContent::Object(ContentRef {
                object: memory_object,
                object_offset: 0,
            }),
        }],
    };
    let memory_id = store
        .put_bytes(&memory.to_canonical_bytes().unwrap())
        .unwrap();
    let execution_id = store.put_bytes(b"execution").unwrap();

    let layer_id = "layer_00000000000000000000000000000001";
    let layers = source.join("layers");
    std::fs::create_dir(&layers).unwrap();
    std::fs::write(layers.join(format!("{layer_id}.qcow2")), b"QFI\xfbhead").unwrap();
    let disk = DiskGenerationManifest {
        schema: "microsandbox.disk-generation/1".into(),
        volume_id: "vol_test".into(),
        device_id: "vdb".into(),
        generation: 1,
        layers: vec![DiskLayerRef {
            file_size: 8,
            layer_id: layer_id.into(),
            format: "qcow2".into(),
            virtual_size: 4096,
            predecessor: None,
            integrity_root: None,
        }],
        head: layer_id.into(),
        pause_generation: 1,
    };
    let disk_id = store
        .put_bytes(&disk.to_canonical_bytes().unwrap())
        .unwrap();

    let checkpoint = CheckpointManifest {
        schema: "microsandbox.checkpoint/1".into(),
        checkpoint_id: "checkpoint_archive".into(),
        capture_intent: CaptureIntent::FullSnapshot,
        geometry: CheckpointGeometry {
            vcpus: 1,
            max_vcpus: 1,
            memory_mib: 128,
            max_memory_mib: 128,
        },
        architecture: std::env::consts::ARCH.into(),
        pause_generation: 1,
        execution_state: execution_id,
        memory: memory_id,
        disks: vec![disk_id],
        devices: Vec::new(),
        resources: Vec::new(),
        owned_volumes: Vec::new(),
        requires: Vec::new(),
    };
    let checkpoint_bytes = checkpoint.to_canonical_bytes().unwrap();
    let checkpoint_root = ObjectId::from_bytes(&checkpoint_bytes).unwrap();
    std::fs::write(source.join("checkpoint.json"), checkpoint_bytes).unwrap();

    let manifest = Manifest {
        schema: SCHEMA.into(),
        snapshot_id: SnapshotId::new("snap_00000000000000000000000000000002").unwrap(),
        scope: SnapshotScope::Full,
        state: SnapshotState::Checkpoint(CheckpointSnapshotState {
            checkpoint_id: checkpoint.checkpoint_id,
            checkpoint_root: checkpoint_root.to_string(),
            restore_intents: vec!["clone".into(), "resume".into()],
            requirements_summary: BTreeMap::new(),
        }),
        capture: SnapshotCapture {
            created_at: "2026-09-17T00:00:00Z".into(),
            source_lineage: None,
            source_checkpoint: None,
            consistency: SnapshotConsistency::ApplicationConsistent,
        },
        image: ImageRef {
            reference: "docker.io/library/alpine:3.21".into(),
            manifest_digest: format!("sha256:{}", "2".repeat(64)),
        },
        root_disk: SnapshotRootDisk::Managed,
        parent: None,
        extensions: BTreeMap::new(),
        requires: Vec::new(),
    };
    let out = root.join("checkpoint.msnap");
    save_direct_checkpoint_snapshot(
        &manifest,
        &BTreeMap::new(),
        "checkpoint",
        &source,
        &out,
        false,
        false,
        crate::test_support::DEFAULT_FS_STATE_LIMIT,
    )
    .await
    .unwrap();
    out
}

async fn backend(root: &Path, patch: u8) -> Arc<LocalBackend> {
    let executable = root.join("historical-msb");
    // Version discovery is real, but no VM should ever be launched in these tests.
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\nif [ \"$1\" = --version ]; then echo 'msb 0.6.{patch}'; else exit 99; fi\n"
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
    let firmware = root.join("firmware");
    std::fs::write(&firmware, b"not launched").unwrap();
    let backend = local_backend(GlobalConfig {
        home: Some(root.join("home")),
        paths: PathsConfig {
            msb: Some(executable),
            libkrunfw: Some(firmware),
            ..Default::default()
        },
        ..Default::default()
    });
    backend.db().await.unwrap();
    Arc::new(backend)
}

async fn assert_rejection_preserves_target(
    backend: Arc<LocalBackend>,
    archive: &Path,
    reason: &str,
) {
    let mut request = replaceable_config();
    request.replace_existing = true;
    request.snapshot_reference = Some(SnapshotReference::path(archive.to_string_lossy()));

    assert_request_preserves_target(backend, request, reason).await;
}

/// Existing sandbox that a rejected replacement request must leave untouched.
fn replaceable_config() -> SandboxConfig {
    let mut config = SandboxConfig::default();
    config.spec.name = "replaceable".into();
    config.spec.image = RootfsSource::oci("alpine:3.21");
    config.spec.resources.max_cpus = config.spec.resources.cpus;
    config.spec.resources.max_memory_mib = config.spec.resources.memory_mib;

    config
}

async fn assert_request_preserves_target(
    backend: Arc<LocalBackend>,
    request: impl Into<SandboxBuilder>,
    reason: &str,
) {
    let config = replaceable_config();
    let pools = backend.db().await.unwrap();
    let id = LocalBackend::insert_sandbox_record_with_status(
        pools.write(),
        &config,
        SandboxStatus::Stopped,
    )
    .await
    .unwrap();
    let before = sandbox_entity::Entity::find_by_id(id)
        .one(pools.read())
        .await
        .unwrap()
        .unwrap();
    let child = backend.sandboxes_dir().join(&config.spec.name);
    std::fs::create_dir_all(&child).unwrap();
    std::fs::write(child.join("sentinel"), b"keep my disk").unwrap();

    let error = match backend
        .create_sandbox(backend.clone(), request, SpawnMode::Attached, None)
        .await
    {
        Ok(_) => panic!("unsupported archive must not launch"),
        Err(error) => error,
    };

    assert!(error.to_string().contains(reason), "{error}");
    assert_eq!(
        std::fs::read(child.join("sentinel")).unwrap(),
        b"keep my disk"
    );
    assert_eq!(
        sandbox_entity::Entity::find_by_id(id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap(),
        before
    );
    let entries = std::fs::read_dir(backend.sandboxes_dir())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    assert_eq!(
        entries,
        vec![std::ffi::OsString::from("replaceable")],
        "staging must be reclaimed"
    );
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn archive_flat_layout_is_admitted_before_replacement() {
    for patch in [0, 8] {
        for plain in [false, true] {
            let root = tempfile::tempdir_in("/tmp").unwrap();
            let archive = archive(root.path(), true, plain).await;
            assert_rejection_preserves_target(
                backend(root.path(), patch).await,
                &archive,
                "newer runtime launch contract",
            )
            .await;
        }
    }
}

#[tokio::test]
async fn archive_disk_chain_is_admitted_before_replacement() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let archive = archive(root.path(), false, false).await;
    assert_rejection_preserves_target(
        backend(root.path(), 18).await,
        &archive,
        "disk chains require a newer runtime launch contract",
    )
    .await;
}

#[tokio::test]
async fn managed_root_layout_conflict_preserves_replacement_target() {
    use crate::config::{GlobalConfigPatch, layers::BackendConfig};

    for flat in [false, true] {
        let root = tempfile::tempdir_in("/tmp").unwrap();
        let archive = archive(root.path(), flat, false).await;
        let mut backend = backend(root.path(), 18).await;
        let user = GlobalConfigPatch::from_present_fields(backend.config().clone());
        let managed = serde_json::from_value(serde_json::json!({
            "sandbox_defaults": {"oci": {"root_disk": {
                "kind": if flat { "managed" } else { "flat" }
            }}}
        }))
        .unwrap();
        Arc::get_mut(&mut backend).unwrap().config = BackendConfig::new(user, managed);
        assert_rejection_preserves_target(backend, &archive, "captured root disk layout").await;
    }
}

#[tokio::test]
async fn corrupt_archive_does_not_replace_target() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let archive = root.path().join("broken.msnap");
    std::fs::write(&archive, b"not a tar archive").unwrap();
    let backend = backend(root.path(), 18).await;
    let stage = tempfile::tempdir_in(root.path()).unwrap();
    let reason = match crate::snapshot::materialize_archive_for_child(
        &backend,
        &archive,
        stage.path(),
        false,
        None,
        &Default::default(),
        Default::default(),
    )
    .await
    {
        Ok(_) => panic!("corrupt archive accepted"),
        Err(error) => error.to_string(),
    };
    assert_rejection_preserves_target(backend, &archive, &reason).await;
}

#[tokio::test]
async fn copy_on_write_disk_archive_preserves_replacement_target() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let archive = archive(root.path(), false, false).await;
    // Without an installed runtime, launch-contract checks are skipped, so only
    // the copy-on-write checks can reject this request.
    let backend = Arc::new(local_backend(GlobalConfig {
        home: Some(root.path().join("home")),
        ..Default::default()
    }));

    // A disk archive has no checkpoint, so CoW memory must fail before replacement.
    let request = SandboxBuilder::new("replaceable")
        .with_snapshot_reference(SnapshotReference::path(archive.to_string_lossy()))
        .forked()
        .replace();

    assert_request_preserves_target(
        backend,
        request,
        "copy-on-write memory requires a full snapshot restore",
    )
    .await;
}

#[tokio::test]
async fn disk_only_restore_from_full_archive_passes_admission() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let archive = checkpoint_archive(root.path()).await;
    // The newest historical contract admits the request, then rejects the
    // materialized disk chain, so reaching that check proves restore admission passed.
    let backend = backend(root.path(), 18).await;

    // Match the public restore builder: the reference is resolved during preparation.
    let builder = SandboxBuilder::new("disk-only-child")
        .with_snapshot_reference(SnapshotReference::path(archive.to_string_lossy()))
        .disk_only();
    let error = match backend
        .create_sandbox(backend.clone(), builder, SpawnMode::Attached, None)
        .await
    {
        Ok(_) => panic!("the stub runtime must not launch"),
        Err(error) => error,
    };

    assert!(
        error
            .to_string()
            .contains("disk chains require a newer runtime launch contract"),
        "{error}"
    );
}

#[test]
fn archive_relocation_moves_only_child_owned_paths() {
    let stage = Path::new("/staging/unique-child");
    let child = Path::new("/sandboxes/child");
    let mut config = SandboxConfig {
        checkpoint_restore: Some(
            serde_json::from_value(serde_json::json!({
                "local_branch": false, "forked": false,
                "closure": stage.join(".checkpoint-restore"),
                "checkpoint_root": "unused", "checkpoint_id": "unused",
            }))
            .unwrap(),
        ),
        snapshot_upper_source: Some(stage.join("upper.ext4")),
        ..Default::default()
    };
    for host in [
        stage.join("additional-disks/data.raw"),
        "/external/data.raw".into(),
    ] {
        config
            .spec
            .mounts
            .push(microsandbox_types::VolumeMount::DiskImage {
                host,
                guest: "/data".into(),
                format: microsandbox_types::DiskImageFormat::Raw,
                fstype: None,
                options: Default::default(),
            });
    }
    super::relocate_archive_config(&mut config, stage, child);
    assert_eq!(
        config.checkpoint_restore.unwrap().closure,
        child.join(".checkpoint-restore")
    );
    assert_eq!(
        config.snapshot_upper_source.unwrap(),
        child.join("upper.ext4")
    );
    for (mount, expected) in config.spec.mounts.iter().zip([
        child.join("additional-disks/data.raw"),
        "/external/data.raw".into(),
    ]) {
        let microsandbox_types::VolumeMount::DiskImage { host, .. } = mount else {
            panic!()
        };
        assert_eq!(host, &expected);
    }
}

#[tokio::test]
async fn current_catalog_persistence_is_separate_from_create_admission() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let backend = backend(root.path(), 8).await;
    let pools = backend.db().await.unwrap();
    assert!(database::is_current(pools.read()).await.unwrap());
    let mut config = SandboxConfig::default();
    config.spec.image = RootfsSource::oci("alpine:3.21");
    crate::sandbox::apply_snapshot_root_layout(&mut config, &SnapshotRootDisk::Flat).unwrap();
    // Desired state can be saved, but cannot become a Starting sandbox through
    // a historical executable that does not understand the requested layout.
    let encoded = serde_json::to_string(&config).unwrap();
    assert!(encoded.contains("flat"));
    let error = LocalBackend::insert_starting_sandbox_record(
        pools.write(),
        &config,
        Some(backend.config()),
    )
    .await
    .unwrap_err();
    assert!(
        error.to_string().contains("newer runtime launch contract"),
        "{error}"
    );
    assert!(
        sandbox_entity::Entity::find()
            .all(pools.read())
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn archive_publication_preserves_relative_disk_chain() {
    let root = tempfile::tempdir_in("/tmp").unwrap();
    let archive = archive(root.path(), false, false).await;
    let backend = backend(root.path(), 18).await;
    let stage = tempfile::tempdir_in(root.path()).unwrap();
    let materialized = crate::snapshot::materialize_archive_for_child(
        &backend,
        &archive,
        stage.path(),
        false,
        None,
        &Default::default(),
        Default::default(),
    )
    .await
    .unwrap();
    let mut config = SandboxConfig {
        snapshot_upper_layers: materialized.upper_layers,
        ..Default::default()
    };
    let child = root.path().join("child");
    super::relocate_archive_config(&mut config, stage.path(), &child);
    std::fs::rename(stage.path(), &child).unwrap();
    drop(stage);
    assert_eq!(config.snapshot_upper_layers.len(), 2);
    for pair in config.snapshot_upper_layers.windows(2) {
        assert!(pair[0].path.is_file());
        let backing =
            microsandbox_image::checkpoint::qcow2_backing_basename(&pair[1].path).unwrap();
        assert_eq!(pair[0].path, child.join(backing));
    }
}
