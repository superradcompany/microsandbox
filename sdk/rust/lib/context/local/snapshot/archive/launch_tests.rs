use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox_image::snapshot::{
    DESCRIPTOR_FILENAME, DiskLayer, DiskLayerId, FileSnapshotState, ImageRef, LayerFileKind,
    LayerPayload, Manifest, SnapshotCapture, SnapshotConsistency, SnapshotFormat, SnapshotId,
    SnapshotRootDisk, SnapshotScope, SnapshotState,
};

use crate::context::{Context, LocalContext};
use crate::snapshot::SaveOpts;

use super::super::save_snapshot;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn descriptor(id: u128, layers: Vec<DiskLayer>, parent: Option<SnapshotId>) -> Manifest {
    Manifest {
        schema: "microsandbox.snapshot/1".into(),
        snapshot_id: SnapshotId::new(format!("snap_{id:032x}")).unwrap(),
        scope: SnapshotScope::Disk,
        root_disk: SnapshotRootDisk::Managed,
        state: SnapshotState::File(FileSnapshotState {
            disk_format: layers.last().unwrap().format,
            filesystem: "ext4".into(),
            virtual_size: 65536,
            head: layers.last().unwrap().layer_id.clone(),
            layers,
        }),
        capture: SnapshotCapture {
            created_at: "2026-10-19T00:00:00Z".into(),
            source_lineage: None,
            source_checkpoint: None,
            consistency: SnapshotConsistency::CrashConsistent,
        },
        image: ImageRef {
            reference: "docker.io/library/alpine:3.20".into(),
            manifest_digest: format!("sha256:{}", "0".repeat(64)),
        },
        parent,
        extensions: BTreeMap::new(),
        requires: Vec::new(),
    }
}

fn raw_source(root: &Path, id: u128, byte: u8) -> Manifest {
    let layer = DiskLayer {
        layer_id: DiskLayerId::new(format!("layer_{id:032x}")).unwrap(),
        format: SnapshotFormat::Raw,
        virtual_size: 65536,
        backing: None,
        payload: LayerPayload {
            file_kind: LayerFileKind::Regular,
            integrity: None,
        },
    };
    let manifest = descriptor(id, vec![layer.clone()], None);
    std::fs::create_dir_all(root.join("layers")).unwrap();
    std::fs::write(
        root.join(microsandbox_image::snapshot::layer_path(
            &layer.layer_id,
            layer.format,
        )),
        vec![byte; 65536],
    )
    .unwrap();
    write_manifest(root, &manifest);
    manifest
}

fn write_manifest(root: &Path, manifest: &Manifest) {
    std::fs::write(
        root.join(DESCRIPTOR_FILENAME),
        manifest.to_canonical_bytes().unwrap(),
    )
    .unwrap();
}

async fn incremental_pair(
    local: &LocalContext,
    root: &Path,
) -> (Manifest, PathBuf, PathBuf, PathBuf) {
    let base_dir = root.join("base");
    let base = raw_source(&base_dir, 1, 91);
    let child_dir = root.join("child");
    std::fs::create_dir_all(child_dir.join("layers")).unwrap();
    let SnapshotState::File(state) = &base.state else {
        unreachable!()
    };
    let base_layer = state.layers[0].clone();
    let base_path = state.layer_path(&base_layer);
    std::fs::copy(base_dir.join(&base_path), child_dir.join(&base_path)).unwrap();
    let layer = DiskLayer {
        layer_id: DiskLayerId::new(format!("layer_{:032x}", 2)).unwrap(),
        format: SnapshotFormat::Qcow2,
        virtual_size: 65536,
        backing: Some(base_layer.layer_id.clone()),
        payload: LayerPayload {
            file_kind: LayerFileKind::Regular,
            integrity: None,
        },
    };
    let layer_path = microsandbox_image::snapshot::layer_path(&layer.layer_id, layer.format);
    microsandbox_image::checkpoint::create_qcow2_overlay(
        &child_dir.join(layer_path),
        65536,
        &child_dir.join(&base_path),
        "raw",
    )
    .await
    .unwrap();
    let child = descriptor(2, vec![base_layer, layer], Some(base.snapshot_id));
    write_manifest(&child_dir, &child);
    let base_archive = root.join("base.msb");
    let child_archive = root.join("child.unusual-extension");
    save_snapshot(
        local,
        base_dir.to_str().unwrap(),
        &base_archive,
        SaveOpts::default(),
    )
    .await
    .unwrap();
    save_snapshot(
        local,
        child_dir.to_str().unwrap(),
        &child_archive,
        SaveOpts {
            since: Some(base_dir.to_string_lossy().into_owned()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    (child, child_dir, base_archive, child_archive)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn reversed_incremental_paths_prepare_without_installing_a_group() {
    let temp = tempfile::tempdir().unwrap();
    let local = Arc::new(
        crate::test_support::local_backend_builder(temp.path().join("home"))
            .build()
            .unwrap(),
    );
    let (child, child_dir, base_archive, child_archive) =
        incremental_pair(&local, temp.path()).await;
    let original = std::fs::read(child_dir.join(DESCRIPTOR_FILENAME)).unwrap();
    let backend: Arc<dyn Context> = local.clone();
    async {
        for inputs in [
            vec![child_archive.clone(), base_archive.clone()],
            vec![base_archive.clone(), child_archive.clone()],
            vec![
                child_archive.clone(),
                child_dir.clone(),
                base_archive.clone(),
                child_archive.clone(),
            ],
        ] {
            let config = backend
                .sandboxes()
                .builder("destination")
                .override_snapshot_paths(inputs, None)
                .build()
                .await
                .unwrap();
            assert_eq!(
                config.snapshot_parent.as_deref(),
                Some(child.snapshot_id.as_str())
            );
            assert_eq!(config.snapshot_root_layer_sources.len(), 2);
            assert_eq!(
                std::fs::read(&config.snapshot_root_layer_sources[0].path).unwrap(),
                vec![91; 65536]
            );
            let selected_path = config.snapshot_root_layer_sources[0].path.clone();
            let private_stages: Vec<_> = config
                .snapshot_prepared_sources
                .as_ref()
                .unwrap()
                ._archives
                .iter()
                .flat_map(|archive| {
                    [
                        archive.snapshots.path().to_path_buf(),
                        archive.cache.path().to_path_buf(),
                    ]
                })
                .collect();
            assert!(config.snapshot_prepared_sources.is_some());
            assert!(
                serde_json::to_value(&config)
                    .unwrap()
                    .get("snapshot_prepared_sources")
                    .is_none()
            );
            assert!(config.snapshot_lease.is_some());
            assert!(backend.snapshots().list().await.unwrap().is_empty());
            assert!(backend.checkpoints().list().await.unwrap().is_empty());
            assert!(!local.sandboxes_dir().join("destination").exists());
            drop(config);
            assert_eq!(
                selected_path.exists(),
                selected_path.starts_with(&child_dir)
            );
            assert!(
                private_stages.iter().all(|stage| !stage.exists()),
                "operation staging survived its last owner"
            );
        }
        let error = backend
            .sandboxes()
            .builder("destination")
            .override_snapshot_paths(vec![child_archive], None)
            .build()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("missing"), "{error}");
        assert!(!local.sandboxes_dir().join("destination").exists());
        assert!(backend.snapshots().list().await.unwrap().is_empty());
    }
    .await;
    assert_eq!(
        std::fs::read(child_dir.join(DESCRIPTOR_FILENAME)).unwrap(),
        original
    );
}

#[tokio::test]
async fn missing_resource_waiver_cannot_discard_an_explicit_captured_disk() {
    let temp = tempfile::tempdir().unwrap();
    let local = Arc::new(
        crate::test_support::local_backend_builder(temp.path().join("home"))
            .build()
            .unwrap(),
    );
    let source = temp.path().join("disk-source");
    raw_source(&source, 27, 4);
    let backend: Arc<dyn Context> = local.clone();
    async {
        for allow_missing in [false, true] {
            let error = backend
                .sandboxes()
                .builder("child")
                .override_snapshot_paths(vec![source.clone()], None)
                .snapshot_launch_options(false, false)
                .snapshot_resource_options(allow_missing, false, None)
                .volume("/data", |mount| mount.captured())
                .build()
                .await
                .unwrap_err();
            assert!(
                error.to_string().contains("no captured additional disks"),
                "{error}"
            );
            assert!(!local.sandboxes_dir().join("child").exists());
        }
        assert!(backend.snapshots().list().await.unwrap().is_empty());
    }
    .await;
}

#[tokio::test]
async fn unrelated_tips_require_an_exact_target_and_conflicts_never_pick_input_order() {
    let temp = tempfile::tempdir().unwrap();
    let local = Arc::new(
        crate::test_support::local_backend_builder(temp.path().join("home"))
            .build()
            .unwrap(),
    );
    let left = temp.path().join("left");
    let right = temp.path().join("right");
    let left_manifest = raw_source(&left, 10, 3);
    raw_source(&right, 11, 4);
    let backend: Arc<dyn Context> = local;
    async {
        let paths = vec![left.clone(), right.clone()];
        let error = backend
            .sandboxes()
            .builder("child")
            .override_snapshot_paths(paths.clone(), None)
            .build()
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("multiple terminal checkpoints"),
            "{error}"
        );
        let config = backend
            .sandboxes()
            .builder("child")
            .override_snapshot_paths(paths.clone(), Some(left_manifest.snapshot_id.clone()))
            .build()
            .await
            .unwrap();
        assert_eq!(
            config.snapshot_parent.as_deref(),
            Some(left_manifest.snapshot_id.as_str())
        );
        drop(config);
        let absent = SnapshotId::new(format!("snap_{:032x}", 999)).unwrap();
        let error = backend
            .sandboxes()
            .builder("child")
            .override_snapshot_paths(paths, Some(absent))
            .build()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("not present"), "{error}");

        let conflicting = temp.path().join("conflicting");
        raw_source(&conflicting, 10, 5);
        for paths in [
            vec![left.clone(), conflicting.clone()],
            vec![conflicting.clone(), left.clone()],
        ] {
            let error = backend
                .sandboxes()
                .builder("child")
                .override_snapshot_paths(paths, None)
                .build()
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("conflicting disk layer payloads"),
                "{error}"
            );
        }
        let mut shared_layer = left_manifest.clone();
        shared_layer.snapshot_id = SnapshotId::new(format!("snap_{:032x}", 12)).unwrap();
        write_manifest(&conflicting, &shared_layer);
        let error = backend
            .sandboxes()
            .builder("child")
            .override_snapshot_paths(
                vec![left.clone(), conflicting.clone()],
                Some(left_manifest.snapshot_id.clone()),
            )
            .build()
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("conflicting disk layer payloads"),
            "{error}"
        );

        raw_source(&conflicting, 10, 3);
        let mut different = left_manifest.clone();
        different.image.reference = "different:latest".into();
        write_manifest(&conflicting, &different);
        let error = backend
            .sandboxes()
            .builder("child")
            .override_snapshot_paths(vec![left, conflicting], None)
            .build()
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("conflicting descriptors"),
            "{error}"
        );
        assert!(backend.snapshots().list().await.unwrap().is_empty());
    }
    .await;
}

#[tokio::test]
async fn shared_file_layer_allows_independent_integrity_recording() {
    let temp = tempfile::tempdir().unwrap();
    let local = crate::test_support::local_backend_builder(temp.path().join("home"))
        .build()
        .unwrap();
    let plain = temp.path().join("plain");
    let checked = temp.path().join("checked");
    let original = raw_source(&plain, 10, 3);
    let mut copy = raw_source(&checked, 10, 3);
    copy.snapshot_id = SnapshotId::new(format!("snap_{:032x}", 11)).unwrap();
    let SnapshotState::File(file) = &mut copy.state else {
        unreachable!()
    };
    let layer = &mut file.layers[0];
    let relative = microsandbox_image::snapshot::layer_path(&layer.layer_id, layer.format);
    layer.payload.integrity = Some(
        crate::context::local::snapshot::verify::compute_merkle_integrity(&checked.join(&relative))
            .await
            .unwrap(),
    );
    write_manifest(&checked, &copy);
    let backend: Arc<dyn Context> = Arc::new(local);
    async {
        for paths in [
            vec![plain.clone(), checked.clone()],
            vec![checked.clone(), plain.clone()],
        ] {
            backend
                .sandboxes()
                .builder("child")
                .override_snapshot_paths(paths, Some(original.snapshot_id.clone()))
                .build()
                .await
                .unwrap();
        }
        // The unchecked descriptor gives no checksum guarantee of its own.
        // Divergence must still be caught even with the checksummed input first.
        std::fs::write(plain.join(relative), vec![4u8; 65536]).unwrap();
        for paths in [
            vec![plain.clone(), checked.clone()],
            vec![checked.clone(), plain.clone()],
        ] {
            let error = backend
                .sandboxes()
                .builder("child")
                .override_snapshot_paths(paths, Some(original.snapshot_id.clone()))
                .build()
                .await
                .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("conflicting disk layer payloads"),
                "{error}"
            );
        }
    }
    .await;
}

#[tokio::test]
async fn supplied_parent_cycle_is_refused_even_with_an_explicit_target() {
    let temp = tempfile::tempdir().unwrap();
    let local = Arc::new(
        crate::test_support::local_backend_builder(temp.path().join("home"))
            .build()
            .unwrap(),
    );
    let left = temp.path().join("left");
    let right = temp.path().join("right");
    let mut a = raw_source(&left, 20, 3);
    let mut b = raw_source(&right, 21, 4);
    a.parent = Some(b.snapshot_id.clone());
    b.parent = Some(a.snapshot_id.clone());
    write_manifest(&left, &a);
    write_manifest(&right, &b);
    let backend: Arc<dyn Context> = local;
    async {
        let error = backend
            .sandboxes()
            .builder("child")
            .override_snapshot_paths(vec![left, right], Some(a.snapshot_id))
            .build()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("cycle"), "{error}");
    }
    .await;
}

#[cfg(feature = "cloud")]
#[tokio::test]
async fn explicit_local_paths_on_cloud_refuse_before_filesystem_resolution() {
    let cloud = crate::test_support::cloud_backend("https://api.example.test", "test-key").unwrap();
    async {
        use crate::Context as _;
        let error = cloud
            .sandboxes()
            .builder("destination")
            .override_snapshot_paths(vec![PathBuf::from("/missing/backup.msb")], None)
            .build()
            .await
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("snapshot path sets require a local backend"),
            "{error}"
        );
    }
    .await;
}
