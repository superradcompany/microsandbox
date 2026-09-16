//! Local backend: Archive-level fixtures exercise transport and staging, not hypervisor execution codecs.

use super::*;
use microsandbox_image::checkpoint::{
    CaptureIntent, CheckpointManifest, ContentRef, DeviceStateRef, DiskGenerationManifest,
    LocalObjectStore, MemoryCaptureMode, MemoryExtent, MemoryManifest, sparse_file_integrity,
};
use microsandbox_image::snapshot::{
    CheckpointSnapshotState, ImageRef, SnapshotCapture, SnapshotConsistency, SnapshotId,
    SnapshotRootDisk, SnapshotScope,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn fixture(
    local: &LocalBackend,
    path: &Path,
    generation: u64,
    previous: Option<&Snapshot>,
    disk: bool,
) -> Snapshot {
    let root = path.join(CHECKPOINT_DIRECTORY);
    let store = LocalObjectStore::open(&root).unwrap();
    // Packed objects deliberately contain bytes not selected by the map. Export is object-based.
    let original = store.put_bytes(&vec![0xa5; 8192]).unwrap();
    let changed = store
        .put_bytes(&vec![(generation / 3) as u8; 8192])
        .unwrap();
    let memory = MemoryManifest {
        schema: "microsandbox.memory/1".into(),
        architecture: std::env::consts::ARCH.into(),
        guest_page_size: 4096,
        topology_generation: 1,
        generation,
        capture_mode: if generation == 1 {
            MemoryCaptureMode::Full
        } else {
            MemoryCaptureMode::Incremental
        },
        pause_generation: generation,
        extents: vec![
            MemoryExtent {
                start: 0,
                length: 4096,
                content: MemoryExtentContent::Object(ContentRef {
                    object: original,
                    object_offset: 4096,
                }),
            },
            MemoryExtent {
                start: 4096,
                length: 4096,
                content: MemoryExtentContent::Object(ContentRef {
                    object: changed,
                    object_offset: 4096,
                }),
            },
            MemoryExtent {
                start: 8192,
                length: 4096,
                content: MemoryExtentContent::Zero,
            },
        ],
    };
    let mut disks = Vec::new();
    if disk {
        std::fs::create_dir_all(root.join("layers")).unwrap();
        let mut layers = Vec::new();
        if let Some(previous) = previous {
            for old in physical_layers(previous.manifest(), previous.path()).unwrap() {
                let LayerIdentity::Checkpoint(layer) = old.required.identity else {
                    unreachable!()
                };
                let dest = root
                    .join("layers")
                    .join(format!("{}.{}", layer.layer_id, layer.format));
                microsandbox_utils::copy::fast_copy(&old.source, &dest).unwrap();
                layers.push(layer);
            }
        }
        let layer_id = format!("layer_{generation:032x}");
        let format = if layers.is_empty() { "raw" } else { "qcow2" };
        let layer_path = root.join("layers").join(format!("{layer_id}.{format}"));
        if let Some(base) = layers.last() {
            microsandbox_image::checkpoint::create_qcow2_overlay(
                &layer_path,
                65536,
                &root
                    .join("layers")
                    .join(format!("{}.{}", base.layer_id, base.format)),
                &base.format,
            )
            .await
            .unwrap();
        } else {
            std::fs::write(&layer_path, vec![17u8; 65536]).unwrap();
        }
        let layer = DiskLayerRef {
            file_size: std::fs::metadata(&layer_path).unwrap().len(),
            layer_id: layer_id.clone(),
            format: format.into(),
            virtual_size: 65536,
            predecessor: layers.last().map(|layer| layer.layer_id.clone()),
            integrity_root: Some(sparse_file_integrity(&layer_path).unwrap().root),
        };
        layers.push(layer);
        let disk = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: "vol_test".into(),
            device_id: "vdb".into(),
            generation,
            layers,
            head: layer_id,
            pause_generation: generation,
        };
        disks.push(
            store
                .put_bytes(&disk.to_canonical_bytes().unwrap())
                .unwrap(),
        );
    }
    let checkpoint = CheckpointManifest {
        schema: "microsandbox.checkpoint/1".into(),
        checkpoint_id: format!("checkpoint_{generation}"),
        capture_intent: CaptureIntent::FullSnapshot,
        geometry: microsandbox_image::checkpoint::CheckpointGeometry {
            vcpus: 1,
            max_vcpus: 1,
            memory_mib: 128,
            max_memory_mib: 128,
        },
        architecture: std::env::consts::ARCH.into(),
        pause_generation: generation,
        execution_state: store
            .put_bytes(format!("execution-{generation}").as_bytes())
            .unwrap(),
        memory: store
            .put_bytes(&memory.to_canonical_bytes().unwrap())
            .unwrap(),
        disks,
        owned_volumes: Vec::new(),
        devices: vec![DeviceStateRef {
            device_type: 4,
            device_id: "rng".into(),
            state: store.put_bytes(b"unchanged-device-state").unwrap(),
        }],
        resources: Vec::new(),
        requires: Vec::new(),
    };
    let bytes = checkpoint.to_canonical_bytes().unwrap();
    let root_id = ObjectId::from_bytes(&bytes).unwrap();
    std::fs::write(root.join("checkpoint.json"), bytes).unwrap();
    let manifest = Manifest {
        schema: "microsandbox.snapshot/1".into(),
        snapshot_id: SnapshotId::new(format!("snap_{generation:032x}")).unwrap(),
        scope: SnapshotScope::Full,
        root_disk: if disk {
            SnapshotRootDisk::Managed
        } else {
            SnapshotRootDisk::Tmpfs { size_mib: None }
        },
        state: SnapshotState::Checkpoint(CheckpointSnapshotState {
            checkpoint_id: checkpoint.checkpoint_id,
            checkpoint_root: root_id.to_string(),
            restore_intents: vec!["clone".into(), "resume".into()],
            requirements_summary: BTreeMap::from([
                ("vcpus".into(), 1.into()),
                ("max_vcpus".into(), 1.into()),
                ("memory_mib".into(), 128.into()),
                ("max_memory_mib".into(), 128.into()),
            ]),
        }),
        capture: SnapshotCapture {
            created_at: "2026-09-10T00:00:00Z".into(),
            source_lineage: None,
            source_checkpoint: None,
            consistency: SnapshotConsistency::ApplicationConsistent,
        },
        image: ImageRef {
            reference: "docker.io/library/alpine:3.20".into(),
            manifest_digest: format!("sha256:{}", "0".repeat(64)),
        },
        parent: previous.map(|snapshot| snapshot.id().clone()),
        extensions: BTreeMap::new(),
        requires: Vec::new(),
    };
    std::fs::write(
        path.join(DESCRIPTOR_FILENAME),
        manifest.to_canonical_bytes().unwrap(),
    )
    .unwrap();
    store::open_snapshot(local, path.to_str().unwrap())
        .await
        .unwrap()
}

fn assert_ram(path: &Path, generation: u64) {
    let closure = CheckpointClosure::open_portable(path.join(CHECKPOINT_DIRECTORY), None).unwrap();
    closure.verify_memory_objects().unwrap();
    let mut ram = Vec::new();
    for extent in &closure.memory().extents {
        match &extent.content {
            MemoryExtentContent::Zero => ram.extend(vec![0; extent.length as usize]),
            MemoryExtentContent::Object(content) => {
                let object = closure.read_object(&content.object, 8192).unwrap();
                let start = content.object_offset as usize;
                ram.extend_from_slice(&object[start..start + extent.length as usize]);
            }
        }
    }
    assert_eq!(&ram[..4096], &vec![0xa5; 4096]);
    assert_eq!(&ram[4096..8192], &vec![(generation / 3) as u8; 4096]);
    assert_eq!(&ram[8192..], &vec![0; 4096]);
    assert_eq!(
        closure
            .read_object(&closure.checkpoint().execution_state, 128)
            .unwrap(),
        format!("execution-{generation}").as_bytes()
    );
}

async fn unpack(path: &Path, stage: &Path) -> ArchiveInventory {
    let file = BufReader::new(tokio::fs::File::open(path).await.unwrap());
    let cache = stage.join("cache");
    tokio::fs::create_dir_all(&cache).await.unwrap();
    // Tests use plain tar to inspect exactly which payloads were physically transported.
    unpack_archive(file, stage, &cache)
        .await
        .unwrap()
        .inventory
        .unwrap()
}

async fn with_owned_volumes(local: &LocalBackend, snapshot: Snapshot, generation: u64) -> Snapshot {
    use microsandbox_image::snapshot::{
        OwnedDirectoryPayload, OwnedMountSnapshot, OwnedVolumeCapture, OwnedVolumeData,
    };
    use microsandbox_types::{OwnedVolumeStorage, VolumeMount};
    let root = snapshot.path().join(CHECKPOINT_DIRECTORY);
    let closure = CheckpointClosure::open_portable(&root, None).unwrap();
    let mut checkpoint = closure.checkpoint().clone();
    let store = LocalObjectStore::open(&root).unwrap();
    let source = tempfile::tempdir().unwrap();
    std::fs::write(
        source.path().join(if generation == 1 {
            "original"
        } else {
            "renamed"
        }),
        b"unchanged bytes",
    )
    .unwrap();
    std::fs::write(
        source
            .path()
            .join(if generation == 1 { "deleted" } else { "added" }),
        if generation == 1 { b"old" } else { b"new" },
    )
    .unwrap();
    let mount_id = microsandbox_types::owned_volume_mount_id("/cache");
    std::fs::create_dir_all(root.join("owned")).unwrap();
    let captured = microsandbox_filesystem::OwnedDirectorySnapshot::capture(
        source.path(),
        &root.join("owned").join(&mount_id),
    )
    .unwrap();
    let directory = VolumeMount::Owned {
        guest: "/cache".into(),
        storage: OwnedVolumeStorage::Directory {
            quota_mib: Some(32),
        },
        options: Default::default(),
        stat_virtualization: microsandbox_types::StatVirtualization::Strict,
        host_permissions: microsandbox_types::HostPermissions::Private,
    };
    let directory = OwnedVolumeCapture {
        mount_id,
        mount: OwnedMountSnapshot::from_mount(&directory).unwrap(),
        data: OwnedVolumeData::Directory {
            descriptor: OwnedDirectoryPayload {
                digest: captured.digest().unwrap(),
                bytes: captured.descriptor_bytes().unwrap().len() as u64,
            },
            files: captured
                .payloads()
                .into_iter()
                .map(|payload| OwnedDirectoryPayload {
                    digest: payload.digest,
                    bytes: payload.bytes,
                })
                .collect(),
        },
    };
    let mount_id = crate::runtime::spawn::guest_mount_tag("/data");
    // Unchanged readonly capture retains the physical layer identity across generations.
    let layer_id = format!("layer_{:032x}", 5001);
    std::fs::create_dir_all(root.join("layers")).unwrap();
    let path = root.join("layers").join(format!("{layer_id}.raw"));
    std::fs::write(&path, vec![37; 1024 * 1024]).unwrap();
    let disk = DiskGenerationManifest {
        schema: "microsandbox.disk-generation/1".into(),
        volume_id: "vol_owned".into(),
        device_id: mount_id.clone(),
        generation,
        head: layer_id.clone(),
        pause_generation: checkpoint.pause_generation,
        layers: vec![DiskLayerRef {
            layer_id,
            format: "raw".into(),
            virtual_size: 1024 * 1024,
            predecessor: None,
            file_size: std::fs::metadata(&path).unwrap().len(),
            integrity_root: Some(sparse_file_integrity(&path).unwrap().root),
        }],
    };
    checkpoint.disks.push(
        store
            .put_bytes(&disk.to_canonical_bytes().unwrap())
            .unwrap(),
    );
    let disk_mount = VolumeMount::Owned {
        guest: "/data".into(),
        storage: OwnedVolumeStorage::Disk { capacity_mib: 1 },
        options: Default::default(),
        stat_virtualization: microsandbox_types::StatVirtualization::Strict,
        host_permissions: microsandbox_types::HostPermissions::Private,
    };
    checkpoint.owned_volumes = vec![
        directory,
        OwnedVolumeCapture {
            mount_id,
            mount: OwnedMountSnapshot::from_mount(&disk_mount).unwrap(),
            data: OwnedVolumeData::Disk { generation: disk },
        },
    ];
    checkpoint.resources = checkpoint
        .owned_volumes
        .iter()
        .map(|volume| {
            let binding = match volume.data {
                OwnedVolumeData::Directory { .. } => BTreeMap::from([
                    ("role".into(), "owned_directory".into()),
                    ("guest_tag".into(), volume.mount_id.clone()),
                ]),
                OwnedVolumeData::Disk { .. } => BTreeMap::from([
                    ("lifecycle_owned".into(), "true".into()),
                    ("device_id".into(), volume.mount_id.clone()),
                    ("guest_path".into(), volume.mount.guest.clone()),
                ]),
            };
            microsandbox_image::checkpoint::ResourceDescriptor {
                id: volume.mount_id.clone(),
                kind: "virtio".into(),
                treatment: microsandbox_image::checkpoint::ResourceTreatment::Serialize,
                binding,
            }
        })
        .collect();
    let bytes = checkpoint.to_canonical_bytes().unwrap();
    let root_id = ObjectId::from_bytes(&bytes).unwrap();
    std::fs::write(root.join("checkpoint.json"), bytes).unwrap();
    let mut manifest = snapshot.manifest().clone();
    manifest
        .set_owned_volumes(checkpoint.owned_volumes)
        .unwrap();
    let SnapshotState::Checkpoint(state) = &mut manifest.state else {
        unreachable!()
    };
    state.checkpoint_root = root_id.to_string();
    std::fs::write(
        snapshot.path().join(DESCRIPTOR_FILENAME),
        manifest.to_canonical_bytes().unwrap(),
    )
    .unwrap();
    store::open_snapshot(local, snapshot.path().to_str().unwrap())
        .await
        .unwrap()
}

async fn with_owned_disk_chain(
    local: &LocalBackend,
    snapshot: Snapshot,
    layers: u64,
    previous: Option<&Snapshot>,
) -> Snapshot {
    use microsandbox_image::snapshot::OwnedVolumeData;

    let root = snapshot.path().join(CHECKPOINT_DIRECTORY);
    let closure = CheckpointClosure::open_portable(&root, None).unwrap();
    let mut checkpoint = closure.checkpoint().clone();
    let store = LocalObjectStore::open(&root).unwrap();
    let volume = checkpoint
        .owned_volumes
        .iter_mut()
        .find(|volume| matches!(volume.data, OwnedVolumeData::Disk { .. }))
        .unwrap();
    let OwnedVolumeData::Disk { generation } = &mut volume.data else {
        unreachable!()
    };
    let old = ObjectId::from_bytes(&generation.to_canonical_bytes().unwrap()).unwrap();
    if let Some(previous) = previous {
        let prior_volumes = previous.manifest().owned_volumes().unwrap();
        let prior = prior_volumes
            .iter()
            .find(|prior| prior.mount_id == volume.mount_id)
            .unwrap();
        let OwnedVolumeData::Disk { generation: prior } = &prior.data else {
            unreachable!()
        };
        assert_eq!(generation.layers[0], prior.layers[0]);
        assert!(prior.layers.len() <= layers as usize);
        let prior_root = if matches!(previous.manifest().state, SnapshotState::Checkpoint(_)) {
            previous.path().join(CHECKPOINT_DIRECTORY)
        } else {
            previous.path().to_path_buf()
        };
        // Equivalent newly created QCOW2 images need not have identical physical headers.
        // Reuse the actual sealed prefix, just as runtime capture does, rather than recreating it.
        for layer in prior.layers.iter().skip(1) {
            let name = format!("{}.{}", layer.layer_id, layer.format);
            let target = root.join("layers").join(&name);
            microsandbox_utils::copy::fast_copy(&prior_root.join("layers").join(name), &target)
                .unwrap();
            assert_eq!(
                sparse_file_integrity(&target).unwrap().root,
                *layer.integrity_root.as_ref().expect("owned disk integrity")
            );
            generation.layers.push(layer.clone());
        }
        generation.head = prior.head.clone();
    }
    for index in generation.layers.len() as u64 + 1..=layers {
        let predecessor = generation.layers.last().unwrap();
        let layer_id = format!("layer_{:032x}", 5000 + index);
        let path = root.join("layers").join(format!("{layer_id}.qcow2"));
        microsandbox_image::checkpoint::create_qcow2_overlay(
            &path,
            1024 * 1024,
            &root
                .join("layers")
                .join(format!("{}.{}", predecessor.layer_id, predecessor.format)),
            &predecessor.format,
        )
        .await
        .unwrap();
        generation.layers.push(DiskLayerRef {
            layer_id: layer_id.clone(),
            format: "qcow2".into(),
            virtual_size: 1024 * 1024,
            predecessor: Some(predecessor.layer_id.clone()),
            file_size: std::fs::metadata(&path).unwrap().len(),
            integrity_root: Some(sparse_file_integrity(&path).unwrap().root),
        });
        generation.head = layer_id;
    }
    let updated = store
        .put_bytes(&generation.to_canonical_bytes().unwrap())
        .unwrap();
    *checkpoint.disks.iter_mut().find(|id| **id == old).unwrap() = updated;
    let bytes = checkpoint.to_canonical_bytes().unwrap();
    let root_id = ObjectId::from_bytes(&bytes).unwrap();
    std::fs::write(root.join("checkpoint.json"), bytes).unwrap();
    let mut manifest = snapshot.manifest().clone();
    manifest
        .set_owned_volumes(checkpoint.owned_volumes)
        .unwrap();
    let SnapshotState::Checkpoint(state) = &mut manifest.state else {
        unreachable!()
    };
    state.checkpoint_root = root_id.to_string();
    std::fs::write(
        snapshot.path().join(DESCRIPTOR_FILENAME),
        manifest.to_canonical_bytes().unwrap(),
    )
    .unwrap();
    store::open_snapshot(local, snapshot.path().to_str().unwrap())
        .await
        .unwrap()
}

async fn as_owned_file_snapshot(local: &LocalBackend, snapshot: Snapshot) -> Snapshot {
    use microsandbox_image::snapshot::{
        DiskLayerId, FileSnapshotState, LayerFileKind, LayerPayload, SnapshotFormat,
    };

    for member in ["owned", "layers"] {
        std::fs::rename(
            snapshot.path().join(CHECKPOINT_DIRECTORY).join(member),
            snapshot.path().join(member),
        )
        .unwrap();
    }
    let root_id = DiskLayerId::new(format!("layer_{:032x}", 9001)).unwrap();
    std::fs::write(
        snapshot
            .path()
            .join("layers")
            .join(format!("{root_id}.raw")),
        vec![92; 4096],
    )
    .unwrap();
    let mut manifest = snapshot.manifest().clone();
    manifest.scope = SnapshotScope::Disk;
    manifest.root_disk = SnapshotRootDisk::Managed;
    manifest.state = SnapshotState::File(FileSnapshotState {
        disk_format: SnapshotFormat::Raw,
        filesystem: "ext4".into(),
        virtual_size: 4096,
        head: root_id.clone(),
        layers: vec![DiskLayer {
            layer_id: root_id,
            format: SnapshotFormat::Raw,
            virtual_size: 4096,
            backing: None,
            payload: LayerPayload {
                file_kind: LayerFileKind::Regular,
                integrity: None,
            },
        }],
    });
    std::fs::write(
        snapshot.path().join(DESCRIPTOR_FILENAME),
        manifest.to_canonical_bytes().unwrap(),
    )
    .unwrap();
    store::open_snapshot(local, snapshot.path().to_str().unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn owned_qcow2_file_delta_and_direct_archive_preserve_physical_identity() {
    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let base = fixture(&local, &temp.path().join("base"), 2, None, false).await;
    let base = with_owned_volumes(&local, base, 2).await;
    let base = with_owned_disk_chain(&local, base, 2, None).await;
    let base = as_owned_file_snapshot(&local, base).await;
    let head = fixture(&local, &temp.path().join("head"), 3, Some(&base), false).await;
    let head = with_owned_volumes(&local, head, 3).await;
    let head = with_owned_disk_chain(&local, head, 3, Some(&base)).await;
    let head = as_owned_file_snapshot(&local, head).await;
    let base_archive = temp.path().join("base.msb");
    let delta = temp.path().join("delta.msb");
    let direct = temp.path().join("direct.msb");
    save_snapshot(
        &local,
        base.path().to_str().unwrap(),
        &base_archive,
        SaveOpts {
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    save_snapshot(
        &local,
        head.path().to_str().unwrap(),
        &delta,
        SaveOpts {
            plain_tar: true,
            since: Some(base.path().to_string_lossy().into_owned()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let inventory = unpack(&delta, &temp.path().join("inspect")).await;
    let dependencies = validate(&inventory).unwrap().unwrap();
    assert_eq!(
        dependencies
            .owned
            .iter()
            .filter(|payload| matches!(payload.identity, OwnedPayloadIdentity::Disk { .. }))
            .count(),
        2
    );
    assert_eq!(
        inventory
            .entries
            .iter()
            .filter(|entry| entry.kind == "owned-disk-layer" && entry.included)
            .count(),
        1
    );
    let file = head.manifest().state.as_file().unwrap();
    save_direct_file_snapshot(
        head.manifest(),
        &Default::default(),
        "owned-chain",
        &[head.path().join(file.layer_path(&file.layers[0]))],
        Some(head.path()),
        &direct,
        true,
        false,
    )
    .await
    .unwrap();
    let expected = head.manifest().owned_volumes().unwrap();
    std::fs::remove_dir_all(base.path()).unwrap();
    std::fs::remove_dir_all(head.path()).unwrap();
    for (archive, base) in [
        (&delta, Some(base_archive.to_str().unwrap())),
        (&direct, None),
    ] {
        let loaded = load_snapshot_with_base(&local, archive, None, base)
            .await
            .unwrap();
        let snapshot = store::open_snapshot(&local, loaded.path().to_str().unwrap())
            .await
            .unwrap();
        assert_eq!(snapshot.manifest().owned_volumes().unwrap(), expected);
        snapshot.verify().await.unwrap();
    }
}

#[tokio::test]
async fn owned_qcow2_last_layers_selector_keeps_owned_chains_complete() {
    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let base = fixture(&local, &temp.path().join("base"), 1, None, true).await;
    let head = fixture(&local, &temp.path().join("head"), 2, Some(&base), true).await;
    let head = with_owned_volumes(&local, head, 2).await;
    let head = with_owned_disk_chain(&local, head, 3, None).await;
    let archive = temp.path().join("last.msb");
    save_snapshot(
        &local,
        head.path().to_str().unwrap(),
        &archive,
        SaveOpts {
            last_layers: Some(1),
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let inventory = unpack(&archive, &temp.path().join("inspect")).await;
    let dependencies = validate(&inventory).unwrap().unwrap();
    assert_eq!(dependencies.disks.len(), 1);
    assert!(dependencies.owned.is_empty());
    let owned_layer_ids: BTreeSet<_> = head
        .manifest()
        .owned_volumes()
        .unwrap()
        .iter()
        .flat_map(|volume| match &volume.data {
            microsandbox_image::snapshot::OwnedVolumeData::Disk { generation } => generation
                .layers
                .iter()
                .map(|layer| format!("{}.{}", layer.layer_id, layer.format))
                .collect(),
            _ => Vec::new(),
        })
        .collect();
    assert_eq!(
        inventory
            .entries
            .iter()
            .filter(|entry| entry
                .path
                .rsplit('/')
                .next()
                .is_some_and(|name| owned_layer_ids.contains(name))
                && entry.included)
            .count(),
        3
    );
}

#[tokio::test]
async fn owned_qcow2_delta_borrows_exact_prefix_and_survives_source_deletion() {
    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let base = fixture(&local, &temp.path().join("base"), 2, None, false).await;
    let base = with_owned_volumes(&local, base, 2).await;
    let base = with_owned_disk_chain(&local, base, 2, None).await;
    let head = fixture(&local, &temp.path().join("head"), 3, Some(&base), false).await;
    let head = with_owned_volumes(&local, head, 3).await;
    let head = with_owned_disk_chain(&local, head, 3, Some(&base)).await;
    let baseline = temp.path().join("base.msb");
    let delta = temp.path().join("delta.msb");
    save_snapshot(
        &local,
        base.path().to_str().unwrap(),
        &baseline,
        SaveOpts {
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    save_snapshot(
        &local,
        head.path().to_str().unwrap(),
        &delta,
        SaveOpts {
            plain_tar: true,
            since: Some(base.path().to_string_lossy().into_owned()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let stage = temp.path().join("inspect");
    let inventory = unpack(&delta, &stage).await;
    let dependencies = validate(&inventory).unwrap().unwrap();
    assert_eq!(
        dependencies
            .owned
            .iter()
            .filter(|payload| matches!(payload.identity, OwnedPayloadIdentity::Disk { .. }))
            .count(),
        2
    );
    let newest = format!("layer_{:032x}.qcow2", 5003);
    assert!(
        inventory
            .entries
            .iter()
            .any(|entry| entry.path.ends_with(&newest) && entry.included)
    );
    let borrowed = format!("layer_{:032x}.qcow2", 5002);
    assert!(
        inventory
            .entries
            .iter()
            .any(|entry| entry.path.ends_with(&borrowed) && !entry.included)
    );
    std::fs::remove_dir_all(base.path()).unwrap();
    std::fs::remove_dir_all(head.path()).unwrap();
    assert!(
        load_snapshot_with_base(&local, &delta, None, None)
            .await
            .is_err()
    );
    let loaded = load_snapshot_with_base(&local, &delta, None, Some(baseline.to_str().unwrap()))
        .await
        .unwrap();
    let root = loaded.path().join(CHECKPOINT_DIRECTORY);
    let closure = CheckpointClosure::open_portable(&root, None).unwrap();
    let disk = closure
        .disks()
        .iter()
        .find(|disk| disk.device_id == microsandbox_types::owned_volume_mount_id("/data"))
        .unwrap();
    assert_eq!(disk.layers.len(), 3);
    let borrowed = root.join("layers").join(borrowed);
    assert_ne!(std::fs::metadata(&borrowed).unwrap().len(), 1024 * 1024);
    let identity = OwnedPayloadIdentity::Disk {
        integrity_root: disk.layers[1].integrity_root.clone().unwrap(),
        bytes: 1024 * 1024,
    };
    verify_owned_payload(&borrowed, &identity).await.unwrap();
    assert!(
        verify_owned_payload(
            &borrowed,
            &OwnedPayloadIdentity::Disk {
                integrity_root: disk.layers[1].integrity_root.clone().unwrap(),
                bytes: 2 * 1024 * 1024,
            }
        )
        .await
        .is_err()
    );
    // Release the closure's read handles before deliberately mutating its file:
    // Windows prevents write access while those handles pin the checkpoint.
    drop(closure);
    // Changing a relative backing name changes physical identity, even with unchanged guest data.
    microsandbox_image::checkpoint::relocate_qcow2_backing(&borrowed, Path::new("different.raw"))
        .unwrap();
    assert!(verify_owned_payload(&borrowed, &identity).await.is_err());
}

#[tokio::test]
async fn hashless_owned_layers_are_not_omitted_as_borrowed_dependencies() {
    use microsandbox_image::snapshot::OwnedVolumeData;

    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let snapshot = fixture(&local, &temp.path().join("base"), 2, None, false).await;
    let snapshot = with_owned_volumes(&local, snapshot, 2).await;
    let mut manifest = snapshot.manifest().clone();
    let mut volumes = manifest.owned_volumes().unwrap();
    for volume in &mut volumes {
        if let OwnedVolumeData::Disk { generation } = &mut volume.data {
            for layer in &mut generation.layers {
                layer.integrity_root = None;
            }
        }
    }
    manifest.set_owned_volumes(volumes).unwrap();
    // Planning has no filesystem root and must neither open ambient relative paths nor
    // claim that a hashless layer has the old hash-based owned dependency identity.
    let required = owned_since_dependencies(&manifest, &manifest).unwrap();
    assert!(
        required
            .iter()
            .all(|payload| matches!(payload.identity, OwnedPayloadIdentity::Directory { .. }))
    );
    let payloads = owned_payloads(&manifest, Path::new("")).unwrap();
    assert!(
        payloads
            .iter()
            .all(|(payload, _)| matches!(payload.identity, OwnedPayloadIdentity::Directory { .. }))
    );
}

#[tokio::test]
async fn owned_since_refuses_compacted_or_reinterpreted_prefix_and_allows_new_devices() {
    use microsandbox_image::snapshot::OwnedVolumeData;

    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let snapshot = fixture(&local, &temp.path().join("base"), 2, None, false).await;
    let snapshot = with_owned_volumes(&local, snapshot, 2).await;
    let snapshot = with_owned_disk_chain(&local, snapshot, 2, None).await;
    let baseline = snapshot.manifest();
    for mismatch in ["id", "hash", "compacted"] {
        let mut target = baseline.clone();
        let mut owned = target.owned_volumes().unwrap();
        let volume = owned
            .iter_mut()
            .find(|volume| matches!(volume.data, OwnedVolumeData::Disk { .. }))
            .unwrap();
        let OwnedVolumeData::Disk { generation } = &mut volume.data else {
            unreachable!()
        };
        match mismatch {
            "id" => {
                generation.layers[0].layer_id = "replaced".into();
                generation.layers[1].predecessor = Some("replaced".into());
            }
            "hash" => {
                generation.layers[0].integrity_root = Some(format!("blake3:{}", "f".repeat(64)))
            }
            "compacted" => {
                generation.layers.remove(0);
                generation.layers[0].predecessor = None;
            }
            _ => unreachable!(),
        }
        target.set_owned_volumes(owned).unwrap();
        let error = owned_since_dependencies(&target, baseline).unwrap_err();
        assert!(
            error.to_string().contains("export the new base first"),
            "{mismatch}: {error}"
        );
        owned_since_dependencies(&target, &target).unwrap();
    }
    let mut branch = baseline.clone();
    let mut owned = branch.owned_volumes().unwrap();
    for volume in &mut owned {
        if let OwnedVolumeData::Disk { generation } = &mut volume.data {
            generation.volume_id = "private-child".into();
        }
    }
    branch.set_owned_volumes(owned).unwrap();
    assert_eq!(
        owned_since_dependencies(&branch, baseline).unwrap(),
        owned_since_dependencies(baseline, baseline).unwrap()
    );
    let mut target = baseline.clone();
    let mut volumes = target.owned_volumes().unwrap();
    let mut added = volumes
        .iter()
        .find(|volume| matches!(volume.data, OwnedVolumeData::Disk { .. }))
        .unwrap()
        .clone();
    added.mount.guest = "/other".into();
    added.mount_id = microsandbox_types::owned_volume_mount_id(&added.mount.guest);
    let OwnedVolumeData::Disk { generation } = &mut added.data else {
        unreachable!()
    };
    generation.device_id = added.mount_id.clone();
    generation.layers[0].layer_id = "other-base".into();
    generation.layers[1].layer_id = "other-head".into();
    generation.layers[1].predecessor = Some("other-base".into());
    generation.head = "other-head".into();
    volumes.push(added);
    target.set_owned_volumes(volumes.clone()).unwrap();
    assert_eq!(
        owned_since_dependencies(&target, baseline)
            .unwrap()
            .iter()
            .filter(|payload| matches!(payload.identity, OwnedPayloadIdentity::Disk { .. }))
            .count(),
        2,
        "a newly added device must be included whole"
    );
    let same_devices = target.clone();
    let OwnedVolumeData::Disk { generation } = &mut volumes.last_mut().unwrap().data else {
        unreachable!()
    };
    generation.layers[0].integrity_root = Some(format!("blake3:{}", "e".repeat(64)));
    target.set_owned_volumes(volumes).unwrap();
    let error = owned_since_dependencies(&target, &same_devices).unwrap_err();
    assert!(
        error.to_string().contains("/other"),
        "every device must validate its own prefix: {error}"
    );
    let mut empty = baseline.clone();
    empty.set_owned_volumes(Vec::new()).unwrap();
    assert!(
        owned_since_dependencies(baseline, &empty)
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn owned_delta_reuses_bytes_and_restores_private_renamed_namespace_after_source_deletion() {
    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let base = fixture(&local, &temp.path().join("base"), 1, None, false).await;
    let base = with_owned_volumes(&local, base, 1).await;
    let head = fixture(&local, &temp.path().join("head"), 2, Some(&base), false).await;
    let head = with_owned_volumes(&local, head, 2).await;
    let base_archive = temp.path().join("base.msb");
    let delta_archive = temp.path().join("delta.msb");
    save_snapshot(
        &local,
        base.path().to_str().unwrap(),
        &base_archive,
        SaveOpts {
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    save_snapshot(
        &local,
        head.path().to_str().unwrap(),
        &delta_archive,
        SaveOpts {
            plain_tar: true,
            since: Some(base.path().to_string_lossy().into_owned()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let stage = temp.path().join("delta-stage");
    let inventory = unpack(&delta_archive, &stage).await;
    let dependencies = validate(&inventory).unwrap().unwrap();
    assert_eq!(
        dependencies.owned.len(),
        2,
        "unchanged directory data and owned disk must both use the base"
    );
    assert!(
        inventory
            .entries
            .iter()
            .any(|entry| entry.path.ends_with("directory.bin") && entry.included)
    );
    assert!(
        inventory
            .entries
            .iter()
            .any(|entry| entry.kind == "owned-directory-payload"
                && entry.path.contains("/files/")
                && entry.included)
    );
    std::fs::remove_dir_all(base.path()).unwrap();
    std::fs::remove_dir_all(head.path()).unwrap();
    let loaded = load_snapshot_with_base(
        &local,
        &delta_archive,
        None,
        Some(base_archive.to_str().unwrap()),
    )
    .await
    .unwrap();
    let loaded_snapshot = store::open_snapshot(&local, loaded.path().to_str().unwrap())
        .await
        .unwrap();
    let volumes = loaded_snapshot.manifest().owned_volumes().unwrap();
    let source = loaded.path().join(CHECKPOINT_DIRECTORY);
    let first = temp.path().join("first-child");
    let second = temp.path().join("second-child");
    for child in [&first, &second] {
        std::fs::create_dir(child).unwrap();
        let mounts = crate::snapshot::materialize_owned_volumes(
            &volumes,
            &source,
            child,
            &Default::default(),
        )
        .await
        .unwrap();
        assert_eq!(mounts.len(), 2);
        assert!(
            mounts
                .iter()
                .all(|mount| matches!(mount, microsandbox_types::VolumeMount::Owned { .. }))
        );
        let data = child
            .join("owned-volumes")
            .join(crate::runtime::spawn::guest_mount_tag("/cache"))
            .join("data");
        assert_eq!(
            std::fs::read(data.join("renamed")).unwrap(),
            b"unchanged bytes"
        );
        assert_eq!(std::fs::read(data.join("added")).unwrap(), b"new");
        assert!(!data.join("original").exists());
        assert!(!data.join("deleted").exists());
    }
    let disk_chain = |child: &Path| {
        microsandbox_runtime::checkpoint::load_runtime_owned_disk_chain(
            &child.join("runtime"),
            &microsandbox_types::owned_volume_mount_id("/data"),
        )
        .unwrap()
        .unwrap()
    };
    let first_chain = disk_chain(&first);
    let second_chain = disk_chain(&second);
    let first_head = &first_chain.layers.last().unwrap().path;
    let second_head = &second_chain.layers.last().unwrap().path;
    let second_bytes = std::fs::read(second_head).unwrap();
    assert_ne!(first_head, second_head);
    std::fs::write(first_head, b"changed private child head").unwrap();
    assert_eq!(std::fs::read(second_head).unwrap(), second_bytes);
    assert_eq!(
        std::fs::read(&second_chain.layers[0].path).unwrap(),
        vec![37; 1024 * 1024]
    );
    let mut conflict = crate::sandbox::restore_resources::RestoreResources::default();
    conflict.mapped.insert("/cache".into());
    assert!(
        crate::snapshot::materialize_owned_volumes(
            &volumes,
            &source,
            &temp.path().join("conflict"),
            &conflict
        )
        .await
        .is_err()
    );
    let missing = source
        .join(volumes[0].directory_path())
        .join("directory.bin");
    std::fs::remove_file(missing).unwrap();
    assert!(CheckpointClosure::open_portable(&source, None).is_err());
}

#[tokio::test]
async fn owned_file_archives_restore_all_backing_without_source_or_inheritance() {
    use microsandbox_image::snapshot::{
        DiskLayer, DiskLayerId, FileSnapshotState, LayerFileKind, LayerPayload, SnapshotFormat,
    };
    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let snapshot = fixture(&local, &temp.path().join("source"), 21, None, false).await;
    let snapshot = with_owned_volumes(&local, snapshot, 2).await;
    let mut manifest = snapshot.manifest().clone();
    // Convert the same owned closure fixture to the independently supported cold-boot format.
    for directory in ["owned", "layers"] {
        std::fs::rename(
            snapshot.path().join(CHECKPOINT_DIRECTORY).join(directory),
            snapshot.path().join(directory),
        )
        .unwrap();
    }
    let empty = tempfile::tempdir().unwrap();
    let empty_mount = microsandbox_types::VolumeMount::Owned {
        guest: "/缓存 data".into(),
        storage: microsandbox_types::OwnedVolumeStorage::Directory { quota_mib: None },
        options: Default::default(),
        stat_virtualization: microsandbox_types::StatVirtualization::Strict,
        host_permissions: microsandbox_types::HostPermissions::Private,
    };
    let mount_id = microsandbox_types::owned_volume_mount_id(empty_mount.guest());
    let captured = microsandbox_filesystem::OwnedDirectorySnapshot::capture(
        empty.path(),
        &snapshot.path().join("owned").join(&mount_id),
    )
    .unwrap();
    let mut volumes = manifest.owned_volumes().unwrap();
    volumes.push(microsandbox_image::snapshot::OwnedVolumeCapture {
        mount_id,
        mount: microsandbox_image::snapshot::OwnedMountSnapshot::from_mount(&empty_mount).unwrap(),
        data: microsandbox_image::snapshot::OwnedVolumeData::Directory {
            descriptor: microsandbox_image::snapshot::OwnedDirectoryPayload {
                digest: captured.digest().unwrap(),
                bytes: captured.descriptor_bytes().unwrap().len() as u64,
            },
            files: Vec::new(),
        },
    });
    manifest.set_owned_volumes(volumes).unwrap();
    let layer_id = DiskLayerId::new(format!("layer_{:032x}", 9001)).unwrap();
    let root_file = snapshot
        .path()
        .join("layers")
        .join(format!("{layer_id}.raw"));
    std::fs::write(&root_file, vec![92; 4096]).unwrap();
    manifest.scope = SnapshotScope::Disk;
    manifest.root_disk = SnapshotRootDisk::Managed;
    manifest.state = SnapshotState::File(FileSnapshotState {
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
    });
    std::fs::write(
        snapshot.path().join(DESCRIPTOR_FILENAME),
        manifest.to_canonical_bytes().unwrap(),
    )
    .unwrap();
    let direct = temp.path().join("direct.msb");
    let installed = temp.path().join("installed.msb");
    save_direct_file_snapshot(
        &manifest,
        &Default::default(),
        "owned-file",
        &[root_file],
        Some(snapshot.path()),
        &direct,
        true,
        false,
    )
    .await
    .unwrap();
    save_snapshot(
        &local,
        snapshot.path().to_str().unwrap(),
        &installed,
        SaveOpts {
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    std::fs::remove_dir_all(snapshot.path()).unwrap();
    for (index, archive) in [&direct, &installed].into_iter().enumerate() {
        let child = temp.path().join(format!("child-{index}"));
        let restored = materialize_archive_for_child_with_base(
            &local,
            archive,
            &child,
            false,
            None,
            &Default::default(),
        )
        .await
        .unwrap();
        assert_eq!(restored.disk_mounts.len(), 3);
        let data = child
            .join("owned-volumes")
            .join(microsandbox_types::owned_volume_mount_id("/cache"))
            .join("data");
        assert_eq!(
            std::fs::read(data.join("renamed")).unwrap(),
            b"unchanged bytes"
        );
        assert!(!data.join("deleted").exists());
        let disk = microsandbox_runtime::checkpoint::load_runtime_owned_disk_chain(
            &child.join("runtime"),
            &microsandbox_types::owned_volume_mount_id("/data"),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            std::fs::read(&disk.layers[0].path).unwrap(),
            vec![37; 1024 * 1024]
        );
        assert_eq!(disk.layers.last().unwrap().format, "qcow2");
        let empty = child
            .join("owned-volumes")
            .join(microsandbox_types::owned_volume_mount_id("/缓存 data"))
            .join("data");
        assert_eq!(std::fs::read_dir(empty).unwrap().count(), 0);
    }
    let loaded = load_snapshot(&local, &installed, None).await.unwrap();
    let loaded = store::open_snapshot(&local, loaded.path().to_str().unwrap())
        .await
        .unwrap();
    assert_eq!(
        loaded.manifest().owned_volumes().unwrap(),
        manifest.owned_volumes().unwrap()
    );
    super::super::super::verify::verify_snapshot(&loaded)
        .await
        .unwrap();
}

async fn with_additional_disks(
    local: &LocalBackend,
    snapshot: Snapshot,
    generation: u64,
) -> Snapshot {
    let root = snapshot.path().join(CHECKPOINT_DIRECTORY);
    let closure = CheckpointClosure::open_portable(&root, None).unwrap();
    let mut checkpoint = closure.checkpoint().clone();
    let store = LocalObjectStore::open(&root).unwrap();
    for number in 1..=2 {
        let layer_id = format!("layer_{:032x}", 100 * generation + number);
        let path = root.join("layers").join(format!("{layer_id}.raw"));
        std::fs::write(&path, vec![(10 * generation + number) as u8; 65536]).unwrap();
        let disk = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: format!("vol_data_{number}"),
            device_id: format!("data_{number}"),
            generation,
            layers: vec![DiskLayerRef {
                file_size: std::fs::metadata(&path).unwrap().len(),
                layer_id: layer_id.clone(),
                format: "raw".into(),
                virtual_size: 65536,
                predecessor: None,
                integrity_root: Some(sparse_file_integrity(&path).unwrap().root),
            }],
            head: layer_id,
            pause_generation: checkpoint.pause_generation,
        };
        // Runtime inventories may put additional device IDs before the root. Neither loading
        // nor direct restore may confuse that manifest order with the selected root chain.
        checkpoint.disks.insert(
            0,
            store
                .put_bytes(&disk.to_canonical_bytes().unwrap())
                .unwrap(),
        );
    }
    let bytes = checkpoint.to_canonical_bytes().unwrap();
    let root_id = ObjectId::from_bytes(&bytes).unwrap();
    std::fs::write(root.join("checkpoint.json"), bytes).unwrap();
    let mut manifest = snapshot.manifest().clone();
    let SnapshotState::Checkpoint(state) = &mut manifest.state else {
        unreachable!()
    };
    state.checkpoint_root = root_id.to_string();
    std::fs::write(
        snapshot.path().join(DESCRIPTOR_FILENAME),
        manifest.to_canonical_bytes().unwrap(),
    )
    .unwrap();
    store::open_snapshot(local, snapshot.path().to_str().unwrap())
        .await
        .unwrap()
}

#[tokio::test]
async fn incremental_selectors_only_count_root_layers_and_include_each_additional_disk_whole() {
    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let base = fixture(&local, &temp.path().join("base"), 1, None, true).await;
    let head = fixture(&local, &temp.path().join("head"), 2, Some(&base), true).await;
    let base = with_additional_disks(&local, base, 1).await;
    let head = with_additional_disks(&local, head, 2).await;
    for (label, opts) in [
        (
            "since",
            SaveOpts {
                since: Some(base.path().to_string_lossy().into_owned()),
                plain_tar: true,
                ..Default::default()
            },
        ),
        (
            "last",
            SaveOpts {
                last_layers: Some(1),
                plain_tar: true,
                ..Default::default()
            },
        ),
    ] {
        let archive = temp.path().join(format!("{label}.msb"));
        save_snapshot(&local, head.path().to_str().unwrap(), &archive, opts)
            .await
            .unwrap();
        let stage = temp.path().join(format!("unpacked-{label}"));
        let inventory = unpack(&archive, &stage).await;
        let dependencies = validate(&inventory).unwrap().unwrap();
        assert_eq!(
            dependencies.disks.len(),
            1,
            "only the oldest root layer is omitted"
        );
        let LayerIdentity::Checkpoint(root) = &dependencies.disks[0].identity else {
            unreachable!()
        };
        assert_eq!(root.layer_id, format!("layer_{:032x}", 1));
        for number in 1..=2 {
            let name = format!("layer_{:032x}.raw", 200 + number);
            let entry = inventory
                .entries
                .iter()
                .find(|entry| entry.path.ends_with(&name))
                .unwrap();
            assert!(
                entry.included,
                "{label} must include whole additional disk {number}"
            );
            assert!(
                inventory_entry_target(&entry.path, &stage, &stage.join("cache"))
                    .unwrap()
                    .is_file()
            );
        }
        // Exercise direct-archive restore's resolver as well as installed/batch loading.
        resolve(
            &local,
            &inventory,
            &stage,
            &stage.join("cache"),
            Some(base.path().to_str().unwrap()),
        )
        .await
        .unwrap();
        let loaded =
            load_snapshot_with_base(&local, &archive, None, Some(base.path().to_str().unwrap()))
                .await
                .unwrap();
        let closure =
            CheckpointClosure::open_portable(loaded.path().join(CHECKPOINT_DIRECTORY), None)
                .unwrap();
        assert_eq!(closure.disks().len(), 3);
        for number in 1..=2 {
            let disk = closure
                .disks()
                .iter()
                .find(|disk| disk.device_id == format!("data_{number}"))
                .unwrap();
            assert_eq!(disk.generation, 2);
            assert_eq!(disk.layers.len(), 1);
            assert_eq!(
                std::fs::read(closure.disk_layer_path(&disk.layers[0])).unwrap(),
                vec![(20 + number) as u8; 65536]
            );
        }
    }
}

async fn chain(disk: bool) {
    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let mut previous = None;
    let mut loaded: Option<SnapshotHandle> = None;
    for generation in 1..=12 {
        let source = fixture(
            &local,
            &temp.path().join(format!("source-{generation}")),
            generation,
            previous.as_ref(),
            disk,
        )
        .await;
        let archive = temp.path().join(format!("cp{generation:02}.msb"));
        save_snapshot(
            &local,
            source.path().to_str().unwrap(),
            &archive,
            SaveOpts {
                since: previous
                    .as_ref()
                    .map(|snapshot: &Snapshot| snapshot.path().to_string_lossy().into_owned()),
                plain_tar: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let stage = temp.path().join(format!("unpacked-{generation}"));
        let inventory = unpack(&archive, &stage).await;
        if generation > 1 {
            let dependencies = validate(&inventory).unwrap().unwrap();
            assert_eq!(
                dependencies.disks.len(),
                if disk { generation as usize - 1 } else { 0 }
            );
            assert!(!dependencies.memory.is_empty());
            for id in &dependencies.memory {
                let path = memory_archive_path(source.id().as_str(), id);
                assert!(
                    !inventory_entry_target(&path, &stage, &stage.join("cache"))
                        .unwrap()
                        .exists()
                );
            }
            let closure =
                CheckpointClosure::open_portable(source.path().join(CHECKPOINT_DIRECTORY), None)
                    .unwrap();
            for id in [
                &closure.checkpoint().memory,
                &closure.checkpoint().execution_state,
                &closure.checkpoint().devices[0].state,
            ] {
                assert!(inventory.entries.iter().any(|entry| entry.path
                    == memory_archive_path(source.id().as_str(), id)
                    && entry.included));
            }
            assert!(load_snapshot(&local, &archive, None).await.is_err());
        } else {
            assert!(validate(&inventory).unwrap().is_none());
        }
        let base = loaded
            .as_ref()
            .map(|snapshot| snapshot.path().to_str().unwrap());
        if generation == 12 {
            // Direct archive restore must use the same dependency resolver, without installation.
            let child = temp.path().join("child");
            let result = materialize_archive_for_child_with_base(
                &local,
                &archive,
                &child,
                false,
                base,
                &Default::default(),
            )
            .await
            .unwrap();
            assert!(result.checkpoint_restore.is_some());
            let closure =
                CheckpointClosure::open_portable(child.join(".checkpoint-restore"), None).unwrap();
            closure.verify_memory_objects().unwrap();
            assert!(!local.snapshots_dir().join(source.id().as_str()).exists());
        }
        let current = load_snapshot_with_base(&local, &archive, None, base)
            .await
            .unwrap();
        assert_ram(current.path(), generation);
        if let Some(old) = loaded.take() {
            // These are exclusively test-owned artifacts; later loads cannot depend on their paths.
            std::fs::remove_dir_all(old.path()).unwrap();
            assert_ram(current.path(), generation);
        }
        loaded = Some(current);
        previous = Some(source);
    }
    let final_snapshot = loaded.unwrap();
    let standalone = temp.path().join("standalone.msb");
    save_snapshot(
        &local,
        final_snapshot.path().to_str().unwrap(),
        &standalone,
        SaveOpts::default(),
    )
    .await
    .unwrap();
    let other = load_snapshot(&local, &standalone, Some(&temp.path().join("other-host")))
        .await
        .unwrap();
    assert_ram(other.path(), 12);
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn owned_disk_payload_verification_is_send() {
    fn assert_send<T: Send>(_: T) {}

    let identity = OwnedPayloadIdentity::Disk {
        integrity_root: "0".repeat(64),
        bytes: 1024 * 1024,
    };
    // SDK backend futures are Send even though the underlying image reader is thread-local.
    assert_send(verify_owned_payload(Path::new("layer.qcow2"), &identity));
}

#[tokio::test]
async fn unordered_batch_resolves_disk_and_ram_from_all_supplied_archives() {
    for disk in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let local = LocalBackend::builder()
            .home(temp.path().join("home"))
            .build()
            .await
            .unwrap();
        let mut previous = None;
        let mut archives = Vec::new();
        for generation in 1..=6 {
            let source = fixture(
                &local,
                &temp.path().join(format!("source-{generation}")),
                generation,
                previous.as_ref(),
                disk,
            )
            .await;
            let archive = temp.path().join(format!("cp{generation}.msb"));
            save_snapshot(
                &local,
                source.path().to_str().unwrap(),
                &archive,
                SaveOpts {
                    since: previous
                        .as_ref()
                        .map(|snapshot: &Snapshot| snapshot.path().to_string_lossy().into_owned()),
                    plain_tar: generation % 2 == 0,
                    ..Default::default()
                },
            )
            .await
            .unwrap();
            archives.push(archive);
            previous = Some(source);
        }
        archives.reverse();
        let loaded = load_snapshots(
            &local,
            &archives,
            LoadOpts {
                group: Some("received".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        for (offset, snapshot) in loaded.iter().enumerate() {
            assert_ram(snapshot.path(), 6 - offset as u64);
        }
        assert_eq!(loaded[0].head_update().unwrap().head, loaded[0].snapshot_id);
        // Neither source files, archive bytes, nor other installed generations are needed by
        // the final snapshot after the batch has reconstructed destination-owned closures.
        for generation in 1..=6 {
            std::fs::remove_dir_all(temp.path().join(format!("source-{generation}"))).unwrap();
        }
        for archive in &archives {
            std::fs::remove_file(archive).unwrap();
        }
        for snapshot in &loaded[1..] {
            std::fs::remove_dir_all(snapshot.path()).unwrap();
        }
        assert_ram(loaded[0].path(), 6);
    }
}

#[tokio::test]
async fn automatic_group_sources_fill_ram_and_disks_without_base_flag() {
    for disk in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let local = LocalBackend::builder()
            .home(temp.path().join("home"))
            .build()
            .await
            .unwrap();
        let base = fixture(&local, &temp.path().join("base"), 1, None, disk).await;
        let target = fixture(&local, &temp.path().join("target"), 3, Some(&base), disk).await;
        let baseline = temp.path().join("base.msb");
        let delta = temp.path().join("delta.msb");
        save_snapshot(
            &local,
            base.path().to_str().unwrap(),
            &baseline,
            SaveOpts::default(),
        )
        .await
        .unwrap();
        save_snapshot(
            &local,
            target.path().to_str().unwrap(),
            &delta,
            SaveOpts {
                since: Some(base.path().to_string_lossy().into_owned()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let opts = LoadOpts {
            group: Some("received".into()),
            ..Default::default()
        };
        let installed_base = load_snapshot_with_options(&local, &baseline, opts.clone())
            .await
            .unwrap();
        // The same dependent archive cannot search a different, unnamed group implicitly.
        let error = load_snapshot_with_options(&local, &delta, LoadOpts::default())
            .await
            .unwrap_err();
        assert!(
            error.to_string().contains("missing dependencies"),
            "{error}"
        );
        assert!(!local.snapshots_dir().join("elsewhere").exists());
        let imported = load_snapshot_with_options(&local, &delta, opts)
            .await
            .unwrap();
        assert_ram(imported.path(), 3);
        std::fs::remove_dir_all(installed_base.path()).unwrap();
        assert_ram(imported.path(), 3);
    }
}

#[tokio::test]
async fn missing_or_corrupt_borrowed_ram_never_publishes_target() {
    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let base = fixture(&local, &temp.path().join("base"), 1, None, false).await;
    let target = fixture(&local, &temp.path().join("target"), 3, Some(&base), false).await;
    let baseline = temp.path().join("base.msb");
    let delta = temp.path().join("delta.msb");
    save_snapshot(
        &local,
        base.path().to_str().unwrap(),
        &baseline,
        SaveOpts::default(),
    )
    .await
    .unwrap();
    save_snapshot(
        &local,
        target.path().to_str().unwrap(),
        &delta,
        SaveOpts {
            since: Some(base.path().to_string_lossy().into_owned()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let opts = LoadOpts {
        group: Some("received".into()),
        ..Default::default()
    };
    let installed = load_snapshot_with_options(&local, &baseline, opts.clone())
        .await
        .unwrap();
    let id = memory_objects(&base)
        .unwrap()
        .intersection(&memory_objects(&target).unwrap())
        .next()
        .unwrap()
        .clone();
    let path = checkpoint_object_path(&installed.path().join(CHECKPOINT_DIRECTORY), &id);
    let original = std::fs::read(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    let missing = load_snapshot_with_options(&local, &delta, opts.clone())
        .await
        .unwrap_err();
    assert!(
        missing.to_string().contains("missing dependencies"),
        "{missing}"
    );
    std::fs::write(&path, vec![0x42; original.len()]).unwrap();
    let corrupt = load_snapshot_with_options(&local, &delta, opts)
        .await
        .unwrap_err();
    assert!(
        corrupt
            .to_string()
            .contains("RAM object content does not match"),
        "{corrupt}"
    );
    assert!(
        !installed
            .path()
            .parent()
            .unwrap()
            .join(target.id().as_str())
            .exists()
    );
    let head = super::super::super::group::select(&local.snapshots_dir(), "received")
        .await
        .unwrap();
    assert_eq!(head.head, base.id().as_str());
}

#[tokio::test]
async fn twelve_ram_only_archives_resolve_without_intermediate_vms() {
    chain(false).await;
}

#[tokio::test]
async fn twelve_disk_and_ram_archives_resolve_without_intermediate_vms() {
    chain(true).await;
}

#[tokio::test]
async fn last_layers_keeps_ram_complete_and_wrong_ram_base_fails() {
    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let base = fixture(&local, &temp.path().join("base"), 1, None, true).await;
    let target = fixture(&local, &temp.path().join("target"), 2, Some(&base), true).await;
    let selection = selection(
        &local,
        &target,
        &SaveOpts {
            last_layers: Some(1),
            ..Default::default()
        },
    )
    .await
    .unwrap()
    .unwrap();
    assert!(selection.memory.is_empty());
    let archive = temp.path().join("delta.msb");
    save_snapshot(
        &local,
        target.path().to_str().unwrap(),
        &archive,
        SaveOpts {
            since: Some(base.path().to_string_lossy().into_owned()),
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let ids = memory_objects(&base).unwrap();
    let missing = checkpoint_object_path(
        &base.path().join(CHECKPOINT_DIRECTORY),
        ids.first().unwrap(),
    );
    let saved = std::fs::read(&missing).unwrap();
    std::fs::remove_file(&missing).unwrap();
    assert!(
        load_snapshot_with_base(&local, &archive, None, Some(base.path().to_str().unwrap()))
            .await
            .is_err()
    );
    assert!(!local.snapshots_dir().join(target.id().as_str()).exists());
    std::fs::write(&missing, vec![0x33; saved.len()]).unwrap();
    assert!(
        load_snapshot_with_base(&local, &archive, None, Some(base.path().to_str().unwrap()))
            .await
            .is_err()
    );
    std::fs::write(&missing, saved).unwrap();
    let loaded =
        load_snapshot_with_base(&local, &archive, None, Some(base.path().to_str().unwrap()))
            .await
            .unwrap();
    assert_ram(loaded.path(), 2);
}

#[tokio::test]
async fn memory_dependency_validation_rejects_incomplete_and_misbound_inventories() {
    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let base = fixture(&local, &temp.path().join("base"), 1, None, false).await;
    let target = fixture(&local, &temp.path().join("target"), 4, None, false).await;
    let archive = temp.path().join("delta.tar");
    save_snapshot(
        &local,
        target.path().to_str().unwrap(),
        &archive,
        SaveOpts {
            since: Some(base.path().to_string_lossy().into_owned()),
            plain_tar: true,
            ..Default::default()
        },
    )
    .await
    .unwrap();
    let stage = temp.path().join("stage");
    let inventory = unpack(&archive, &stage).await;
    assert!(validate(&inventory).unwrap().is_some());
    let clone = || {
        serde_json::from_value::<ArchiveInventory>(serde_json::to_value(&inventory).unwrap())
            .unwrap()
    };
    let mut missing_requirement = clone();
    missing_requirement
        .requires
        .retain(|name| name != REQUIREMENT);
    assert!(validate(&missing_requirement).is_err());
    let mut no_dependencies = clone();
    no_dependencies.extensions.insert(
        REQUIREMENT.into(),
        serde_json::json!({"disks": [], "memory": []}),
    );
    assert!(validate(&no_dependencies).is_err());
    let mut duplicate = clone();
    let mut deps = validate(&duplicate).unwrap().unwrap();
    deps.memory.push(deps.memory[0].clone());
    duplicate
        .extensions
        .insert(REQUIREMENT.into(), serde_json::to_value(&deps).unwrap());
    assert!(validate(&duplicate).is_err());
    for kind in ["snapshot-descriptor", "checkpoint-root", "image-object"] {
        let mut wrong_kind = clone();
        wrong_kind
            .entries
            .iter_mut()
            .find(|entry| !entry.included)
            .unwrap()
            .kind = kind.into();
        assert!(validate(&wrong_kind).is_err());
    }
    let mut wrong_owner = clone();
    wrong_owner
        .entries
        .iter_mut()
        .find(|entry| !entry.included)
        .unwrap()
        .owner_snapshot = Some(base.id().to_string());
    assert!(validate(&wrong_owner).is_err());
    let mut undeclared = clone();
    undeclared
        .entries
        .iter_mut()
        .find(|entry| entry.kind == "checkpoint-root")
        .unwrap()
        .included = false;
    assert!(validate(&undeclared).is_err());

    // An inventory can describe an existing base object that the target does not reference.
    // Structural inventory validation alone is insufficient: resolve must check the target map.
    let mut unreferenced = clone();
    let extra = memory_objects(&base)
        .unwrap()
        .difference(&memory_objects(&target).unwrap())
        .next()
        .unwrap()
        .clone();
    let mut deps = validate(&unreferenced).unwrap().unwrap();
    deps.memory.push(extra.clone());
    deps.memory.sort();
    unreferenced
        .extensions
        .insert(REQUIREMENT.into(), serde_json::to_value(&deps).unwrap());
    let mut entry = serde_json::from_value::<ArchiveEntry>(
        serde_json::to_value(
            unreferenced
                .entries
                .iter()
                .find(|entry| !entry.included)
                .unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    entry.path = memory_archive_path(target.id().as_str(), &extra);
    unreferenced.entries.push(entry);
    assert!(
        resolve(
            &local,
            &unreferenced,
            &stage,
            &stage.join("cache"),
            Some(base.path().to_str().unwrap())
        )
        .await
        .is_err()
    );
    assert!(!local.snapshots_dir().join(target.id().as_str()).exists());

    let truncated = temp.path().join("truncated.msb");
    let bytes = std::fs::read(&archive).unwrap();
    std::fs::write(&truncated, &bytes[..bytes.len() / 2]).unwrap();
    assert!(
        load_snapshot_with_base(
            &local,
            &truncated,
            None,
            Some(base.path().to_str().unwrap())
        )
        .await
        .is_err()
    );
    assert!(!local.snapshots_dir().join(target.id().as_str()).exists());
}

#[tokio::test]
async fn standalone_base_archive_resolves_ram_but_dependent_base_archive_is_refused() {
    let temp = tempfile::tempdir().unwrap();
    let local = LocalBackend::builder()
        .home(temp.path().join("home"))
        .build()
        .await
        .unwrap();
    let base = fixture(&local, &temp.path().join("base"), 1, None, false).await;
    let target = fixture(&local, &temp.path().join("target"), 4, None, false).await;
    let base_archive = temp.path().join("base.msb");
    save_snapshot(
        &local,
        base.path().to_str().unwrap(),
        &base_archive,
        SaveOpts::default(),
    )
    .await
    .unwrap();
    let delta = temp.path().join("delta.msb");
    save_snapshot(
        &local,
        target.path().to_str().unwrap(),
        &delta,
        SaveOpts {
            since: Some(base_archive.to_string_lossy().into_owned()),
            ..Default::default()
        },
    )
    .await
    .unwrap();
    assert!(open_base(&local, delta.to_str().unwrap()).await.is_err());
    let loaded =
        load_snapshot_with_base(&local, &delta, None, Some(base_archive.to_str().unwrap()))
            .await
            .unwrap();
    assert_ram(loaded.path(), 4);
    let child = temp.path().join("child");
    assert!(
        materialize_archive_for_child_with_base(
            &local,
            &delta,
            &child,
            false,
            Some(base_archive.to_str().unwrap()),
            &Default::default(),
        )
        .await
        .unwrap()
        .checkpoint_restore
        .is_some()
    );
}
