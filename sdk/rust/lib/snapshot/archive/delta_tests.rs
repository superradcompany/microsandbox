//! Archive-level fixtures exercise transport and staging, not hypervisor execution codecs.

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
