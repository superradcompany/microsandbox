//! Exact physical-prefix dependencies for explicitly incremental disk exports.

use microsandbox_image::checkpoint::{DiskLayerExportPlan, DiskLayerRef};
use microsandbox_image::snapshot::{DiskLayer, Manifest};

use super::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const REQUIREMENT: &str = "msb-disk-layer-dependencies-v1";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "layer",
    rename_all = "kebab-case",
    deny_unknown_fields
)]
enum LayerIdentity {
    File(DiskLayer),
    Checkpoint(DiskLayerRef),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredLayer {
    path: String,
    identity: LayerIdentity,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct DiskDependencies {
    required: Vec<RequiredLayer>,
}

struct PhysicalLayer {
    required: RequiredLayer,
    source: PathBuf,
}

struct BaseSnapshot {
    snapshot: Snapshot,
    // Keep archive staging alive until all required layers have been copied to the destination.
    _stage: Option<tempfile::TempDir>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn selection(
    local: &LocalBackend,
    head: &Snapshot,
    opts: &SaveOpts,
) -> MicrosandboxResult<Option<DiskDependencies>> {
    if opts.since.is_none() && opts.last_layers.is_none() {
        return Ok(None);
    }
    if opts.with_parents || (opts.since.is_some() && opts.last_layers.is_some()) {
        return Err(MicrosandboxError::InvalidConfig(
            "disk-layer export takes either since or last_layers, without with_parents".into(),
        ));
    }
    let layers = physical_layers(head.manifest(), head.path())?;
    let plan = if let Some(base) = &opts.since {
        let base = open_base(local, base).await?;
        let baseline = physical_layers(base.snapshot.manifest(), base.snapshot.path())?;
        DiskLayerExportPlan::since(
            &layers
                .iter()
                .map(|layer| &layer.required.identity)
                .collect::<Vec<_>>(),
            &baseline
                .iter()
                .map(|layer| &layer.required.identity)
                .collect::<Vec<_>>(),
        )
    } else {
        DiskLayerExportPlan::last(layers.len(), opts.last_layers.expect("selector checked"))
    }
    .map_err(|error| MicrosandboxError::InvalidConfig(error.to_string()))?;
    if plan.is_disk_complete() {
        return Ok(None);
    }
    Ok(Some(DiskDependencies {
        required: layers[plan.required()]
            .iter()
            .map(|layer| layer.required.clone())
            .collect(),
    }))
}

pub(super) fn apply(
    inventory: &mut ArchiveInventory,
    dependencies: &DiskDependencies,
) -> MicrosandboxResult<()> {
    for required in &dependencies.required {
        let entry = inventory
            .entries
            .iter_mut()
            .find(|entry| entry.path == required.path)
            .ok_or_else(|| {
                MicrosandboxError::SnapshotIntegrity(
                    "required disk layer is absent from archive inventory".into(),
                )
            })?;
        entry.included = false;
        entry.encoded_size = 0;
        entry.sparse_ranges.clear();
        entry.transport_integrity = None;
    }
    inventory.completeness = "disk-dependent".into();
    inventory.requires.push(REQUIREMENT.into());
    inventory.requires.sort();
    inventory
        .extensions
        .insert(REQUIREMENT.into(), serde_json::to_value(dependencies)?);
    inventory.limits.entry_count = inventory
        .entries
        .iter()
        .filter(|entry| entry.included)
        .count() as u64;
    inventory.limits.encoded_bytes = inventory
        .entries
        .iter()
        .filter(|entry| entry.included)
        .map(|entry| entry.encoded_size)
        .sum();
    inventory.limits.apparent_bytes = inventory
        .entries
        .iter()
        .filter(|entry| entry.included)
        .map(|entry| entry.apparent_size)
        .sum();
    Ok(())
}

pub(super) fn validate(
    inventory: &ArchiveInventory,
) -> MicrosandboxResult<Option<DiskDependencies>> {
    let extension = inventory.extensions.get(REQUIREMENT);
    let required = inventory
        .requires
        .iter()
        .any(|requirement| requirement == REQUIREMENT);
    if inventory.completeness == "boot-complete" && !required && extension.is_none() {
        if inventory.entries.iter().any(|entry| !entry.included) {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "complete archive cannot omit payloads".into(),
            ));
        }
        return Ok(None);
    }
    if inventory.completeness != "disk-dependent" || !required || extension.is_none() {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "invalid disk dependency capability/completeness binding".into(),
        ));
    }
    let dependencies: DiskDependencies = serde_json::from_value(extension.unwrap().clone())?;
    if dependencies.required.is_empty() || dependencies.required.len() > 256 {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "invalid disk dependency count".into(),
        ));
    }
    let mut paths = HashSet::new();
    for layer in &dependencies.required {
        let entry = inventory
            .entries
            .iter()
            .find(|entry| entry.path == layer.path)
            .ok_or_else(|| {
                MicrosandboxError::SnapshotIntegrity(
                    "disk dependency lacks an inventory entry".into(),
                )
            })?;
        if entry.included
            || !matches!(
                entry.kind.as_str(),
                "file-payload" | "checkpoint-disk-layer"
            )
            || entry.owner_snapshot.as_deref() != Some(inventory.head.as_str())
            || entry.encoded_size != 0
            || !entry.sparse_ranges.is_empty()
            || entry.transport_integrity.is_some()
            || !paths.insert(&layer.path)
        {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "invalid omitted disk-layer binding".into(),
            ));
        }
    }
    if inventory
        .entries
        .iter()
        .filter(|entry| !entry.included)
        .count()
        != paths.len()
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "archive omits a non-disk dependency".into(),
        ));
    }
    Ok(Some(dependencies))
}

/// Resolve only a caller-supplied base; never search ambient directories or qcow backing paths.
pub(super) async fn resolve(
    local: &LocalBackend,
    inventory: &ArchiveInventory,
    snapshots_dir: &Path,
    cache_dir: &Path,
    base: Option<&str>,
) -> MicrosandboxResult<()> {
    let Some(dependencies) = validate(inventory)? else {
        return Ok(());
    };
    let base = base.ok_or_else(|| MicrosandboxError::InvalidConfig(
        "this disk-dependent archive requires an explicit base snapshot or standalone base archive".into(),
    ))?;
    let base = open_base(local, base).await?;
    let available = physical_layers(base.snapshot.manifest(), base.snapshot.path())?;
    if available.len() != dependencies.required.len()
        || available
            .iter()
            .zip(&dependencies.required)
            .any(|(layer, required)| layer.required.identity != required.identity)
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "supplied base is not the exact required physical disk prefix".into(),
        ));
    }
    // Copy into operation-owned staging. Imported artifacts must survive deleting the supplied
    // base and must never inherit a writable hardlink into another sandbox.
    for (source, required) in available.iter().zip(&dependencies.required) {
        let target = inventory_entry_target(&required.path, snapshots_dir, cache_dir)?;
        if target.exists() {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "dependency collides with an extracted member".into(),
            ));
        }
        if let Some(parent) = target.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let source = source.source.clone();
        tokio::task::spawn_blocking(move || microsandbox_utils::copy::fast_copy(&source, &target))
            .await
            .map_err(|error| MicrosandboxError::Runtime(format!("base layer copy: {error}")))??;
    }
    let artifact = snapshots_dir.join(&inventory.head);
    let manifest =
        Manifest::from_bytes(&tokio::fs::read(artifact.join(DESCRIPTOR_FILENAME)).await?)
            .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let target = physical_layers(&manifest, &artifact)?;
    if target.len() < dependencies.required.len()
        || target
            .iter()
            .zip(&dependencies.required)
            .any(|(layer, required)| &layer.required != required)
    {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "dependency list is not the target descriptor's exact disk prefix".into(),
        ));
    }
    Ok(())
}

fn physical_layers(
    manifest: &Manifest,
    directory: &Path,
) -> MicrosandboxResult<Vec<PhysicalLayer>> {
    match &manifest.state {
        SnapshotState::File(file) => file
            .layers
            .iter()
            .map(|layer| {
                Ok(PhysicalLayer {
                    required: RequiredLayer {
                        path: portable_archive_path(&file.layer_path(layer))?,
                        identity: LayerIdentity::File(layer.clone()),
                    },
                    source: directory.join(file.layer_path(layer)),
                })
            })
            .collect(),
        SnapshotState::Checkpoint(state) => {
            let root = directory.join(CHECKPOINT_DIRECTORY);
            let expected = ObjectId::new(&state.checkpoint_root)
                .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
            let closure = CheckpointClosure::open_portable(&root, Some(&expected))
                .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
            if closure.disks().len() != 1 {
                return Err(MicrosandboxError::InvalidConfig(
                    "disk-layer selection requires exactly one checkpoint disk".into(),
                ));
            }
            Ok(closure.disks()[0]
                .layers
                .iter()
                .map(|layer| PhysicalLayer {
                    required: RequiredLayer {
                        path: format!(
                            "checkpoints/{}/layers/{}.{}",
                            manifest.snapshot_id, layer.layer_id, layer.format
                        ),
                        identity: LayerIdentity::Checkpoint(layer.clone()),
                    },
                    source: closure.disk_layer_path(layer),
                })
                .collect())
        }
    }
}

async fn open_base(local: &LocalBackend, input: &str) -> MicrosandboxResult<BaseSnapshot> {
    let path = Path::new(input);
    if !path.is_file() {
        let snapshot = store::open_snapshot(local, input).await?;
        snapshot.verify().await?;
        return Ok(BaseSnapshot {
            snapshot,
            _stage: None,
        });
    }
    let stage = tempfile::tempdir()?;
    let snapshots_dir = stage.path().join("snapshots");
    let cache_dir = stage.path().join("cache");
    tokio::fs::create_dir_all(&snapshots_dir).await?;
    tokio::fs::create_dir_all(&cache_dir).await?;
    let mut reader = BufReader::new(tokio::fs::File::open(path).await?);
    let compressed = reader
        .fill_buf()
        .await?
        .starts_with(&[0x28, 0xb5, 0x2f, 0xfd]);
    let unpacked = if compressed {
        Box::pin(unpack_archive(
            ZstdDecoder::new(reader),
            &snapshots_dir,
            &cache_dir,
        ))
        .await?
    } else {
        Box::pin(unpack_archive(reader, &snapshots_dir, &cache_dir)).await?
    };
    if let Some(inventory) = &unpacked.inventory {
        if validate(inventory)?.is_some() {
            return Err(MicrosandboxError::InvalidConfig("the supplied base archive must be standalone; load dependent bases explicitly first".into()));
        }
        materialize_inventory_layers(inventory, &snapshots_dir).await?;
    } else {
        super::super::migration::normalize_staged(local.db().await?, &unpacked.manifest_dirs)
            .await?;
    }
    let imported = verify_imported_snapshots(local, &unpacked.manifest_dirs).await?;
    let head = match unpacked.head {
        Some(head) => imported
            .iter()
            .position(|snapshot| snapshot.id().as_str() == head)
            .ok_or_else(|| {
                MicrosandboxError::SnapshotIntegrity("base archive head is missing".into())
            })?,
        None => select_head_snapshot(&imported)?,
    };
    if let Some(inventory) = &unpacked.inventory {
        validate_inventory_snapshot_bindings(inventory, &imported)?;
    }
    Ok(BaseSnapshot {
        snapshot: imported[head].clone(),
        _stage: Some(stage),
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_image::snapshot::{
        DiskLayerId, FileSnapshotState, ImageRef, LayerFileKind, LayerPayload, SnapshotCapture,
        SnapshotConsistency, SnapshotFormat, SnapshotId, SnapshotRootDisk, SnapshotScope,
    };

    #[tokio::test]
    async fn delta_load_and_direct_restore_require_exact_base_and_own_their_closure() {
        let temp = tempfile::tempdir().unwrap();
        let local = LocalBackend::builder()
            .home(temp.path().join("home"))
            .build()
            .await
            .unwrap();
        let base_dir = temp.path().join("base");
        let head_dir = temp.path().join("head");
        tokio::fs::create_dir_all(base_dir.join("layers"))
            .await
            .unwrap();
        tokio::fs::create_dir_all(head_dir.join("layers"))
            .await
            .unwrap();
        let base_layer = DiskLayer {
            layer_id: DiskLayerId::new("layer_00000000000000000000000000000001").unwrap(),
            format: SnapshotFormat::Raw,
            virtual_size: 65536,
            backing: None,
            payload: LayerPayload {
                file_kind: LayerFileKind::Regular,
                integrity: None,
            },
        };
        let top = DiskLayer {
            layer_id: DiskLayerId::new("layer_00000000000000000000000000000002").unwrap(),
            format: SnapshotFormat::Qcow2,
            virtual_size: 65536,
            backing: Some(base_layer.layer_id.clone()),
            payload: base_layer.payload.clone(),
        };
        let descriptor = |id: &str, layers: Vec<DiskLayer>| Manifest {
            schema: "microsandbox.snapshot/1".into(),
            snapshot_id: SnapshotId::new(id).unwrap(),
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
                created_at: "2026-09-05T00:00:00Z".into(),
                source_lineage: None,
                source_checkpoint: None,
                consistency: SnapshotConsistency::CrashConsistent,
            },
            image: ImageRef {
                reference: "docker.io/library/alpine:3.20".into(),
                manifest_digest: format!("sha256:{}", "0".repeat(64)),
            },
            parent: None,
            extensions: BTreeMap::new(),
            requires: vec![],
        };
        let base = descriptor(
            "snap_00000000000000000000000000000001",
            vec![base_layer.clone()],
        );
        let head = descriptor(
            "snap_00000000000000000000000000000002",
            vec![base_layer.clone(), top.clone()],
        );
        let base_path =
            microsandbox_image::snapshot::layer_path(&base_layer.layer_id, base_layer.format);
        let top_path = microsandbox_image::snapshot::layer_path(&top.layer_id, top.format);
        std::fs::write(base_dir.join(&base_path), vec![91u8; 65536]).unwrap();
        std::fs::copy(base_dir.join(&base_path), head_dir.join(&base_path)).unwrap();
        microsandbox_image::checkpoint::create_qcow2_overlay(
            &head_dir.join(top_path),
            65536,
            &head_dir.join(&base_path),
            "raw",
        )
        .await
        .unwrap();
        std::fs::write(
            base_dir.join(DESCRIPTOR_FILENAME),
            base.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        std::fs::write(
            head_dir.join(DESCRIPTOR_FILENAME),
            head.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        let base_name = base_dir.to_str().unwrap();
        let head_name = head_dir.to_str().unwrap();
        let archive = temp.path().join("delta.tar.zst");
        save_snapshot(
            &local,
            head_name,
            &archive,
            SaveOpts {
                since: Some(base_name.into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert!(load_snapshot(&local, &archive, None).await.is_err());
        assert!(
            load_snapshot_with_base(&local, &archive, None, Some(head_name))
                .await
                .is_err()
        );
        let loaded = load_snapshot_with_base(&local, &archive, None, Some(base_name))
            .await
            .unwrap();
        assert!(loaded.path().join(&base_path).exists());
        let child = temp.path().join("child");
        let result = materialize_archive_for_child_with_base(
            &local,
            &archive,
            &child,
            false,
            Some(base_name),
        )
        .await
        .unwrap();
        assert_eq!(result.upper_layers.len(), 3);
        let base_archive = temp.path().join("base.tar");
        save_snapshot(
            &local,
            base_name,
            &base_archive,
            SaveOpts {
                plain_tar: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let last = temp.path().join("last.tar");
        save_snapshot(
            &local,
            head_name,
            &last,
            SaveOpts {
                last_layers: Some(1),
                plain_tar: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let other_dest = temp.path().join("imported");
        load_snapshot_with_base(
            &local,
            &last,
            Some(&other_dest),
            Some(base_archive.to_str().unwrap()),
        )
        .await
        .unwrap();
        std::fs::remove_dir_all(&base_dir).unwrap();
        assert_eq!(
            std::fs::read(loaded.path().join(&base_path)).unwrap(),
            vec![91u8; 65536]
        );
        assert!(result.upper_layers.iter().all(|layer| layer.path.exists()));
        for count in [0, 3] {
            assert!(
                save_snapshot(
                    &local,
                    head_name,
                    &temp.path().join("invalid.tar"),
                    SaveOpts {
                        last_layers: Some(count),
                        ..Default::default()
                    }
                )
                .await
                .is_err()
            );
        }
        // An intact head must not hide a corrupt recorded ancestor in a file-state chain.
        let mut recorded = head.clone();
        let SnapshotState::File(file) = &mut recorded.state else {
            unreachable!()
        };
        file.layers[0].payload.integrity = Some(
            super::super::super::verify::compute_merkle_integrity(&head_dir.join(&base_path))
                .await
                .unwrap(),
        );
        std::fs::write(
            head_dir.join(DESCRIPTOR_FILENAME),
            recorded.to_canonical_bytes().unwrap(),
        )
        .unwrap();
        let snapshot = store::open_snapshot(&local, head_name).await.unwrap();
        snapshot.verify().await.unwrap();
        std::fs::write(head_dir.join(&base_path), vec![92u8; 65536]).unwrap();
        assert!(snapshot.verify().await.is_err());
    }
}
