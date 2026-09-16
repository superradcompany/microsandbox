//! Local backend: Child-owned materialization for full snapshot restore.

mod additional_disks;
mod owned;

pub(crate) use additional_disks::{apply_additional_disks, materialize_additional_disks};
pub(crate) use owned::materialize_owned_volumes;

use std::path::{Path, PathBuf};

use microsandbox_image::checkpoint::{CheckpointClosure, ObjectId};
use microsandbox_image::snapshot::SnapshotRootDisk;
use microsandbox_runtime::launch::{CheckpointRestoreConfig, RootfsUpperLayerConfig};

use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

use super::create::{copy_checkpoint_file, stage_checkpoint_closure};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CHILD_CHECKPOINT_DIRECTORY: &str = ".checkpoint-restore";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Child-owned construction state prepared from one installed checkpoint snapshot.
pub(crate) struct CheckpointChildMaterialization {
    /// Eager memory/device restore source consumed during the first launch.
    pub(crate) restore: CheckpointRestoreConfig,
    /// Complete root chain ending in a fresh child-private writable head.
    pub(crate) upper_layers: Vec<RootfsUpperLayerConfig>,
    /// Independent managed-volume images, keyed by their captured guest mount paths.
    pub(crate) disk_mounts: Vec<microsandbox_types::VolumeMount>,
}

/// Child-owned disk state materialized without restoring checkpoint execution.
pub(crate) struct CheckpointDiskMaterialization {
    /// Complete root chain ending in a fresh child-private writable head.
    pub(crate) upper_layers: Vec<RootfsUpperLayerConfig>,
    pub(crate) disk_mounts: Vec<microsandbox_types::VolumeMount>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Copy one validated installed closure into child staging and create its private disk successor.
pub(crate) async fn materialize_checkpoint_for_child(
    source: &CheckpointRestoreConfig,
    child_stage: &Path,
    root_disk: &SnapshotRootDisk,
    choices: &crate::sandbox::restore_resources::RestoreResources,
) -> MicrosandboxResult<CheckpointChildMaterialization> {
    // Validate once after obtaining child-owned files. Validating the source first neither
    // protects against a later source mutation nor substitutes for validation of the child.
    tokio::fs::create_dir_all(child_stage).await?;
    let closure_destination = child_stage.join(CHILD_CHECKPOINT_DIRECTORY);
    let source_path = source.closure.clone();
    let destination_for_copy = closure_destination.clone();
    tokio::task::spawn_blocking(move || {
        stage_checkpoint_closure(&source_path, &destination_for_copy)
    })
    .await
    .map_err(|error| MicrosandboxError::Custom(format!("checkpoint child copy task: {error}")))??;

    materialize_checkpoint_child_state(
        &closure_destination,
        &source.checkpoint_root,
        &source.checkpoint_id,
        child_stage,
        root_disk,
        choices,
    )
    .await
}

/// Materialize only the disk closure from an installed full snapshot.
///
/// The source checkpoint is opened portably because memory and execution compatibility are
/// irrelevant to a cold boot. Only referenced disk layers are copied into child staging.
pub(crate) async fn materialize_checkpoint_disk_for_child(
    source: &CheckpointRestoreConfig,
    child_stage: &Path,
    root_disk: &SnapshotRootDisk,
    choices: &crate::sandbox::restore_resources::RestoreResources,
) -> MicrosandboxResult<CheckpointDiskMaterialization> {
    let expected = ObjectId::new(&source.checkpoint_root)
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let source_closure = CheckpointClosure::open_portable(&source.closure, Some(&expected))
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    validate_checkpoint_identity(&source_closure, &source.checkpoint_id)?;
    validate_root_disk_closure(&source_closure, root_disk, true)?;
    tokio::fs::create_dir_all(child_stage).await?;
    let upper_layers =
        materialize_checkpoint_disk_layers(&source_closure, child_stage, root_disk).await?;
    let disk_mounts =
        materialize_closure_disks(&source_closure, child_stage, root_disk, choices).await?;
    Ok(CheckpointDiskMaterialization {
        upper_layers,
        disk_mounts,
    })
}

/// Adopt an already child-owned closure and create its private disk successor.
///
/// Direct archive restore extracts the closure inside child staging, then renames it to the final
/// eager-restore location. Keeping disk-chain construction separate avoids copying the closure a
/// second time.
pub(crate) async fn materialize_checkpoint_child_state(
    closure_destination: &Path,
    checkpoint_root: &str,
    checkpoint_id: &str,
    child_stage: &Path,
    root_disk: &SnapshotRootDisk,
    choices: &crate::sandbox::restore_resources::RestoreResources,
) -> MicrosandboxResult<CheckpointChildMaterialization> {
    let expected = ObjectId::new(checkpoint_root)
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let child_closure = CheckpointClosure::open(closure_destination, Some(&expected))
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    validate_checkpoint_identity(&child_closure, checkpoint_id)?;
    validate_root_disk_closure(&child_closure, root_disk, false)?;
    let upper_layers =
        materialize_checkpoint_disk_layers(&child_closure, child_stage, root_disk).await?;
    let disk_mounts =
        materialize_closure_disks(&child_closure, child_stage, root_disk, choices).await?;

    Ok(CheckpointChildMaterialization {
        restore: CheckpointRestoreConfig {
            memory_descriptor: false,
            network_gateway_mac: microsandbox_runtime::checkpoint::captured_gateway_mac(
                &child_closure.checkpoint().resources,
            )
            .map_err(MicrosandboxError::SnapshotIntegrity)?,
            external_mount_policy: Default::default(),
            external_mounts: Vec::new(),
            unavailable_disks: Default::default(),
            local_branch: false,
            forked: false,
            closure: closure_destination.to_path_buf(),
            checkpoint_root: checkpoint_root.to_string(),
            checkpoint_id: checkpoint_id.to_string(),
        },
        upper_layers,
        disk_mounts,
    })
}

/// Adopt an extracted checkpoint closure only long enough to materialize its disk state.
pub(crate) async fn materialize_checkpoint_child_disk_state(
    closure: &Path,
    checkpoint_root: &str,
    checkpoint_id: &str,
    child_stage: &Path,
    root_disk: &SnapshotRootDisk,
    choices: &crate::sandbox::restore_resources::RestoreResources,
) -> MicrosandboxResult<CheckpointDiskMaterialization> {
    let expected = ObjectId::new(checkpoint_root)
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let child_closure = CheckpointClosure::open_portable(closure, Some(&expected))
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    validate_checkpoint_identity(&child_closure, checkpoint_id)?;
    validate_root_disk_closure(&child_closure, root_disk, true)?;
    let upper_layers =
        materialize_checkpoint_disk_layers(&child_closure, child_stage, root_disk).await?;
    let disk_mounts =
        materialize_closure_disks(&child_closure, child_stage, root_disk, choices).await?;
    Ok(CheckpointDiskMaterialization {
        upper_layers,
        disk_mounts,
    })
}

/// Materialize installed file-snapshot layers into child-owned storage and add a writable head.
pub(crate) async fn materialize_file_snapshot_for_child(
    sources: &[RootfsUpperLayerConfig],
    virtual_size: u64,
    child_stage: &Path,
    root_disk: &SnapshotRootDisk,
) -> MicrosandboxResult<CheckpointDiskMaterialization> {
    if sources.is_empty() || matches!(root_disk, SnapshotRootDisk::Tmpfs { .. }) {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "file snapshot has no restorable disk closure".into(),
        ));
    }
    tokio::fs::create_dir_all(child_stage).await?;
    let mut layers = Vec::with_capacity(sources.len() + 1);
    for (index, source) in sources.iter().enumerate() {
        let target = checkpoint_layer_target(child_stage, root_disk, index, &source.format)?;
        let source_path = source.path.clone();
        let target_for_copy = target.clone();
        let predecessor = layers
            .last()
            .map(|layer: &RootfsUpperLayerConfig| layer.path.clone());
        tokio::task::spawn_blocking(move || {
            copy_child_disk_layer(&source_path, &target_for_copy, predecessor.as_deref())
        })
        .await
        .map_err(|error| {
            MicrosandboxError::Custom(format!("snapshot layer copy task: {error}"))
        })??;
        layers.push(RootfsUpperLayerConfig {
            path: target,
            format: source.format.clone(),
        });
    }
    append_private_writable_head(&mut layers, virtual_size, child_stage, root_disk).await?;
    Ok(CheckpointDiskMaterialization {
        upper_layers: layers,
        disk_mounts: Vec::new(),
    })
}

/// Adopt a local handoff using independent directory entries, without duplicating disk bytes.
pub(crate) async fn adopt_local_branch_for_child(
    sources: &[RootfsUpperLayerConfig],
    virtual_size: u64,
    child_stage: &Path,
    root_disk: &SnapshotRootDisk,
) -> MicrosandboxResult<Vec<RootfsUpperLayerConfig>> {
    let directory = child_stage.join(".branch-restore").join("layers");
    if sources.is_empty() || matches!(root_disk, SnapshotRootDisk::Tmpfs { .. }) {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "local branch has no root layers".into(),
        ));
    }
    for source in sources {
        if source.path.parent() != Some(directory.as_path())
            || !std::fs::symlink_metadata(&source.path)?.is_file()
        {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "local branch layer is not child-owned".into(),
            ));
        }
    }
    let backing_names = sources
        .iter()
        .skip(1)
        .map(|layer| microsandbox_image::checkpoint::qcow2_backing_basename(&layer.path))
        .collect::<std::io::Result<Vec<_>>>()?;
    let mut layers: Vec<RootfsUpperLayerConfig> = Vec::with_capacity(sources.len() + 1);
    for (index, source) in sources.iter().enumerate() {
        let canonical = child_stage.join(source.path.file_name().expect("confined layer"));
        let mut target = if index == 0 {
            // Preserve the ordinary configured base for later cold startup.
            checkpoint_layer_target(child_stage, root_disk, 0, &source.format)?
        } else if let Some(name) = backing_names.get(index) {
            child_stage.join(name)
        } else {
            canonical.clone()
        };
        if target.exists() || layers.iter().any(|layer| layer.path == target) {
            target = canonical;
        }
        if target.exists() || layers.iter().any(|layer| layer.path == target) {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "local branch layer name conflicts".into(),
            ));
        }
        let previous = layers.last().map(|layer| layer.path.clone());
        let unchanged_header = previous.as_ref().is_none_or(|path| {
            path.file_name().and_then(|name| name.to_str())
                == Some(backing_names[index - 1].as_str())
        });
        if unchanged_header {
            tokio::fs::hard_link(&source.path, &target).await?;
        } else {
            // Old/imported names may conflict with the fixed cold-boot base or another owned
            // filename. Relocate only that layer; never mutate a shared captured inode.
            let source_path = source.path.clone();
            let target_path = target.clone();
            tokio::task::spawn_blocking(move || {
                copy_child_disk_layer(&source_path, &target_path, previous.as_deref())
            })
            .await
            .map_err(|error| {
                MicrosandboxError::Custom(format!("local disk relocation task: {error}"))
            })??;
        }
        layers.push(RootfsUpperLayerConfig {
            path: target,
            format: source.format.clone(),
        });
    }
    // Exactly one owned name per chain layer remains after the consumed closure is removed.
    // This retains compaction/growth's basename and reclamation contracts.
    append_private_writable_head(&mut layers, virtual_size, child_stage, root_disk).await?;
    Ok(layers)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

pub(crate) fn root_device(root: &SnapshotRootDisk) -> Option<&'static str> {
    match root {
        SnapshotRootDisk::Managed => Some("vdb"),
        SnapshotRootDisk::Flat => Some("vda"),
        SnapshotRootDisk::Tmpfs { .. } => None,
    }
}

async fn materialize_closure_disks(
    closure: &CheckpointClosure,
    child: &Path,
    root: &SnapshotRootDisk,
    choices: &crate::sandbox::restore_resources::RestoreResources,
) -> MicrosandboxResult<Vec<microsandbox_types::VolumeMount>> {
    let source = closure.root();
    let mut mounts = owned::materialize_owned_volumes(
        &closure.checkpoint().owned_volumes,
        source,
        child,
        choices,
    )
    .await?;
    mounts.extend(
        additional_disks::materialize_additional_disks(
            closure.disks(),
            &closure.checkpoint().resources,
            source,
            child,
            root_device(root),
            choices,
        )
        .await?,
    );
    Ok(mounts)
}

fn validate_checkpoint_identity(
    closure: &CheckpointClosure,
    checkpoint_id: &str,
) -> MicrosandboxResult<()> {
    if closure.checkpoint().checkpoint_id != checkpoint_id {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "checkpoint restore source has another identity".into(),
        ));
    }
    Ok(())
}

fn validate_root_disk_closure(
    closure: &CheckpointClosure,
    root_disk: &SnapshotRootDisk,
    disk_only: bool,
) -> MicrosandboxResult<()> {
    let expected_device = match root_disk {
        SnapshotRootDisk::Managed => Some("vdb"),
        SnapshotRootDisk::Flat => Some("vda"),
        SnapshotRootDisk::Tmpfs { .. } => None,
    };
    if disk_only && expected_device.is_none() {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(
                "disk-only restore is unavailable for a tmpfs root because its writable state is memory-resident"
                    .into(),
            ),
        ));
    }
    let roots = closure
        .disks()
        .iter()
        .filter(|disk| matches!(disk.device_id.as_str(), "vda" | "vdb"))
        .collect::<Vec<_>>();
    match (roots.as_slice(), expected_device) {
        ([], None) => Ok(()),
        ([disk], Some(device)) if disk.device_id == device => Ok(()),
        _ => Err(MicrosandboxError::SnapshotIntegrity(format!(
            "checkpoint disk closure does not match the {:?} root layout",
            root_disk
        ))),
    }
}

async fn materialize_checkpoint_disk_layers(
    closure: &CheckpointClosure,
    child_stage: &Path,
    root_disk: &SnapshotRootDisk,
) -> MicrosandboxResult<Vec<RootfsUpperLayerConfig>> {
    if matches!(root_disk, SnapshotRootDisk::Tmpfs { .. }) {
        return Ok(Vec::new());
    }
    let device_id = root_device(root_disk).expect("tmpfs returned above");
    let disk = closure
        .disks()
        .iter()
        .find(|disk| disk.device_id == device_id)
        .ok_or_else(|| {
            MicrosandboxError::SnapshotIntegrity("missing root disk generation".into())
        })?;
    let mut upper_layers = Vec::with_capacity(disk.layers.len() + 1);
    for (index, layer) in disk.layers.iter().enumerate() {
        let target = checkpoint_layer_target(child_stage, root_disk, index, &layer.format)?;
        let source_layer = closure.disk_layer_path(layer);
        let source_for_copy = source_layer.clone();
        let target_for_copy = target.clone();
        let predecessor = upper_layers
            .last()
            .map(|layer: &RootfsUpperLayerConfig| layer.path.clone());
        tokio::task::spawn_blocking(move || {
            copy_child_disk_layer(&source_for_copy, &target_for_copy, predecessor.as_deref())
        })
        .await
        .map_err(|error| {
            MicrosandboxError::Custom(format!("checkpoint disk copy task: {error}"))
        })??;
        upper_layers.push(RootfsUpperLayerConfig {
            path: target,
            format: layer.format.clone(),
        });
    }

    let virtual_size = disk
        .layers
        .last()
        .map(|layer| layer.virtual_size)
        .ok_or_else(|| {
            MicrosandboxError::SnapshotIntegrity("checkpoint disk closure is empty".into())
        })?;
    append_private_writable_head(&mut upper_layers, virtual_size, child_stage, root_disk).await?;
    Ok(upper_layers)
}

async fn append_private_writable_head(
    layers: &mut Vec<RootfsUpperLayerConfig>,
    virtual_size: u64,
    child_stage: &Path,
    root_disk: &SnapshotRootDisk,
) -> MicrosandboxResult<()> {
    let sealed_head = layers.last().ok_or_else(|| {
        MicrosandboxError::SnapshotIntegrity("snapshot disk closure is empty".into())
    })?;
    let prefix = match root_disk {
        SnapshotRootDisk::Managed => "upper",
        SnapshotRootDisk::Flat => "root",
        SnapshotRootDisk::Tmpfs { .. } => unreachable!("tmpfs returned above"),
    };
    let writable_head = child_stage.join(format!(
        "{prefix}-restore-{:016x}.qcow2",
        rand::random::<u64>()
    ));
    let writable_head_for_create = writable_head.clone();
    let sealed_path = sealed_head.path.clone();
    let sealed_format = sealed_head.format.clone();
    tokio::task::spawn_blocking(move || -> MicrosandboxResult<()> {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(microsandbox_image::checkpoint::create_qcow2_overlay(
            &writable_head_for_create,
            virtual_size,
            &sealed_path,
            &sealed_format,
        ))?;
        Ok(())
    })
    .await
    .map_err(|error| {
        MicrosandboxError::Custom(format!("checkpoint overlay create task: {error}"))
    })??;
    layers.push(RootfsUpperLayerConfig {
        path: writable_head,
        format: "qcow2".into(),
    });
    Ok(())
}

fn copy_child_disk_layer(
    source: &Path,
    target: &Path,
    predecessor: Option<&Path>,
) -> std::io::Result<()> {
    if let Some(predecessor) = predecessor {
        // Only qcow2 layers may have a predecessor. Their relocated header must not write into
        // an inode shared with the source artifact or another restored child.
        microsandbox_utils::copy::fast_copy(source, target)?;
        microsandbox_image::checkpoint::relocate_qcow2_backing(target, predecessor)
    } else {
        copy_checkpoint_file(source, target)
    }
}

fn checkpoint_layer_target(
    child_stage: &Path,
    root_disk: &SnapshotRootDisk,
    index: usize,
    format: &str,
) -> MicrosandboxResult<PathBuf> {
    let prefix = match root_disk {
        SnapshotRootDisk::Managed => "upper",
        SnapshotRootDisk::Flat => "root",
        SnapshotRootDisk::Tmpfs { .. } => unreachable!("tmpfs has no disk layers"),
    };
    match (index, format) {
        (0, "raw") if matches!(root_disk, SnapshotRootDisk::Managed) => {
            Ok(child_stage.join("upper.ext4"))
        }
        (0, "raw") => Ok(child_stage.join("rootfs.raw")),
        (0, "qcow2") => Ok(child_stage.join(format!("{prefix}-sealed-000.qcow2"))),
        (_, "qcow2") => Ok(child_stage.join(format!("{prefix}-sealed-{index:03}.qcow2"))),
        _ => Err(MicrosandboxError::SnapshotIntegrity(format!(
            "checkpoint disk layer {index} uses unsupported format {format:?}"
        ))),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_image::checkpoint::{
        CaptureIntent, CheckpointManifest, ContentRef, DiskGenerationManifest, DiskLayerRef,
        LocalObjectStore, MemoryCaptureMode, MemoryExtent, MemoryExtentContent, MemoryManifest,
        sparse_file_integrity,
    };

    use super::*;

    #[tokio::test]
    async fn local_adoption_preserves_owned_layers_and_cold_boot_base() {
        for (root_disk, base_name) in [
            (SnapshotRootDisk::Managed, "upper.ext4"),
            (SnapshotRootDisk::Flat, "rootfs.raw"),
        ] {
            for overlay_count in [0, 1, 3] {
                let dir = tempfile::tempdir().unwrap();
                let child = dir.path().join("child");
                let layers = child.join(".branch-restore/layers");
                std::fs::create_dir_all(&layers).unwrap();
                let base = layers.join("layer_base.raw");
                std::fs::write(&base, vec![29; 131072]).unwrap();
                let mut sources = vec![RootfsUpperLayerConfig {
                    path: base.clone(),
                    format: "raw".into(),
                }];
                for index in 0..overlay_count {
                    let alias = layers.join(if index == 0 {
                        base_name.into()
                    } else {
                        format!("native-{}.qcow2", index - 1)
                    });
                    let previous = sources.last().unwrap();
                    std::fs::hard_link(&previous.path, &alias).unwrap();
                    let overlay = layers.join(format!("layer_overlay_{index}.qcow2"));
                    microsandbox_image::checkpoint::create_qcow2_overlay(
                        &overlay,
                        131072,
                        &alias,
                        &previous.format,
                    )
                    .await
                    .unwrap();
                    sources.push(RootfsUpperLayerConfig {
                        path: overlay,
                        format: "qcow2".into(),
                    });
                }
                let original = sources
                    .iter()
                    .map(|layer| std::fs::read(&layer.path).unwrap())
                    .collect::<Vec<_>>();
                let result = adopt_local_branch_for_child(&sources, 131072, &child, &root_disk)
                    .await
                    .unwrap();
                assert_eq!(result.len(), sources.len() + 1);
                assert_eq!(result[0].path, child.join(base_name));
                assert_eq!(std::fs::read(&result[0].path).unwrap(), original[0]);
                for ((source, bytes), owned) in sources.iter().zip(original).zip(&result) {
                    assert_eq!(std::fs::read(&source.path).unwrap(), bytes);
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::MetadataExt;
                        assert_eq!(
                            std::fs::metadata(&source.path).unwrap().ino(),
                            std::fs::metadata(&owned.path).unwrap().ino()
                        );
                    }
                }
                let head = &result.last().unwrap().path;
                assert_eq!(head.parent(), Some(child.as_path()));
                // Ordinary completion removes the entire transient closure. Exactly the listed
                // owned chain remains, with no alias names left to defeat later reclamation.
                std::fs::remove_dir_all(child.join(".branch-restore")).unwrap();
                for pair in result.windows(2) {
                    let predecessor =
                        microsandbox_image::checkpoint::qcow2_backing_basename(&pair[1].path)
                            .unwrap();
                    assert_eq!(child.join(predecessor), pair[0].path);
                }
                let restored = dir.path().join("durable-child");
                materialize_file_snapshot_for_child(
                    &result[..result.len() - 1],
                    131072,
                    &restored,
                    &root_disk,
                )
                .await
                .unwrap();
                assert_eq!(
                    std::fs::read(child.join(base_name)).unwrap(),
                    vec![29; 131072]
                );
            }
        }
    }

    #[test]
    fn checkpoint_layer_paths_preserve_root_layout() {
        let child = Path::new("child");
        assert_eq!(
            checkpoint_layer_target(child, &SnapshotRootDisk::Managed, 0, "raw").unwrap(),
            child.join("upper.ext4")
        );
        assert_eq!(
            checkpoint_layer_target(child, &SnapshotRootDisk::Flat, 0, "raw").unwrap(),
            child.join("rootfs.raw")
        );
        assert_eq!(
            checkpoint_layer_target(child, &SnapshotRootDisk::Flat, 1, "qcow2").unwrap(),
            child.join("root-sealed-001.qcow2")
        );
    }

    #[tokio::test]
    async fn child_owns_restore_closure_and_a_private_writable_head() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let store = LocalObjectStore::open(&source).unwrap();
        let memory_bytes = b"restored-memory";
        let memory_object = store.put_bytes(memory_bytes).unwrap();
        let memory = MemoryManifest {
            schema: "microsandbox.memory/1".into(),
            architecture: std::env::consts::ARCH.into(),
            guest_page_size: 4096,
            topology_generation: 1,
            generation: 1,
            capture_mode: MemoryCaptureMode::Full,
            pause_generation: 7,
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

        let layers = source.join("layers");
        std::fs::create_dir(&layers).unwrap();
        let source_layer = layers.join("layer_base.raw");
        let layer_file = std::fs::File::create(&source_layer).unwrap();
        layer_file.set_len(4 * 1024 * 1024).unwrap();
        // Windows cannot clone a fixture while its writable handle remains open.
        drop(layer_file);
        let layer_integrity = sparse_file_integrity(&source_layer).unwrap();
        let disk = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: "vol_test".into(),
            device_id: "vda".into(),
            generation: 1,
            layers: vec![DiskLayerRef {
                file_size: std::fs::metadata(&source_layer).unwrap().len(),
                layer_id: "layer_base".into(),
                format: "raw".into(),
                virtual_size: 4 * 1024 * 1024,
                predecessor: None,
                integrity_root: Some(layer_integrity.root),
            }],
            head: "layer_base".into(),
            pause_generation: 7,
        };
        let disk_id = store
            .put_bytes(&disk.to_canonical_bytes().unwrap())
            .unwrap();
        let checkpoint = CheckpointManifest {
            schema: "microsandbox.checkpoint/1".into(),
            checkpoint_id: "checkpoint_test".into(),
            capture_intent: CaptureIntent::FullSnapshot,
            geometry: microsandbox_image::checkpoint::CheckpointGeometry {
                vcpus: 1,
                max_vcpus: 1,
                memory_mib: 128,
                max_memory_mib: 128,
            },
            architecture: std::env::consts::ARCH.into(),
            pause_generation: 7,
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
        let restore = CheckpointRestoreConfig {
            memory_descriptor: false,
            network_gateway_mac: None,
            external_mount_policy: Default::default(),
            external_mounts: Vec::new(),
            unavailable_disks: Default::default(),
            local_branch: false,
            forked: false,
            closure: source.clone(),
            checkpoint_root: checkpoint_root.to_string(),
            checkpoint_id: checkpoint.checkpoint_id,
        };
        let child = temp.path().join("child");
        let disk_child = temp.path().join("disk-child");

        let disk_materialized = materialize_checkpoint_disk_for_child(
            &restore,
            &disk_child,
            &SnapshotRootDisk::Flat,
            &Default::default(),
        )
        .await
        .unwrap();
        assert_eq!(disk_materialized.upper_layers.len(), 2);
        assert_eq!(
            disk_materialized.upper_layers[0]
                .path
                .file_name()
                .and_then(|value| value.to_str()),
            Some("rootfs.raw")
        );
        assert!(
            disk_materialized.upper_layers[1]
                .path
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("root-restore-")
        );
        assert!(!disk_child.join(CHILD_CHECKPOINT_DIRECTORY).exists());

        let materialized = materialize_checkpoint_for_child(
            &restore,
            &child,
            &SnapshotRootDisk::Flat,
            &Default::default(),
        )
        .await
        .unwrap();
        std::fs::remove_dir_all(source).unwrap();

        assert_eq!(materialized.upper_layers.len(), 2);
        assert_eq!(materialized.upper_layers[0].format, "raw");
        assert_eq!(materialized.upper_layers[1].format, "qcow2");
        assert!(materialized.upper_layers[0].path.exists());
        assert!(materialized.upper_layers[1].path.exists());
        let reopened =
            CheckpointClosure::open(&materialized.restore.closure, Some(&checkpoint_root)).unwrap();
        assert_eq!(reopened.checkpoint().checkpoint_id, "checkpoint_test");
    }
}
