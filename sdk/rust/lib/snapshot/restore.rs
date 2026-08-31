//! Child-owned materialization for resumable snapshot restore.

use std::path::{Path, PathBuf};

use microsandbox_image::checkpoint::{CheckpointClosure, ObjectId};
use microsandbox_runtime::launch::{CheckpointRestoreConfig, RootfsUpperLayerConfig};

use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};

use super::create::{copy_checkpoint_file, materialize_checkpoint_closure};

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
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Copy one validated installed closure into child staging and create its private disk successor.
pub(crate) async fn materialize_checkpoint_for_child(
    source: &CheckpointRestoreConfig,
    child_stage: &Path,
) -> MicrosandboxResult<CheckpointChildMaterialization> {
    let expected = ObjectId::new(&source.checkpoint_root)
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let source_closure = CheckpointClosure::open(&source.closure, Some(&expected))
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    if source_closure.checkpoint().checkpoint_id != source.checkpoint_id {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "checkpoint restore source has another identity".into(),
        ));
    }
    if source_closure.disks().len() != 1 {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(
                "resumable restore currently requires exactly one managed root disk generation"
                    .into(),
            ),
        ));
    }

    tokio::fs::create_dir_all(child_stage).await?;
    let closure_destination = child_stage.join(CHILD_CHECKPOINT_DIRECTORY);
    let source_path = source.closure.clone();
    let destination_for_copy = closure_destination.clone();
    tokio::task::spawn_blocking(move || {
        materialize_checkpoint_closure(&source_path, &destination_for_copy)
    })
    .await
    .map_err(|error| MicrosandboxError::Custom(format!("checkpoint child copy task: {error}")))??;

    materialize_checkpoint_child_state(
        &closure_destination,
        &source.checkpoint_root,
        &source.checkpoint_id,
        child_stage,
    )
    .await
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
) -> MicrosandboxResult<CheckpointChildMaterialization> {
    let expected = ObjectId::new(checkpoint_root)
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    let child_closure = CheckpointClosure::open(closure_destination, Some(&expected))
        .map_err(|error| MicrosandboxError::SnapshotIntegrity(error.to_string()))?;
    if child_closure.checkpoint().checkpoint_id != checkpoint_id {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "checkpoint restore source has another identity".into(),
        ));
    }
    if child_closure.disks().len() != 1 {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(
                "resumable restore currently requires exactly one managed root disk generation"
                    .into(),
            ),
        ));
    }
    let disk = &child_closure.disks()[0];
    let mut upper_layers = Vec::with_capacity(disk.layers.len() + 1);
    for (index, layer) in disk.layers.iter().enumerate() {
        let target = checkpoint_layer_target(child_stage, index, &layer.format)?;
        let source_layer = child_closure.disk_layer_path(layer);
        let source_for_copy = source_layer.clone();
        let target_for_copy = target.clone();
        tokio::task::spawn_blocking(move || {
            copy_checkpoint_file(&source_for_copy, &target_for_copy)
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

    let sealed_head = upper_layers.last().ok_or_else(|| {
        MicrosandboxError::SnapshotIntegrity("checkpoint disk closure is empty".into())
    })?;
    let virtual_size = disk
        .layers
        .last()
        .map(|layer| layer.virtual_size)
        .ok_or_else(|| {
            MicrosandboxError::SnapshotIntegrity("checkpoint disk closure is empty".into())
        })?;
    let writable_head = child_stage.join(format!(
        "upper-restore-{:016x}.qcow2",
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
    upper_layers.push(RootfsUpperLayerConfig {
        path: writable_head,
        format: "qcow2".into(),
    });

    Ok(CheckpointChildMaterialization {
        restore: CheckpointRestoreConfig {
            closure: closure_destination.to_path_buf(),
            checkpoint_root: checkpoint_root.to_string(),
            checkpoint_id: checkpoint_id.to_string(),
        },
        upper_layers,
    })
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn checkpoint_layer_target(
    child_stage: &Path,
    index: usize,
    format: &str,
) -> MicrosandboxResult<PathBuf> {
    match (index, format) {
        (0, "raw" | "qcow2") => Ok(child_stage.join("upper.ext4")),
        (_, "qcow2") => Ok(child_stage.join(format!("upper-sealed-{index:03}.qcow2"))),
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
        let layer_integrity = sparse_file_integrity(&source_layer).unwrap();
        let disk = DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: "vol_test".into(),
            generation: 1,
            layers: vec![DiskLayerRef {
                layer_id: "layer_base".into(),
                format: "raw".into(),
                virtual_size: 4 * 1024 * 1024,
                predecessor: None,
                integrity_root: layer_integrity.root,
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
            capture_intent: CaptureIntent::ResumableSnapshot,
            architecture: std::env::consts::ARCH.into(),
            pause_generation: 7,
            execution_state: execution_id,
            memory: memory_id,
            disks: vec![disk_id],
            devices: Vec::new(),
            resources: Vec::new(),
            requires: Vec::new(),
        };
        let checkpoint_bytes = checkpoint.to_canonical_bytes().unwrap();
        let checkpoint_root = ObjectId::from_bytes(&checkpoint_bytes).unwrap();
        std::fs::write(source.join("checkpoint.json"), checkpoint_bytes).unwrap();
        let restore = CheckpointRestoreConfig {
            closure: source.clone(),
            checkpoint_root: checkpoint_root.to_string(),
            checkpoint_id: checkpoint.checkpoint_id,
        };
        let child = temp.path().join("child");

        let materialized = materialize_checkpoint_for_child(&restore, &child)
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
