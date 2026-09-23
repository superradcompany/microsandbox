//! Local backend: Private reconstruction of required sandbox-owned backing.

use std::path::Path;

use microsandbox_image::checkpoint::{CompactLayer, DiskGenerationManifest};
use microsandbox_image::snapshot::{OwnedVolumeCapture, OwnedVolumeData};
use microsandbox_runtime::checkpoint::RuntimeOwnedRootLayer;
use microsandbox_types::VolumeMount;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Materialize every owned mount, independently of external-resource inheritance choices.
pub(crate) async fn materialize_owned_volumes(
    volumes: &[OwnedVolumeCapture],
    source: &Path,
    child: &Path,
    choices: &crate::sandbox::restore_resources::RestoreResources,
) -> MicrosandboxResult<Vec<VolumeMount>> {
    microsandbox_image::snapshot::validate_owned_volumes(volumes)?;
    // Check all destinations before starting workers: explicit replacement would silently
    // discard captured state and is never an alternate authorization for owned storage.
    for volume in volumes {
        if microsandbox_types::owned_volume_mount_id(&volume.mount.guest) != volume.mount_id {
            return Err(invalid(
                "owned mount identity differs from its canonical guest path",
            ));
        }
        if choices.mapped.contains(&volume.mount.guest) {
            return Err(invalid(&format!(
                "owned mount {} cannot be replaced by an explicit mapping",
                volume.mount.guest
            )));
        }
    }
    let staging_parent = child
        .parent()
        .ok_or_else(|| invalid("owned storage child has no parent"))?;
    for volume in volumes {
        let directory = child.join("owned-volumes").join(&volume.mount_id);
        match &volume.data {
            OwnedVolumeData::Disk { generation } => {
                let source = source.to_path_buf();
                let parent = staging_parent.to_path_buf();
                let generation = generation.clone();
                let mount_id = volume.mount_id.clone();
                let readonly = volume.mount.options.readonly;
                let staging = tokio::task::spawn_blocking(move || {
                    stage_owned_disk(&source, &parent, &mount_id, &generation, readonly)
                })
                .await
                .map_err(|error| invalid(&format!("owned disk restore worker: {error}")))??;
                // The worker knows only its private synthetic sandbox. Both paths can be
                // relocated without rewriting data or retaining its temporary host path.
                let journal = child.join("runtime/owned-disks").join(&volume.mount_id);
                std::fs::create_dir_all(directory.parent().expect("owned parent"))?;
                std::fs::create_dir_all(journal.parent().expect("journal parent"))?;
                std::fs::rename(
                    staging.path().join("owned-volumes").join(&volume.mount_id),
                    &directory,
                )?;
                std::fs::rename(
                    staging
                        .path()
                        .join("runtime/owned-disks")
                        .join(&volume.mount_id),
                    journal,
                )?;
            }
            OwnedVolumeData::Directory { descriptor, files } => {
                let source = source.join(volume.directory_path());
                let parent = staging_parent.to_path_buf();
                let descriptor = descriptor.clone();
                let files = files.clone();
                let staging = tokio::task::spawn_blocking(
                    move || -> MicrosandboxResult<tempfile::TempDir> {
                        let snapshot =
                            microsandbox_filesystem::OwnedDirectorySnapshot::open_expected(
                                &source,
                                &descriptor.digest,
                            )?;
                        let payloads = snapshot.payloads();
                        if snapshot.descriptor_bytes()?.len() as u64 != descriptor.bytes
                            || payloads.len() != files.len()
                            || payloads.iter().zip(&files).any(|(actual, expected)| {
                                actual.digest != expected.digest || actual.bytes != expected.bytes
                            })
                        {
                            return Err(invalid(
                                "owned namespace descriptor and payload inventory disagree",
                            ));
                        }
                        let staging = tempfile::Builder::new()
                            .prefix(".owned-directory-restore-")
                            .tempdir_in(parent)?;
                        snapshot.materialize(&source, &staging.path().join("data"))?;
                        Ok(staging)
                    },
                )
                .await
                .map_err(|error| invalid(&format!("owned directory restore worker: {error}")))??;
                // A cancelled copy knows only unique staging. Publish while this async poll
                // still holds the caller's sandbox transition and lifecycle guards.
                std::fs::create_dir_all(&directory)?;
                std::fs::rename(staging.path().join("data"), directory.join("data"))?;
            }
        }
    }
    Ok(volumes
        .iter()
        .map(|volume| volume.mount.to_mount())
        .collect())
}

/// Prepare the immutable closure and a private head without touching a named child.
fn stage_owned_disk(
    source: &Path,
    parent: &Path,
    mount_id: &str,
    generation: &DiskGenerationManifest,
    readonly: bool,
) -> MicrosandboxResult<tempfile::TempDir> {
    let stage = tempfile::Builder::new()
        .prefix(".owned-disk-restore-")
        .tempdir_in(parent)?;
    let directory = stage.path().join("owned-volumes").join(mount_id);
    std::fs::create_dir_all(&directory)?;
    let mut layers: Vec<RuntimeOwnedRootLayer> = Vec::with_capacity(generation.layers.len() + 1);
    for (index, layer) in generation.layers.iter().enumerate() {
        let source = source
            .join("layers")
            .join(format!("{}.{}", layer.layer_id, layer.format));
        let target = directory.join(format!("sealed-{index:03}.{}", layer.format));
        // The immutable base can retain its own hard link, exactly like a root restore.
        // Successors need private inodes because relocating a qcow2 header writes to it.
        // No captured layer is ever opened as the child's writable head.
        if index == 0 {
            super::copy_child_disk_layer(&source, &target, None)?;
        } else {
            microsandbox_utils::copy::fast_copy(&source, &target)?;
        }
        if std::fs::metadata(&target)?.len() != layer.file_size {
            return Err(invalid(
                "owned disk length changed during child materialization",
            ));
        }
        if let Some(expected) = &layer.integrity_root
            && microsandbox_image::checkpoint::sparse_file_integrity(&target)?.root != *expected
        {
            return Err(invalid("owned disk changed during child materialization"));
        }
        if let Some(previous) = layers.last() {
            microsandbox_image::checkpoint::relocate_qcow2_backing(&target, &previous.path)?;
        } else if layer.format == "qcow2" {
            microsandbox_image::checkpoint::validate_standalone_qcow2(&std::fs::File::open(
                &target,
            )?)?;
        }
        layers.push(RuntimeOwnedRootLayer {
            path: target,
            format: layer.format.clone(),
        });
    }
    let compact: Vec<_> = layers
        .iter()
        .map(|layer| CompactLayer {
            path: layer.path.clone(),
            qcow2: layer.format == "qcow2",
        })
        .collect();
    let capacities = microsandbox_image::checkpoint::layer_capacities(compact.clone())?;
    if capacities
        .iter()
        .zip(&generation.layers)
        .any(|(actual, layer)| *actual != layer.virtual_size)
    {
        return Err(invalid(
            "owned disk layer capacity differs from its descriptor",
        ));
    }
    let sealed = layers
        .last()
        .ok_or_else(|| invalid("owned disk has no captured layers"))?;
    let size = *capacities
        .last()
        .ok_or_else(|| invalid("owned disk has no capacity"))?;
    let writable = directory.join("writable.qcow2");
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        // Explicit opening refuses undeclared dependencies, even if a qcow2 header
        // contains an ambient host path. The private writable layer is never shared.
        microsandbox_image::checkpoint::validate_compact_chain(&compact).await?;
        microsandbox_image::checkpoint::create_qcow2_overlay(
            &writable,
            size,
            &sealed.path,
            &sealed.format,
        )
        .await
    })?;
    layers.push(RuntimeOwnedRootLayer {
        path: writable,
        format: "qcow2".into(),
    });
    microsandbox_runtime::checkpoint::seed_runtime_owned_disk_chain(
        &stage.path().join("runtime"),
        mount_id,
        &directory.join("disk.raw"),
        &layers,
        readonly,
    )
    .map_err(MicrosandboxError::SnapshotIntegrity)?;
    Ok(stage)
}

fn invalid(message: &str) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(message.into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::MountBuilder;
    use microsandbox_image::checkpoint::{
        DiskLayerRef, create_qcow2_overlay, sparse_file_integrity,
    };
    use microsandbox_image::snapshot::OwnedMountSnapshot;

    async fn fixture(source: &Path) -> OwnedVolumeCapture {
        let mount = MountBuilder::new("/data")
            .owned_with(|owned| owned.disk().size(1_u32))
            .build()
            .unwrap();
        let mount_id = microsandbox_types::owned_volume_mount_id("/data");
        std::fs::create_dir_all(source.join("layers")).unwrap();
        let base = source.join("layers/base.raw");
        let upper = source.join("layers/change.qcow2");
        std::fs::write(&base, vec![37_u8; 1024 * 1024]).unwrap();
        create_qcow2_overlay(&upper, 1024 * 1024, &base, "raw")
            .await
            .unwrap();
        OwnedVolumeCapture {
            mount_id: mount_id.clone(),
            mount: OwnedMountSnapshot::from_mount(&mount).unwrap(),
            data: OwnedVolumeData::Disk {
                generation: DiskGenerationManifest {
                    schema: "microsandbox.disk-generation/1".into(),
                    volume_id: "volume_owned".into(),
                    device_id: mount_id,
                    generation: 2,
                    head: "change".into(),
                    pause_generation: 0,
                    layers: vec![
                        DiskLayerRef {
                            layer_id: "base".into(),
                            format: "raw".into(),
                            file_size: std::fs::metadata(&base).unwrap().len(),
                            virtual_size: 1024 * 1024,
                            predecessor: None,
                            integrity_root: Some(sparse_file_integrity(&base).unwrap().root),
                        },
                        DiskLayerRef {
                            layer_id: "change".into(),
                            format: "qcow2".into(),
                            file_size: std::fs::metadata(&upper).unwrap().len(),
                            virtual_size: 1024 * 1024,
                            predecessor: Some("base".into()),
                            integrity_root: Some(sparse_file_integrity(&upper).unwrap().root),
                        },
                    ],
                },
            },
        }
    }

    #[tokio::test]
    async fn owned_chain_restore_survives_child_rename_and_source_removal() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("snapshot");
        let volume = fixture(&source).await;
        let child = home.path().join("child-staging");
        let choices = crate::sandbox::restore_resources::RestoreResources::default();
        let mounts =
            materialize_owned_volumes(std::slice::from_ref(&volume), &source, &child, &choices)
                .await
                .unwrap();
        let final_child = home.path().join("child");
        std::fs::rename(&child, &final_child).unwrap();
        std::fs::remove_dir_all(&source).unwrap();
        crate::runtime::owned_volumes::validate(&final_child, &mounts).unwrap();
        let chain = microsandbox_runtime::checkpoint::load_runtime_owned_disk_chain(
            &final_child.join("runtime"),
            &volume.mount_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(chain.layers.len(), 3);
        assert_eq!(chain.virtual_size, 1024 * 1024);
        assert!(
            chain
                .layers
                .iter()
                .all(|layer| layer.path.starts_with(&final_child))
        );
        assert!(
            !final_child
                .join("owned-volumes")
                .join(&volume.mount_id)
                .join("disk.raw")
                .exists()
        );
        microsandbox_image::checkpoint::validate_compact_chain(
            &chain
                .layers
                .iter()
                .map(|layer| CompactLayer {
                    path: layer.path.clone(),
                    qcow2: layer.format == "qcow2",
                })
                .collect::<Vec<_>>(),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn owned_chain_without_capture_hashes_still_checks_physical_lengths() {
        for truncate in [false, true] {
            let home = tempfile::tempdir().unwrap();
            let source = home.path().join("snapshot");
            let mut volume = fixture(&source).await;
            let OwnedVolumeData::Disk { generation } = &mut volume.data else {
                unreachable!()
            };
            for layer in &mut generation.layers {
                layer.integrity_root = None;
            }
            if truncate {
                std::fs::OpenOptions::new()
                    .write(true)
                    .open(source.join("layers/base.raw"))
                    .unwrap()
                    .set_len(512)
                    .unwrap();
            }
            let child = home.path().join("child");
            let result =
                materialize_owned_volumes(&[volume], &source, &child, &Default::default()).await;
            if truncate {
                assert!(result.is_err());
                assert!(!child.exists(), "invalid backing was published");
            } else {
                result.unwrap();
            }
        }
    }

    #[tokio::test]
    async fn owned_chain_restore_rejects_changed_payload_before_publication() {
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("snapshot");
        let volume = fixture(&source).await;
        std::fs::write(source.join("layers/base.raw"), vec![99_u8; 1024 * 1024]).unwrap();
        let child = home.path().join("child");
        let choices = crate::sandbox::restore_resources::RestoreResources::default();
        assert!(
            materialize_owned_volumes(&[volume], &source, &child, &choices)
                .await
                .is_err()
        );
        assert!(
            !child.exists(),
            "a rejected disk must not publish backing or its journal"
        );
    }
}
