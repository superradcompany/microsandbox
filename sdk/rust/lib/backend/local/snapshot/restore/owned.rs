//! Local backend: Private reconstruction of required sandbox-owned backing.

use std::path::Path;

use microsandbox_image::checkpoint::{CompactLayer, DiskGenerationManifest};
use microsandbox_image::snapshot::{OwnedVolumeCapture, OwnedVolumeData};
use microsandbox_runtime::checkpoint::{OwnedDiskBase, RuntimeOwnedRootLayer};
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
        let needs_base = volume.has_external_base();
        if needs_base != choices.owned_bases.contains_key(&volume.mount.guest) {
            return Err(MicrosandboxError::InvalidConfig(if needs_base {
                format!(
                    "owned disk {} was captured over an external base; supply its path to restore",
                    volume.mount.guest
                )
            } else {
                format!(
                    "owned volume {} was not captured over an external base",
                    volume.mount.guest
                )
            }));
        }
    }
    if let Some(guest) = choices
        .owned_bases
        .keys()
        .find(|guest| !volumes.iter().any(|volume| &volume.mount.guest == *guest))
    {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "no owned disk at {guest} needs an external base"
        )));
    }
    let mut bases = std::collections::BTreeMap::new();
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
                let base = choices.owned_bases.get(&volume.mount.guest).cloned();
                let pin = super::super::lease::pin_source(&source)?;
                let (staging, base) = tokio::task::spawn_blocking(move || {
                    let _lease = pin;
                    stage_owned_disk(
                        &source,
                        &parent,
                        &mount_id,
                        &generation,
                        readonly,
                        base.as_deref(),
                    )
                })
                .await
                .map_err(|error| invalid(&format!("owned disk restore worker: {error}")))??;
                if let Some(base) = base {
                    bases.insert(volume.mount.guest.clone(), base.path().to_path_buf());
                }
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
                let pin = super::super::lease::pin_source(&source)?;
                let staging = tokio::task::spawn_blocking(
                    move || -> MicrosandboxResult<tempfile::TempDir> {
                        let _lease = pin;
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
        .map(|volume| {
            let mut mount = volume.mount.to_mount();
            if let VolumeMount::Owned { base, .. } = &mut mount {
                // The child records the verified path it was restored over, not the capture's.
                *base = bases.remove(&volume.mount.guest);
            }
            mount
        })
        .collect())
}

/// Prepare the immutable closure and a private head without touching a named child.
fn stage_owned_disk(
    source: &Path,
    parent: &Path,
    mount_id: &str,
    generation: &DiskGenerationManifest,
    readonly: bool,
    base: Option<&Path>,
) -> MicrosandboxResult<(tempfile::TempDir, Option<OwnedDiskBase>)> {
    let external = match (&generation.external_base, base) {
        (Some(identity), Some(path)) => Some(
            microsandbox_runtime::checkpoint::verify_owned_disk_base(path, Some(identity))
                .map_err(MicrosandboxError::SnapshotIntegrity)?,
        ),
        (None, None) => None,
        _ => return Err(invalid("owned disk base choice differs from its capture")),
    };
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
        } else if external.is_some() {
            // The first layer reads through the external base. It stays a shared hard link, so
            // its header is never rewritten; attachment passes the base explicitly.
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
    let chain: Vec<_> = external
        .iter()
        .map(|base| CompactLayer {
            path: base.path().to_path_buf(),
            qcow2: false,
        })
        .chain(compact.iter().cloned())
        .collect();
    runtime.block_on(async {
        // Explicit opening refuses undeclared dependencies, even if a qcow2 header
        // contains an ambient host path. The private writable layer is never shared.
        microsandbox_image::checkpoint::validate_compact_chain(&chain).await?;
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
    match &external {
        Some(base) => microsandbox_runtime::checkpoint::seed_runtime_owned_disk_chain_over_base(
            &stage.path().join("runtime"),
            mount_id,
            &directory.join("disk.raw"),
            &layers,
            readonly,
            base.clone(),
        ),
        None => microsandbox_runtime::checkpoint::seed_runtime_owned_disk_chain(
            &stage.path().join("runtime"),
            mount_id,
            &directory.join("disk.raw"),
            &layers,
            readonly,
        ),
    }
    .map_err(MicrosandboxError::SnapshotIntegrity)?;
    Ok((stage, external))
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
                    external_base: None,
                },
            },
        }
    }

    /// A captured disk whose only layer is a qcow2 head over a base kept outside the snapshot.
    async fn based_fixture(source: &Path, base: &Path) -> OwnedVolumeCapture {
        std::fs::create_dir_all(base.parent().unwrap()).unwrap();
        std::fs::write(base, vec![41_u8; 1024 * 1024]).unwrap();
        let mount = MountBuilder::new("/data")
            .owned_with(|owned| owned.disk().base(base))
            .build()
            .unwrap();
        let mount_id = microsandbox_types::owned_volume_mount_id("/data");
        std::fs::create_dir_all(source.join("layers")).unwrap();
        let head = source.join("layers/change.qcow2");
        create_qcow2_overlay(&head, 1024 * 1024, base, "raw")
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
                    generation: 1,
                    head: "change".into(),
                    pause_generation: 0,
                    layers: vec![DiskLayerRef {
                        layer_id: "change".into(),
                        format: "qcow2".into(),
                        file_size: std::fs::metadata(&head).unwrap().len(),
                        virtual_size: 1024 * 1024,
                        predecessor: None,
                        integrity_root: Some(sparse_file_integrity(&head).unwrap().root),
                    }],
                    external_base: Some(
                        microsandbox_runtime::checkpoint::verify_owned_disk_base(base, None)
                            .unwrap()
                            .identity(),
                    ),
                },
            },
        }
    }

    #[tokio::test]
    async fn owned_disk_restore_over_external_base_requires_and_checks_the_base() {
        use crate::sandbox::restore_resources::RestoreResources;
        let home = tempfile::tempdir().unwrap();
        let source = home.path().join("snapshot");
        let base = home.path().join("bases/app.raw");
        let volume = based_fixture(&source, &base).await;
        let volumes = std::slice::from_ref(&volume);
        let child = home.path().join("child");

        let error =
            materialize_owned_volumes(volumes, &source, &child, &RestoreResources::default())
                .await
                .unwrap_err();
        assert!(error.to_string().contains("external base"), "{error}");
        assert!(!child.join("owned-volumes").exists());

        let other = home.path().join("bases/other.raw");
        std::fs::write(&other, vec![1_u8; 1024 * 1024]).unwrap();
        let mut wrong = RestoreResources::default();
        wrong.owned_bases.insert("/data".into(), other);
        assert!(
            materialize_owned_volumes(volumes, &source, &child, &wrong)
                .await
                .is_err()
        );
        assert!(!child.join("owned-volumes").exists());

        let mut extra = RestoreResources::default();
        extra.owned_bases.insert("/data".into(), base.clone());
        extra.owned_bases.insert("/elsewhere".into(), base.clone());
        assert!(
            materialize_owned_volumes(volumes, &source, &child, &extra)
                .await
                .is_err()
        );

        let mut choices = RestoreResources::default();
        choices.owned_bases.insert("/data".into(), base.clone());
        let mounts = materialize_owned_volumes(volumes, &source, &child, &choices)
            .await
            .unwrap();
        let canonical = std::fs::canonicalize(&base).unwrap();
        assert!(
            matches!(&mounts[0], VolumeMount::Owned { base: Some(path), .. } if *path == canonical)
        );
        crate::runtime::owned_volumes::validate(&child, &mounts).unwrap();
        let chain = microsandbox_runtime::checkpoint::load_runtime_owned_disk_chain(
            &child.join("runtime"),
            &volume.mount_id,
        )
        .unwrap()
        .unwrap();
        assert_eq!(chain.layers.len(), 3);
        assert_eq!(chain.layers[0].path, canonical);
        assert!(
            chain.layers[1..]
                .iter()
                .all(|layer| layer.path.starts_with(&child))
        );
        let copied: u64 = std::fs::read_dir(child.join("owned-volumes").join(&volume.mount_id))
            .unwrap()
            .map(|entry| entry.unwrap().metadata().unwrap().len())
            .sum();
        assert!(
            copied < 1024 * 1024,
            "the base must not be copied into the child"
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
