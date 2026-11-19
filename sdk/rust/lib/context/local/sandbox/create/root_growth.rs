//! Offline growth of an unpublished snapshot child, before replacement touches its destination.

#[cfg(test)]
use std::path::PathBuf;

use microsandbox_image::checkpoint::CompactLayer;
use microsandbox_runtime::launch::{CheckpointRestoreConfig, RootfsUpperLayerConfig};
#[cfg(test)]
use tempfile::TempDir;

use crate::context::local::creation::CreationStorage;
use crate::sandbox::config::SnapshotRestoreMode;
use crate::sandbox::{RootDisk, RootfsSource};
use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Own all staging in a detached worker, including across blocking filesystem work.
/// Dropping the caller never deletes a directory while a materializer still writes it.
#[cfg(test)]
pub(super) async fn prepare(
    config: SandboxConfig,
    sources: Vec<RootfsUpperLayerConfig>,
    virtual_size: Option<u64>,
    checkpoint: Option<CheckpointRestoreConfig>,
    stage: Option<TempDir>,
    directory: PathBuf,
    fs_state_limit: usize,
) -> MicrosandboxResult<(SandboxConfig, TempDir)> {
    let stage = match stage {
        Some(stage) => stage,
        None => {
            tokio::fs::create_dir_all(&directory).await?;
            tempfile::Builder::new()
                .prefix(".snapshot-grow-")
                .tempdir_in(&directory)?
        }
    };
    let storage = CreationStorage::for_test(stage.path());
    prepare_owned(
        config,
        sources,
        virtual_size,
        checkpoint,
        stage,
        storage,
        fs_state_limit,
    )
    .await
}

pub(super) async fn prepare_owned<T: AsRef<std::path::Path> + Send + 'static>(
    mut config: SandboxConfig,
    sources: Vec<RootfsUpperLayerConfig>,
    virtual_size: Option<u64>,
    checkpoint: Option<CheckpointRestoreConfig>,
    stage: T,
    storage: CreationStorage,
    fs_state_limit: usize,
) -> MicrosandboxResult<(SandboxConfig, T)> {
    tokio::spawn(async move {
        let growth = config.snapshot_root_growth_mib.take();
        let size = growth
            .map(|size_mib| {
                u64::from(size_mib)
                    .checked_mul(1024 * 1024)
                    .filter(|size| *size > 0)
                    .ok_or_else(|| {
                        MicrosandboxError::InvalidConfig(
                            "snapshot root capacity is zero or too large".into(),
                        )
                    })
            })
            .transpose()?;
        let layout = super::snapshot_root_layout_from_config(&config)?;
        // A fresh catalog reservation owns its path before any filesystem worker starts.
        tokio::fs::create_dir_all(stage.as_ref()).await?;
        if let Some(checkpoint) = checkpoint {
            if config.snapshot_restore_mode != SnapshotRestoreMode::DiskOnly {
                return Err(MicrosandboxError::InvalidConfig(
                    "changing a full snapshot disk requires disk-only mode".into(),
                ));
            }
            let materialized = crate::snapshot::materialize_checkpoint_disk_for_child(
                &checkpoint.closure,
                &checkpoint.checkpoint_root,
                &checkpoint.checkpoint_id,
                &storage,
                &layout,
                &config.restore_resources,
                fs_state_limit,
            )
            .await?;
            crate::snapshot::apply_additional_disks(&mut config, materialized.disk_mounts);
            config.snapshot_upper_layers = materialized.upper_layers;
        } else if !sources.is_empty() {
            let virtual_size = virtual_size.ok_or_else(|| {
                MicrosandboxError::SnapshotIntegrity("snapshot root capacity is missing".into())
            })?;
            let materialized = crate::snapshot::materialize_file_snapshot_for_child(
                &sources,
                virtual_size,
                &storage,
                &layout,
            )
            .await?;
            config.snapshot_upper_layers = materialized.upper_layers;
        }
        if config.snapshot_upper_layers.is_empty()
            && let Some(raw) = config.snapshot_upper_source.take()
        {
            use microsandbox_runtime::launch::RootfsUpperLayerConfig;
            let size = tokio::fs::metadata(&raw).await?.len();
            let mut layers = vec![RootfsUpperLayerConfig {
                path: raw.clone(),
                format: "raw".into(),
            }];
            // A legacy archive may already occupy the canonical raw base in this stage.
            // Keep it sealed and append a head. Installed legacy bases still need local ownership.
            if raw.parent() == Some(stage.as_ref()) {
                crate::snapshot::append_private_writable_head(&mut layers, size, &storage, &layout)
                    .await?;
                config.snapshot_upper_layers = layers;
            } else {
                config.snapshot_upper_layers =
                    crate::snapshot::materialize_file_snapshot_for_child(
                        &layers, size, &storage, &layout,
                    )
                    .await?
                    .upper_layers;
            }
        }
        if config.checkpoint_restore.is_some() {
            return Err(MicrosandboxError::InvalidConfig(
                "disk edits or growth cannot modify captured execution state".into(),
            ));
        }
        let layers = config
            .snapshot_upper_layers
            .iter()
            .map(|layer| {
                let qcow2 = match layer.format.as_str() {
                    "raw" => false,
                    "qcow2" => true,
                    format => {
                        return Err(MicrosandboxError::InvalidConfig(format!(
                            "snapshot root growth does not support {format} layers"
                        )));
                    }
                };
                Ok(CompactLayer {
                    path: layer.path.clone(),
                    qcow2,
                })
            })
            .collect::<MicrosandboxResult<Vec<_>>>()?;
        if layers.is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "snapshot root growth requires a child-owned ext4 disk chain".into(),
            ));
        }
        if layers
            .iter()
            .any(|layer| !layer.path.starts_with(stage.as_ref()))
            || !layers.last().is_some_and(|layer| layer.qcow2)
        {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "snapshot root growth requires an unpublished child-owned writable head".into(),
            ));
        }
        let Some((size_mib, size)) = growth.zip(size) else {
            return Ok((config, stage));
        };
        #[cfg(test)]
        tests::pause_staged_worker(stage.as_ref().parent().expect("staging has a parent")).await;
        // Transfer staging into the blocking task too: even runtime shutdown must not
        // remove its head while ext4 metadata is being rewritten. No captured inode is writable.
        let stage = tokio::task::spawn_blocking(move || {
            microsandbox_image::ext4::grow_chain(&layers, size).map_err(|error| {
                MicrosandboxError::InvalidConfig(format!(
                    "cannot grow snapshot child root: {error}"
                ))
            })?;
            Ok::<_, MicrosandboxError>(stage)
        })
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("snapshot root growth: {error}")))??;
        if let RootfsSource::Oci(oci) = &mut config.spec.image {
            match oci.root_disk.as_mut() {
                Some(
                    RootDisk::Managed { size_mib: capacity }
                    | RootDisk::Flat {
                        size_mib: capacity, ..
                    },
                ) => {
                    *capacity = Some(size_mib);
                }
                _ => {
                    return Err(MicrosandboxError::InvalidConfig(
                        "snapshot root growth cannot change the captured disk layout".into(),
                    ));
                }
            }
        }
        Ok((config, stage))
    })
    .await
    .map_err(|error| MicrosandboxError::Custom(format!("snapshot root preparation: {error}")))?
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_image::checkpoint::{layer_capacities, sparse_file_integrity};
    use microsandbox_image::ext4::{Ext4FormatOptions, format_ext4};
    use std::path::Path;
    use std::sync::{Arc, Mutex};
    use tokio::sync::Notify;

    type WorkerGate = (PathBuf, Arc<Notify>, Arc<Notify>);

    // Key the gate by this test's private directory; concurrent growth tests never wait.
    static PAUSE: Mutex<Option<WorkerGate>> = Mutex::new(None);

    pub(super) async fn pause_staged_worker(directory: &Path) {
        let gate = PAUSE
            .lock()
            .unwrap()
            .as_ref()
            .filter(|(path, ..)| path == directory)
            .map(|(_, entered, release)| (entered.clone(), release.clone()));
        if let Some((entered, release)) = gate {
            entered.notify_one();
            release.notified().await;
        }
    }

    #[tokio::test]
    async fn snapshot_root_growth_cancellation_retains_then_discards_private_stage() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("sealed.raw");
        let mib = 1024 * 1024;
        format_ext4(
            &source,
            &Ext4FormatOptions {
                size_bytes: 256 * mib,
                journal_blocks: 4096,
            },
        )
        .unwrap();
        let original = sparse_file_integrity(&source).unwrap().root;
        let mut config = SandboxConfig::default();
        config.spec.image = RootfsSource::oci("test");
        let RootfsSource::Oci(oci) = &mut config.spec.image else {
            unreachable!()
        };
        oci.root_disk = Some(RootDisk::managed(256));
        config.snapshot_root_growth_mib = Some(512);
        let parent = dir.path().join("children");
        let entered = Arc::new(Notify::new());
        let release = Arc::new(Notify::new());
        *PAUSE.lock().unwrap() = Some((parent.clone(), entered.clone(), release.clone()));
        let caller = tokio::spawn(prepare(
            config,
            vec![RootfsUpperLayerConfig {
                path: source.clone(),
                format: "raw".into(),
            }],
            Some(256 * mib),
            None,
            None,
            parent.clone(),
            1024,
        ));
        tokio::time::timeout(std::time::Duration::from_secs(5), entered.notified())
            .await
            .unwrap();
        let staged = std::fs::read_dir(&parent)
            .unwrap()
            .next()
            .unwrap()
            .unwrap()
            .path();
        caller.abort();
        assert!(caller.await.unwrap_err().is_cancelled());
        assert!(
            staged.is_dir(),
            "cancelling the caller must not remove an active worker's disk"
        );
        release.notify_one();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            while staged.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        *PAUSE.lock().unwrap() = None;
        assert_eq!(sparse_file_integrity(&source).unwrap().root, original);
    }

    #[tokio::test]
    async fn snapshot_root_growth_preserves_source_and_layout() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("sealed.raw");
        let mib = 1024 * 1024;
        format_ext4(
            &source,
            &Ext4FormatOptions {
                size_bytes: 256 * mib,
                journal_blocks: 4096,
            },
        )
        .unwrap();
        let original = sparse_file_integrity(&source).unwrap().root;
        for disk in [
            RootDisk::managed(256),
            RootDisk::Flat {
                size_mib: Some(256),
                fstype: Some("ext4".into()),
                clone: Default::default(),
            },
        ] {
            let mut config = SandboxConfig::default();
            config.spec.image = RootfsSource::oci("test");
            let RootfsSource::Oci(oci) = &mut config.spec.image else {
                unreachable!()
            };
            oci.root_disk = Some(disk.clone());
            config.snapshot_root_growth_mib = Some(512);
            let parent = dir.path().join("children");
            let (config, stage) = prepare(
                config,
                vec![RootfsUpperLayerConfig {
                    path: source.clone(),
                    format: "raw".into(),
                }],
                Some(256 * mib),
                None,
                None,
                parent,
                1024,
            )
            .await
            .unwrap();
            assert!(config.snapshot_root_growth_mib.is_none());
            let expected = match disk {
                RootDisk::Managed { .. } => RootDisk::managed(512),
                RootDisk::Flat { fstype, clone, .. } => RootDisk::Flat {
                    size_mib: Some(512),
                    fstype,
                    clone,
                },
                _ => unreachable!(),
            };
            assert_eq!(config.spec.image.oci_root_disk(), Some(&expected));
            let layers = config
                .snapshot_upper_layers
                .iter()
                .map(|layer| CompactLayer {
                    path: layer.path.clone(),
                    qcow2: layer.format == "qcow2",
                })
                .collect();
            let sizes = tokio::task::spawn_blocking(move || layer_capacities(layers))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(sizes, vec![256 * mib, 512 * mib]);
            assert_eq!(sparse_file_integrity(&source).unwrap().root, original);
            let path = stage.path().to_path_buf();
            drop(stage);
            assert!(!path.exists());
        }
    }

    #[tokio::test]
    async fn snapshot_root_shrink_discards_stage_without_changing_source() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("sealed.raw");
        let mib = 1024 * 1024;
        format_ext4(
            &source,
            &Ext4FormatOptions {
                size_bytes: 256 * mib,
                journal_blocks: 4096,
            },
        )
        .unwrap();
        let original = sparse_file_integrity(&source).unwrap().root;
        let mut config = SandboxConfig::default();
        config.spec.image = RootfsSource::oci("test");
        let RootfsSource::Oci(oci) = &mut config.spec.image else {
            unreachable!()
        };
        oci.root_disk = Some(RootDisk::managed(256));
        config.snapshot_root_growth_mib = Some(128);
        let parent = dir.path().join("children");
        let error = prepare(
            config,
            vec![RootfsUpperLayerConfig {
                path: source.clone(),
                format: "raw".into(),
            }],
            Some(256 * mib),
            None,
            None,
            parent.clone(),
            1024,
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("must be larger"), "{error}");
        assert_eq!(std::fs::read_dir(parent).unwrap().count(), 0);
        assert_eq!(sparse_file_integrity(&source).unwrap().root, original);
    }
}
