//! Explicit disk-chain maintenance, separate from persisted desired configuration.

use std::sync::Arc;
#[cfg(feature = "local")]
use std::time::Duration;

#[cfg(feature = "local")]
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

#[cfg(any(feature = "local", test))]
use microsandbox_types::DiskCompactionTarget;

use crate::{MicrosandboxError, MicrosandboxResult, backend::Backend};

#[cfg(feature = "local")]
use super::{SandboxConfig, SandboxStatus};
#[cfg(feature = "local")]
use crate::db::entity::sandbox as sandbox_entity;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Plan or compact immutable root/owned-data disk prefixes without changing existing snapshots.
#[derive(Clone)]
pub struct DiskCompactionBuilder {
    backend: Arc<dyn Backend>,
    name: String,
    layers: Option<usize>,
    disk: Option<String>,
    root_disk_only: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DiskCompactionBuilder {
    pub(crate) fn new(backend: Arc<dyn Backend>, name: String) -> Self {
        Self {
            backend,
            name,
            layers: None,
            disk: None,
            root_disk_only: false,
        }
    }

    /// Select up to `layers` oldest sealed physical layers per disk, counting the base but
    /// never the writable head. The limit must be at least two; only chains with fewer than
    /// two sealed layers are skipped.
    pub fn layers(mut self, layers: usize) -> Self {
        self.layers = Some(layers);
        self
    }

    /// Select one sandbox-owned data disk by absolute guest mount path (`/` selects the root).
    /// Cannot be combined with [`root_disk_only`](Self::root_disk_only).
    pub fn disk(mut self, guest_path: impl Into<String>) -> Self {
        self.disk = Some(guest_path.into());
        self
    }

    /// Select only the managed or flat root disk. Cannot be combined with [`disk`](Self::disk).
    pub fn root_disk_only(mut self) -> Self {
        self.root_disk_only = true;
        self
    }

    /// Resolve the selection without writing files or pausing the sandbox.
    pub async fn dry_run(self) -> MicrosandboxResult<DiskCompactionResult> {
        self.execute(true).await
    }

    /// Compact the selection. By default this covers the managed/flat root and every owned
    /// data disk, never named/external disks or directories. Omitted layers selects the entire
    /// sealed prefix; chains shorter than two are unchanged. Existing snapshots keep their files.
    pub async fn apply(self) -> MicrosandboxResult<DiskCompactionResult> {
        self.execute(false).await
    }

    #[cfg(not(feature = "local"))]
    async fn execute(self, _dry_run: bool) -> MicrosandboxResult<DiskCompactionResult> {
        let _ = (&self.backend, &self.name);
        Err(MicrosandboxError::InvalidConfig(
            "disk compaction is only supported by the local backend".into(),
        ))
    }

    #[cfg(feature = "local")]
    async fn execute(self, dry_run: bool) -> MicrosandboxResult<DiskCompactionResult> {
        let target = compaction_target(self.disk.as_deref(), self.root_disk_only, self.layers)?;
        let local = self.backend.as_local().ok_or_else(|| {
            MicrosandboxError::InvalidConfig(
                "disk compaction is only supported by the local backend".into(),
            )
        })?;
        let model = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(&self.name))
            .one(local.db().await?.read())
            .await?
            .ok_or_else(|| MicrosandboxError::SandboxNotFound(self.name.clone()))?;
        let config: SandboxConfig = serde_json::from_str(&model.config)?;
        crate::LocalBackend::validate_completed_restore(&config)?;
        validate_root_selection(&config, &target)?;
        if model.status == SandboxStatus::Running {
            return super::modify::control_disk_compact(
                local,
                &self.name,
                target,
                self.layers,
                dry_run,
            )
            .await;
        }
        if matches!(
            model.status,
            SandboxStatus::Draining | SandboxStatus::Paused
        ) {
            return Err(MicrosandboxError::InvalidConfig(
                "disk compaction requires a running or fully stopped sandbox".into(),
            ));
        }
        // A status row alone is not ownership: hold the same lock as startup before touching disk.
        let _guard = crate::runtime::acquire_sandbox_lifecycle_guard(
            &local.config().run_dir(),
            &self.name,
            Duration::from_secs(5),
        )
        .await?;
        let current = sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(&self.name))
            .one(local.db().await?.read())
            .await?
            .ok_or_else(|| MicrosandboxError::SandboxNotFound(self.name.clone()))?;
        if current.id != model.id
            || matches!(
                current.status,
                SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
            )
        {
            return Err(MicrosandboxError::InvalidConfig(
                "sandbox changed while acquiring disk ownership; retry compaction".into(),
            ));
        }
        let runtime_dir = local.sandboxes_dir().join(&self.name).join("runtime");
        let current_config: SandboxConfig = serde_json::from_str(&current.config)?;
        crate::LocalBackend::validate_completed_restore(&current_config)?;
        // The configuration can change before ownership is acquired. Classify the root from
        // this fresh row, not a stale pre-lock view or a journal's incidental presence.
        let root_eligible = validate_root_selection(&current_config, &target)?;
        tokio::task::spawn_blocking(move || {
            // Dropping an SDK future does not cancel spawn_blocking. Keep disk ownership in the
            // worker until it finishes, even when its caller disconnects or cancels the await.
            let _guard = _guard;
            microsandbox_runtime::checkpoint::compact_stopped_disks(
                &runtime_dir,
                &current_config.spec.mounts,
                root_eligible,
                &target,
                self.layers,
                dry_run,
            )
        })
        .await
        .map_err(|e| MicrosandboxError::Runtime(format!("disk compaction task failed: {e}")))?
        .map_err(MicrosandboxError::Runtime)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "local")]
fn validate_root_selection(
    config: &SandboxConfig,
    target: &DiskCompactionTarget,
) -> MicrosandboxResult<bool> {
    use microsandbox_types::{RootDisk, RootfsSource};

    let eligible = config.manifest_digest.is_some()
        && matches!(&config.spec.image, RootfsSource::Oci(source)
            if matches!(source.root_disk, None | Some(RootDisk::Managed { .. } | RootDisk::Flat { .. })));
    if matches!(target, DiskCompactionTarget::Root) && !eligible {
        return Err(MicrosandboxError::InvalidConfig(
            "disk compaction requires a Microsandbox-owned managed or flat OCI root disk".into(),
        ));
    }
    Ok(eligible)
}

#[cfg(any(feature = "local", test))]
fn compaction_target(
    disk: Option<&str>,
    root_only: bool,
    layers: Option<usize>,
) -> MicrosandboxResult<DiskCompactionTarget> {
    if layers.is_some_and(|layers| layers < 2) {
        return Err(MicrosandboxError::InvalidConfig(
            "compaction layers must be at least two".into(),
        ));
    }
    if disk.is_some() && root_only {
        return Err(MicrosandboxError::InvalidConfig(
            "disk and root_disk_only are mutually exclusive".into(),
        ));
    }
    let Some(disk) = disk else {
        return Ok(if root_only {
            DiskCompactionTarget::Root
        } else {
            DiskCompactionTarget::All
        });
    };
    if !disk.starts_with('/')
        || disk.contains(['\0', '\\', ':', ';', ','])
        || disk.split('/').any(|component| component == "..")
    {
        return Err(MicrosandboxError::InvalidConfig(
            "compaction disk must be an absolute guest mount path without '..'".into(),
        ));
    }
    let components = disk
        .split('/')
        .filter(|part| !part.is_empty() && *part != ".")
        .collect::<Vec<_>>();
    if components.is_empty() {
        Ok(DiskCompactionTarget::Root)
    } else {
        Ok(DiskCompactionTarget::Disk {
            guest_path: format!("/{}", components.join("/")),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compaction_selectors_and_limits_are_explicit() {
        assert_eq!(
            compaction_target(None, false, None).unwrap(),
            DiskCompactionTarget::All
        );
        assert_eq!(
            compaction_target(Some("/"), false, Some(999)).unwrap(),
            DiskCompactionTarget::Root
        );
        assert_eq!(
            compaction_target(Some("//data/./"), false, None).unwrap(),
            DiskCompactionTarget::Disk {
                guest_path: "/data".into()
            }
        );
        assert!(compaction_target(Some("/data"), true, None).is_err());
        for path in ["data", "/data/../other", "/data\\other", ""] {
            assert!(compaction_target(Some(path), false, None).is_err());
        }
        for layers in [0, 1] {
            assert!(compaction_target(None, false, Some(layers)).is_err());
        }
    }

    #[cfg(feature = "local")]
    #[test]
    fn compaction_root_eligibility_excludes_external_and_tmpfs_sources() {
        use microsandbox_types::{DiskImageFormat, OciRootfsSource, RootDisk, RootfsSource};

        let mut config = SandboxConfig {
            manifest_digest: Some("sha256:test".into()),
            ..Default::default()
        };
        for root_disk in [
            None,
            Some(RootDisk::Managed { size_mib: None }),
            Some(RootDisk::Flat {
                size_mib: None,
                fstype: None,
                clone: Default::default(),
            }),
        ] {
            config.spec.image = RootfsSource::Oci(OciRootfsSource {
                reference: "alpine".into(),
                root_disk,
            });
            assert!(validate_root_selection(&config, &DiskCompactionTarget::Root).unwrap());
        }
        for image in [
            RootfsSource::Oci(OciRootfsSource {
                reference: "alpine".into(),
                root_disk: Some(RootDisk::Tmpfs { size_mib: None }),
            }),
            RootfsSource::Oci(OciRootfsSource {
                reference: "alpine".into(),
                root_disk: Some(RootDisk::DiskImage {
                    path: "/external.raw".into(),
                    format: DiskImageFormat::Raw,
                    fstype: None,
                }),
            }),
            RootfsSource::Bind {
                path: "/external".into(),
                follow_root_symlinks: false,
            },
            RootfsSource::DiskImage {
                path: "/external.raw".into(),
                format: DiskImageFormat::Raw,
                fstype: None,
            },
        ] {
            config.spec.image = image;
            assert!(!validate_root_selection(&config, &DiskCompactionTarget::All).unwrap());
            assert!(
                !validate_root_selection(
                    &config,
                    &DiskCompactionTarget::Disk {
                        guest_path: "/data".into()
                    }
                )
                .unwrap()
            );
            assert!(validate_root_selection(&config, &DiskCompactionTarget::Root).is_err());
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::{DiskCompactionDiskResult, DiskCompactionResult};
