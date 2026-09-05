//! Explicit disk-chain maintenance, separate from persisted desired configuration.

use std::{sync::Arc, time::Duration};

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::{
    MicrosandboxError, MicrosandboxResult, backend::Backend, db::entity::sandbox as sandbox_entity,
};

use super::{SandboxConfig, SandboxStatus};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Plan or compact an immutable disk prefix without changing existing snapshots.
#[derive(Clone)]
pub struct DiskCompactionBuilder {
    backend: Arc<dyn Backend>,
    name: String,
    layers: Option<usize>,
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
        }
    }

    /// Select the oldest `layers` physical layers, counting the base but never the writable head.
    /// The explicit count must be at least two and no larger than the sealed prefix.
    pub fn layers(mut self, layers: usize) -> Self {
        self.layers = Some(layers);
        self
    }

    /// Resolve the selection without writing files or pausing the sandbox.
    pub async fn dry_run(self) -> MicrosandboxResult<DiskCompactionResult> {
        self.execute(true).await
    }

    /// Compact the selection. Omission selects all sealed layers; a chain with fewer than two
    /// sealed layers is unchanged. Existing snapshots and clones keep their original files.
    pub async fn apply(self) -> MicrosandboxResult<DiskCompactionResult> {
        self.execute(false).await
    }

    async fn execute(self, dry_run: bool) -> MicrosandboxResult<DiskCompactionResult> {
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
        use microsandbox_types::RootDisk;
        if config.manifest_digest.is_none()
            || matches!(
                config.spec.image.oci_root_disk(),
                Some(RootDisk::Tmpfs { .. } | RootDisk::DiskImage { .. })
            )
        {
            return Err(MicrosandboxError::InvalidConfig(
                "disk compaction requires a Microsandbox-owned managed or flat OCI root disk"
                    .into(),
            ));
        }
        if model.status == SandboxStatus::Running {
            return super::modify::control_disk_compact(&self.name, self.layers, dry_run).await;
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
        tokio::task::spawn_blocking(move || {
            // Dropping an SDK future does not cancel spawn_blocking. Keep disk ownership in the
            // worker until it finishes, even when its caller disconnects or cancels the await.
            let _guard = _guard;
            microsandbox_runtime::checkpoint::compact_stopped_root(
                &runtime_dir,
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
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_runtime::checkpoint::DiskCompactionResult;
