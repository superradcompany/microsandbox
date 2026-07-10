//! Named volume management.
//!
//! Volumes are persistent named storage. Locally they are host-side
//! directories under `~/.microsandbox/volumes/<name>/` with metadata tracked
//! in SQLite. Cloud-side they ultimately live in the org's S3 namespace via
//! msb-cloud (Phase 6; today every cloud op returns `Unsupported`).
//!
//! Per the SDK local-cloud parity plan (D6.4) [`Volume`] and [`VolumeHandle`]
//! stay single types regardless of backend. Each holds an
//! [`Arc<dyn Backend>`](crate::backend::Backend) to route lifecycle ops
//! through, and a backend-private [`VolumeInner`] / [`VolumeHandleInner`]
//! enum carrying variant-specific state.

pub mod fs;
pub use fs::{VolumeFs, VolumeFsReadStream, VolumeFsWriteSink};
pub use microsandbox_types::{VolumeKind, VolumeSpec, VolumeSpec as VolumeConfig};

use std::fs::File;
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox_image::ext4::{self, Ext4FormatOptions};
use sea_orm::ConnectionTrait;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};

use crate::backend::{
    Backend, BackendKind, LocalBackend, VolumeHandleInner, VolumeHandleLocalState, VolumeInner,
    VolumeLocalState,
};
use crate::{
    MicrosandboxError, MicrosandboxResult,
    db::entity::{sandbox as sandbox_entity, volume as volume_entity},
    sandbox::{SandboxConfig, SandboxStatus, VolumeMount},
    size::Mebibytes,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A named volume.
///
/// Holds the backend it was created on plus a backend-private
/// [`VolumeInner`] enum carrying variant-specific state. Reach variant data
/// via [`Volume::local`] / [`Volume::cloud`]; the public surface stays
/// backend-agnostic.
#[derive(Clone)]
pub struct Volume {
    backend: Arc<dyn Backend>,
    inner: Arc<VolumeInner>,
    name: String,
}

/// A lightweight handle to a volume.
///
/// Provides metadata access and management operations without requiring a
/// live [`Volume`] instance. Obtained via [`Volume::get`] or [`Volume::list`].
///
/// Like [`Volume`], holds an [`Arc<dyn Backend>`] plus a backend-private
/// [`VolumeHandleInner`] enum; users see a single uniform type.
#[derive(Clone)]
pub struct VolumeHandle {
    backend: Arc<dyn Backend>,
    inner: VolumeHandleInner,
    name: String,
}

/// Builder for creating a volume.
pub struct VolumeBuilder {
    config: VolumeConfig,
}

//--------------------------------------------------------------------------------------------------
// Methods: Volume (static)
//--------------------------------------------------------------------------------------------------

impl Volume {
    /// Start building a new named volume. Call `.create()` on the returned
    /// builder to persist it.
    pub fn builder(name: impl Into<String>) -> VolumeBuilder {
        VolumeBuilder::new(name)
    }

    /// Provision a volume.
    ///
    /// Routes through the ambient
    /// [`default_backend`](crate::backend::default_backend) so a cloud profile
    /// dispatches to [`CloudBackend`](crate::backend::CloudBackend) instead of
    /// the local disk path. The returned `Volume` carries the backend it was
    /// created on; subsequent method calls keep using that backend.
    ///
    /// Locally fails with [`MicrosandboxError::VolumeAlreadyExists`] if a
    /// volume with the same name already exists.
    pub async fn create(config: VolumeConfig) -> MicrosandboxResult<Self> {
        let backend = crate::backend::default_backend();
        backend.volumes().create(backend.clone(), config).await
    }

    /// Get a volume handle by name from the active backend.
    pub async fn get(name: &str) -> MicrosandboxResult<VolumeHandle> {
        let backend = crate::backend::default_backend();
        backend.volumes().get(backend.clone(), name).await
    }

    /// List all volumes from the active backend.
    pub async fn list() -> MicrosandboxResult<Vec<VolumeHandle>> {
        let backend = crate::backend::default_backend();
        backend.volumes().list(backend.clone()).await
    }

    /// Remove a volume by name via the active backend.
    pub async fn remove(name: &str) -> MicrosandboxResult<()> {
        let backend = crate::backend::default_backend();
        backend.volumes().remove(backend.clone(), name).await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Volume (construction helpers)
//--------------------------------------------------------------------------------------------------

impl Volume {
    /// Build an outer `Volume` from local-variant inner state.
    pub(crate) fn from_local(
        backend: Arc<dyn Backend>,
        local: VolumeLocalState,
        name: String,
    ) -> Self {
        Self {
            backend,
            inner: Arc::new(VolumeInner::Local(local)),
            name,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Volume (instance)
//--------------------------------------------------------------------------------------------------

impl Volume {
    /// Unique name identifying this volume.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Which backend variant this volume is bound to.
    pub fn backend_kind(&self) -> BackendKind {
        self.backend.kind()
    }

    /// Local-only volume state. Returns `Some` for local-backed volumes.
    pub fn local(&self) -> Option<&VolumeLocalState> {
        match &*self.inner {
            VolumeInner::Local(s) => Some(s),
            VolumeInner::Cloud(_) => None,
        }
    }

    /// Cloud-only volume state. Returns `Some` for cloud-backed volumes.
    pub fn cloud(&self) -> Option<&crate::backend::VolumeCloudState> {
        match &*self.inner {
            VolumeInner::Cloud(s) => Some(s),
            VolumeInner::Local(_) => None,
        }
    }

    /// Host-side directory where this volume's data is stored (local backend
    /// only).
    ///
    /// Errors with [`MicrosandboxError::Unsupported`] for cloud volumes —
    /// cloud bytes live in the org's S3 namespace, not on the caller's host.
    pub fn path(&self) -> MicrosandboxResult<&Path> {
        match &*self.inner {
            VolumeInner::Local(s) => Ok(&s.path),
            VolumeInner::Cloud(_) => Err(MicrosandboxError::Unsupported {
                feature: "Volume::path on cloud".into(),
                available_when: "never — cloud volumes don't live on the host".into(),
            }),
        }
    }

    /// Storage kind for this volume.
    pub fn kind(&self) -> VolumeKind {
        match &*self.inner {
            VolumeInner::Local(s) => s.kind,
            VolumeInner::Cloud(s) => s.kind,
        }
    }

    /// Disk capacity in bytes for disk volumes.
    pub fn capacity_bytes(&self) -> Option<u64> {
        match &*self.inner {
            VolumeInner::Local(s) => s.capacity_bytes,
            VolumeInner::Cloud(s) => s.capacity_bytes,
        }
    }

    /// Disk image format for disk volumes.
    pub fn disk_format(&self) -> Option<&str> {
        match &*self.inner {
            VolumeInner::Local(s) => s.disk_format.as_deref(),
            VolumeInner::Cloud(s) => s.disk_format.as_deref(),
        }
    }

    /// Inner disk filesystem for disk volumes.
    pub fn disk_fstype(&self) -> Option<&str> {
        match &*self.inner {
            VolumeInner::Local(s) => s.disk_fstype.as_deref(),
            VolumeInner::Cloud(s) => s.disk_fstype.as_deref(),
        }
    }

    /// Host path to the managed raw disk image for disk volumes.
    pub fn disk_path(&self) -> Option<PathBuf> {
        (self.kind() == VolumeKind::Disk).then(|| {
            self.path()
                .expect("disk_path is only available for local disk volumes")
                .join("disk.raw")
        })
    }

    /// Operate on the volume's filesystem (read, write, list files) without
    /// needing a running sandbox.
    ///
    /// Routes through the backend trait — local ops hit `tokio::fs`, cloud
    /// ops will route through msb-cloud HTTP once Phase 6 lands.
    pub fn fs(&self) -> VolumeFs<'_> {
        VolumeFs::new(self.backend.clone(), &self.name)
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: VolumeHandle
//--------------------------------------------------------------------------------------------------

impl VolumeHandle {
    /// Build a handle from a local volume DB row.
    ///
    /// Derives the host-side path from the `backend`'s [`LocalBackend`]
    /// view — callers don't have to thread the same backend in twice.
    /// Panics if `backend` is not a [`LocalBackend`]; this is the local
    /// construction path and is only called from `get_local` / `list_local`,
    /// which have already routed through the local trait impl.
    pub(crate) fn from_local_model(backend: Arc<dyn Backend>, model: volume_entity::Model) -> Self {
        let labels = model
            .labels
            .as_deref()
            .map(|s| {
                serde_json::from_str::<Vec<(String, String)>>(s).unwrap_or_else(|e| {
                    tracing::warn!(volume = %model.name, error = %e, "failed to parse volume labels JSON");
                    Vec::new()
                })
            })
            .unwrap_or_default();

        let local_backend = backend
            .as_local()
            .expect("from_local_model called outside a LocalBackend context");
        let path = local_backend.volume_path(&model.name);
        let name = model.name;
        Self {
            backend,
            inner: VolumeHandleInner::Local(VolumeHandleLocalState {
                db_id: model.id,
                path,
                kind: VolumeKind::from_db_value(&model.kind),
                quota_mib: model.quota_mib.map(|v| v.max(0) as u32),
                used_bytes: model.size_bytes.unwrap_or(0).max(0) as u64,
                capacity_bytes: model.capacity_bytes.map(|v| v.max(0) as u64),
                disk_format: model.disk_format,
                disk_fstype: model.disk_fstype,
                labels,
                created_at: model.created_at.map(|dt| dt.and_utc()),
            }),
            name,
        }
    }

    /// Unique name identifying this volume.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Which backend variant this handle is bound to.
    pub fn backend_kind(&self) -> BackendKind {
        self.backend.kind()
    }

    /// Local-only handle state. Returns `Some` for local-backed handles.
    pub fn local(&self) -> Option<&VolumeHandleLocalState> {
        match &self.inner {
            VolumeHandleInner::Local(s) => Some(s),
            VolumeHandleInner::Cloud(_) => None,
        }
    }

    /// Cloud-only handle state. Returns `Some` for cloud-backed handles.
    pub fn cloud(&self) -> Option<&crate::backend::VolumeHandleCloudState> {
        match &self.inner {
            VolumeHandleInner::Cloud(s) => Some(s),
            VolumeHandleInner::Local(_) => None,
        }
    }

    /// Maximum storage in MiB, or `None` if unlimited.
    pub fn quota_mib(&self) -> Option<u32> {
        match &self.inner {
            VolumeHandleInner::Local(s) => s.quota_mib,
            VolumeHandleInner::Cloud(s) => s.quota_mib,
        }
    }

    /// Storage kind for this volume.
    pub fn kind(&self) -> VolumeKind {
        match &self.inner {
            VolumeHandleInner::Local(s) => s.kind,
            VolumeHandleInner::Cloud(s) => s.kind,
        }
    }

    /// Disk usage snapshot from when this handle was created. Not live —
    /// call [`Volume::get`] again for a fresh reading.
    pub fn used_bytes(&self) -> u64 {
        match &self.inner {
            VolumeHandleInner::Local(s) => s.used_bytes,
            VolumeHandleInner::Cloud(s) => s.used_bytes,
        }
    }

    /// Disk capacity in bytes for disk volumes.
    pub fn capacity_bytes(&self) -> Option<u64> {
        match &self.inner {
            VolumeHandleInner::Local(s) => s.capacity_bytes,
            VolumeHandleInner::Cloud(s) => s.capacity_bytes,
        }
    }

    /// Disk image format for disk volumes.
    pub fn disk_format(&self) -> Option<&str> {
        match &self.inner {
            VolumeHandleInner::Local(s) => s.disk_format.as_deref(),
            VolumeHandleInner::Cloud(s) => s.disk_format.as_deref(),
        }
    }

    /// Inner disk filesystem for disk volumes.
    pub fn disk_fstype(&self) -> Option<&str> {
        match &self.inner {
            VolumeHandleInner::Local(s) => s.disk_fstype.as_deref(),
            VolumeHandleInner::Cloud(s) => s.disk_fstype.as_deref(),
        }
    }

    /// Host path to the managed raw disk image for disk volumes.
    pub fn disk_path(&self) -> Option<PathBuf> {
        match &self.inner {
            VolumeHandleInner::Local(s) if s.kind == VolumeKind::Disk => {
                Some(s.path.join("disk.raw"))
            }
            _ => None,
        }
    }

    /// Key-value labels for organizing and filtering volumes.
    pub fn labels(&self) -> &[(String, String)] {
        match &self.inner {
            VolumeHandleInner::Local(s) => &s.labels,
            VolumeHandleInner::Cloud(s) => &s.labels,
        }
    }

    /// When this volume was first created, if recorded.
    pub fn created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match &self.inner {
            VolumeHandleInner::Local(s) => s.created_at,
            VolumeHandleInner::Cloud(s) => s.created_at,
        }
    }

    /// Operate on the volume's filesystem (read, write, list files) without
    /// needing a running sandbox. Routes through the bound backend.
    pub fn fs(&self) -> VolumeFs<'_> {
        VolumeFs::new(self.backend.clone(), &self.name)
    }

    /// Remove this volume.
    ///
    /// Locally deletes the DB record first, then the directory. An orphaned
    /// directory is easier to detect and clean up than an orphaned DB record.
    /// Cloud handles route through the backend's remove endpoint.
    pub async fn remove(&self) -> MicrosandboxResult<()> {
        self.backend
            .volumes()
            .remove(self.backend.clone(), &self.name)
            .await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: VolumeBuilder
//--------------------------------------------------------------------------------------------------

impl VolumeBuilder {
    /// Start building a volume with the given name. Names must contain only
    /// alphanumeric characters, dots, hyphens, and underscores.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            config: VolumeConfig {
                name: name.into(),
                kind: VolumeKind::Directory,
                quota_mib: None,
                capacity_mib: None,
                labels: Vec::new(),
            },
        }
    }

    /// Create a directory-backed named volume.
    pub fn directory(mut self) -> Self {
        self.config.kind = VolumeKind::Directory;
        self
    }

    /// Create a raw ext4 disk-image named volume.
    pub fn disk(mut self) -> Self {
        self.config.kind = VolumeKind::Disk;
        self
    }

    /// Limit the volume's storage capacity. Accepts bare `u32` (MiB) or a
    /// [`SizeExt`](crate::size::SizeExt) helper:
    ///
    /// ```ignore
    /// .quota(1024)         // 1024 MiB
    /// .quota(1.gib())      // 1 GiB = 1024 MiB
    /// ```
    ///
    /// Omit to allow unlimited growth (default).
    pub fn quota(mut self, size: impl Into<Mebibytes>) -> Self {
        self.config.quota_mib = Some(size.into().as_u32());
        self
    }

    /// Set disk volume capacity. Required for disk volumes.
    pub fn size(mut self, size: impl Into<Mebibytes>) -> Self {
        self.config.capacity_mib = Some(size.into().as_u32());
        self
    }

    /// Attach a key-value label for organizing and filtering volumes.
    /// Can be called multiple times.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.config.labels.push((key.into(), value.into()));
        self
    }

    /// Build the volume config without creating it.
    pub fn build(self) -> VolumeConfig {
        self.config
    }

    /// Create the volume. Routes through the ambient
    /// [`default_backend`](crate::backend::default_backend).
    pub async fn create(self) -> MicrosandboxResult<Volume> {
        Volume::create(self.config).await
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<VolumeConfig> for VolumeBuilder {
    fn from(config: VolumeConfig) -> Self {
        Self { config }
    }
}

impl std::fmt::Debug for VolumeHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VolumeHandle")
            .field("name", &self.name)
            .field("backend_kind", &self.backend.kind())
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Local lifecycle (called from the LocalBackend VolumeBackend impl)
//--------------------------------------------------------------------------------------------------

/// Local create path. Inserts a DB record, creates the host directory, and
/// returns a wrapped [`Volume`]. On directory-create failure rolls back the
/// DB insert so we don't leak phantom rows.
pub(crate) async fn create_local(
    backend: Arc<dyn Backend>,
    config: VolumeConfig,
) -> MicrosandboxResult<Volume> {
    tracing::debug!(name = %config.name, quota_mib = ?config.quota_mib, "Volume::create");
    validate_volume_name(&config.name)?;
    validate_volume_config(&config)?;

    let local_backend = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::Unsupported {
            feature: "Volume::create_local".into(),
            available_when: "with a LocalBackend".into(),
        })?;
    let pools = local_backend.db().await?;
    let _name_lock = lock_volume_name(local_backend, &config.name)?;

    // Check for existing volume.
    let existing = volume_entity::Entity::find()
        .filter(volume_entity::Column::Name.eq(&config.name))
        .one(pools.read())
        .await?;
    if existing.is_some() {
        return Err(MicrosandboxError::VolumeAlreadyExists(config.name));
    }
    let path = local_backend.volume_path(&config.name);
    materialize_volume_path(&config, &path).await?;

    // Serialize labels.
    let labels_json = if config.labels.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&config.labels)?)
    };

    // The filesystem artifact is already materialized. If the DB insert
    // loses a race, remove it so no orphaned final path remains.
    let now = chrono::Utc::now().naive_utc();
    let model = volume_entity::ActiveModel {
        name: Set(config.name.clone()),
        kind: Set(config.kind.as_str().to_string()),
        quota_mib: Set(config.quota_mib.map(|v| v as i32)),
        size_bytes: Set(None),
        capacity_bytes: Set(config.capacity_mib.map(|mib| i64::from(mib) * 1024 * 1024)),
        disk_format: Set((config.kind == VolumeKind::Disk).then(|| "raw".to_string())),
        disk_fstype: Set((config.kind == VolumeKind::Disk).then(|| "ext4".to_string())),
        labels: Set(labels_json),
        created_at: Set(Some(now)),
        updated_at: Set(Some(now)),
        ..Default::default()
    };

    if let Err(e) = volume_entity::Entity::insert(model)
        .exec(pools.write())
        .await
    {
        let _ = tokio::fs::remove_dir_all(&path).await;
        return Err(e.into());
    }

    Ok(Volume::from_local(
        backend,
        VolumeLocalState {
            path,
            kind: config.kind,
            capacity_bytes: config.capacity_mib.map(|mib| u64::from(mib) * 1024 * 1024),
            disk_format: (config.kind == VolumeKind::Disk).then(|| "raw".to_string()),
            disk_fstype: (config.kind == VolumeKind::Disk).then(|| "ext4".to_string()),
        },
        config.name,
    ))
}

/// Local get path. Loads a volume row by name and wraps it in a
/// [`VolumeHandle`] bound to the supplied backend.
pub(crate) async fn get_local(
    backend: Arc<dyn Backend>,
    name: &str,
) -> MicrosandboxResult<VolumeHandle> {
    let local_backend = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::Unsupported {
            feature: "Volume::get_local".into(),
            available_when: "with a LocalBackend".into(),
        })?;
    let db = local_backend.db().await?.read();

    let model = volume_entity::Entity::find()
        .filter(volume_entity::Column::Name.eq(name))
        .one(db)
        .await?
        .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.into()))?;

    let handle = VolumeHandle::from_local_model(backend.clone(), model);
    Ok(handle)
}

/// Local list path. Returns all volumes ordered newest-first.
pub(crate) async fn list_local(backend: Arc<dyn Backend>) -> MicrosandboxResult<Vec<VolumeHandle>> {
    let local_backend = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::Unsupported {
            feature: "Volume::list_local".into(),
            available_when: "with a LocalBackend".into(),
        })?;
    let db = local_backend.db().await?.read();

    let models = volume_entity::Entity::find()
        .order_by_desc(volume_entity::Column::CreatedAt)
        .all(db)
        .await?;

    Ok(models
        .into_iter()
        .map(|m| VolumeHandle::from_local_model(backend.clone(), m))
        .collect())
}

/// Local remove path. Deletes the DB record first, then the directory.
pub(crate) async fn remove_local(backend: Arc<dyn Backend>, name: &str) -> MicrosandboxResult<()> {
    let local_backend = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::Unsupported {
            feature: "Volume::remove_local".into(),
            available_when: "with a LocalBackend".into(),
        })?;
    let pools = local_backend.db().await?;

    let model = volume_entity::Entity::find()
        .filter(volume_entity::Column::Name.eq(name))
        .one(pools.read())
        .await?
        .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.into()))?;
    let handle = VolumeHandle::from_local_model(backend.clone(), model);
    let _name_lock = lock_volume_name(local_backend, name)?;
    let _disk_lock = lock_disk_volume_for_remove(&handle)?;
    ensure_volume_not_referenced_by_active_sandbox(pools.read(), name).await?;

    volume_entity::Entity::delete_by_id(handle.local().expect("local handle").db_id)
        .exec(pools.write())
        .await?;

    let path = local_backend.volume_path(name);
    if path.exists() {
        tokio::fs::remove_dir_all(&path).await?;
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Materialize a volume under a temporary sibling directory, then atomically
/// rename it into place. This keeps failed disk formatting from exposing a
/// half-populated final volume path.
pub(crate) async fn materialize_volume_path(
    config: &VolumeConfig,
    path: &Path,
) -> MicrosandboxResult<()> {
    let parent = path.parent().ok_or_else(|| {
        MicrosandboxError::InvalidConfig(format!(
            "volume path has no parent directory: {}",
            path.display()
        ))
    })?;

    tokio::fs::create_dir_all(parent).await?;
    if path.exists() {
        return Err(MicrosandboxError::VolumeAlreadyExists(config.name.clone()));
    }

    let temp = tempfile::Builder::new()
        .prefix(&format!(".{}.", config.name))
        .tempdir_in(parent)?;
    provision_volume_path(config, temp.path()).await?;
    tokio::fs::rename(temp.path(), path).await?;
    let _ = temp.keep();
    Ok(())
}

pub(crate) async fn provision_volume_path(
    config: &VolumeConfig,
    path: &Path,
) -> MicrosandboxResult<()> {
    tokio::fs::create_dir_all(path).await?;

    match config.kind {
        VolumeKind::Directory => Ok(()),
        VolumeKind::Disk => {
            let capacity_mib = config.capacity_mib.ok_or_else(|| {
                MicrosandboxError::InvalidConfig(
                    "disk named volumes require .size(...) / --size".into(),
                )
            })?;
            let disk_path = path.join("disk.raw");
            let options = Ext4FormatOptions {
                size_bytes: u64::from(capacity_mib) * 1024 * 1024,
                ..Default::default()
            };
            tokio::task::spawn_blocking(move || ext4::format_ext4(&disk_path, &options))
                .await
                .map_err(|e| MicrosandboxError::Custom(format!("ext4 format task failed: {e}")))?
                .map_err(|e| {
                    MicrosandboxError::Custom(format!("failed to create disk.raw: {e}"))
                })?;
            Ok(())
        }
    }
}

pub(crate) fn lock_volume_name(local: &LocalBackend, name: &str) -> MicrosandboxResult<File> {
    let volumes_dir = local.volumes_dir();
    std::fs::create_dir_all(&volumes_dir)?;
    let locks_dir = volumes_dir.join(".locks");
    std::fs::create_dir_all(&locks_dir)?;
    let path = locks_dir.join(format!("{name}.lock"));
    let file = std::fs::OpenOptions::new()
        .create(true)
        .read(true)
        .truncate(false)
        .write(true)
        .open(&path)?;

    #[cfg(unix)]
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }

    Ok(file)
}

fn lock_disk_volume_for_remove(handle: &VolumeHandle) -> MicrosandboxResult<Option<File>> {
    if handle.kind() != VolumeKind::Disk {
        return Ok(None);
    }

    let Some(path) = handle.disk_path() else {
        return Ok(None);
    };
    if !path.exists() {
        return Ok(None);
    }

    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .map_err(|err| {
            MicrosandboxError::InvalidConfig(format!(
                "open disk named volume {} for removal: {err}",
                handle.name()
            ))
        })?;

    #[cfg(unix)]
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        let err = std::io::Error::last_os_error();
        if matches!(err.kind(), std::io::ErrorKind::WouldBlock) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "volume {:?} is currently attached by a running sandbox",
                handle.name()
            )));
        }
        return Err(MicrosandboxError::InvalidConfig(format!(
            "lock disk named volume {} for removal: {err}",
            handle.name()
        )));
    }

    Ok(Some(file))
}

async fn ensure_volume_not_referenced_by_active_sandbox<C>(
    db: &C,
    name: &str,
) -> MicrosandboxResult<()>
where
    C: ConnectionTrait,
{
    let sandboxes = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Status.is_in([
            SandboxStatus::Running,
            SandboxStatus::Draining,
            SandboxStatus::Paused,
        ]))
        .all(db)
        .await?;

    for sandbox in sandboxes {
        let config: SandboxConfig = serde_json::from_str(&sandbox.config)?;
        if config.spec.mounts.iter().any(|mount| {
            matches!(
                mount,
                VolumeMount::Named {
                    name: mounted_name,
                    ..
                } if mounted_name == name
            )
        }) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "volume {name:?} is attached to active sandbox {:?}",
                sandbox.name
            )));
        }
    }

    Ok(())
}

pub(crate) fn validate_volume_config(config: &VolumeConfig) -> MicrosandboxResult<()> {
    match config.kind {
        VolumeKind::Directory => {
            if config.capacity_mib.is_some() {
                return Err(MicrosandboxError::InvalidConfig(
                    "directory named volumes do not support .size(...) / --size".into(),
                ));
            }
            Ok(())
        }
        VolumeKind::Disk => {
            if config.capacity_mib.is_none() {
                return Err(MicrosandboxError::InvalidConfig(
                    "disk named volumes require .size(...) / --size".into(),
                ));
            }
            if config.quota_mib.is_some() {
                return Err(MicrosandboxError::InvalidConfig(
                    "disk named volumes do not support .quota(...)".into(),
                ));
            }
            Ok(())
        }
    }
}

/// Validate that a volume name is safe for use as a directory name.
///
/// Names must start with an alphanumeric character and contain only
/// alphanumeric characters, dots, hyphens, and underscores.
pub(crate) fn validate_volume_name(name: &str) -> MicrosandboxResult<()> {
    if name.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "volume name must not be empty".into(),
        ));
    }

    let valid = name
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_alphanumeric())
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '.' || c == '-' || c == '_');

    if !valid {
        return Err(MicrosandboxError::InvalidConfig(format!(
            "volume name must start with an alphanumeric character and contain only \
             alphanumeric characters, dots, hyphens, and underscores: {name}"
        )));
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use sea_orm::{ActiveModelTrait, Set};

    use crate::backend::{Backend, LocalBackend};
    use crate::sandbox::{HostPermissions, MountOptions, SandboxStatus, StatVirtualization};

    use super::*;

    #[tokio::test]
    async fn test_remove_local_rejects_active_named_volume_reference() {
        let temp = tempfile::tempdir().unwrap();
        let local = Arc::new(
            LocalBackend::builder()
                .home(temp.path().join("home"))
                .build()
                .await
                .unwrap(),
        );
        let backend: Arc<dyn Backend> = local.clone();
        create_local(
            backend.clone(),
            VolumeConfig {
                name: "active-cache".to_string(),
                kind: VolumeKind::Directory,
                quota_mib: None,
                capacity_mib: None,
                labels: Vec::new(),
            },
        )
        .await
        .unwrap();

        let config = SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                name: "active-sandbox".to_string(),
                mounts: vec![VolumeMount::Named {
                    name: "active-cache".to_string(),
                    guest: "/cache".to_string(),
                    create: None,
                    options: MountOptions::default(),
                    stat_virtualization: StatVirtualization::Strict,
                    host_permissions: HostPermissions::Private,
                    follow_root_symlinks: false,
                }],
                ..Default::default()
            },
            ..Default::default()
        };
        sandbox_entity::ActiveModel {
            name: Set("active-sandbox".to_string()),
            config: Set(serde_json::to_string(&config).unwrap()),
            status: Set(SandboxStatus::Running),
            ephemeral: Set(false),
            created_at: Set(Some(chrono::Utc::now().naive_utc())),
            updated_at: Set(Some(chrono::Utc::now().naive_utc())),
            ..Default::default()
        }
        .insert(local.db().await.unwrap().write())
        .await
        .unwrap();

        let err = remove_local(backend, "active-cache").await.unwrap_err();

        assert!(err.to_string().contains("attached to active sandbox"));
        assert!(local.volume_path("active-cache").exists());
    }
}
