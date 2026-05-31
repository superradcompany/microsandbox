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

use std::path::Path;
use std::sync::Arc;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};

use crate::backend::{
    Backend, BackendKind, VolumeHandleInner, VolumeHandleLocalState, VolumeInner, VolumeLocalState,
};
use crate::{
    MicrosandboxError, MicrosandboxResult, db::entity::volume as volume_entity, size::Mebibytes,
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

/// Configuration for creating a volume.
#[derive(Debug, Clone)]
pub struct VolumeConfig {
    /// Volume name.
    pub name: String,

    /// Size quota in MiB (None = unlimited).
    pub quota_mib: Option<u32>,

    /// Labels for organization (JSON-serialized in DB).
    pub labels: Vec<(String, String)>,
}

/// A lightweight handle to a volume.
///
/// Provides metadata access and management operations without requiring a
/// live [`Volume`] instance. Obtained via [`Volume::get`] or [`Volume::list`].
///
/// Like [`Volume`], holds an [`Arc<dyn Backend>`] plus a backend-private
/// [`VolumeHandleInner`] enum; users see a single uniform type.
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
                quota_mib: model.quota_mib.map(|v| v.max(0) as u32),
                used_bytes: model.size_bytes.unwrap_or(0).max(0) as u64,
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

    /// Disk usage snapshot from when this handle was created. Not live —
    /// call [`Volume::get`] again for a fresh reading.
    pub fn used_bytes(&self) -> u64 {
        match &self.inner {
            VolumeHandleInner::Local(s) => s.used_bytes,
            VolumeHandleInner::Cloud(s) => s.used_bytes,
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
                quota_mib: None,
                labels: Vec::new(),
            },
        }
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

    let local_backend = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::Unsupported {
            feature: "Volume::create_local".into(),
            available_when: "with a LocalBackend".into(),
        })?;
    let pools = local_backend.db().await?;

    // Check for existing volume.
    let existing = volume_entity::Entity::find()
        .filter(volume_entity::Column::Name.eq(&config.name))
        .one(pools.read())
        .await?;
    if existing.is_some() {
        return Err(MicrosandboxError::VolumeAlreadyExists(config.name));
    }

    // Serialize labels.
    let labels_json = if config.labels.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&config.labels)?)
    };

    // Insert DB record first — orphaned directories are easier to clean
    // up than orphaned DB records.
    let now = chrono::Utc::now().naive_utc();
    let model = volume_entity::ActiveModel {
        name: Set(config.name.clone()),
        quota_mib: Set(config.quota_mib.map(|v| v as i32)),
        size_bytes: Set(None),
        labels: Set(labels_json),
        created_at: Set(Some(now)),
        updated_at: Set(Some(now)),
        ..Default::default()
    };

    volume_entity::Entity::insert(model)
        .exec(pools.write())
        .await?;

    // Create the volume directory. If this fails, clean up the DB record.
    let path = local_backend.volume_path(&config.name);

    if let Err(e) = tokio::fs::create_dir_all(&path).await {
        let _ = volume_entity::Entity::delete_many()
            .filter(volume_entity::Column::Name.eq(&config.name))
            .exec(pools.write())
            .await;
        return Err(e.into());
    }

    Ok(Volume::from_local(
        backend,
        VolumeLocalState { path },
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

    let handle = VolumeHandle::from_local_model(backend, model);
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

    volume_entity::Entity::delete_by_id(model.id)
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
