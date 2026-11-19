//! Unified persistent volume resource, creation and deletion.

use super::{VolumeConfig, VolumeFs, VolumeId, VolumeKind, identity};

#[cfg(feature = "local")]
use std::fs::File;
#[cfg(all(feature = "local", unix))]
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;

#[cfg(feature = "local")]
use microsandbox_image::ext4::{self, Ext4FormatOptions};
#[cfg(feature = "local")]
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, EntityTrait, QueryFilter, QueryOrder, Set,
    Statement,
};

#[cfg(feature = "local")]
use crate::context::local::creation::CreationStorage;
use crate::context::{Context, ContextKind, VolumeInner, VolumeLocalState, VolumeRemoteState};
use crate::{MicrosandboxError, MicrosandboxResult, error::Operation, size::Mebibytes};
#[cfg(feature = "local")]
use crate::{
    context::LocalContext,
    db::entity::{sandbox as sandbox_entity, volume as volume_entity},
    sandbox::{SandboxConfig, SandboxStatus, VolumeMount},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A persistent volume with a stable identity and retained context.
/// Creation, lookup and listing all return this same type. Dropping it does not delete storage.
#[derive(Clone)]
pub struct Volume {
    backend: Arc<dyn Context>,
    inner: Arc<VolumeInner>,
    id: VolumeId,
    name: String,
    fs_target: String,
}

/// Builder for creating a volume.
pub struct VolumeBuilder {
    context: Arc<dyn Context>,
    config: VolumeConfig,
}

//--------------------------------------------------------------------------------------------------
// Methods: Volume (static)
//--------------------------------------------------------------------------------------------------

impl Volume {
    /// The captured destination. This performs no I/O or allocation.
    pub fn context(&self) -> &dyn Context {
        self.backend.as_ref()
    }

    /// Stable identity of this persisted resource, independent of its reusable name.
    pub fn id(&self) -> &VolumeId {
        &self.id
    }

    /// Host storage path, unavailable for remote volumes.
    pub fn path(&self) -> MicrosandboxResult<&Path> {
        self.local_state()
            .map(|state| state.path.as_path())
            .ok_or_else(|| MicrosandboxError::local_only(Operation::VolumePath))
    }

    /// Start building a new named volume. Call `.create()` on the returned
    /// builder to persist it.
    pub fn builder(name: impl Into<String>) -> VolumeBuilder {
        VolumeBuilder::new(name)
    }

    /// Provision a volume.
    ///
    /// Uses the configured backend, which defaults to local. For an explicit destination,
    /// use `Volume::ctx(&context).create(config)`. The returned resource retains it.
    ///
    /// Locally fails with [`MicrosandboxError::VolumeAlreadyExists`] if a
    /// volume with the same name already exists.
    pub async fn create(config: VolumeConfig) -> MicrosandboxResult<Self> {
        let backend = crate::context::configured_context();
        backend.volume_ops().create(backend.clone(), config).await
    }

    /// Look up a unified volume on the configured backend.
    pub async fn get(name: &str) -> MicrosandboxResult<Volume> {
        let backend = crate::context::configured_context();
        backend.volume_ops().get(backend.clone(), name).await
    }

    /// Get the cloud account's always-present default volume.
    ///
    /// The local backend deliberately returns [`MicrosandboxError::Unsupported`]
    /// so a missing cloud credential can never turn this into host filesystem access.
    pub async fn get_default() -> MicrosandboxResult<Volume> {
        let backend = crate::context::configured_context();
        backend.volume_ops().get_default(backend.clone()).await
    }

    /// List unified volumes on the configured backend.
    pub async fn list() -> MicrosandboxResult<Vec<Volume>> {
        let backend = crate::context::configured_context();
        backend.volume_ops().list(backend.clone()).await
    }

    /// Remove the name-selected volume on the configured backend.
    pub async fn remove(name: &str) -> MicrosandboxResult<()> {
        let backend = crate::context::configured_context();
        backend.volume_ops().remove(backend.clone(), name).await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Volume
//--------------------------------------------------------------------------------------------------

impl Volume {
    /// Build a handle from a local volume DB row.
    ///
    /// Derives the host-side path from the `backend`'s [`LocalContext`]
    /// view — callers don't have to thread the same backend in twice.
    /// Panics if `backend` is not a [`LocalContext`]; this is the local
    /// construction path and is only called from `get_local` / `list_local`,
    /// which have already routed through the local trait impl.
    #[cfg(feature = "local")]
    pub(crate) fn from_local_model(backend: Arc<dyn Context>, model: volume_entity::Model) -> Self {
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
            .expect("from_local_model called outside a LocalContext context");
        let path = local_backend.volume_path(&model.name);
        let name = model.name;
        Self {
            backend,
            id: VolumeId::local(model.id),
            inner: Arc::new(VolumeInner::Local(VolumeLocalState {
                db_id: model.id,
                path,
                kind: VolumeKind::from_db_value(&model.kind),
                quota_mib: model.quota_mib.map(|v| v.max(0) as u32),
                used_bytes: model.size_bytes.and_then(|bytes| u64::try_from(bytes).ok()),
                capacity_bytes: model.capacity_bytes.map(|v| v.max(0) as u64),
                disk_format: model.disk_format,
                disk_fstype: model.disk_fstype,
                labels,
                created_at: model.created_at.map(|dt| dt.and_utc()),
            })),
            fs_target: format!("local-id:{}:{name}", model.id),
            name,
        }
    }

    /// Build a handle from the cloud's volume snapshot.
    ///
    /// The org's shared default volume has no name and carries an empty one
    /// here; it is addressed by kind, not name.
    #[cfg(feature = "cloud")]
    pub(crate) fn from_cloud(
        backend: Arc<dyn Context>,
        cloud: VolumeRemoteState,
        name: String,
    ) -> Self {
        Self {
            backend,
            fs_target: format!("cloud-id:{}", cloud.id),
            id: VolumeId::remote(&cloud.id),
            inner: Arc::new(VolumeInner::Cloud(cloud)),
            name,
        }
    }

    /// Name captured at creation or lookup; not a live rename observation.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The retained context kind; this does not perform I/O.
    pub fn context_kind(&self) -> ContextKind {
        self.backend.kind()
    }

    /// Local-only handle state. Returns `Some` for local-backed handles.
    pub fn local_state(&self) -> Option<&VolumeLocalState> {
        match self.inner.as_ref() {
            VolumeInner::Local(s) => Some(s),
            VolumeInner::Cloud(_) => None,
        }
    }

    /// Cloud-only handle state. Returns `Some` for cloud-backed handles.
    pub fn remote_state(&self) -> Option<&VolumeRemoteState> {
        match self.inner.as_ref() {
            VolumeInner::Cloud(s) => Some(s),
            VolumeInner::Local(_) => None,
        }
    }

    /// Whether this is the cloud account's always-present default volume.
    pub fn is_default(&self) -> bool {
        matches!(
            self.inner.as_ref(), VolumeInner::Cloud(state)
                if state.kind == crate::context::CloudVolumeKind::Host
        )
    }

    /// Maximum storage in MiB, or `None` if unlimited.
    pub(crate) fn quota_mib_snapshot(&self) -> Option<u32> {
        match self.inner.as_ref() {
            VolumeInner::Local(s) => s.quota_mib,
            // Cloud volumes are elastic volumes; their per-volume limit
            // surfaces here (in MiB). Absent = no per-volume limit.
            VolumeInner::Cloud(s) => s
                .capacity_bytes
                .map(|bytes| u32::try_from(bytes.div_ceil(1024 * 1024)).unwrap_or(u32::MAX)),
        }
    }

    /// Storage kind for this volume.
    pub fn kind(&self) -> VolumeKind {
        match self.inner.as_ref() {
            VolumeInner::Local(s) => s.kind,
            // CloudVolumeKind distinguishes the org's shared host volume from
            // a user-created managed volume; it does not describe the storage
            // representation. Both are directory volumes from the SDK's point
            // of view. The cloud-specific lifecycle kind remains available
            // through `cloud().kind`.
            VolumeInner::Cloud(_) => VolumeKind::Directory,
        }
    }

    /// Disk capacity in bytes for disk volumes.
    pub(crate) fn capacity_bytes_snapshot(&self) -> Option<u64> {
        match self.inner.as_ref() {
            VolumeInner::Local(s) => s.capacity_bytes,
            // The cloud's per-volume storage limit, byte-exact. `quota_mib`
            // reports the same limit in MiB. Absent = no per-volume limit.
            VolumeInner::Cloud(s) => s.capacity_bytes,
        }
    }

    /// Disk image format for disk volumes.
    pub fn disk_format(&self) -> Option<&str> {
        match self.inner.as_ref() {
            VolumeInner::Local(s) => s.disk_format.as_deref(),
            VolumeInner::Cloud(_) => None,
        }
    }

    /// Inner disk filesystem for disk volumes.
    pub fn disk_fstype(&self) -> Option<&str> {
        match self.inner.as_ref() {
            VolumeInner::Local(s) => s.disk_fstype.as_deref(),
            VolumeInner::Cloud(_) => None,
        }
    }

    /// Host path to the managed raw disk image for disk volumes.
    pub fn disk_path(&self) -> Option<PathBuf> {
        match self.inner.as_ref() {
            VolumeInner::Local(s) if s.kind == VolumeKind::Disk => Some(s.path.join("disk.raw")),
            _ => None,
        }
    }

    /// Key-value labels for organizing and filtering volumes.
    pub(crate) fn labels_snapshot(&self) -> &[(String, String)] {
        match self.inner.as_ref() {
            VolumeInner::Local(s) => &s.labels,
            VolumeInner::Cloud(s) => &s.labels,
        }
    }

    /// When this volume was first created, if recorded.
    pub fn created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        match self.inner.as_ref() {
            VolumeInner::Local(s) => s.created_at,
            VolumeInner::Cloud(s) => Some(s.created_at),
        }
    }

    /// Operate on the volume's filesystem (read, write, list files) without
    /// needing a running sandbox. Routes through the bound backend.
    pub fn fs(&self) -> VolumeFs<'_> {
        VolumeFs::new(self.backend.clone(), &self.fs_target)
    }

    /// Remove this volume.
    ///
    /// Locally deletes the files before the database record, so interrupted
    /// removal can be retried.
    /// Remote deletion addresses the captured ID directly. A same-name replacement is untouched.
    pub async fn destroy(&self) -> MicrosandboxResult<()> {
        if self.is_default() {
            return Err(MicrosandboxError::unsupported(
                Operation::VolumeRemove,
                crate::error::UnsupportedReason::NotAvailable(
                    "the default volume cannot be removed".into(),
                ),
            ));
        }
        self.backend
            .volume_ops()
            .destroy(self.backend.clone(), &self.fs_target)
            .await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: VolumeBuilder
//--------------------------------------------------------------------------------------------------

impl VolumeBuilder {
    /// The destination retained before deferred creation.
    pub fn context(&self) -> &dyn Context {
        self.context.as_ref()
    }

    /// Start building a volume with the given name. Names must contain only
    /// alphanumeric characters, dots, hyphens, and underscores.
    pub fn new(name: impl Into<String>) -> Self {
        Self::for_context(crate::context::configured_context(), name)
    }

    pub(crate) fn for_context(context: Arc<dyn Context>, name: impl Into<String>) -> Self {
        Self {
            context,
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

    /// Create a persistent volume in the builder’s retained destination.
    /// Fails with [`MicrosandboxError::VolumeAlreadyExists`] for an existing name.
    pub async fn create(self) -> MicrosandboxResult<Volume> {
        self.context
            .volume_ops()
            .create(self.context.clone(), self.config)
            .await
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<VolumeConfig> for VolumeBuilder {
    fn from(config: VolumeConfig) -> Self {
        Self {
            context: crate::context::configured_context(),
            config,
        }
    }
}

impl std::fmt::Debug for Volume {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Volume")
            .field("name", &self.name)
            .field("backend_kind", &self.backend.kind())
            .finish()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Local lifecycle (called from the LocalContext VolumeOps impl)
//--------------------------------------------------------------------------------------------------

/// Reserve a volume before writing its files. Interrupted creation remains removable.
#[cfg(feature = "local")]
pub(crate) async fn create_local(
    backend: Arc<dyn Context>,
    config: VolumeConfig,
) -> MicrosandboxResult<Volume> {
    tracing::debug!(name = %config.name, quota_mib = ?config.quota_mib, "Volume::create");
    validate_volume_name(&config.name)?;
    validate_volume_config(&config)?;

    let local_backend = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::local_only(Operation::VolumeCreate))?;
    let pools = local_backend.db().await?;
    let name_lock = lock_volume_name(local_backend, &config.name).await?;

    // Check for existing volume.
    let existing = volume_entity::Entity::find()
        .filter(volume_entity::Column::Name.eq(&config.name))
        .one(pools.read())
        .await?;

    if let Some(existing) = existing {
        local_backend
            .ensure_volume_available(existing.id, None)
            .await?;

        return Err(MicrosandboxError::VolumeAlreadyExists(config.name));
    }

    let path = local_backend.volume_path(&config.name);
    if tokio::fs::try_exists(&path).await? {
        return Err(MicrosandboxError::VolumeAlreadyExists(config.name));
    }

    // Serialize labels.
    let labels_json = if config.labels.is_empty() {
        None
    } else {
        Some(serde_json::to_string(&config.labels)?)
    };

    // Reserve the row and recovery marker atomically before any filesystem work.
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

    let volume_id = pools
        .write()
        .transaction(|txn| {
            let model = model.clone();

            async move {
                let id = volume_entity::Entity::insert(model)
                    .exec(&txn)
                    .await?
                    .last_insert_id;

                txn.execute_raw(Statement::from_sql_and_values(
                    DatabaseBackend::Sqlite,
                    "UPDATE volume SET creation_state = 'creating' WHERE id = ?",
                    [id.into()],
                ))
                .await?;

                Ok::<_, MicrosandboxError>((txn, id))
            }
        })
        .await?;

    if let Err(error) = local_backend
        .materialize_volume(&config, volume_id, name_lock.clone())
        .await
    {
        return Err(
            match local_backend
                .remove_volume_storage(volume_id, path, name_lock, None)
                .await
            {
                Ok(()) => error,
                Err(cleanup) => MicrosandboxError::Runtime(format!(
                    "{error}; volume cleanup remains pending: {cleanup}"
                )),
            },
        );
    }

    let model = volume_entity::Entity::find_by_id(volume_id)
        .one(pools.read())
        .await?
        .ok_or_else(|| MicrosandboxError::VolumeNotFound(config.name.clone()))?;
    Ok(Volume::from_local_model(backend.clone(), model))
}

/// Local get path. Loads a volume row by name and wraps it in a
/// [`Volume`] bound to the supplied backend.
#[cfg(feature = "local")]
pub(crate) async fn get_local(backend: Arc<dyn Context>, name: &str) -> MicrosandboxResult<Volume> {
    let local_backend = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::local_only(Operation::VolumeGet))?;
    let db = local_backend.db().await?.read();

    let model = volume_entity::Entity::find()
        .filter(volume_entity::Column::Name.eq(name))
        .one(db)
        .await?
        .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.into()))?;

    local_backend
        .ensure_volume_available(model.id, None)
        .await?;

    let handle = Volume::from_local_model(backend.clone(), model);
    Ok(handle)
}

/// Local list path. Returns all volumes ordered newest-first.
#[cfg(feature = "local")]
pub(crate) async fn list_local(backend: Arc<dyn Context>) -> MicrosandboxResult<Vec<Volume>> {
    let local_backend = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::local_only(Operation::VolumeList))?;
    let db = local_backend.db().await?.read();

    let models = volume_entity::Entity::find()
        .order_by_desc(volume_entity::Column::CreatedAt)
        .all(db)
        .await?;

    Ok(models
        .into_iter()
        .map(|m| Volume::from_local_model(backend.clone(), m))
        .collect())
}

/// Local remove path. Keeps the DB record until the directory is removed.
#[cfg(feature = "local")]
pub(crate) async fn remove_local(backend: Arc<dyn Context>, name: &str) -> MicrosandboxResult<()> {
    remove_local_identity(backend, name, None).await
}

#[cfg(feature = "local")]
pub(crate) async fn destroy_local(
    backend: Arc<dyn Context>,
    target: &str,
) -> MicrosandboxResult<()> {
    let (name, expected) = identity::local_target(target)?;
    let expected = expected.ok_or_else(|| {
        MicrosandboxError::InvalidConfig("volume destruction requires a captured identity".into())
    })?;
    remove_local_identity(backend, name, Some(expected)).await
}

#[cfg(feature = "local")]
async fn remove_local_identity(
    backend: Arc<dyn Context>,
    name: &str,
    expected: Option<i32>,
) -> MicrosandboxResult<()> {
    let local_backend = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::local_only(Operation::VolumeRemove))?;
    // The name now reaches the lock-file path before a DB lookup. Preserve the
    // previous not-found result for names that could never be stored as volumes.
    if validate_volume_name(name).is_err() {
        return Err(MicrosandboxError::VolumeNotFound(name.into()));
    }
    let pools = local_backend.db().await?;
    let name_lock = lock_volume_name(local_backend, name).await?;

    let model = volume_entity::Entity::find()
        .filter(volume_entity::Column::Name.eq(name))
        .one(pools.read())
        .await?
        .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.into()))?;
    if expected.is_some_and(|id| id != model.id) {
        return Err(MicrosandboxError::VolumeNotFound(name.to_owned()));
    }
    if !local_backend.volume_creation_pending(model.id).await? {
        local_backend
            .ensure_volume_available(model.id, None)
            .await?;
    }

    let handle = Volume::from_local_model(backend.clone(), model);
    let disk_lock = lock_disk_volume_for_remove(&handle)?;
    ensure_volume_not_referenced_by_active_sandbox(pools.read(), name).await?;

    local_backend
        .remove_volume_storage(
            handle.local_state().expect("local handle").db_id,
            local_backend.volume_path(name),
            name_lock,
            disk_lock,
        )
        .await
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "local")]
pub(crate) async fn provision_volume_path(
    config: &VolumeConfig,
    path: &CreationStorage,
) -> MicrosandboxResult<()> {
    let path = path.clone();
    let config = config.clone();
    tokio::task::spawn_blocking(move || provision_volume_path_sync(&config, &path))
        .await
        .map_err(|error| MicrosandboxError::Runtime(format!("volume path: {error}")))?
}

#[cfg(feature = "local")]
pub(crate) fn provision_volume_path_sync(
    config: &VolumeConfig,
    path: &Path,
) -> MicrosandboxResult<()> {
    std::fs::create_dir_all(path)?;
    if config.kind == VolumeKind::Disk {
        let capacity_mib = config.capacity_mib.ok_or_else(|| {
            MicrosandboxError::InvalidConfig(
                "disk named volumes require .size(...) / --size".into(),
            )
        })?;
        let options = Ext4FormatOptions {
            size_bytes: u64::from(capacity_mib) * 1024 * 1024,
            ..Default::default()
        };
        ext4::format_ext4(&path.join("disk.raw"), &options).map_err(|error| {
            MicrosandboxError::Custom(format!("failed to create disk.raw: {error}"))
        })?;
    }
    Ok(())
}

#[cfg(feature = "local")]
pub(crate) async fn lock_volume_name(
    local: &LocalContext,
    name: &str,
) -> MicrosandboxResult<Arc<File>> {
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

    // A sibling create can hold this lock while awaiting its guest's readiness. Never block
    // the task polling both creates, and keep the file owned by this future during each wait
    // so cancellation releases it without leaving a background lock-acquisition worker.
    // Use the shared primitive on Windows too: a no-op would let batch siblings provision
    // the same name concurrently before either publishes its volume record.
    while !microsandbox_utils::process_lock::try_lock_exclusive(&file)? {
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }

    Ok(Arc::new(file))
}

#[cfg(feature = "local")]
fn lock_disk_volume_for_remove(handle: &Volume) -> MicrosandboxResult<Option<File>> {
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

#[cfg(feature = "local")]
async fn ensure_volume_not_referenced_by_active_sandbox<C>(
    db: &C,
    name: &str,
) -> MicrosandboxResult<()>
where
    C: ConnectionTrait,
{
    let sandboxes = microsandbox_db::catalog::sandbox_query(db)
        .await?
        .filter(sandbox_entity::Column::Status.is_in([
            // A cancelled create can retain its provisional row while the runtime still
            // owns startup. Its named mounts are no less live than a Running sandbox's.
            SandboxStatus::Starting,
            SandboxStatus::Running,
            SandboxStatus::Draining,
            SandboxStatus::Paused,
        ]))
        .all(db)
        .await?;

    for sandbox in sandboxes {
        let config: SandboxConfig = serde_json::from_str::<SandboxConfig>(&sandbox.config)?;
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
    #[cfg(feature = "cloud")]
    use std::sync::Arc;

    #[cfg(feature = "local")]
    use sea_orm::{ActiveModelTrait, Set};

    #[cfg(feature = "local")]
    use crate::context::LocalContext;
    #[cfg(feature = "cloud")]
    use crate::context::{CloudVolumeKind, CloudVolumeStatus, Context, VolumeRemoteState};
    #[cfg(feature = "local")]
    use crate::sandbox::{HostPermissions, MountOptions, SandboxStatus, StatVirtualization};

    use super::*;

    #[cfg(feature = "local")]
    #[tokio::test]
    async fn unified_volume_retains_identity_across_create_get_list_and_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let context = crate::test_support::local_backend_builder(temp.path().join("home"))
            .build()
            .unwrap();
        let volumes = context.volumes();
        let created: Volume = volumes
            .builder("shared")
            .quota(64)
            .label("owner", "test")
            .create()
            .await
            .unwrap();
        let fetched: Volume = volumes.get("shared").await.unwrap();
        let listed: Vec<Volume> = volumes.list().await.unwrap();
        assert_eq!(created.id(), fetched.id());
        assert_eq!(listed[0].id(), created.id());
        assert_eq!(
            created.labels().await.unwrap(),
            &[("owner".into(), "test".into())]
        );
        assert_eq!(created.quota_mib().await.unwrap(), Some(64));
        assert!(created.created_at().is_some());
        // An existing resource must observe edits made by another catalog client.
        context.db().await.unwrap().write().inner().execute_unprepared(
            r#"UPDATE volume SET quota_mib = 128, labels = '[["owner","updated"]]' WHERE name = 'shared'"#,
        ).await.unwrap();
        let observation = fetched.info().await.unwrap();
        assert_eq!(observation.quota_mib, Some(128));
        assert_eq!(observation.labels, vec![("owner".into(), "updated".into())]);
        created.fs().write("marker", b"old".to_vec()).await.unwrap();
        fetched.destroy().await.unwrap();
        let replacement = volumes.builder("shared").create().await.unwrap();
        assert!(created.info().await.is_err());
        replacement
            .fs()
            .write("marker", b"replacement".to_vec())
            .await
            .unwrap();
        assert_ne!(created.id(), replacement.id());
        assert!(matches!(
            created.destroy().await,
            Err(MicrosandboxError::VolumeNotFound(_))
        ));
        assert!(matches!(
            created.fs().read("marker").await,
            Err(MicrosandboxError::VolumeNotFound(_))
        ));
        assert!(matches!(
            created.fs().write("marker", b"wrong".to_vec()).await,
            Err(MicrosandboxError::VolumeNotFound(_))
        ));
        assert_eq!(
            replacement.fs().read("marker").await.unwrap().as_ref(),
            b"replacement"
        );
        drop(context);
        replacement.destroy().await.unwrap();
    }

    #[cfg(feature = "cloud")]
    #[tokio::test]
    async fn destroy_remote_volume_uses_captured_id_without_name_lookup() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let context = crate::test_support::cloud_backend(
            format!("http://{}", listener.local_addr().unwrap()),
            "test-key",
        )
        .unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut request = String::new();
            loop {
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                if line == "\r\n" || line.is_empty() {
                    break;
                }
                request.push_str(&line);
            }
            assert!(request.starts_with("DELETE /v1/volumes/original-id HTTP/1.1\r\n"));
            assert!(
                request
                    .to_ascii_lowercase()
                    .contains("authorization: bearer test-key")
            );
            let body = r#"{"message":"deleted"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            stream
                .get_mut()
                .write_all(response.as_bytes())
                .await
                .unwrap();
        });
        let now = chrono::Utc::now();
        let volume = Volume::from_cloud(
            Arc::new(context),
            VolumeRemoteState {
                id: "original-id".into(),
                used_bytes: None,
                capacity_bytes: None,
                labels: Vec::new(),
                kind: CloudVolumeKind::Managed,
                status: CloudVolumeStatus::Active,
                created_at: now,
                updated_at: now,
            },
            "reused-name".into(),
        );
        volume.destroy().await.unwrap();
        server.await.unwrap();
    }

    #[cfg(feature = "local")]
    #[tokio::test]
    async fn failed_directory_removal_keeps_volume_available_for_retry() {
        let temp = tempfile::tempdir().unwrap();
        let local = Arc::new(
            crate::test_support::local_backend_builder(temp.path().join("home"))
                .build()
                .unwrap(),
        );
        let backend: Arc<dyn Context> = local.clone();
        create_local(
            backend.clone(),
            VolumeConfig {
                name: "retryable".into(),
                kind: VolumeKind::Directory,
                quota_mib: None,
                capacity_mib: None,
                labels: Vec::new(),
            },
        )
        .await
        .unwrap();

        let path = local.volume_path("retryable");
        let parked = temp.path().join("parked-volume");
        std::fs::write(path.join("marker"), b"volume data").unwrap();
        std::fs::rename(&path, &parked).unwrap();
        // A regular file at the volume path makes remove_dir_all fail on every OS.
        std::fs::write(&path, b"blocked").unwrap();

        assert!(remove_local(backend.clone(), "retryable").await.is_err());
        assert!(get_local(backend.clone(), "retryable").await.is_ok());
        assert_eq!(
            std::fs::read(parked.join("marker")).unwrap(),
            b"volume data"
        );

        std::fs::remove_file(&path).unwrap();
        std::fs::rename(&parked, &path).unwrap();
        remove_local(backend.clone(), "retryable").await.unwrap();
        assert!(!path.exists());
        assert!(matches!(
            get_local(backend, "retryable").await,
            Err(MicrosandboxError::VolumeNotFound(_))
        ));
    }

    #[cfg(feature = "local")]
    #[tokio::test(flavor = "current_thread")]
    async fn named_volume_lock_contention_yields_to_executor() {
        use std::sync::mpsc;
        use std::time::Duration;

        use microsandbox_utils::process_lock::unlock;

        let directory = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(directory.path().join("home"))
            .build()
            .unwrap();
        let winner = lock_volume_name(&local, "shared").await.unwrap();
        let (release_tx, release_rx) = mpsc::channel();
        let holder = std::thread::spawn(move || {
            // Release even if a blocking acquisition stalls the executor, so the
            // regression fails an assertion instead of hanging the test suite.
            let released_by_test = release_rx.recv_timeout(Duration::from_secs(5)).is_ok();
            // Closing alone can leave a lock held by an unrelated parallel test's
            // pre-exec child. Explicit unlock releases it across inherited copies.
            unlock(&winner).unwrap();
            released_by_test
        });

        let mut waiter = Box::pin(lock_volume_name(&local, "shared"));
        let stayed_pending = tokio::time::timeout(Duration::from_millis(20), waiter.as_mut())
            .await
            .is_err();

        // Reaching this point while the holder is still locked proves the timer
        // could run on the same executor as the contended acquisition.
        let _ = release_tx.send(());
        let released_by_test = holder.join().unwrap();
        assert!(
            released_by_test,
            "lock acquisition blocked the executor until the watchdog fired"
        );
        assert!(
            stayed_pending,
            "contended acquisition returned before the holder unlocked"
        );

        let acquired = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("waiter did not acquire the released lock")
            .unwrap();
        unlock(&acquired).unwrap();
    }

    #[test]
    #[cfg(feature = "cloud")]
    fn cloud_managed_volume_reports_directory_storage_kind() {
        let backend: Arc<dyn Context> = Arc::new(
            crate::test_support::cloud_backend("https://msb.example.com", "msb_test_abc").unwrap(),
        );
        let now = chrono::Utc::now();
        let handle = Volume::from_cloud(
            backend,
            VolumeRemoteState {
                id: "volume-id".into(),
                used_bytes: Some(0),
                capacity_bytes: None,
                labels: Vec::new(),
                kind: CloudVolumeKind::Managed,
                status: CloudVolumeStatus::Active,
                created_at: now,
                updated_at: now,
            },
            "data".into(),
        );

        assert_eq!(handle.kind(), VolumeKind::Directory);
        assert_eq!(
            handle.remote_state().unwrap().kind,
            CloudVolumeKind::Managed
        );
        assert_eq!(handle.fs_target, "cloud-id:volume-id");
    }

    #[tokio::test]
    #[cfg(feature = "cloud")]
    async fn cloud_default_volume_is_identified_and_cannot_be_removed() {
        let backend: Arc<dyn Context> = Arc::new(
            crate::test_support::cloud_backend("https://msb.example.com", "msb_test_abc").unwrap(),
        );
        let now = chrono::Utc::now();
        let handle = Volume::from_cloud(
            backend,
            VolumeRemoteState {
                id: "default-volume-id".into(),
                used_bytes: Some(0),
                capacity_bytes: None,
                labels: Vec::new(),
                kind: CloudVolumeKind::Host,
                status: CloudVolumeStatus::Active,
                created_at: now,
                updated_at: now,
            },
            String::new(),
        );

        assert!(handle.is_default());
        assert_eq!(handle.fs_target, "cloud-id:default-volume-id");
        assert!(matches!(
            handle.destroy().await,
            Err(MicrosandboxError::Unsupported { .. })
        ));
    }

    #[cfg(feature = "local")]
    async fn exercise_active_named_volume_reference(status: SandboxStatus) {
        let temp = tempfile::tempdir().unwrap();
        let local = Arc::new(
            LocalContext::builder()
                .config_path(temp.path().join("home").join("config.json"))
                .managed_config_path(temp.path().join("home").join("managed.json"))
                .home(temp.path().join("home"))
                .build()
                .unwrap(),
        );
        let backend: Arc<dyn Context> = local.clone();
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

        let mut config = SandboxConfig {
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
        if status == SandboxStatus::Starting {
            config.checkpoint_restore =
                Some(microsandbox_runtime::launch::CheckpointRestoreConfig {
                    memory_descriptor: false,
                    network_gateway_mac: None,
                    external_mount_policy: Default::default(),
                    external_mounts: Vec::new(),
                    unavailable_disks: Default::default(),
                    local_branch: false,
                    forked: true,
                    closure: temp.path().join("pending-checkpoint"),
                    checkpoint_root: "blake3:pending".into(),
                    checkpoint_id: "pending".into(),
                });
        }
        let sandbox = sandbox_entity::ActiveModel {
            name: Set("active-sandbox".to_string()),
            config: Set(serde_json::to_string(&config).unwrap()),
            status: Set(status),
            ephemeral: Set(false),
            created_at: Set(Some(chrono::Utc::now().naive_utc())),
            updated_at: Set(Some(chrono::Utc::now().naive_utc())),
            ..Default::default()
        }
        .insert(local.db().await.unwrap().write())
        .await
        .unwrap();
        let sentinel = local.volume_path("active-cache").join("sentinel");
        std::fs::write(&sentinel, b"runtime-owned data").unwrap();

        let err = remove_local(backend, "active-cache").await.unwrap_err();

        assert!(err.to_string().contains("attached to active sandbox"));
        assert_eq!(std::fs::read(sentinel).unwrap(), b"runtime-owned data");
        let pools = local.db().await.unwrap();
        assert!(
            volume_entity::Entity::find()
                .filter(volume_entity::Column::Name.eq("active-cache"))
                .one(pools.read())
                .await
                .unwrap()
                .is_some()
        );
        // Removal refusal must leave both the active status and any incomplete restore
        // discriminator untouched; releasing transient creator leases is not completion.
        assert_eq!(
            sandbox_entity::Entity::find_by_id(sandbox.id)
                .one(pools.read())
                .await
                .unwrap(),
            Some(sandbox)
        );
    }

    #[tokio::test]
    #[cfg(feature = "local")]
    async fn test_remove_local_rejects_active_named_volume_reference() {
        exercise_active_named_volume_reference(SandboxStatus::Running).await;
    }

    #[tokio::test]
    #[cfg(feature = "local")]
    async fn test_remove_local_preserves_starting_restore_named_volume_reference() {
        exercise_active_named_volume_reference(SandboxStatus::Starting).await;
    }
}
