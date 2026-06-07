//! Named volume management.
//!
//! Volumes are persistent host-side directories stored under
//! `~/.microsandbox/volumes/<name>/` with metadata tracked in the database.

pub mod fs;
pub use fs::{VolumeFs, VolumeFsReadStream, VolumeFsWriteSink};

use std::{fs::File, os::fd::AsRawFd, path::PathBuf};

use microsandbox_image::ext4::{self, Ext4FormatOptions};
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter, QueryOrder, Set};

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
pub struct Volume {
    name: String,
    path: PathBuf,
    kind: VolumeKind,
    capacity_bytes: Option<u64>,
    disk_format: Option<String>,
    disk_fstype: Option<String>,
}

/// Configuration for creating a volume.
#[derive(Debug, Clone)]
pub struct VolumeConfig {
    /// Volume name.
    pub name: String,

    /// Storage kind.
    pub kind: VolumeKind,

    /// Size quota in MiB (None = unlimited).
    pub quota_mib: Option<u32>,

    /// Disk capacity in MiB. Required for disk volumes.
    pub capacity_mib: Option<u32>,

    /// Labels for organization (JSON-serialized in DB).
    pub labels: Vec<(String, String)>,
}

/// Storage kind for a named volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeKind {
    /// Directory-backed named volume mounted through virtiofs.
    Directory,

    /// Raw ext4 disk-image named volume mounted through virtio-blk.
    Disk,
}

/// A lightweight handle to a volume from the database.
///
/// Provides metadata access and management operations without requiring
/// a live [`Volume`] instance. Obtained via [`Volume::get`] or [`Volume::list`].
#[derive(Debug)]
pub struct VolumeHandle {
    db_id: i32,
    name: String,
    kind: VolumeKind,
    quota_mib: Option<u32>,
    used_bytes: u64,
    capacity_bytes: Option<u64>,
    disk_format: Option<String>,
    disk_fstype: Option<String>,
    labels: Vec<(String, String)>,
    created_at: Option<chrono::DateTime<chrono::Utc>>,
}

/// Builder for creating a volume.
pub struct VolumeBuilder {
    config: VolumeConfig,
}

//--------------------------------------------------------------------------------------------------
// Methods: VolumeHandle
//--------------------------------------------------------------------------------------------------

impl VolumeHandle {
    /// Create a handle from a database entity model.
    pub(crate) fn from_model(model: volume_entity::Model) -> Self {
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

        Self {
            db_id: model.id,
            name: model.name,
            kind: VolumeKind::from_db_value(&model.kind),
            quota_mib: model.quota_mib.map(|v| v.max(0) as u32),
            used_bytes: model.size_bytes.unwrap_or(0).max(0) as u64,
            capacity_bytes: model.capacity_bytes.map(|v| v.max(0) as u64),
            disk_format: model.disk_format,
            disk_fstype: model.disk_fstype,
            labels,
            created_at: model.created_at.map(|dt| dt.and_utc()),
        }
    }

    /// Unique name identifying this volume. Used to reference the volume
    /// in sandbox mount configurations via `v.named(handle.name())`.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Storage kind for this volume.
    pub fn kind(&self) -> VolumeKind {
        self.kind
    }

    /// Maximum storage in MiB, or `None` if unlimited.
    pub fn quota_mib(&self) -> Option<u32> {
        self.quota_mib
    }

    /// Disk usage snapshot from when this handle was created. Not live —
    /// call [`Volume::get`] again for a fresh reading.
    pub fn used_bytes(&self) -> u64 {
        self.used_bytes
    }

    /// Disk capacity in bytes for disk volumes.
    pub fn capacity_bytes(&self) -> Option<u64> {
        self.capacity_bytes
    }

    /// Disk image format for disk volumes. V1 always creates `raw`.
    pub fn disk_format(&self) -> Option<&str> {
        self.disk_format.as_deref()
    }

    /// Inner disk filesystem for disk volumes. V1 always creates `ext4`.
    pub fn disk_fstype(&self) -> Option<&str> {
        self.disk_fstype.as_deref()
    }

    /// Host path to the managed raw disk image for disk volumes.
    pub fn disk_path(&self) -> Option<PathBuf> {
        (self.kind == VolumeKind::Disk).then(|| {
            crate::config::config()
                .volumes_dir()
                .join(&self.name)
                .join("disk.raw")
        })
    }

    /// Key-value labels for organizing and filtering volumes.
    pub fn labels(&self) -> &[(String, String)] {
        &self.labels
    }

    /// When this volume was first created, if recorded.
    pub fn created_at(&self) -> Option<chrono::DateTime<chrono::Utc>> {
        self.created_at
    }

    /// Operate on the volume's host-side directory (read, write, list files)
    /// without needing a running sandbox.
    pub fn fs(&self) -> fs::VolumeFs<'_> {
        let path = crate::config::config().volumes_dir().join(&self.name);
        fs::VolumeFs::from_path(path)
    }

    /// Remove this volume from the database and filesystem.
    ///
    /// Deletes the DB record first, then the directory. An orphaned directory
    /// is easier to detect and clean up than an orphaned DB record.
    pub async fn remove(&self) -> MicrosandboxResult<()> {
        let _name_lock = lock_volume_name(&self.name)?;
        let _disk_lock = lock_disk_volume_for_remove(self)?;
        let pools = crate::db::init_global().await?;
        ensure_volume_not_referenced_by_active_sandbox(pools.read(), &self.name).await?;

        // Delete the DB record first.
        volume_entity::Entity::delete_by_id(self.db_id)
            .exec(pools.write())
            .await?;

        // Then delete the directory.
        let path = crate::config::config().volumes_dir().join(&self.name);
        if path.exists() {
            tokio::fs::remove_dir_all(&path).await?;
        }

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Static
//--------------------------------------------------------------------------------------------------

impl Volume {
    /// Start building a new named volume. Call `.create()` on the returned
    /// builder to persist it.
    pub fn builder(name: impl Into<String>) -> VolumeBuilder {
        VolumeBuilder::new(name)
    }

    /// Provision a volume: creates the host directory and database record.
    /// Fails with [`MicrosandboxError::VolumeAlreadyExists`] if a volume
    /// with the same name already exists.
    pub async fn create(config: VolumeConfig) -> MicrosandboxResult<Self> {
        tracing::debug!(
            name = %config.name,
            kind = config.kind.as_str(),
            quota_mib = ?config.quota_mib,
            capacity_mib = ?config.capacity_mib,
            "Volume::create"
        );
        validate_volume_name(&config.name)?;
        validate_volume_config(&config)?;
        let _name_lock = lock_volume_name(&config.name)?;

        let pools = crate::db::init_global().await?;

        // Check for existing volume.
        let existing = volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq(&config.name))
            .one(pools.read())
            .await?;
        if existing.is_some() {
            return Err(MicrosandboxError::VolumeAlreadyExists(config.name));
        }

        let volumes_dir = crate::config::config().volumes_dir();
        tokio::fs::create_dir_all(&volumes_dir).await?;
        let path = volumes_dir.join(&config.name);
        if path.exists() {
            return Err(MicrosandboxError::VolumeAlreadyExists(config.name));
        }

        let temp = tempfile::Builder::new()
            .prefix(&format!(".{}.", config.name))
            .tempdir_in(&volumes_dir)?;
        provision_volume_path(&config, temp.path()).await?;
        tokio::fs::rename(temp.path(), &path).await?;
        let _ = temp.keep();

        // Serialize labels.
        let labels_json = if config.labels.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&config.labels)?)
        };

        // Insert DB record first — orphaned directories are easier to clean
        // up than orphaned DB records.
        let now = chrono::Utc::now().naive_utc();
        let capacity_bytes = config.capacity_mib.map(|mib| i64::from(mib) * 1024 * 1024);
        let model = volume_entity::ActiveModel {
            name: Set(config.name.clone()),
            kind: Set(config.kind.as_str().to_string()),
            quota_mib: Set(config.quota_mib.map(|v| v as i32)),
            size_bytes: Set(None),
            capacity_bytes: Set(capacity_bytes),
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

        Ok(Self {
            name: config.name,
            path,
            kind: config.kind,
            capacity_bytes: capacity_bytes.map(|v| v as u64),
            disk_format: (config.kind == VolumeKind::Disk).then(|| "raw".to_string()),
            disk_fstype: (config.kind == VolumeKind::Disk).then(|| "ext4".to_string()),
        })
    }

    /// Insert the volume DB record inside the caller's transaction.
    ///
    /// Lets `SandboxBuilder::auto_volume` create the volume and the
    /// sandbox in one atomic write so a concurrent `Volume::list`
    /// cannot observe the volume before the owning sandbox exists.
    /// Returns [`MicrosandboxError::VolumeAlreadyExists`] if the name
    /// is already in the table.
    ///
    /// The caller is responsible for creating the on-disk directory
    /// after the transaction commits (or rolling back via
    /// `Volume::remove` if the directory step fails).
    pub(crate) async fn create_in_transaction<C: ConnectionTrait>(
        txn: &C,
        config: &VolumeConfig,
    ) -> MicrosandboxResult<()> {
        validate_volume_name(&config.name)?;
        validate_volume_config(config)?;

        let existing = volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq(&config.name))
            .one(txn)
            .await?;
        if existing.is_some() {
            return Err(MicrosandboxError::VolumeAlreadyExists(config.name.clone()));
        }

        let labels_json = if config.labels.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&config.labels)?)
        };
        let now = chrono::Utc::now().naive_utc();
        let capacity_bytes = config.capacity_mib.map(|mib| i64::from(mib) * 1024 * 1024);
        let model = volume_entity::ActiveModel {
            name: Set(config.name.clone()),
            kind: Set(config.kind.as_str().to_string()),
            quota_mib: Set(config.quota_mib.map(|v| v as i32)),
            size_bytes: Set(None),
            capacity_bytes: Set(capacity_bytes),
            disk_format: Set((config.kind == VolumeKind::Disk).then(|| "raw".to_string())),
            disk_fstype: Set((config.kind == VolumeKind::Disk).then(|| "ext4".to_string())),
            labels: Set(labels_json),
            created_at: Set(Some(now)),
            updated_at: Set(Some(now)),
            ..Default::default()
        };
        volume_entity::Entity::insert(model).exec(txn).await?;
        Ok(())
    }

    /// Resolve the on-disk path for a named volume.
    pub(crate) fn path_for(name: &str) -> PathBuf {
        crate::config::config().volumes_dir().join(name)
    }

    /// Provision the on-disk artifact for a volume registered via
    /// [`create_in_transaction`].
    pub(crate) async fn materialise_for(config: &VolumeConfig) -> MicrosandboxResult<()> {
        let volumes_dir = crate::config::config().volumes_dir();
        tokio::fs::create_dir_all(&volumes_dir).await?;
        let path = volumes_dir.join(&config.name);
        if path.exists() {
            return Err(MicrosandboxError::VolumeAlreadyExists(config.name.clone()));
        }
        let temp = tempfile::Builder::new()
            .prefix(&format!(".{}.", config.name))
            .tempdir_in(&volumes_dir)?;
        provision_volume_path(config, temp.path()).await?;
        tokio::fs::rename(temp.path(), &path).await?;
        let _ = temp.keep();
        Ok(())
    }

    /// Get a volume handle by name from the database.
    ///
    /// Returns a lightweight handle for metadata and management operations.
    pub async fn get(name: &str) -> MicrosandboxResult<VolumeHandle> {
        let db = crate::db::init_global().await?.read();

        let model = volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq(name))
            .one(db)
            .await?
            .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.into()))?;

        Ok(VolumeHandle::from_model(model))
    }

    /// List all volumes, ordered by creation time (newest first).
    pub async fn list() -> MicrosandboxResult<Vec<VolumeHandle>> {
        let db = crate::db::init_global().await?.read();

        let models = volume_entity::Entity::find()
            .order_by_desc(volume_entity::Column::CreatedAt)
            .all(db)
            .await?;

        Ok(models.into_iter().map(VolumeHandle::from_model).collect())
    }

    /// Delete a volume's database record and host directory.
    /// Fails with [`MicrosandboxError::VolumeNotFound`] if no such volume exists.
    pub async fn remove(name: &str) -> MicrosandboxResult<()> {
        Self::get(name).await?.remove().await
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Instance
//--------------------------------------------------------------------------------------------------

impl Volume {
    /// Unique name identifying this volume.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Storage kind for this volume.
    pub fn kind(&self) -> VolumeKind {
        self.kind
    }

    /// Host-side directory where this volume's data is stored
    /// (under `~/.microsandbox/volumes/<name>/`).
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Disk capacity in bytes for disk volumes.
    pub fn capacity_bytes(&self) -> Option<u64> {
        self.capacity_bytes
    }

    /// Disk image format for disk volumes. V1 always creates `raw`.
    pub fn disk_format(&self) -> Option<&str> {
        self.disk_format.as_deref()
    }

    /// Inner disk filesystem for disk volumes. V1 always creates `ext4`.
    pub fn disk_fstype(&self) -> Option<&str> {
        self.disk_fstype.as_deref()
    }

    /// Host path to the managed raw disk image for disk volumes.
    pub fn disk_path(&self) -> Option<PathBuf> {
        (self.kind == VolumeKind::Disk).then(|| self.path.join("disk.raw"))
    }

    /// Operate on the volume's host-side directory (read, write, list files)
    /// without needing a running sandbox.
    pub fn fs(&self) -> fs::VolumeFs<'_> {
        fs::VolumeFs::from_path_ref(&self.path)
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

    /// Create the volume.
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

//--------------------------------------------------------------------------------------------------
// Methods: VolumeKind
//--------------------------------------------------------------------------------------------------

impl VolumeKind {
    /// Database string for this volume kind.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "dir",
            Self::Disk => "disk",
        }
    }

    fn from_db_value(value: &str) -> Self {
        match value {
            "disk" => Self::Disk,
            _ => Self::Directory,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn provision_volume_path(
    config: &VolumeConfig,
    path: &std::path::Path,
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

fn validate_volume_config(config: &VolumeConfig) -> MicrosandboxResult<()> {
    match config.kind {
        VolumeKind::Directory => {
            if config.capacity_mib.is_some() {
                return Err(MicrosandboxError::InvalidConfig(
                    "directory named volumes do not support .size(...) / --size in v1".into(),
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

fn lock_volume_name(name: &str) -> MicrosandboxResult<File> {
    let volumes_dir = crate::config::config().volumes_dir();
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
        .map_err(|e| {
            MicrosandboxError::InvalidConfig(format!(
                "open disk named volume {} for removal: {e}",
                handle.name()
            ))
        })?;

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
        if config.mounts.iter().any(|mount| {
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
