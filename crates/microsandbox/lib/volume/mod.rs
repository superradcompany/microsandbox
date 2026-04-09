//! Named volume management.
//!
//! Volumes are persistent host-side directories stored under
//! `~/.microsandbox/volumes/<name>/` with metadata tracked in the database.

pub mod fs;
pub use fs::{VolumeFsReadStream, VolumeFsWriteSink};

use std::path::PathBuf;

use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder, Set};

use crate::{
    MicrosandboxError, MicrosandboxResult, db::entity::volume as volume_entity, size::Mebibytes,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A named volume.
pub struct Volume {
    name: String,
    path: PathBuf,
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

/// A lightweight handle to a volume from the database.
///
/// Provides metadata access and management operations without requiring
/// a live [`Volume`] instance. Obtained via [`Volume::get`] or [`Volume::list`].
#[derive(Debug)]
pub struct VolumeHandle {
    db_id: i32,
    name: String,
    quota_mib: Option<u32>,
    used_bytes: u64,
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
            quota_mib: model.quota_mib.map(|v| v.max(0) as u32),
            used_bytes: model.size_bytes.unwrap_or(0).max(0) as u64,
            labels,
            created_at: model.created_at.map(|dt| dt.and_utc()),
        }
    }

    /// Unique name identifying this volume. Used to reference the volume
    /// in sandbox mount configurations via `v.named(handle.name())`.
    pub fn name(&self) -> &str {
        &self.name
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
        let db = crate::db::init_global().await?;

        // Delete the DB record first.
        volume_entity::Entity::delete_by_id(self.db_id)
            .exec(db)
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
        tracing::debug!(name = %config.name, quota_mib = ?config.quota_mib, "Volume::create");
        validate_volume_name(&config.name)?;

        let db = crate::db::init_global().await?;

        // Check for existing volume.
        let existing = volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq(&config.name))
            .one(db)
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

        volume_entity::Entity::insert(model).exec(db).await?;

        // Create the volume directory. If this fails, clean up the DB record.
        let volumes_dir = crate::config::config().volumes_dir();
        let path = volumes_dir.join(&config.name);

        if let Err(e) = tokio::fs::create_dir_all(&path).await {
            let _ = volume_entity::Entity::delete_many()
                .filter(volume_entity::Column::Name.eq(&config.name))
                .exec(db)
                .await;
            return Err(e.into());
        }

        Ok(Self {
            name: config.name,
            path,
        })
    }

    /// Get a volume handle by name from the database.
    ///
    /// Returns a lightweight handle for metadata and management operations.
    pub async fn get(name: &str) -> MicrosandboxResult<VolumeHandle> {
        let db = crate::db::init_global().await?;

        let model = volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq(name))
            .one(db)
            .await?
            .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.into()))?;

        Ok(VolumeHandle::from_model(model))
    }

    /// List all volumes, ordered by creation time (newest first).
    pub async fn list() -> MicrosandboxResult<Vec<VolumeHandle>> {
        let db = crate::db::init_global().await?;

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

    /// Host-side directory where this volume's data is stored
    /// (under `~/.microsandbox/volumes/<name>/`).
    pub fn path(&self) -> &std::path::Path {
        &self.path
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
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate that a volume name is safe for use as a directory name.
///
/// Names must start with an alphanumeric character and contain only
/// alphanumeric characters, dots, hyphens, and underscores.
fn validate_volume_name(name: &str) -> MicrosandboxResult<()> {
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
