//! Named volume management.
//!
//! Volumes are persistent host-side directories stored under
//! `~/.microsandbox/volumes/<name>/` with metadata tracked in the database.

pub mod fs;

use std::path::PathBuf;

use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, Set,
    sea_query::OnConflict,
};

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

/// Summary information about a volume (re-exported from entity model).
pub type VolumeInfo = volume_entity::Model;

/// Builder for creating a volume.
pub struct VolumeBuilder {
    config: VolumeConfig,
}

//--------------------------------------------------------------------------------------------------
// Methods: Static
//--------------------------------------------------------------------------------------------------

impl Volume {
    /// Create a builder for a new volume.
    pub fn builder(name: impl Into<String>) -> VolumeBuilder {
        VolumeBuilder::new(name)
    }

    /// Create a volume from a config.
    pub async fn create(config: VolumeConfig) -> MicrosandboxResult<Self> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        let volumes_dir = crate::config::config().volumes_dir();
        let path = volumes_dir.join(&config.name);

        // Create the volume directory.
        tokio::fs::create_dir_all(&path).await?;

        // Serialize labels.
        let labels_json = if config.labels.is_empty() {
            None
        } else {
            Some(serde_json::to_string(&config.labels)?)
        };

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
            .on_conflict(
                OnConflict::column(volume_entity::Column::Name)
                    .update_columns([
                        volume_entity::Column::QuotaMib,
                        volume_entity::Column::Labels,
                        volume_entity::Column::UpdatedAt,
                    ])
                    .to_owned(),
            )
            .exec(db)
            .await?;

        Ok(Self {
            name: config.name,
            path,
        })
    }

    /// Get an existing volume by name.
    pub async fn get(name: &str) -> MicrosandboxResult<Self> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq(name))
            .one(db)
            .await?
            .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.into()))?;

        let path = crate::config::config().volumes_dir().join(name);

        Ok(Self {
            name: name.to_string(),
            path,
        })
    }

    /// List all volumes.
    pub async fn list() -> MicrosandboxResult<Vec<VolumeInfo>> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        volume_entity::Entity::find()
            .order_by_desc(volume_entity::Column::CreatedAt)
            .all(db)
            .await
            .map_err(Into::into)
    }

    /// Remove a volume by name.
    pub async fn remove(name: &str) -> MicrosandboxResult<()> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        let model = volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq(name))
            .one(db)
            .await?
            .ok_or_else(|| MicrosandboxError::VolumeNotFound(name.into()))?;

        // Delete the directory.
        let path = crate::config::config().volumes_dir().join(name);
        if path.exists() {
            tokio::fs::remove_dir_all(&path).await?;
        }

        // Delete the DB record.
        model.into_active_model().delete(db).await?;

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Instance
//--------------------------------------------------------------------------------------------------

impl Volume {
    /// Get the volume name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Get the host-side path of the volume directory.
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }

    /// Get volume info from the database.
    pub async fn info(&self) -> MicrosandboxResult<VolumeInfo> {
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;

        volume_entity::Entity::find()
            .filter(volume_entity::Column::Name.eq(&self.name))
            .one(db)
            .await?
            .ok_or_else(|| MicrosandboxError::VolumeNotFound(self.name.clone()))
    }

    /// Access the filesystem API for this volume.
    pub fn fs(&self) -> fs::VolumeFs<'_> {
        fs::VolumeFs::new(self)
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: VolumeBuilder
//--------------------------------------------------------------------------------------------------

impl VolumeBuilder {
    /// Create a new volume builder.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            config: VolumeConfig {
                name: name.into(),
                quota_mib: None,
                labels: Vec::new(),
            },
        }
    }

    /// Set the size quota.
    ///
    /// Accepts bare `u32` (interpreted as MiB) or a [`SizeExt`](crate::size::SizeExt) helper:
    /// ```ignore
    /// .quota(1024)         // 1024 MiB
    /// .quota(1024.mib())   // 1024 MiB (explicit)
    /// .quota(1.gib())      // 1 GiB = 1024 MiB
    /// ```
    pub fn quota(mut self, size: impl Into<Mebibytes>) -> Self {
        self.config.quota_mib = Some(size.into().as_u32());
        self
    }

    /// Add a label.
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
