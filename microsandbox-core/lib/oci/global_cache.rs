use std::{path::PathBuf, str::FromStr, sync::Arc};

use async_trait::async_trait;
use oci_spec::image::Digest;
use sqlx::{Pool, Sqlite};
use tokio::fs;

use crate::{
    MicrosandboxResult,
    management::db,
    oci::{
        Reference,
        layer::{Layer, LayerOps},
    },
};

/// Trait defining methods for interacting with on-disk image layers.
#[async_trait]
pub trait GlobalCacheOps: Send + Sync {
    /// Returns the directory where layers tar files are stored.
    fn tar_download_dir(&self) -> &PathBuf;

    /// Returns the directory where extracted layers are stored.
    fn extracted_layers_dir(&self) -> &PathBuf;

    /// Get a layer ops by digest.
    ///
    /// # Arguments
    ///
    /// * `digest` - The digest of the layer to get
    async fn build_layer(&self, digest: &Digest) -> Arc<dyn LayerOps>;

    /// Get a layer ops by digest, returning None if the corresponding layer tar file does not exist
    /// on disk.
    ///
    /// # Arguments
    ///
    /// * `digest` - The digest of the layer to get
    async fn get_downloaded_layer(&self, digest: &Digest) -> Option<Arc<dyn LayerOps>> {
        let layer = self.build_layer(digest).await;
        let tar_path = layer.tar_path();
        if !tar_path.exists() {
            tracing::warn!(?digest, tar_path = %tar_path.display(), "layer does not exist");
            return None;
        }

        // if there's at least one file in that specific layer directory, it means the layer already exists
        let parent = tar_path.parent().expect("tar path to have parent");
        if let Ok(mut read_dir) = tokio::fs::read_dir(parent).await {
            if let Ok(Some(_)) = read_dir.next_entry().await {
                return Some(layer);
            }
        }

        tracing::warn!(?digest, "layer exists but is empty");
        None
    }

    /// Checks if all layers for an image exist in both the database and the layers directory.
    ///
    /// ## Arguments
    ///
    /// * `image` - The reference to the image to check
    ///
    /// ## Returns
    ///
    /// Returns Ok(true) if all layers exist and are valid, Ok(false) if any layer is missing.
    async fn all_layers_extracted(&self, image: &Reference) -> MicrosandboxResult<bool>;
}

/// Abstraction around the global storage destinations. This includes:
/// - The directory where layers are downloaded to
/// - The directory where extracted layers are stored
/// - The database pool for layer metadata
#[derive(Clone)]
pub(crate) struct GlobalCache {
    /// Directory where layers tar files are stored
    tar_download_dir: PathBuf,

    /// Directory where extracted layers are stored
    extracted_layers_dir: PathBuf,

    /// Database pool for layer metadata
    db: Pool<Sqlite>,
}

impl GlobalCache {
    /// Creates a new global layer cache
    ///
    /// ## Arguments
    ///
    /// * `tar_download_dir` - The directory where layers tar files are stored
    /// * `extracted_layers_dir` - The directory where extracted layers are stored
    /// * `db` - The database pool for layer metadata
    ///
    /// ## Returns
    ///
    /// Returns a new global layer cache
    pub async fn new(
        tar_download_dir: PathBuf,
        extracted_layers_dir: PathBuf,
        db: Pool<Sqlite>,
    ) -> MicrosandboxResult<Self> {
        let this = Self {
            tar_download_dir,
            extracted_layers_dir,
            db,
        };
        this.ensure_layers_dir().await?;
        Ok(this)
    }

    /// Create layers directory if it doesn't exist
    async fn ensure_layers_dir(&self) -> MicrosandboxResult<()> {
        fs::create_dir_all(&self.extracted_layers_dir).await?;
        Ok(())
    }
}

#[async_trait]
impl GlobalCacheOps for GlobalCache {
    fn tar_download_dir(&self) -> &PathBuf {
        &self.tar_download_dir
    }

    fn extracted_layers_dir(&self) -> &PathBuf {
        &self.extracted_layers_dir
    }

    async fn build_layer(&self, digest: &Digest) -> Arc<dyn LayerOps> {
        Arc::new(Layer::new(Arc::new(self.clone()), digest.clone()))
    }

    /// Checks if all layers for an image exist in both the database and the layers directory.
    ///
    /// ## Arguments
    ///
    /// * `image` - The reference to the image to check
    async fn all_layers_extracted(&self, image: &Reference) -> MicrosandboxResult<bool> {
        // Check if the image exists in the database
        match db::image_exists(&self.db, &image.to_string()).await {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(?image, "Image does not exist in db");
                return Ok(false);
            }
            Err(err) => {
                tracing::warn!(?err, ?image, "Error checking image existence");
                return Ok(false);
            }
        }

        // Image exists, get all layer digests for this image
        let layer_digests = match db::get_image_layer_digests(&self.db, &image.to_string()).await {
            Ok(layer_digests) => layer_digests,
            Err(err) => {
                tracing::warn!(?err, ?image, "Error checking layer digests");
                return Ok(false);
            }
        };

        tracing::info!(?image, ?layer_digests, "Layer digests");
        if layer_digests.is_empty() {
            tracing::warn!(?image, "No layers found for image");
            return Ok(false);
        }

        // Check if all layers exist in the extracted layers directory.
        // We don't keep the tar file around after extraction, so we can't
        // rely on that to check if it's downloaded.
        for digest in &layer_digests {
            let digest = Digest::from_str(digest)?;
            let layer = self.build_layer(&digest).await;

            // confirm that the layer directory actually has content
            let (extracted, _) = layer.extracted().await?;
            if !extracted {
                tracing::warn!(?digest, "Layer not fully extracted");
                return Ok(false);
            }

            tracing::trace!(?digest, "Layer fully extracted and valid");
        }

        // Get the OCI config from database to verify database records exist for all digests
        let Some(config) = db::get_image_config(&self.db, &image.to_string()).await? else {
            tracing::warn!(?image, "Image config does not exist in db");
            return Ok(false);
        };
        let Some(diff_ids) = &config.rootfs_diff_ids_json else {
            tracing::warn!(?image, "Failed to parse rootfs diff ids from db");
            return Ok(false);
        };

        let diff_ids = serde_json::from_str::<Vec<String>>(diff_ids)
            .map_err(|_| anyhow::anyhow!("Failed to parse rootfs diff ids"))?;

        if diff_ids.len() != layer_digests.len() {
            tracing::warn!(
                ?image,
                db_digest_len = diff_ids.len(),
                disk_digest_len = layer_digests.len(),
                "Layer count mismatch",
            );
            return Ok(false);
        }

        tracing::info!(?image, "All layers for image exist and are valid");
        Ok(true)
    }
}
