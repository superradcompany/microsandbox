//! Global on-disk image and layer cache.

use std::path::{Path, PathBuf};

use oci_client::Reference;
use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::{
    config::ImageConfig,
    digest::Digest,
    error::{ImageError, ImageResult},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Subdirectory under the cache root for layer storage.
const LAYERS_DIR: &str = "layers";

/// Subdirectory under the cache root for image metadata.
const IMAGES_DIR: &str = "images";

/// Marker file written as the last step of extraction.
pub(crate) const COMPLETE_MARKER: &str = ".complete";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// On-disk global cache for OCI layers.
///
/// Layout (all flat in `cache/layers/`, content-addressable by digest):
/// ```text
/// ~/.microsandbox/cache/layers/<digest_safe>.tar.gz            # compressed downloads
/// ~/.microsandbox/cache/layers/<digest_safe>.extracted/        # extracted layer trees
/// ~/.microsandbox/cache/layers/<digest_safe>.index             # binary sidecar indexes
/// ~/.microsandbox/cache/layers/<digest_safe>.implicit_dirs     # pending implicit-dir fixups
/// ~/.microsandbox/cache/layers/<digest_safe>.lock              # extraction flock files
/// ~/.microsandbox/cache/layers/<digest_safe>.download.lock     # download flock files
/// ```
pub struct GlobalCache {
    /// Root of the layer cache directory (`~/.microsandbox/cache/layers/`).
    layers_dir: PathBuf,

    /// Root of the image metadata directory (`~/.microsandbox/cache/images/`).
    images_dir: PathBuf,
}

/// Cached metadata for a pulled image reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CachedImageMetadata {
    /// Content-addressable digest of the resolved manifest.
    pub manifest_digest: String,
    /// Parsed OCI image configuration.
    pub config: ImageConfig,
    /// Layer metadata in bottom-to-top order.
    pub layers: Vec<CachedLayerMetadata>,
}

/// Cached metadata for a single layer descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct CachedLayerMetadata {
    /// Compressed layer digest from the manifest.
    pub digest: String,
    /// OCI media type of the layer blob.
    pub media_type: Option<String>,
    /// Compressed blob size in bytes.
    pub size_bytes: Option<u64>,
    /// Uncompressed diff ID from the image config.
    pub diff_id: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl GlobalCache {
    /// Create a new GlobalCache using the provided cache directory.
    ///
    /// Creates `<cache_dir>/layers/` if it doesn't exist.
    pub fn new(cache_dir: &Path) -> ImageResult<Self> {
        let layers_dir = cache_dir.join(LAYERS_DIR);
        let images_dir = cache_dir.join(IMAGES_DIR);
        std::fs::create_dir_all(&layers_dir).map_err(|e| ImageError::Cache {
            path: layers_dir.clone(),
            source: e,
        })?;
        std::fs::create_dir_all(&images_dir).map_err(|e| ImageError::Cache {
            path: images_dir.clone(),
            source: e,
        })?;
        Ok(Self {
            layers_dir,
            images_dir,
        })
    }

    /// Root layer cache directory.
    pub fn layers_dir(&self) -> &Path {
        &self.layers_dir
    }

    /// Path to the compressed tarball for a layer.
    pub fn tar_path(&self, digest: &Digest) -> PathBuf {
        self.layers_dir
            .join(format!("{}.tar.gz", digest.to_path_safe()))
    }

    /// Path to the partial download file for a layer.
    pub fn part_path(&self, digest: &Digest) -> PathBuf {
        self.layers_dir
            .join(format!("{}.tar.gz.part", digest.to_path_safe()))
    }

    /// Path to the extracted layer directory.
    pub fn extracted_dir(&self, digest: &Digest) -> PathBuf {
        self.layers_dir
            .join(format!("{}.extracted", digest.to_path_safe()))
    }

    /// Path to the in-progress extraction temp directory.
    pub fn extracting_dir(&self, digest: &Digest) -> PathBuf {
        self.layers_dir
            .join(format!("{}.extracting", digest.to_path_safe()))
    }

    /// Path to the binary sidecar index for a layer.
    pub fn index_path(&self, digest: &Digest) -> PathBuf {
        self.layers_dir
            .join(format!("{}.index", digest.to_path_safe()))
    }

    /// Path to the pending implicit-dir fixup sidecar for a layer.
    pub fn implicit_dirs_path(&self, digest: &Digest) -> PathBuf {
        self.layers_dir
            .join(format!("{}.implicit_dirs", digest.to_path_safe()))
    }

    /// Path to the extraction lock file for a layer.
    pub fn lock_path(&self, digest: &Digest) -> PathBuf {
        self.layers_dir
            .join(format!("{}.lock", digest.to_path_safe()))
    }

    /// Path to the download lock file for a layer.
    pub fn download_lock_path(&self, digest: &Digest) -> PathBuf {
        self.layers_dir
            .join(format!("{}.download.lock", digest.to_path_safe()))
    }

    /// Check if a layer is fully extracted (`.complete` marker present).
    pub fn is_extracted(&self, digest: &Digest) -> bool {
        self.extracted_dir(digest).join(COMPLETE_MARKER).exists()
    }

    /// Check if all given layer digests are fully extracted.
    pub fn all_layers_extracted(&self, digests: &[Digest]) -> bool {
        digests.iter().all(|d| self.is_extracted(d))
    }

    /// Read cached metadata for an image reference.
    pub(crate) fn read_image_metadata(
        &self,
        reference: &Reference,
    ) -> ImageResult<Option<CachedImageMetadata>> {
        let path = self.image_metadata_path(reference);
        if !path.exists() {
            return Ok(None);
        }

        let data = std::fs::read_to_string(&path).map_err(|e| ImageError::Cache {
            path: path.clone(),
            source: e,
        })?;

        match serde_json::from_str::<CachedImageMetadata>(&data) {
            Ok(metadata) => Ok(Some(metadata)),
            Err(e) => {
                tracing::warn!(path = %path.display(), error = %e, "corrupt image metadata cache, ignoring");
                Ok(None)
            }
        }
    }

    /// Write cached metadata for an image reference.
    pub(crate) fn write_image_metadata(
        &self,
        reference: &Reference,
        metadata: &CachedImageMetadata,
    ) -> ImageResult<()> {
        let path = self.image_metadata_path(reference);
        let temp_path = path.with_extension("json.part");
        let payload = serde_json::to_vec(metadata).map_err(|e| {
            ImageError::ConfigParse(format!("failed to serialize cached image metadata: {e}"))
        })?;

        std::fs::write(&temp_path, payload).map_err(|e| ImageError::Cache {
            path: temp_path.clone(),
            source: e,
        })?;
        std::fs::rename(&temp_path, &path).map_err(|e| ImageError::Cache { path, source: e })?;

        Ok(())
    }

    /// Path to the cached metadata file for an image reference.
    fn image_metadata_path(&self, reference: &Reference) -> PathBuf {
        let mut hasher = Sha256::new();
        hasher.update(reference.to_string().as_bytes());
        let key = hex::encode(hasher.finalize());
        self.images_dir.join(format!("{key}.json"))
    }
}
