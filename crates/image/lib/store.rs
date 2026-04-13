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

/// Subdirectory for per-layer EROFS images (keyed by diff_id).
const LAYERS_DIR: &str = "layers";

/// Subdirectory for flat-mode merged EROFS images (keyed by manifest digest).
const FLAT_DIR: &str = "flat";

/// Subdirectory for cached manifest + config metadata.
const MANIFESTS_DIR: &str = "manifests";

/// Subdirectory for transient staging (downloads, work dirs).
const TMP_DIR: &str = "tmp";

/// EROFS images are emitted in 4 KiB filesystem blocks.
const EROFS_ALIGNMENT_BYTES: u64 = 4096;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// On-disk global cache for OCI layers and EROFS images.
///
/// Layout:
/// ```text
/// ~/.microsandbox/cache/manifests/<sha256-of-ref>.json       # manifest + config metadata
/// ~/.microsandbox/cache/tmp/<blob>.part                      # partial downloads
/// ~/.microsandbox/cache/tmp/<blob>.download.lock             # download flock files
/// ~/.microsandbox/cache/tmp/<blob>.work/                     # materialization work dirs
/// ~/.microsandbox/cache/layers/<diff_id_safe>.erofs          # per-layer EROFS (layered mode)
/// ~/.microsandbox/cache/layers/<diff_id_safe>.erofs.lock     # materialization flock
/// ~/.microsandbox/cache/flat/<manifest_safe>.erofs           # merged EROFS (flat mode)
/// ~/.microsandbox/cache/flat/<manifest_safe>.erofs.lock      # materialization flock
/// ```
pub struct GlobalCache {
    /// Root of the layer EROFS cache (`~/.microsandbox/cache/layers/`).
    layers_dir: PathBuf,

    /// Root of the flat EROFS cache (`~/.microsandbox/cache/flat/`).
    flat_dir: PathBuf,

    /// Root of the manifest metadata cache (`~/.microsandbox/cache/manifests/`).
    manifests_dir: PathBuf,

    /// Root of the transient staging area (`~/.microsandbox/cache/tmp/`).
    tmp_dir: PathBuf,
}

/// Cached metadata for a pulled image reference.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedImageMetadata {
    /// Content-addressable digest of the resolved manifest.
    pub manifest_digest: String,
    /// Content-addressable digest of the config blob.
    pub config_digest: String,
    /// Parsed OCI image configuration.
    pub config: ImageConfig,
    /// Layer metadata in bottom-to-top order.
    pub layers: Vec<CachedLayerMetadata>,
}

/// Cached metadata for a single layer descriptor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedLayerMetadata {
    /// Compressed layer digest from the manifest (blob digest).
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
    /// Creates all subdirectories if they don't exist.
    pub fn new(cache_dir: &Path) -> ImageResult<Self> {
        let layers_dir = cache_dir.join(LAYERS_DIR);
        let flat_dir = cache_dir.join(FLAT_DIR);
        let manifests_dir = cache_dir.join(MANIFESTS_DIR);
        let tmp_dir = cache_dir.join(TMP_DIR);

        for dir in [&layers_dir, &flat_dir, &manifests_dir, &tmp_dir] {
            std::fs::create_dir_all(dir).map_err(|e| ImageError::Cache {
                path: dir.clone(),
                source: e,
            })?;
        }

        Ok(Self {
            layers_dir,
            flat_dir,
            manifests_dir,
            tmp_dir,
        })
    }

    // ── Layer EROFS paths (keyed by diff_id) ─────────────────────────

    /// Root layer EROFS cache directory.
    pub fn layers_dir(&self) -> &Path {
        &self.layers_dir
    }

    /// Path to the per-layer EROFS image for a given diff_id.
    pub fn layer_erofs_path(&self, diff_id: &Digest) -> PathBuf {
        self.layers_dir
            .join(format!("{}.erofs", diff_id.to_path_safe()))
    }

    /// Path to the materialization lock for a layer EROFS image.
    pub fn layer_erofs_lock_path(&self, diff_id: &Digest) -> PathBuf {
        self.layers_dir
            .join(format!("{}.erofs.lock", diff_id.to_path_safe()))
    }

    /// Check if a layer EROFS image exists.
    pub fn is_layer_materialized(&self, diff_id: &Digest) -> bool {
        is_valid_erofs_artifact(&self.layer_erofs_path(diff_id))
    }

    /// Check if all given layer diff_ids have materialized EROFS images.
    pub fn all_layers_materialized(&self, diff_ids: &[Digest]) -> bool {
        diff_ids.iter().all(|d| self.is_layer_materialized(d))
    }

    // ── Flat EROFS paths (keyed by manifest digest) ──────────────────

    /// Root flat EROFS cache directory.
    pub fn flat_dir(&self) -> &Path {
        &self.flat_dir
    }

    /// Path to the flat merged EROFS image for a given manifest digest.
    pub fn flat_erofs_path(&self, manifest_digest: &Digest) -> PathBuf {
        self.flat_dir
            .join(format!("{}.erofs", manifest_digest.to_path_safe()))
    }

    /// Path to the materialization lock for a flat EROFS image.
    pub fn flat_erofs_lock_path(&self, manifest_digest: &Digest) -> PathBuf {
        self.flat_dir
            .join(format!("{}.erofs.lock", manifest_digest.to_path_safe()))
    }

    /// Check if a flat EROFS image exists.
    pub fn is_flat_materialized(&self, manifest_digest: &Digest) -> bool {
        is_valid_erofs_artifact(&self.flat_erofs_path(manifest_digest))
    }

    // ── Staging/tmp paths (downloads, work dirs) ─────────────────────

    /// Root staging directory.
    pub fn tmp_dir(&self) -> &Path {
        &self.tmp_dir
    }

    /// Path to the partial download file for a blob.
    pub fn part_path(&self, blob_digest: &Digest) -> PathBuf {
        self.tmp_dir
            .join(format!("{}.part", blob_digest.to_path_safe()))
    }

    /// Path to the download lock file for a blob.
    pub fn download_lock_path(&self, blob_digest: &Digest) -> PathBuf {
        self.tmp_dir
            .join(format!("{}.download.lock", blob_digest.to_path_safe()))
    }

    /// Path to the materialization work directory for an EROFS build.
    pub fn work_dir(&self, key: &Digest) -> PathBuf {
        self.tmp_dir.join(format!("{}.work", key.to_path_safe()))
    }

    // ── Manifest metadata cache ──────────────────────────────────────

    /// Root manifest metadata directory.
    pub fn manifests_dir(&self) -> &Path {
        &self.manifests_dir
    }

    /// Path to the pull lock file for an image reference.
    pub fn image_lock_path(&self, reference: &Reference) -> PathBuf {
        self.manifests_dir
            .join(format!("{}.lock", image_cache_key(reference)))
    }

    /// Read cached metadata for an image reference.
    pub fn read_image_metadata(
        &self,
        reference: &Reference,
    ) -> ImageResult<Option<CachedImageMetadata>> {
        let path = self.image_metadata_path(reference);

        let data = match std::fs::read_to_string(&path) {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ImageError::Cache { path, source: e }),
        };

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

    /// Delete cached metadata for an image reference.
    pub fn delete_image_metadata(&self, reference: &Reference) -> ImageResult<()> {
        let path = self.image_metadata_path(reference);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ImageError::Cache { path, source: e }),
        }
    }

    /// Path to the cached metadata file for an image reference.
    fn image_metadata_path(&self, reference: &Reference) -> PathBuf {
        self.manifests_dir
            .join(format!("{}.json", image_cache_key(reference)))
    }

    // ── Blob cache paths ──────────────────────────────────────────────

    /// Path to the cached compressed tarball for a layer blob.
    pub fn tar_path(&self, digest: &Digest) -> PathBuf {
        self.layers_dir
            .join(format!("{}.tar.gz", digest.to_path_safe()))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn image_cache_key(reference: &Reference) -> String {
    let mut hasher = Sha256::new();
    hasher.update(reference.to_string().as_bytes());
    hex::encode(hasher.finalize())
}

pub(crate) fn is_valid_erofs_artifact(path: &Path) -> bool {
    match std::fs::metadata(path) {
        Ok(meta) => {
            let len = meta.len();
            len > 0 && len % EROFS_ALIGNMENT_BYTES == 0
        }
        Err(_) => false,
    }
}
