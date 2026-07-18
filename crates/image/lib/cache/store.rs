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

/// Subdirectory for fsmeta EROFS images (keyed by manifest digest).
const FSMETA_DIR: &str = "fsmeta";

/// Subdirectory for VMDK descriptors (keyed by manifest digest).
const VMDK_DIR: &str = "vmdk";

/// Root directory for reusable flat ext4 artifacts.
const FLAT_DIR: &str = "flat";
const FLAT_REFS_DIR: &str = "refs";
const FLAT_BLOBS_DIR: &str = "blobs";
const FLAT_LOCKS_DIR: &str = "locks";

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
/// ~/.microsandbox/cache/layers/<diff_id_safe>.erofs          # per-layer EROFS
/// ~/.microsandbox/cache/layers/<diff_id_safe>.erofs.lock     # materialization flock
/// ~/.microsandbox/cache/fsmeta/<manifest_safe>.erofs         # fsmeta EROFS (fsmerge metadata)
/// ~/.microsandbox/cache/fsmeta/<manifest_safe>.erofs.lock    # materialization flock
/// ~/.microsandbox/cache/vmdk/<manifest_safe>.vmdk            # VMDK descriptor
/// ~/.microsandbox/cache/vmdk/<manifest_safe>.vmdk.lock       # materialization flock
/// ```
pub struct GlobalCache {
    /// Root of the layer EROFS cache (`~/.microsandbox/cache/layers/`).
    layers_dir: PathBuf,

    /// Root of the fsmeta EROFS cache (`~/.microsandbox/cache/fsmeta/`).
    fsmeta_dir: PathBuf,

    /// Root of the VMDK descriptor cache (`~/.microsandbox/cache/vmdk/`).
    vmdk_dir: PathBuf,

    /// Manifest-keyed references to immutable flat artifacts.
    flat_refs_dir: PathBuf,

    /// Content-addressed immutable raw ext4 artifacts.
    flat_blobs_dir: PathBuf,

    /// Per-derivation materialization locks.
    flat_locks_dir: PathBuf,

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
    /// Raw resolved image manifest JSON.
    pub raw_manifest_json: String,
    /// Raw image config JSON.
    pub raw_config_json: String,
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

/// Manifest-keyed reference to one validated immutable flat rootfs artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlatRootfsRef {
    /// Reference schema version.
    pub schema: u32,
    /// Resolved OCI manifest digest used as the requested input.
    pub manifest_digest: String,
    /// Complete derivation digest including platform and materializer profile.
    pub derivation_digest: String,
    /// SHA-256 digest of the validated raw ext4 bytes.
    pub artifact_digest: String,
    /// Pure-Rust materializer ABI.
    pub materializer_abi: u32,
    /// Deterministic ext4 UUID as lowercase hexadecimal.
    pub uuid: String,
    /// Logical sparse image size.
    pub virtual_size_bytes: u64,
    /// Unique inode count in the materialized rootfs.
    pub inode_count: u64,
    /// Unique regular-file content bytes.
    pub content_bytes: u64,
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
        let fsmeta_dir = cache_dir.join(FSMETA_DIR);
        let vmdk_dir = cache_dir.join(VMDK_DIR);
        let flat_dir = cache_dir.join(FLAT_DIR);
        let flat_refs_dir = flat_dir.join(FLAT_REFS_DIR);
        let flat_blobs_dir = flat_dir.join(FLAT_BLOBS_DIR);
        let flat_locks_dir = flat_dir.join(FLAT_LOCKS_DIR);
        let manifests_dir = cache_dir.join(MANIFESTS_DIR);
        let tmp_dir = cache_dir.join(TMP_DIR);

        for dir in [
            &layers_dir,
            &fsmeta_dir,
            &vmdk_dir,
            &flat_refs_dir,
            &flat_blobs_dir,
            &flat_locks_dir,
            &manifests_dir,
            &tmp_dir,
        ] {
            std::fs::create_dir_all(dir).map_err(|e| ImageError::Cache {
                path: dir.clone(),
                source: e,
            })?;
        }

        Ok(Self {
            layers_dir,
            fsmeta_dir,
            vmdk_dir,
            flat_refs_dir,
            flat_blobs_dir,
            flat_locks_dir,
            manifests_dir,
            tmp_dir,
        })
    }

    /// Create a new GlobalCache using async filesystem operations.
    pub async fn new_async(cache_dir: &Path) -> ImageResult<Self> {
        let layers_dir = cache_dir.join(LAYERS_DIR);
        let fsmeta_dir = cache_dir.join(FSMETA_DIR);
        let vmdk_dir = cache_dir.join(VMDK_DIR);
        let flat_dir = cache_dir.join(FLAT_DIR);
        let flat_refs_dir = flat_dir.join(FLAT_REFS_DIR);
        let flat_blobs_dir = flat_dir.join(FLAT_BLOBS_DIR);
        let flat_locks_dir = flat_dir.join(FLAT_LOCKS_DIR);
        let manifests_dir = cache_dir.join(MANIFESTS_DIR);
        let tmp_dir = cache_dir.join(TMP_DIR);

        for dir in [
            &layers_dir,
            &fsmeta_dir,
            &vmdk_dir,
            &flat_refs_dir,
            &flat_blobs_dir,
            &flat_locks_dir,
            &manifests_dir,
            &tmp_dir,
        ] {
            tokio::fs::create_dir_all(dir)
                .await
                .map_err(|e| ImageError::Cache {
                    path: dir.clone(),
                    source: e,
                })?;
        }

        Ok(Self {
            layers_dir,
            fsmeta_dir,
            vmdk_dir,
            flat_refs_dir,
            flat_blobs_dir,
            flat_locks_dir,
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

    // ── fsmeta EROFS paths (keyed by manifest digest) ─────────────────

    /// Root fsmeta EROFS cache directory.
    pub fn fsmeta_dir(&self) -> &Path {
        &self.fsmeta_dir
    }

    /// Path to the fsmeta EROFS image for a given manifest digest.
    pub fn fsmeta_erofs_path(&self, manifest_digest: &Digest) -> PathBuf {
        self.fsmeta_dir
            .join(format!("{}.erofs", manifest_digest.to_path_safe()))
    }

    /// Path to the materialization lock for a fsmeta EROFS image.
    pub fn fsmeta_erofs_lock_path(&self, manifest_digest: &Digest) -> PathBuf {
        self.fsmeta_dir
            .join(format!("{}.erofs.lock", manifest_digest.to_path_safe()))
    }

    /// Check if a fsmeta EROFS image exists.
    pub fn is_fsmeta_materialized(&self, manifest_digest: &Digest) -> bool {
        is_valid_erofs_artifact(&self.fsmeta_erofs_path(manifest_digest))
    }

    // ── VMDK descriptor paths (keyed by manifest digest) ────────────

    /// Root VMDK cache directory.
    pub fn vmdk_dir(&self) -> &Path {
        &self.vmdk_dir
    }

    /// Path to the VMDK descriptor for a given manifest digest.
    pub fn vmdk_path(&self, manifest_digest: &Digest) -> PathBuf {
        self.vmdk_dir
            .join(format!("{}.vmdk", manifest_digest.to_path_safe()))
    }

    /// Path to the materialization lock for a VMDK descriptor.
    pub fn vmdk_lock_path(&self, manifest_digest: &Digest) -> PathBuf {
        self.vmdk_dir
            .join(format!("{}.vmdk.lock", manifest_digest.to_path_safe()))
    }

    /// Check if a VMDK descriptor exists for a given manifest digest.
    pub fn is_vmdk_materialized(&self, manifest_digest: &Digest) -> bool {
        self.vmdk_path(manifest_digest).exists()
    }

    // ── Flat ext4 artifact paths (manifest ref → content blob) ───────

    /// Path to the manifest-keyed flat rootfs reference.
    pub fn flat_ref_path(&self, manifest_digest: &Digest) -> PathBuf {
        self.flat_refs_dir
            .join(format!("{}.json", manifest_digest.to_path_safe()))
    }

    /// Path to the immutable content-addressed raw ext4 artifact.
    pub fn flat_blob_path(&self, artifact_digest: &Digest) -> PathBuf {
        self.flat_blobs_dir
            .join(format!("{}.raw", artifact_digest.to_path_safe()))
    }

    /// Path to the per-derivation flat materialization lock.
    pub fn flat_lock_path(&self, derivation_digest: &Digest) -> PathBuf {
        self.flat_locks_dir
            .join(format!("{}.lock", derivation_digest.to_path_safe()))
    }

    /// Read and validate the manifest-keyed flat rootfs reference.
    pub fn read_flat_ref(&self, manifest_digest: &Digest) -> ImageResult<Option<FlatRootfsRef>> {
        let path = self.flat_ref_path(manifest_digest);
        let data = match std::fs::read_to_string(&path) {
            Ok(data) => data,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => return Err(ImageError::Cache { path, source }),
        };
        let reference = match serde_json::from_str::<FlatRootfsRef>(&data) {
            Ok(reference) if reference.schema == 1 => reference,
            Ok(_) => return Ok(None),
            Err(error) => {
                tracing::warn!(path = %path.display(), %error, "corrupt flat rootfs ref, ignoring");
                return Ok(None);
            }
        };
        let artifact_digest = match reference.artifact_digest.parse::<Digest>() {
            Ok(digest) => digest,
            Err(_) => return Ok(None),
        };
        let blob_path = self.flat_blob_path(&artifact_digest);
        match std::fs::metadata(&blob_path) {
            Ok(metadata) if metadata.len() == reference.virtual_size_bytes => Ok(Some(reference)),
            Ok(_) | Err(_) => Ok(None),
        }
    }

    /// Atomically replace a flat rootfs reference after its immutable blob is durable.
    pub fn write_flat_ref(
        &self,
        manifest_digest: &Digest,
        reference: &FlatRootfsRef,
    ) -> ImageResult<()> {
        let path = self.flat_ref_path(manifest_digest);
        let temp_path = path.with_extension("json.part");
        let payload = serde_json::to_vec_pretty(reference).map_err(|error| {
            ImageError::ConfigParse(format!("failed to serialize flat rootfs ref: {error}"))
        })?;
        let mut temp = std::fs::File::create(&temp_path).map_err(|source| ImageError::Cache {
            path: temp_path.clone(),
            source,
        })?;
        use std::io::Write;
        temp.write_all(&payload)
            .map_err(|source| ImageError::Cache {
                path: temp_path.clone(),
                source,
            })?;
        temp.sync_all().map_err(|source| ImageError::Cache {
            path: temp_path.clone(),
            source,
        })?;
        std::fs::rename(&temp_path, &path).map_err(|source| ImageError::Cache {
            path: path.clone(),
            source,
        })?;
        sync_directory(&self.flat_refs_dir)?;
        Ok(())
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

        parse_cached_image_metadata(&path, &data)
    }

    /// Read cached metadata for an image reference using async filesystem I/O.
    pub async fn read_image_metadata_async(
        &self,
        reference: &Reference,
    ) -> ImageResult<Option<CachedImageMetadata>> {
        let path = self.image_metadata_path(reference);

        let data = match tokio::fs::read_to_string(&path).await {
            Ok(data) => data,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(ImageError::Cache { path, source: e }),
        };

        parse_cached_image_metadata(&path, &data)
    }

    /// Write cached metadata for an image reference.
    #[cfg_attr(not(test), allow(dead_code))]
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

    /// Write cached metadata for an image reference using async filesystem I/O.
    pub async fn write_image_metadata_async(
        &self,
        reference: &Reference,
        metadata: &CachedImageMetadata,
    ) -> ImageResult<()> {
        let path = self.image_metadata_path(reference);
        let temp_path = path.with_extension("json.part");
        let payload = serde_json::to_vec(metadata).map_err(|e| {
            ImageError::ConfigParse(format!("failed to serialize cached image metadata: {e}"))
        })?;

        tokio::fs::write(&temp_path, payload)
            .await
            .map_err(|e| ImageError::Cache {
                path: temp_path.clone(),
                source: e,
            })?;
        tokio::fs::rename(&temp_path, &path)
            .await
            .map_err(|e| ImageError::Cache { path, source: e })?;

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

    /// Delete cached metadata for an image reference using async filesystem I/O.
    pub async fn delete_image_metadata_async(&self, reference: &Reference) -> ImageResult<()> {
        let path = self.image_metadata_path(reference);
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(ImageError::Cache { path, source: e }),
        }
    }

    /// Path to the cached metadata file for an image reference.
    pub fn image_metadata_path(&self, reference: &Reference) -> PathBuf {
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

#[cfg(unix)]
fn sync_directory(path: &Path) -> ImageResult<()> {
    let directory = std::fs::File::open(path).map_err(|source| ImageError::Cache {
        path: path.to_path_buf(),
        source,
    })?;
    directory.sync_all().map_err(|source| ImageError::Cache {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(not(unix))]
fn sync_directory(_path: &Path) -> ImageResult<()> {
    Ok(())
}

pub(crate) fn parse_cached_image_metadata(
    path: &Path,
    data: &str,
) -> ImageResult<Option<CachedImageMetadata>> {
    match serde_json::from_str::<CachedImageMetadata>(data) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(e) => {
            tracing::warn!(
                path = %path.display(),
                error = %e,
                "corrupt image metadata cache, ignoring"
            );
            Ok(None)
        }
    }
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

pub(crate) async fn is_valid_erofs_artifact_async(path: &Path) -> bool {
    match tokio::fs::metadata(path).await {
        Ok(meta) => {
            let len = meta.len();
            len > 0 && len % EROFS_ALIGNMENT_BYTES == 0
        }
        Err(_) => false,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(byte: char) -> Digest {
        format!("sha256:{}", byte.to_string().repeat(64))
            .parse()
            .unwrap()
    }

    #[test]
    fn flat_cache_separates_manifest_refs_from_content_blobs() {
        let directory = tempfile::tempdir().unwrap();
        let cache = GlobalCache::new(directory.path()).unwrap();
        let manifest = digest('a');
        let derivation = digest('b');
        let artifact = digest('c');

        assert!(cache.flat_ref_path(&manifest).ends_with(
            "flat/refs/sha256_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.json"
        ));
        assert!(cache.flat_blob_path(&artifact).ends_with(
            "flat/blobs/sha256_cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc.raw"
        ));
        assert!(cache.flat_lock_path(&derivation).ends_with(
            "flat/locks/sha256_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb.lock"
        ));

        let blob_path = cache.flat_blob_path(&artifact);
        let blob = std::fs::File::create(&blob_path).unwrap();
        blob.set_len(4096).unwrap();
        let reference = FlatRootfsRef {
            schema: 1,
            manifest_digest: manifest.to_string(),
            derivation_digest: derivation.to_string(),
            artifact_digest: artifact.to_string(),
            materializer_abi: 1,
            uuid: "00".repeat(16),
            virtual_size_bytes: 4096,
            inode_count: 2,
            content_bytes: 7,
        };
        cache.write_flat_ref(&manifest, &reference).unwrap();

        assert_eq!(cache.read_flat_ref(&manifest).unwrap(), Some(reference));
    }
}
