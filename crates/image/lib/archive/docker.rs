//! Container image archive import/export.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest as Sha2Digest, Sha256};

use crate::{
    CachedImageMetadata, CachedLayerMetadata, Digest, GlobalCache, ImageConfig, ImageError,
    ImageResult, Platform, Reference, Registry,
    erofs::{ErofsEntryKind, ErofsReader},
    path_bytes::{os_str_bytes, os_string_from_vec, path_bytes},
    tar::Compression,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const OCI_CONFIG_MEDIA_TYPE: &str = "application/vnd.oci.image.config.v1+json";
const OCI_MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";
const OCI_INDEX_MEDIA_TYPE: &str = "application/vnd.oci.image.index.v1+json";
const OCI_LAYER_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar";
const OCI_LAYER_GZIP_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+gzip";
const OCI_LAYER_ZSTD_MEDIA_TYPE: &str = "application/vnd.oci.image.layer.v1.tar+zstd";
const OCI_REF_NAME_ANNOTATION: &str = "org.opencontainers.image.ref.name";
const ARCHIVE_METADATA_MAX_BYTES: u64 = 16 * 1024 * 1024;
const ARCHIVE_LAYER_MAX_BYTES: u64 = 10 * 1024 * 1024 * 1024;
const ARCHIVE_MAX_ENTRY_COUNT: u64 = 1_000_000;
static TEMP_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for importing image archives.
#[derive(Debug, Clone, Default)]
pub struct ImageLoadOptions {
    /// Extra tags to apply to the first image in the archive.
    pub tags: Vec<String>,
}

/// Archive format to use when saving images.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ImageArchiveFormat {
    /// Docker `docker save` compatible archive.
    #[default]
    Docker,
    /// OCI Image Layout archive.
    Oci,
}

/// One loaded image reference and its cached metadata.
#[derive(Debug, Clone)]
pub struct LoadedImage {
    /// Image reference imported into the local cache.
    pub reference: String,
    /// Cached image metadata to persist in the database.
    pub metadata: CachedImageMetadata,
}

/// Image data needed to export a Docker archive.
#[derive(Debug, Clone)]
pub struct ImageSaveRequest {
    /// Image reference to write as a Docker `RepoTags` entry.
    pub reference: String,
    /// Image config fields.
    pub config: ImageSaveConfig,
    /// Raw image config JSON to preserve non-runtime metadata on export.
    pub raw_config_json: String,
    /// Ordered layer list, bottom-to-top.
    pub layers: Vec<ImageSaveLayer>,
}

/// Config fields used when synthesizing an exported Docker image config.
#[derive(Debug, Clone, Default)]
pub struct ImageSaveConfig {
    /// Target architecture.
    pub architecture: Option<String>,
    /// Target OS.
    pub os: Option<String>,
    /// Environment variables.
    pub env: Vec<String>,
    /// Entrypoint.
    pub entrypoint: Option<Vec<String>>,
    /// Command.
    pub cmd: Option<Vec<String>>,
    /// Working directory.
    pub working_dir: Option<String>,
    /// User.
    pub user: Option<String>,
    /// Labels.
    pub labels: BTreeMap<String, String>,
}

/// Layer data used when exporting an image.
#[derive(Debug, Clone)]
pub struct ImageSaveLayer {
    /// Original cached layer diff ID.
    pub diff_id: String,
}

#[derive(Debug)]
struct PreparedLoadedImage {
    reference: String,
    metadata: CachedImageMetadata,
}

#[derive(Debug)]
struct PreparedArchiveLoad {
    images: Vec<PreparedLoadedImage>,
    staged_layers: HashMap<String, PathBuf>,
}

#[derive(Debug)]
struct StagedLayerGuard {
    paths: HashMap<String, PathBuf>,
    cleanup_on_drop: bool,
}

#[derive(Debug)]
struct LayerBlobInfo {
    digest: String,
    media_type: String,
    size_bytes: u64,
    path: PathBuf,
}

#[derive(Debug, Deserialize)]
struct DockerManifestEntry {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "RepoTags")]
    repo_tags: Option<Vec<String>>,
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

#[derive(Debug, Serialize)]
struct DockerManifestOut {
    #[serde(rename = "Config")]
    config: String,
    #[serde(rename = "RepoTags")]
    repo_tags: Vec<String>,
    #[serde(rename = "Layers")]
    layers: Vec<String>,
}

#[derive(Debug)]
struct GeneratedLayer {
    diff_id: String,
    hex: String,
    path: PathBuf,
    size: u64,
}

struct DigestingWriter<W> {
    inner: W,
    hasher: Sha256,
    written: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<W> DigestingWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
            written: 0,
        }
    }

    fn finish(self) -> (W, String, u64) {
        (
            self.inner,
            hex::encode(self.hasher.finalize()),
            self.written,
        )
    }
}

impl StagedLayerGuard {
    fn new() -> Self {
        Self {
            paths: HashMap::new(),
            cleanup_on_drop: true,
        }
    }

    fn track(&mut self, digest: String, path: PathBuf) -> PathBuf {
        if let Some(existing_path) = self.paths.get(&digest) {
            let _ = std::fs::remove_file(&path);
            return existing_path.clone();
        }

        self.paths.insert(digest, path.clone());
        path
    }

    fn into_inner(mut self) -> HashMap<String, PathBuf> {
        self.cleanup_on_drop = false;
        std::mem::take(&mut self.paths)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<W: Write> Write for DigestingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hasher.update(&buf[..written]);
        self.written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl Drop for StagedLayerGuard {
    fn drop(&mut self) {
        if !self.cleanup_on_drop {
            return;
        }

        for path in self.paths.values() {
            let _ = std::fs::remove_file(path);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Load a Docker image archive into the microsandbox image cache.
pub async fn load_archive(
    cache_dir: &Path,
    input: &Path,
    options: ImageLoadOptions,
) -> ImageResult<Vec<LoadedImage>> {
    let cache_dir_for_blocking = cache_dir.to_path_buf();
    let input = input.to_path_buf();
    let prepared = tokio::task::spawn_blocking(move || {
        load_archive_blocking(&cache_dir_for_blocking, &input, options)
    })
    .await
    .map_err(|e| ImageError::Io(io::Error::other(e)))??;

    let cache = GlobalCache::new_async(cache_dir).await?;
    let registry = Registry::new(Platform::host_linux(), cache)?;
    let PreparedArchiveLoad {
        images,
        staged_layers,
    } = prepared;
    let cleanup_paths = staged_layers.values().cloned().collect::<Vec<_>>();
    let staged_layers = Arc::new(staged_layers);
    let cache = GlobalCache::new_async(cache_dir).await?;
    let mut loaded = Vec::with_capacity(images.len());

    let result = async {
        for image in images {
            let reference: Reference = image
                .reference
                .parse()
                .map_err(|e| ImageError::ManifestParse(format!("invalid image reference: {e}")))?;

            registry
                .materialize_cached_layers_from_paths(
                    &reference,
                    &image.metadata,
                    false,
                    Arc::clone(&staged_layers),
                )
                .await?;

            cache
                .write_image_metadata_async(&reference, &image.metadata)
                .await?;

            loaded.push(LoadedImage {
                reference: image.reference,
                metadata: image.metadata,
            });
        }

        Ok(loaded)
    }
    .await;

    for path in cleanup_paths {
        let _ = tokio::fs::remove_file(path).await;
    }

    result
}

/// Save images as a Docker-compatible image archive.
pub fn save_docker_archive(
    cache: &GlobalCache,
    output: &Path,
    images: &[ImageSaveRequest],
) -> ImageResult<()> {
    save_archive(cache, output, images, ImageArchiveFormat::Docker)
}

/// Save images as a container image archive.
pub fn save_archive(
    cache: &GlobalCache,
    output: &Path,
    images: &[ImageSaveRequest],
    format: ImageArchiveFormat,
) -> ImageResult<()> {
    match format {
        ImageArchiveFormat::Docker => save_docker_archive_inner(cache, output, images),
        ImageArchiveFormat::Oci => save_oci_archive_inner(cache, output, images),
    }
}

fn save_docker_archive_inner(
    cache: &GlobalCache,
    output: &Path,
    images: &[ImageSaveRequest],
) -> ImageResult<()> {
    if images.is_empty() {
        return Err(ImageError::ManifestParse(
            "at least one image reference is required".into(),
        ));
    }

    let output_file = File::create(output).map_err(|e| ImageError::Cache {
        path: output.to_path_buf(),
        source: e,
    })?;
    let mut archive = tar::Builder::new(BufWriter::new(output_file));
    let mut generated_layers: HashMap<String, GeneratedLayer> = HashMap::new();
    let mut appended_layers: HashSet<String> = HashSet::new();
    let mut manifest_entries = Vec::with_capacity(images.len());
    let mut config_entries = Vec::with_capacity(images.len());

    for image in images {
        let mut layer_paths = Vec::with_capacity(image.layers.len());
        let mut regenerated_diff_ids = Vec::with_capacity(image.layers.len());

        for layer in &image.layers {
            let generated = match generated_layers.get(&layer.diff_id) {
                Some(generated) => generated,
                None => {
                    let generated = generate_layer_tar(cache, layer)?;
                    generated_layers.insert(layer.diff_id.clone(), generated);
                    generated_layers.get(&layer.diff_id).unwrap()
                }
            };

            regenerated_diff_ids.push(generated.diff_id.clone());
            layer_paths.push(format!("{}/layer.tar", generated.hex));
        }

        let config_bytes =
            docker_config_json(&image.config, &image.raw_config_json, &regenerated_diff_ids)?;
        let config_hex = sha256_hex(&config_bytes);
        let config_name = format!("{config_hex}.json");

        config_entries.push((config_name.clone(), config_bytes));

        manifest_entries.push(DockerManifestOut {
            config: config_name,
            repo_tags: vec![image.reference.clone()],
            layers: layer_paths,
        });
    }

    let manifest_bytes = serde_json::to_vec_pretty(&manifest_entries)
        .map_err(|e| ImageError::ConfigParse(format!("serialize docker manifest: {e}")))?;
    append_bytes(&mut archive, "manifest.json", &manifest_bytes)?;

    for (config_name, config_bytes) in config_entries {
        append_bytes(&mut archive, &config_name, &config_bytes)?;
    }

    for image in images {
        for layer in &image.layers {
            let generated = generated_layers.get(&layer.diff_id).ok_or_else(|| {
                ImageError::ManifestParse(format!("missing generated layer {}", layer.diff_id))
            })?;
            if appended_layers.insert(generated.hex.clone()) {
                append_layer_entries(&mut archive, generated)?;
            }
        }
    }

    archive.finish().map_err(ImageError::Io)?;

    for layer in generated_layers.values() {
        let _ = std::fs::remove_file(&layer.path);
    }

    Ok(())
}

fn save_oci_archive_inner(
    cache: &GlobalCache,
    output: &Path,
    images: &[ImageSaveRequest],
) -> ImageResult<()> {
    if images.is_empty() {
        return Err(ImageError::ManifestParse(
            "at least one image reference is required".into(),
        ));
    }

    let output_file = File::create(output).map_err(|e| ImageError::Cache {
        path: output.to_path_buf(),
        source: e,
    })?;
    let mut archive = tar::Builder::new(BufWriter::new(output_file));
    let mut generated_layers: HashMap<String, GeneratedLayer> = HashMap::new();
    let mut appended_metadata_blobs: HashSet<String> = HashSet::new();
    let mut appended_layer_blobs: HashSet<String> = HashSet::new();
    let mut layer_blob_order = Vec::new();
    let mut metadata_blobs = Vec::new();
    let mut index_manifests = Vec::with_capacity(images.len());

    for image in images {
        let mut layer_descriptors = Vec::with_capacity(image.layers.len());
        let mut regenerated_diff_ids = Vec::with_capacity(image.layers.len());

        for layer in &image.layers {
            let generated = match generated_layers.get(&layer.diff_id) {
                Some(generated) => generated,
                None => {
                    let generated = generate_layer_tar(cache, layer)?;
                    generated_layers.insert(layer.diff_id.clone(), generated);
                    generated_layers.get(&layer.diff_id).unwrap()
                }
            };

            regenerated_diff_ids.push(generated.diff_id.clone());
            if appended_layer_blobs.insert(generated.hex.clone()) {
                layer_blob_order.push(layer.diff_id.clone());
            }
            layer_descriptors.push(serde_json::json!({
                "mediaType": OCI_LAYER_MEDIA_TYPE,
                "digest": generated.diff_id,
                "size": generated.size,
            }));
        }

        let config_bytes =
            docker_config_json(&image.config, &image.raw_config_json, &regenerated_diff_ids)?;
        let config_hex = sha256_hex(&config_bytes);
        if appended_metadata_blobs.insert(config_hex.clone()) {
            metadata_blobs.push((config_hex.clone(), config_bytes.clone()));
        }

        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": OCI_CONFIG_MEDIA_TYPE,
                "digest": format!("sha256:{config_hex}"),
                "size": config_bytes.len(),
            },
            "layers": layer_descriptors,
        }))
        .map_err(|e| ImageError::ManifestParse(format!("serialize OCI manifest: {e}")))?;
        let manifest_hex = sha256_hex(&manifest_bytes);
        if appended_metadata_blobs.insert(manifest_hex.clone()) {
            metadata_blobs.push((manifest_hex.clone(), manifest_bytes.clone()));
        }

        index_manifests.push(serde_json::json!({
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "digest": format!("sha256:{manifest_hex}"),
            "size": manifest_bytes.len(),
            "platform": {
                "architecture": image.config.architecture.as_deref().unwrap_or("amd64"),
                "os": image.config.os.as_deref().unwrap_or("linux"),
            },
            "annotations": {
                (OCI_REF_NAME_ANNOTATION): image.reference.clone(),
            },
        }));
    }

    let index_bytes = serde_json::to_vec_pretty(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX_MEDIA_TYPE,
        "manifests": index_manifests,
    }))
    .map_err(|e| ImageError::ManifestParse(format!("serialize OCI index: {e}")))?;

    append_bytes(
        &mut archive,
        "oci-layout",
        br#"{"imageLayoutVersion":"1.0.0"}"#,
    )?;
    append_bytes(&mut archive, "index.json", &index_bytes)?;
    append_directory(&mut archive, "blobs")?;
    append_directory(&mut archive, "blobs/sha256")?;

    for (hex, bytes) in metadata_blobs {
        append_blob_bytes(&mut archive, &hex, &bytes)?;
    }

    for diff_id in layer_blob_order {
        let generated = generated_layers.get(&diff_id).ok_or_else(|| {
            ImageError::ManifestParse(format!("missing generated layer {diff_id}"))
        })?;
        append_blob_file(
            &mut archive,
            &generated.hex,
            &generated.path,
            generated.size,
        )?;
    }

    archive.finish().map_err(ImageError::Io)?;

    for layer in generated_layers.values() {
        let _ = std::fs::remove_file(&layer.path);
    }

    Ok(())
}

fn load_archive_blocking(
    cache_dir: &Path,
    input: &Path,
    options: ImageLoadOptions,
) -> ImageResult<PreparedArchiveLoad> {
    if let Some(manifest_json) = read_archive_entry(input, "manifest.json")? {
        let manifest: Vec<DockerManifestEntry> = serde_json::from_slice(&manifest_json)
            .map_err(|e| ImageError::ManifestParse(format!("docker manifest.json: {e}")))?;
        return load_docker_archive_blocking(cache_dir, input, options, manifest);
    }

    if read_archive_entry(input, "oci-layout")?.is_some() {
        return load_oci_archive_blocking(cache_dir, input, options);
    }

    Err(ImageError::ManifestParse(
        "archive missing manifest.json or oci-layout".into(),
    ))
}

fn load_docker_archive_blocking(
    cache_dir: &Path,
    input: &Path,
    options: ImageLoadOptions,
    manifest: Vec<DockerManifestEntry>,
) -> ImageResult<PreparedArchiveLoad> {
    let cache = GlobalCache::new(cache_dir)?;
    if manifest.is_empty() {
        return Err(ImageError::ManifestParse(
            "docker archive manifest is empty".into(),
        ));
    }

    let required_configs = manifest
        .iter()
        .map(|image| image.config.clone())
        .collect::<HashSet<_>>();
    let required_layers = manifest
        .iter()
        .flat_map(|image| image.layers.iter().cloned())
        .collect::<HashSet<_>>();
    let file = File::open(input).map_err(|e| ImageError::Cache {
        path: input.to_path_buf(),
        source: e,
    })?;
    let mut archive = tar::Archive::new(file);
    let mut configs: HashMap<String, Vec<u8>> = HashMap::new();
    let mut layers: HashMap<String, LayerBlobInfo> = HashMap::new();
    let mut staged_layers = StagedLayerGuard::new();
    let mut temp_counter = 0u64;
    let mut entry_count = 0u64;

    for entry in archive.entries().map_err(ImageError::Io)? {
        let mut entry = entry.map_err(ImageError::Io)?;
        entry_count += 1;
        enforce_archive_entry_count(entry_count)?;
        let path = normalized_archive_path(&entry)?;

        if required_configs.contains(&path) {
            let data = read_entry_to_vec(&mut entry, &path, ARCHIVE_METADATA_MAX_BYTES)?;
            configs.insert(path, data);
            continue;
        }

        if required_layers.contains(&path) {
            let mut info = extract_layer_blob(&cache, &path, &mut entry, temp_counter)?;
            temp_counter += 1;
            info.path = staged_layers.track(info.digest.clone(), info.path);
            verify_docker_layer_path_digest(&path, &info.digest)?;
            layers.insert(path, info);
            continue;
        }
    }

    let mut loaded = Vec::new();
    for (image_index, image) in manifest.into_iter().enumerate() {
        let config_bytes = configs.get(&image.config).ok_or_else(|| {
            ImageError::ConfigParse(format!("docker archive missing config {}", image.config))
        })?;
        let (config, diff_ids) = ImageConfig::parse(config_bytes)?;

        if diff_ids.len() != image.layers.len() {
            return Err(ImageError::ManifestParse(format!(
                "layer count mismatch: config has {} diff_ids but archive manifest has {} layers",
                diff_ids.len(),
                image.layers.len()
            )));
        }

        let config_digest = format!("sha256:{}", sha256_hex(config_bytes));
        let mut layer_metadata = Vec::with_capacity(image.layers.len());
        let mut manifest_layers = Vec::with_capacity(image.layers.len());

        for (position, layer_path) in image.layers.iter().enumerate() {
            let layer = layers.get(layer_path).ok_or_else(|| {
                ImageError::ManifestParse(format!("docker archive missing layer {layer_path}"))
            })?;
            let diff_id = diff_ids[position].clone();
            layer_metadata.push(CachedLayerMetadata {
                digest: layer.digest.clone(),
                media_type: Some(layer.media_type.clone()),
                size_bytes: Some(layer.size_bytes),
                diff_id,
            });
            manifest_layers.push(serde_json::json!({
                "mediaType": layer.media_type,
                "digest": layer.digest,
                "size": layer.size_bytes,
            }));
        }

        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": OCI_CONFIG_MEDIA_TYPE,
                "digest": config_digest,
                "size": config_bytes.len(),
            },
            "layers": manifest_layers,
        }))
        .map_err(|e| ImageError::ManifestParse(format!("serialize manifest: {e}")))?;
        let manifest_digest = format!("sha256:{}", sha256_hex(&manifest_bytes));

        let metadata = CachedImageMetadata {
            manifest_digest,
            config_digest,
            raw_manifest_json: json_bytes_to_string(&manifest_bytes, "docker manifest")?,
            raw_config_json: json_bytes_to_string(config_bytes, "docker config")?,
            config,
            layers: layer_metadata,
        };

        let mut refs = image
            .repo_tags
            .unwrap_or_default()
            .into_iter()
            .filter(|tag| tag != "<none>:<none>")
            .collect::<Vec<_>>();

        if image_index == 0 {
            refs.extend(options.tags.iter().cloned());
        }

        refs.sort();
        refs.dedup();

        if refs.is_empty() {
            return Err(ImageError::ManifestParse(
                "docker archive image has no tags; pass --tag to name it".into(),
            ));
        }

        for reference in refs {
            let _: Reference = reference.parse().map_err(|e| {
                ImageError::ManifestParse(format!("invalid image reference {reference}: {e}"))
            })?;
            loaded.push(PreparedLoadedImage {
                reference,
                metadata: metadata.clone(),
            });
        }
    }

    Ok(PreparedArchiveLoad {
        images: loaded,
        staged_layers: staged_layers.into_inner(),
    })
}

fn load_oci_archive_blocking(
    cache_dir: &Path,
    input: &Path,
    options: ImageLoadOptions,
) -> ImageResult<PreparedArchiveLoad> {
    let cache = GlobalCache::new(cache_dir)?;
    let layout_json = read_archive_entry(input, "oci-layout")?
        .ok_or_else(|| ImageError::ManifestParse("OCI layout missing oci-layout".into()))?;
    serde_json::from_slice::<oci_spec::image::OciLayout>(&layout_json)
        .map_err(|e| ImageError::ManifestParse(format!("oci-layout: {e}")))?;

    let index_json = read_archive_entry(input, "index.json")?
        .ok_or_else(|| ImageError::ManifestParse("OCI layout missing index.json".into()))?;
    let index: oci_spec::image::ImageIndex = serde_json::from_slice(&index_json)
        .map_err(|e| ImageError::ManifestParse(format!("OCI index.json: {e}")))?;
    let manifest_descriptors = selectable_oci_manifests(index.manifests())?;
    if manifest_descriptors.is_empty() {
        return Err(ImageError::ManifestParse(
            "OCI layout contains no image manifests for the host platform".into(),
        ));
    }

    let manifest_paths = manifest_descriptors
        .iter()
        .map(|descriptor| blob_path_from_digest(descriptor.digest().as_ref()))
        .collect::<ImageResult<HashSet<_>>>()?;
    let manifest_blobs = read_archive_entries(input, &manifest_paths)?;
    let mut manifests = Vec::with_capacity(manifest_descriptors.len());
    let mut required_configs = HashSet::new();
    let mut required_layers = HashSet::new();

    for descriptor in &manifest_descriptors {
        let manifest_path = blob_path_from_digest(descriptor.digest().as_ref())?;
        let manifest_bytes = manifest_blobs.get(&manifest_path).ok_or_else(|| {
            ImageError::ManifestParse(format!("OCI layout missing manifest blob {manifest_path}"))
        })?;
        verify_descriptor_blob(descriptor, manifest_bytes)?;
        let manifest: oci_spec::image::ImageManifest = serde_json::from_slice(manifest_bytes)
            .map_err(|e| ImageError::ManifestParse(format!("OCI image manifest: {e}")))?;

        required_configs.insert(blob_path_from_digest(manifest.config().digest().as_ref())?);
        for layer in manifest.layers() {
            required_layers.insert(blob_path_from_digest(layer.digest().as_ref())?);
        }
        manifests.push((descriptor.clone(), manifest, manifest_bytes.clone()));
    }

    let file = File::open(input).map_err(|e| ImageError::Cache {
        path: input.to_path_buf(),
        source: e,
    })?;
    let mut archive = tar::Archive::new(file);
    let mut configs: HashMap<String, Vec<u8>> = HashMap::new();
    let mut layers: HashMap<String, LayerBlobInfo> = HashMap::new();
    let mut staged_layers = StagedLayerGuard::new();
    let mut temp_counter = 0u64;
    let mut entry_count = 0u64;

    for entry in archive.entries().map_err(ImageError::Io)? {
        let mut entry = entry.map_err(ImageError::Io)?;
        entry_count += 1;
        enforce_archive_entry_count(entry_count)?;
        let path = normalized_archive_path(&entry)?;

        if required_configs.contains(&path) {
            let data = read_entry_to_vec(&mut entry, &path, ARCHIVE_METADATA_MAX_BYTES)?;
            configs.insert(path, data);
            continue;
        }

        if required_layers.contains(&path) {
            let mut info = extract_layer_blob(&cache, &path, &mut entry, temp_counter)?;
            temp_counter += 1;
            info.path = staged_layers.track(info.digest.clone(), info.path);
            layers.insert(path, info);
            continue;
        }
    }

    let mut loaded = Vec::new();
    for (image_index, (descriptor, manifest, manifest_bytes)) in manifests.into_iter().enumerate() {
        let config_path = blob_path_from_digest(manifest.config().digest().as_ref())?;
        let config_bytes = configs.get(&config_path).ok_or_else(|| {
            ImageError::ConfigParse(format!("OCI layout missing config blob {config_path}"))
        })?;
        verify_descriptor_blob(manifest.config(), config_bytes)?;
        let (config, diff_ids) = ImageConfig::parse(config_bytes)?;

        if diff_ids.len() != manifest.layers().len() {
            return Err(ImageError::ManifestParse(format!(
                "layer count mismatch: config has {} diff_ids but OCI manifest has {} layers",
                diff_ids.len(),
                manifest.layers().len()
            )));
        }

        let mut layer_metadata = Vec::with_capacity(manifest.layers().len());
        for (position, layer_descriptor) in manifest.layers().iter().enumerate() {
            let layer_path = blob_path_from_digest(layer_descriptor.digest().as_ref())?;
            let layer = layers.get(&layer_path).ok_or_else(|| {
                ImageError::ManifestParse(format!("OCI layout missing layer blob {layer_path}"))
            })?;
            verify_layer_descriptor(layer_descriptor, layer)?;
            layer_metadata.push(CachedLayerMetadata {
                digest: layer.digest.clone(),
                media_type: Some(layer.media_type.clone()),
                size_bytes: Some(layer.size_bytes),
                diff_id: diff_ids[position].clone(),
            });
        }

        let metadata = CachedImageMetadata {
            manifest_digest: format!("sha256:{}", sha256_hex(&manifest_bytes)),
            config_digest: manifest.config().digest().to_string(),
            raw_manifest_json: json_bytes_to_string(&manifest_bytes, "OCI manifest")?,
            raw_config_json: json_bytes_to_string(config_bytes, "OCI config")?,
            config,
            layers: layer_metadata,
        };

        let mut refs = descriptor
            .annotations()
            .as_ref()
            .and_then(|annotations| annotations.get(OCI_REF_NAME_ANNOTATION))
            .cloned()
            .into_iter()
            .collect::<Vec<_>>();

        if image_index == 0 {
            refs.extend(options.tags.iter().cloned());
        }

        refs.sort();
        refs.dedup();

        if refs.is_empty() {
            return Err(ImageError::ManifestParse(
                "OCI layout image has no ref.name annotation; pass --tag to name it".into(),
            ));
        }

        for reference in refs {
            let _: Reference = reference.parse().map_err(|e| {
                ImageError::ManifestParse(format!("invalid image reference {reference}: {e}"))
            })?;
            loaded.push(PreparedLoadedImage {
                reference,
                metadata: metadata.clone(),
            });
        }
    }

    Ok(PreparedArchiveLoad {
        images: loaded,
        staged_layers: staged_layers.into_inner(),
    })
}

fn read_archive_entry(input: &Path, wanted_path: &str) -> ImageResult<Option<Vec<u8>>> {
    let file = File::open(input).map_err(|e| ImageError::Cache {
        path: input.to_path_buf(),
        source: e,
    })?;
    let mut archive = tar::Archive::new(file);
    let mut entry_count = 0u64;

    for entry in archive.entries().map_err(ImageError::Io)? {
        let mut entry = entry.map_err(ImageError::Io)?;
        entry_count += 1;
        enforce_archive_entry_count(entry_count)?;
        let path = normalized_archive_path(&entry)?;
        if path != wanted_path {
            continue;
        }

        let data = read_entry_to_vec(&mut entry, &path, ARCHIVE_METADATA_MAX_BYTES)?;
        return Ok(Some(data));
    }

    Ok(None)
}

fn read_archive_entries(
    input: &Path,
    wanted_paths: &HashSet<String>,
) -> ImageResult<HashMap<String, Vec<u8>>> {
    let file = File::open(input).map_err(|e| ImageError::Cache {
        path: input.to_path_buf(),
        source: e,
    })?;
    let mut archive = tar::Archive::new(file);
    let mut entries = HashMap::new();
    let mut entry_count = 0u64;

    for entry in archive.entries().map_err(ImageError::Io)? {
        let mut entry = entry.map_err(ImageError::Io)?;
        entry_count += 1;
        enforce_archive_entry_count(entry_count)?;
        let path = normalized_archive_path(&entry)?;
        if !wanted_paths.contains(&path) {
            continue;
        }

        let data = read_entry_to_vec(&mut entry, &path, ARCHIVE_METADATA_MAX_BYTES)?;
        entries.insert(path, data);
        if entries.len() == wanted_paths.len() {
            break;
        }
    }

    Ok(entries)
}

fn selectable_oci_manifests(
    descriptors: &[oci_spec::image::Descriptor],
) -> ImageResult<Vec<oci_spec::image::Descriptor>> {
    let host = Platform::host_linux();
    let selected = descriptors
        .iter()
        .filter(|descriptor| is_oci_image_manifest_descriptor(descriptor))
        .filter(|descriptor| descriptor_matches_platform(descriptor, &host))
        .cloned()
        .collect();

    Ok(selected)
}

fn is_oci_image_manifest_descriptor(descriptor: &oci_spec::image::Descriptor) -> bool {
    matches!(
        descriptor.media_type(),
        oci_spec::image::MediaType::ImageManifest
    ) || descriptor.media_type().to_string()
        == "application/vnd.docker.distribution.manifest.v2+json"
}

fn descriptor_matches_platform(descriptor: &oci_spec::image::Descriptor, host: &Platform) -> bool {
    let Some(platform) = descriptor.platform() else {
        return true;
    };

    if *platform.os() != host.os || *platform.architecture() != host.arch {
        return false;
    }

    match (&host.variant, platform.variant()) {
        (Some(host_variant), Some(descriptor_variant)) => host_variant == descriptor_variant,
        (Some(_), None) => false,
        (None, _) => true,
    }
}

fn blob_path_from_digest(digest: &str) -> ImageResult<String> {
    let digest: Digest = digest.parse()?;
    Ok(format!("blobs/{}/{}", digest.algorithm(), digest.hex()))
}

fn verify_descriptor_blob(
    descriptor: &oci_spec::image::Descriptor,
    bytes: &[u8],
) -> ImageResult<()> {
    if descriptor.size() != bytes.len() as u64 {
        return Err(ImageError::ManifestParse(format!(
            "OCI blob {} size mismatch: descriptor has {}, archive has {}",
            descriptor.digest(),
            descriptor.size(),
            bytes.len()
        )));
    }

    verify_digest_bytes(descriptor.digest().as_ref(), bytes)
}

fn verify_layer_descriptor(
    descriptor: &oci_spec::image::Descriptor,
    layer: &LayerBlobInfo,
) -> ImageResult<()> {
    if descriptor.size() != layer.size_bytes {
        return Err(ImageError::ManifestParse(format!(
            "OCI layer {} size mismatch: descriptor has {}, archive has {}",
            descriptor.digest(),
            descriptor.size(),
            layer.size_bytes
        )));
    }

    if descriptor.digest().to_string() != layer.digest {
        return Err(ImageError::ManifestParse(format!(
            "OCI layer digest mismatch: descriptor has {}, archive has {}",
            descriptor.digest(),
            layer.digest
        )));
    }

    Ok(())
}

fn verify_digest_bytes(digest: &str, bytes: &[u8]) -> ImageResult<()> {
    let digest: Digest = digest.parse()?;
    if digest.algorithm() != "sha256" {
        return Err(ImageError::ManifestParse(format!(
            "unsupported OCI digest algorithm: {}",
            digest.algorithm()
        )));
    }

    let actual = sha256_hex(bytes);
    if actual != digest.hex() {
        return Err(ImageError::ManifestParse(format!(
            "OCI blob digest mismatch: expected {}, got sha256:{actual}",
            digest
        )));
    }

    Ok(())
}

fn verify_docker_layer_path_digest(path: &str, digest: &str) -> ImageResult<()> {
    let Some(hex) = path.strip_prefix("blobs/sha256/") else {
        return Ok(());
    };
    if hex.contains('/') {
        return Ok(());
    }

    let expected = format!("sha256:{hex}");
    if expected != digest {
        return Err(ImageError::ManifestParse(format!(
            "docker archive layer path {path} digest mismatch: expected {expected}, got {digest}"
        )));
    }

    Ok(())
}

fn create_unique_temp_file(dir: &Path, prefix: &str, suffix: &str) -> ImageResult<(File, PathBuf)> {
    for _ in 0..128 {
        let id = TEMP_FILE_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = dir.join(format!("{prefix}-{}-{id}{suffix}", std::process::id()));
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(file) => return Ok((file, path)),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(e) => {
                return Err(ImageError::Cache { path, source: e });
            }
        }
    }

    Err(ImageError::Cache {
        path: dir.to_path_buf(),
        source: io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique temporary image archive file",
        ),
    })
}

fn extract_layer_blob(
    cache: &GlobalCache,
    path: &str,
    entry: &mut tar::Entry<'_, File>,
    counter: u64,
) -> ImageResult<LayerBlobInfo> {
    let declared_size = entry.header().size().map_err(ImageError::Io)?;
    if declared_size > ARCHIVE_LAYER_MAX_BYTES {
        return Err(ImageError::ManifestParse(format!(
            "archive layer {path} is {declared_size} bytes; max is {ARCHIVE_LAYER_MAX_BYTES}"
        )));
    }

    let (mut temp, temp_path) =
        create_unique_temp_file(cache.tmp_dir(), &format!("load-{counter}"), ".blob")?;
    let result = (|| {
        let mut hasher = Sha256::new();
        let mut size = 0u64;
        let mut magic = Vec::with_capacity(4);
        let mut buf = [0u8; 64 * 1024];

        loop {
            let read = entry.read(&mut buf).map_err(ImageError::Io)?;
            if read == 0 {
                break;
            }
            if magic.len() < 4 {
                let take = (4 - magic.len()).min(read);
                magic.extend_from_slice(&buf[..take]);
            }
            hasher.update(&buf[..read]);
            temp.write_all(&buf[..read])
                .map_err(|e| ImageError::Cache {
                    path: temp_path.clone(),
                    source: e,
                })?;
            size += read as u64;
            if size > ARCHIVE_LAYER_MAX_BYTES {
                return Err(ImageError::ManifestParse(format!(
                    "archive layer {path} exceeds {ARCHIVE_LAYER_MAX_BYTES} bytes"
                )));
            }
        }
        temp.flush().map_err(|e| ImageError::Cache {
            path: temp_path.clone(),
            source: e,
        })?;
        drop(temp);

        let digest = Digest::new("sha256", hex::encode(hasher.finalize()));
        let staged_path = temp_path.clone();

        let media_type = match Compression::detect(&magic) {
            Compression::None => OCI_LAYER_MEDIA_TYPE,
            Compression::Gzip => OCI_LAYER_GZIP_MEDIA_TYPE,
            Compression::Zstd => OCI_LAYER_ZSTD_MEDIA_TYPE,
        };

        tracing::debug!(path, digest = %digest, size, "loaded layer blob from docker archive");

        Ok(LayerBlobInfo {
            digest: digest.to_string(),
            media_type: media_type.to_string(),
            size_bytes: size,
            path: staged_path,
        })
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }

    result
}

fn generate_layer_tar(cache: &GlobalCache, layer: &ImageSaveLayer) -> ImageResult<GeneratedLayer> {
    let diff_id: Digest = layer.diff_id.parse()?;
    let erofs_path = cache.layer_erofs_path(&diff_id);
    let file = File::open(&erofs_path).map_err(|e| ImageError::Cache {
        path: erofs_path.clone(),
        source: e,
    })?;
    let mut reader = ErofsReader::new(file).map_err(ImageError::Io)?;
    let (temp_file, temp_path) = create_unique_temp_file(cache.tmp_dir(), "save", ".layer.tar")?;
    let result = (|| {
        let digesting = DigestingWriter::new(BufWriter::new(temp_file));
        let mut builder = tar::Builder::new(digesting);
        let mut hardlinks: HashMap<u32, PathBuf> = HashMap::new();

        reader.walk_entries::<ImageError, _>(|reader, entry| {
            if entry.path.as_os_str().is_empty() {
                return Ok(());
            }

            if entry.kind == ErofsEntryKind::CharDevice && entry.rdev == Some((0, 0)) {
                append_whiteout(&mut builder, &entry)?;
                return Ok(());
            }

            append_erofs_entry(&mut builder, reader, &entry, &mut hardlinks)?;

            if entry.kind == ErofsEntryKind::Directory && entry.is_opaque() {
                append_opaque_marker(&mut builder, &entry)?;
            }
            Ok(())
        })?;

        let digesting = builder.into_inner().map_err(ImageError::Io)?;
        let (mut file, hex, size) = digesting.finish();
        file.flush().map_err(|e| ImageError::Cache {
            path: temp_path.clone(),
            source: e,
        })?;

        Ok(GeneratedLayer {
            diff_id: format!("sha256:{hex}"),
            hex,
            path: temp_path.clone(),
            size,
        })
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temp_path);
    }

    result
}

fn append_erofs_entry<W: Write>(
    builder: &mut tar::Builder<DigestingWriter<W>>,
    reader: &mut ErofsReader,
    entry: &crate::erofs::ErofsTreeEntry,
    hardlinks: &mut HashMap<u32, PathBuf>,
) -> ImageResult<()> {
    let mut header = tar::Header::new_gnu();
    apply_header_metadata(&mut header, entry);

    match entry.kind {
        ErofsEntryKind::RegularFile => {
            if let Some(first_path) = hardlinks.get(&entry.nid) {
                header.set_entry_type(tar::EntryType::Link);
                header.set_size(0);
                header.set_link_name(first_path).map_err(ImageError::Io)?;
                header.set_cksum();
                builder
                    .append_data(&mut header, &entry.path, io::empty())
                    .map_err(ImageError::Io)?;
                return Ok(());
            }

            hardlinks.insert(entry.nid, entry.path.clone());
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(entry.size);
            header.set_cksum();
            let mut data = reader.file_data_reader(entry.nid).map_err(ImageError::Io)?;
            builder
                .append_data(&mut header, &entry.path, &mut data)
                .map_err(ImageError::Io)?;
        }
        ErofsEntryKind::Directory => {
            header.set_entry_type(tar::EntryType::Directory);
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, &entry.path, io::empty())
                .map_err(ImageError::Io)?;
        }
        ErofsEntryKind::Symlink => {
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            let target = reader.read_link_by_nid(entry.nid).map_err(ImageError::Io)?;
            header
                .set_link_name_literal(target)
                .map_err(ImageError::Io)?;
            header.set_cksum();
            builder
                .append_data(&mut header, &entry.path, io::empty())
                .map_err(ImageError::Io)?;
        }
        ErofsEntryKind::CharDevice | ErofsEntryKind::BlockDevice => {
            header.set_entry_type(if entry.kind == ErofsEntryKind::CharDevice {
                tar::EntryType::Char
            } else {
                tar::EntryType::Block
            });
            header.set_size(0);
            if let Some((major, minor)) = entry.rdev {
                header.set_device_major(major).map_err(ImageError::Io)?;
                header.set_device_minor(minor).map_err(ImageError::Io)?;
            }
            header.set_cksum();
            builder
                .append_data(&mut header, &entry.path, io::empty())
                .map_err(ImageError::Io)?;
        }
        ErofsEntryKind::Fifo => {
            header.set_entry_type(tar::EntryType::Fifo);
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, &entry.path, io::empty())
                .map_err(ImageError::Io)?;
        }
        ErofsEntryKind::Socket => {
            header.set_entry_type(tar::EntryType::new(0o140));
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, &entry.path, io::empty())
                .map_err(ImageError::Io)?;
        }
    }

    Ok(())
}

fn append_whiteout<W: Write>(
    builder: &mut tar::Builder<DigestingWriter<W>>,
    entry: &crate::erofs::ErofsTreeEntry,
) -> ImageResult<()> {
    let Some(file_name) = entry.path.file_name() else {
        return Ok(());
    };
    let mut path = entry.path.clone();
    let mut whiteout_name = b".wh.".to_vec();
    whiteout_name.extend_from_slice(os_str_bytes(file_name));
    path.set_file_name(os_string_from_vec(whiteout_name).map_err(ImageError::Io)?);
    append_empty_file(builder, &path, entry)
}

fn append_opaque_marker<W: Write>(
    builder: &mut tar::Builder<DigestingWriter<W>>,
    entry: &crate::erofs::ErofsTreeEntry,
) -> ImageResult<()> {
    let path = entry.path.join(".wh..wh..opq");
    append_empty_file(builder, &path, entry)
}

fn append_empty_file<W: Write>(
    builder: &mut tar::Builder<DigestingWriter<W>>,
    path: &Path,
    entry: &crate::erofs::ErofsTreeEntry,
) -> ImageResult<()> {
    let mut header = tar::Header::new_gnu();
    apply_header_metadata(&mut header, entry);
    header.set_mode(0o000);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_size(0);
    header.set_cksum();
    builder
        .append_data(&mut header, path, io::empty())
        .map_err(ImageError::Io)
}

fn append_layer_entries<W: Write>(
    archive: &mut tar::Builder<W>,
    layer: &GeneratedLayer,
) -> ImageResult<()> {
    append_bytes(archive, &format!("{}/VERSION", layer.hex), b"1.0\n")?;
    append_bytes(archive, &format!("{}/json", layer.hex), b"{}")?;

    let mut file = File::open(&layer.path).map_err(|e| ImageError::Cache {
        path: layer.path.clone(),
        source: e,
    })?;
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(layer.size);
    header.set_cksum();
    archive
        .append_data(&mut header, format!("{}/layer.tar", layer.hex), &mut file)
        .map_err(ImageError::Io)
}

fn append_blob_file<W: Write>(
    archive: &mut tar::Builder<W>,
    hex: &str,
    path: &Path,
    size: u64,
) -> ImageResult<()> {
    let mut file = File::open(path).map_err(|e| ImageError::Cache {
        path: path.to_path_buf(),
        source: e,
    })?;
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(size);
    header.set_cksum();
    archive
        .append_data(&mut header, format!("blobs/sha256/{hex}"), &mut file)
        .map_err(ImageError::Io)
}

fn append_blob_bytes<W: Write>(
    archive: &mut tar::Builder<W>,
    hex: &str,
    bytes: &[u8],
) -> ImageResult<()> {
    append_bytes(archive, &format!("blobs/sha256/{hex}"), bytes)
}

fn append_directory<W: Write>(archive: &mut tar::Builder<W>, path: &str) -> ImageResult<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_mode(0o755);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(0);
    header.set_cksum();
    archive
        .append_data(&mut header, path, io::empty())
        .map_err(ImageError::Io)
}

fn append_bytes<W: Write>(
    archive: &mut tar::Builder<W>,
    path: &str,
    bytes: &[u8],
) -> ImageResult<()> {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(bytes.len() as u64);
    header.set_cksum();
    archive
        .append_data(&mut header, path, bytes)
        .map_err(ImageError::Io)
}

fn enforce_archive_entry_count(count: u64) -> ImageResult<()> {
    if count > ARCHIVE_MAX_ENTRY_COUNT {
        return Err(ImageError::ManifestParse(format!(
            "archive has more than {ARCHIVE_MAX_ENTRY_COUNT} entries"
        )));
    }

    Ok(())
}

fn read_entry_to_vec(
    entry: &mut tar::Entry<'_, File>,
    path: &str,
    max_bytes: u64,
) -> ImageResult<Vec<u8>> {
    let declared_size = entry.header().size().map_err(ImageError::Io)?;
    if declared_size > max_bytes {
        return Err(ImageError::ManifestParse(format!(
            "archive metadata entry {path} is {declared_size} bytes; max is {max_bytes}"
        )));
    }

    let mut data = Vec::with_capacity(declared_size as usize);
    entry.read_to_end(&mut data).map_err(ImageError::Io)?;
    Ok(data)
}

fn json_bytes_to_string(bytes: &[u8], context: &str) -> ImageResult<String> {
    std::str::from_utf8(bytes)
        .map(str::to_owned)
        .map_err(|e| ImageError::ConfigParse(format!("{context} is not UTF-8 JSON: {e}")))
}

fn docker_config_json(
    config: &ImageSaveConfig,
    raw_config_json: &str,
    diff_ids: &[String],
) -> ImageResult<Vec<u8>> {
    if !raw_config_json.is_empty() {
        let mut config_json: serde_json::Value = serde_json::from_str(raw_config_json)
            .map_err(|e| ImageError::ConfigParse(format!("parse raw image config: {e}")))?;
        let Some(object) = config_json.as_object_mut() else {
            return Err(ImageError::ConfigParse(
                "raw image config JSON is not an object".into(),
            ));
        };
        object.insert(
            "rootfs".into(),
            serde_json::json!({
                "type": "layers",
                "diff_ids": diff_ids,
            }),
        );
        object.entry("architecture").or_insert_with(|| {
            serde_json::json!(config.architecture.as_deref().unwrap_or("amd64"))
        });
        object
            .entry("os")
            .or_insert_with(|| serde_json::json!(config.os.as_deref().unwrap_or("linux")));
        return serde_json::to_vec(&config_json)
            .map_err(|e| ImageError::ConfigParse(format!("serialize image config: {e}")));
    }

    let config_json = serde_json::json!({
        "architecture": config.architecture.as_deref().unwrap_or("amd64"),
        "os": config.os.as_deref().unwrap_or("linux"),
        "config": {
            "Env": config.env,
            "Entrypoint": config.entrypoint,
            "Cmd": config.cmd,
            "WorkingDir": config.working_dir,
            "User": config.user,
            "Labels": if config.labels.is_empty() {
                serde_json::Value::Null
            } else {
                serde_json::to_value(&config.labels)
                    .map_err(|e| ImageError::ConfigParse(format!("serialize labels: {e}")))?
            },
        },
        "rootfs": {
            "type": "layers",
            "diff_ids": diff_ids,
        },
        "history": diff_ids
            .iter()
            .map(|_| serde_json::json!({"created_by": "microsandbox image save"}))
            .collect::<Vec<_>>(),
    });

    serde_json::to_vec(&config_json)
        .map_err(|e| ImageError::ConfigParse(format!("serialize image config: {e}")))
}

fn apply_header_metadata(header: &mut tar::Header, entry: &crate::erofs::ErofsTreeEntry) {
    header.set_mode((entry.metadata.mode & 0o7777) as u32);
    header.set_uid(entry.metadata.uid as u64);
    header.set_gid(entry.metadata.gid as u64);
    header.set_mtime(entry.metadata.mtime);
}

fn normalized_archive_path(entry: &tar::Entry<'_, File>) -> ImageResult<String> {
    let path = entry.path().map_err(ImageError::Io)?;
    let bytes = path_bytes(path.as_ref());
    let normalized = if let Some(stripped) = bytes.strip_prefix(b"./") {
        stripped
    } else {
        bytes
    };
    String::from_utf8(normalized.to_vec())
        .map_err(|_| ImageError::ManifestParse("archive path is not valid UTF-8".into()))
}

fn sha256_hex(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::io::Cursor;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn docker_archive_load_save_load_roundtrip() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let temp = tempdir().unwrap();
        let input = temp.path().join("image.tar");
        write_test_docker_archive(&input, "tiny:latest");

        let first_cache = temp.path().join("cache-1");
        let loaded = runtime
            .block_on(load_archive(
                &first_cache,
                &input,
                ImageLoadOptions::default(),
            ))
            .unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].reference, "tiny:latest");

        let saved = temp.path().join("saved.tar");
        let request = save_request_from_loaded(&loaded[0]);
        let cache = GlobalCache::new(&first_cache).unwrap();
        save_docker_archive(&cache, &saved, &[request]).unwrap();

        let second_cache = temp.path().join("cache-2");
        let reloaded = runtime
            .block_on(load_archive(
                &second_cache,
                &saved,
                ImageLoadOptions::default(),
            ))
            .unwrap();

        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded[0].reference, "tiny:latest");
        assert_eq!(
            reloaded[0].metadata.config.cmd,
            Some(vec!["cat".into(), "/hello.txt".into()])
        );
    }

    #[test]
    fn docker_archive_loads_manifest_blob_paths() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let temp = tempdir().unwrap();
        let input = temp.path().join("blob-paths.tar");
        write_test_docker_blob_archive_from_layer(&input, "blob-paths:latest", simple_layer_tar());

        let loaded = runtime
            .block_on(load_archive(
                &temp.path().join("cache"),
                &input,
                ImageLoadOptions::default(),
            ))
            .unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].reference, "blob-paths:latest");
        assert_eq!(
            loaded[0].metadata.config.cmd,
            Some(vec!["cat".into(), "/hello.txt".into()])
        );
    }

    #[test]
    fn docker_archive_rejects_mismatched_blob_layer_path() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let temp = tempdir().unwrap();
        let input = temp.path().join("bad-blob-path.tar");
        let layer_bytes = simple_layer_tar();
        let diff_id = format!("sha256:{}", sha256_hex(&layer_bytes));
        let config_bytes = test_config_bytes(&diff_id);
        let config_name = format!("blobs/sha256/{}", sha256_hex(&config_bytes));
        let layer_name = format!("blobs/sha256/{:064x}", 1u8);

        write_test_docker_archive_entries(
            &input,
            "bad-blob-path:latest",
            config_name,
            layer_name,
            config_bytes,
            layer_bytes,
        );

        let err = runtime
            .block_on(load_archive(
                &temp.path().join("cache"),
                &input,
                ImageLoadOptions::default(),
            ))
            .unwrap_err();

        assert!(err.to_string().contains("digest mismatch"));
    }

    #[test]
    fn oci_layout_archive_load_save_load_roundtrip() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let temp = tempdir().unwrap();
        let input = temp.path().join("oci-layout.tar");
        write_test_oci_archive_from_layer(&input, "oci-layout:latest", simple_layer_tar());

        let first_cache = temp.path().join("cache-1");
        let loaded = runtime
            .block_on(load_archive(
                &first_cache,
                &input,
                ImageLoadOptions::default(),
            ))
            .unwrap();

        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].reference, "oci-layout:latest");

        let saved = temp.path().join("saved-oci-layout.tar");
        let request = save_request_from_loaded(&loaded[0]);
        let cache = GlobalCache::new(&first_cache).unwrap();
        save_archive(&cache, &saved, &[request], ImageArchiveFormat::Oci).unwrap();

        let index_bytes = read_archive_entry(&saved, "index.json").unwrap().unwrap();
        let index: oci_spec::image::ImageIndex = serde_json::from_slice(&index_bytes).unwrap();
        assert_eq!(index.manifests().len(), 1);
        assert_eq!(
            index.manifests()[0]
                .annotations()
                .as_ref()
                .unwrap()
                .get(OCI_REF_NAME_ANNOTATION),
            Some(&"oci-layout:latest".to_string())
        );

        let second_cache = temp.path().join("cache-2");
        let reloaded = runtime
            .block_on(load_archive(
                &second_cache,
                &saved,
                ImageLoadOptions::default(),
            ))
            .unwrap();

        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded[0].reference, "oci-layout:latest");
    }

    #[test]
    fn docker_archive_save_preserves_layer_semantics() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let temp = tempdir().unwrap();
        let input = temp.path().join("complex.tar");
        let layer_bytes = complex_layer_tar();
        write_test_docker_archive_from_layer(&input, "complex:latest", layer_bytes);

        let first_cache = temp.path().join("cache-1");
        let loaded = runtime
            .block_on(load_archive(
                &first_cache,
                &input,
                ImageLoadOptions::default(),
            ))
            .unwrap();

        let saved = temp.path().join("saved-complex.tar");
        let request = save_request_from_loaded(&loaded[0]);
        let cache = GlobalCache::new(&first_cache).unwrap();
        save_docker_archive(&cache, &saved, &[request]).unwrap();

        let entries = saved_layer_entries(&saved);
        let config_entry = entries.get("etc/config.txt").unwrap();
        let config_link_entry = entries.get("etc/config.link").unwrap();
        let regular_config_paths = [
            ("etc/config.txt", config_entry),
            ("etc/config.link", config_link_entry),
        ]
        .into_iter()
        .filter(|(_, entry)| entry.entry_type == tar::EntryType::Regular)
        .collect::<Vec<_>>();
        let hardlink_config_paths = [
            ("etc/config.txt", config_entry),
            ("etc/config.link", config_link_entry),
        ]
        .into_iter()
        .filter(|(_, entry)| entry.entry_type == tar::EntryType::Link)
        .collect::<Vec<_>>();

        assert_eq!(regular_config_paths.len(), 1);
        assert_eq!(hardlink_config_paths.len(), 1);
        assert_eq!(regular_config_paths[0].1.data, b"shared config\n");
        assert_eq!(
            hardlink_config_paths[0].1.link_name.as_deref(),
            Some(regular_config_paths[0].0)
        );
        assert_eq!(regular_config_paths[0].1.mode, 0o640);
        assert_eq!(regular_config_paths[0].1.uid, 1000);
        assert_eq!(regular_config_paths[0].1.gid, 1001);
        assert_eq!(regular_config_paths[0].1.mtime, 42);

        let symlink_entry = entries.get("bin/config").unwrap();
        assert_eq!(symlink_entry.entry_type, tar::EntryType::Symlink);
        assert_eq!(
            symlink_entry.link_name.as_deref(),
            Some("../etc/config.txt")
        );

        let whiteout_entry = entries.get("var/.wh.deleted").unwrap();
        assert_eq!(whiteout_entry.entry_type, tar::EntryType::Regular);
        assert!(whiteout_entry.data.is_empty());

        let opaque_entry = entries.get("cache/.wh..wh..opq").unwrap();
        assert_eq!(opaque_entry.entry_type, tar::EntryType::Regular);
        assert!(opaque_entry.data.is_empty());

        let second_cache = temp.path().join("cache-2");
        let reloaded = runtime
            .block_on(load_archive(
                &second_cache,
                &saved,
                ImageLoadOptions::default(),
            ))
            .unwrap();

        assert_eq!(reloaded.len(), 1);
        assert_eq!(reloaded[0].reference, "complex:latest");
    }

    #[test]
    fn docker_archive_save_preserves_raw_config_fields() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let temp = tempdir().unwrap();
        let input = temp.path().join("config-fidelity.tar");
        let layer_bytes = simple_layer_tar();
        let diff_id = format!("sha256:{}", sha256_hex(&layer_bytes));
        let config_bytes = serde_json::to_vec(&serde_json::json!({
            "architecture": "arm64",
            "os": "linux",
            "author": "microsandbox-test",
            "config": {
                "Env": ["PATH=/usr/bin"],
                "Cmd": ["cat", "/hello.txt"],
            },
            "rootfs": {
                "type": "layers",
                "diff_ids": [diff_id],
            },
            "history": [{
                "created_by": "fixture",
                "comment": "keep me",
            }],
        }))
        .unwrap();
        let config_name = format!("{}.json", sha256_hex(&config_bytes));

        write_test_docker_archive_entries(
            &input,
            "config-fidelity:latest",
            config_name,
            "layer/layer.tar".into(),
            config_bytes,
            layer_bytes,
        );

        let first_cache = temp.path().join("cache-1");
        let loaded = runtime
            .block_on(load_archive(
                &first_cache,
                &input,
                ImageLoadOptions::default(),
            ))
            .unwrap();
        let saved = temp.path().join("saved-config-fidelity.tar");
        let request = save_request_from_loaded(&loaded[0]);
        let cache = GlobalCache::new(&first_cache).unwrap();
        save_docker_archive(&cache, &saved, &[request]).unwrap();

        let manifest_bytes = read_archive_entry(&saved, "manifest.json")
            .unwrap()
            .unwrap();
        let manifest: Vec<DockerManifestEntry> = serde_json::from_slice(&manifest_bytes).unwrap();
        let saved_config = read_archive_entry(&saved, &manifest[0].config)
            .unwrap()
            .unwrap();
        let saved_config: serde_json::Value = serde_json::from_slice(&saved_config).unwrap();

        assert_eq!(saved_config["author"], "microsandbox-test");
        assert_eq!(saved_config["history"][0]["comment"], "keep me");
    }

    fn write_test_docker_archive(path: &Path, reference: &str) {
        write_test_docker_archive_from_layer(path, reference, simple_layer_tar());
    }

    fn write_test_docker_archive_from_layer(path: &Path, reference: &str, layer_bytes: Vec<u8>) {
        let diff_id = format!("sha256:{}", sha256_hex(&layer_bytes));
        let config_bytes = test_config_bytes(&diff_id);
        let config_name = format!("{}.json", sha256_hex(&config_bytes));

        write_test_docker_archive_entries(
            path,
            reference,
            config_name,
            "layer/layer.tar".into(),
            config_bytes,
            layer_bytes,
        );
    }

    fn write_test_docker_blob_archive_from_layer(
        path: &Path,
        reference: &str,
        layer_bytes: Vec<u8>,
    ) {
        let diff_id = format!("sha256:{}", sha256_hex(&layer_bytes));
        let config_bytes = test_config_bytes(&diff_id);
        let config_name = format!("blobs/sha256/{}", sha256_hex(&config_bytes));
        let layer_name = format!("blobs/sha256/{}", sha256_hex(&layer_bytes));

        write_test_docker_archive_entries(
            path,
            reference,
            config_name,
            layer_name,
            config_bytes,
            layer_bytes,
        );
    }

    fn write_test_oci_archive_from_layer(path: &Path, reference: &str, layer_bytes: Vec<u8>) {
        let diff_id = format!("sha256:{}", sha256_hex(&layer_bytes));
        let config_bytes = test_config_bytes(&diff_id);
        let config_hex = sha256_hex(&config_bytes);
        let layer_hex = sha256_hex(&layer_bytes);
        let manifest_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "config": {
                "mediaType": OCI_CONFIG_MEDIA_TYPE,
                "digest": format!("sha256:{config_hex}"),
                "size": config_bytes.len(),
            },
            "layers": [{
                "mediaType": OCI_LAYER_MEDIA_TYPE,
                "digest": format!("sha256:{layer_hex}"),
                "size": layer_bytes.len(),
            }],
        }))
        .unwrap();
        let manifest_hex = sha256_hex(&manifest_bytes);
        let host = Platform::host_linux();
        let index_bytes = serde_json::to_vec(&serde_json::json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX_MEDIA_TYPE,
            "manifests": [{
                "mediaType": OCI_MANIFEST_MEDIA_TYPE,
                "digest": format!("sha256:{manifest_hex}"),
                "size": manifest_bytes.len(),
                "platform": {
                    "architecture": host.arch.to_string(),
                    "os": host.os.to_string(),
                },
                "annotations": {
                    (OCI_REF_NAME_ANNOTATION): reference,
                },
            }],
        }))
        .unwrap();

        let file = File::create(path).unwrap();
        let mut archive = tar::Builder::new(file);
        append_bytes(
            &mut archive,
            "oci-layout",
            br#"{"imageLayoutVersion":"1.0.0"}"#,
        )
        .unwrap();
        append_bytes(&mut archive, "index.json", &index_bytes).unwrap();
        append_bytes(
            &mut archive,
            &format!("blobs/sha256/{config_hex}"),
            &config_bytes,
        )
        .unwrap();
        append_bytes(
            &mut archive,
            &format!("blobs/sha256/{manifest_hex}"),
            &manifest_bytes,
        )
        .unwrap();
        append_bytes(
            &mut archive,
            &format!("blobs/sha256/{layer_hex}"),
            &layer_bytes,
        )
        .unwrap();
        archive.finish().unwrap();
    }

    fn simple_layer_tar() -> Vec<u8> {
        let mut layer_bytes = Vec::new();
        {
            let mut layer = tar::Builder::new(&mut layer_bytes);
            let data = b"hello from archive\n";
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_uid(0);
            header.set_gid(0);
            header.set_mtime(0);
            header.set_size(data.len() as u64);
            header.set_cksum();
            layer
                .append_data(&mut header, "hello.txt", Cursor::new(data))
                .unwrap();
            layer.finish().unwrap();
        }

        layer_bytes
    }

    fn test_config_bytes(diff_id: &str) -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "architecture": "arm64",
            "os": "linux",
            "config": {
                "Env": ["PATH=/usr/bin"],
                "Cmd": ["cat", "/hello.txt"],
            },
            "rootfs": {
                "type": "layers",
                "diff_ids": [diff_id],
            },
        }))
        .unwrap()
    }

    fn write_test_docker_archive_entries(
        path: &Path,
        reference: &str,
        config_name: String,
        layer_name: String,
        config_bytes: Vec<u8>,
        layer_bytes: Vec<u8>,
    ) {
        let manifest_bytes = serde_json::to_vec(&vec![DockerManifestOut {
            config: config_name.clone(),
            repo_tags: vec![reference.into()],
            layers: vec![layer_name.clone()],
        }])
        .unwrap();

        let file = File::create(path).unwrap();
        let mut archive = tar::Builder::new(file);
        append_bytes(&mut archive, &config_name, &config_bytes).unwrap();
        append_bytes(&mut archive, "manifest.json", &manifest_bytes).unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(0o644);
        header.set_uid(0);
        header.set_gid(0);
        header.set_mtime(0);
        header.set_size(layer_bytes.len() as u64);
        header.set_cksum();
        archive
            .append_data(&mut header, layer_name, Cursor::new(layer_bytes))
            .unwrap();
        archive.finish().unwrap();
    }

    fn complex_layer_tar() -> Vec<u8> {
        let mut layer_bytes = Vec::new();
        {
            let mut layer = tar::Builder::new(&mut layer_bytes);
            append_test_dir(&mut layer, "bin", 0o755, 0, 0, 1);
            append_test_dir(&mut layer, "cache", 0o755, 0, 0, 1);
            append_test_dir(&mut layer, "etc", 0o755, 0, 0, 1);
            append_test_dir(&mut layer, "var", 0o755, 0, 0, 1);
            append_test_file(
                &mut layer,
                "etc/config.txt",
                b"shared config\n",
                0o640,
                1000,
                1001,
                42,
            );
            append_test_hardlink(&mut layer, "etc/config.link", "etc/config.txt");
            append_test_symlink(&mut layer, "bin/config", "../etc/config.txt");
            append_test_file(&mut layer, "var/.wh.deleted", b"", 0o000, 0, 0, 1);
            append_test_file(&mut layer, "cache/.wh..wh..opq", b"", 0o000, 0, 0, 1);
            layer.finish().unwrap();
        }
        layer_bytes
    }

    fn append_test_dir(
        layer: &mut tar::Builder<&mut Vec<u8>>,
        path: &str,
        mode: u32,
        uid: u64,
        gid: u64,
        mtime: u64,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Directory);
        header.set_mode(mode);
        header.set_uid(uid);
        header.set_gid(gid);
        header.set_mtime(mtime);
        header.set_size(0);
        header.set_cksum();
        layer.append_data(&mut header, path, io::empty()).unwrap();
    }

    fn append_test_file(
        layer: &mut tar::Builder<&mut Vec<u8>>,
        path: &str,
        data: &[u8],
        mode: u32,
        uid: u64,
        gid: u64,
        mtime: u64,
    ) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Regular);
        header.set_mode(mode);
        header.set_uid(uid);
        header.set_gid(gid);
        header.set_mtime(mtime);
        header.set_size(data.len() as u64);
        header.set_cksum();
        layer
            .append_data(&mut header, path, Cursor::new(data))
            .unwrap();
    }

    fn append_test_hardlink(layer: &mut tar::Builder<&mut Vec<u8>>, path: &str, target: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name(target).unwrap();
        header.set_size(0);
        header.set_cksum();
        layer.append_data(&mut header, path, io::empty()).unwrap();
    }

    fn append_test_symlink(layer: &mut tar::Builder<&mut Vec<u8>>, path: &str, target: &str) {
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name(target).unwrap();
        header.set_mode(0o777);
        header.set_size(0);
        header.set_cksum();
        layer.append_data(&mut header, path, io::empty()).unwrap();
    }

    #[derive(Debug)]
    struct SavedLayerEntry {
        entry_type: tar::EntryType,
        link_name: Option<String>,
        mode: u32,
        uid: u64,
        gid: u64,
        mtime: u64,
        data: Vec<u8>,
    }

    fn saved_layer_entries(path: &Path) -> BTreeMap<String, SavedLayerEntry> {
        let file = File::open(path).unwrap();
        let mut archive = tar::Archive::new(file);
        let mut layer_bytes = None;

        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let entry_path = entry.path().unwrap().to_string_lossy().into_owned();
            if entry_path.ends_with("/layer.tar") {
                assert!(layer_bytes.is_none());
                let mut data = Vec::new();
                entry.read_to_end(&mut data).unwrap();
                layer_bytes = Some(data);
            }
        }

        let layer_bytes = layer_bytes.unwrap();
        let mut layer = tar::Archive::new(Cursor::new(layer_bytes));
        let mut entries = BTreeMap::new();

        for entry in layer.entries().unwrap() {
            let mut entry = entry.unwrap();
            let path = entry.path().unwrap().to_string_lossy().into_owned();
            let header = entry.header();
            let entry_type = header.entry_type();
            let mode = header.mode().unwrap();
            let uid = header.uid().unwrap();
            let gid = header.gid().unwrap();
            let mtime = header.mtime().unwrap();
            let link_name = if matches!(entry_type, tar::EntryType::Link | tar::EntryType::Symlink)
            {
                Some(String::from_utf8_lossy(entry.link_name_bytes().unwrap().as_ref()).into())
            } else {
                None
            };
            let mut data = Vec::new();
            entry.read_to_end(&mut data).unwrap();

            entries.insert(
                path,
                SavedLayerEntry {
                    entry_type,
                    link_name,
                    mode,
                    uid,
                    gid,
                    mtime,
                    data,
                },
            );
        }

        entries
    }

    fn save_request_from_loaded(image: &LoadedImage) -> ImageSaveRequest {
        let host = Platform::host_linux();
        ImageSaveRequest {
            reference: image.reference.clone(),
            config: ImageSaveConfig {
                architecture: Some(host.arch.to_string()),
                os: Some(host.os.to_string()),
                env: image.metadata.config.env.clone(),
                entrypoint: image.metadata.config.entrypoint.clone(),
                cmd: image.metadata.config.cmd.clone(),
                working_dir: image.metadata.config.working_dir.clone(),
                user: image.metadata.config.user.clone(),
                labels: image
                    .metadata
                    .config
                    .labels
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect(),
            },
            raw_config_json: image.metadata.raw_config_json.clone(),
            layers: image
                .metadata
                .layers
                .iter()
                .map(|layer| ImageSaveLayer {
                    diff_id: layer.diff_id.clone(),
                })
                .collect(),
        }
    }
}
