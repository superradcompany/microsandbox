//! OCI registry client.
//!
//! Wraps `oci-client` with platform resolution, caching, and progress reporting.

use std::{
    collections::{HashMap, HashSet},
    io,
    os::fd::AsRawFd,
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use oci_client::{Client, client::ClientConfig, manifest::ImageIndexEntry};
use tokio::{
    io::{AsyncRead, ReadBuf},
    sync::Semaphore,
    task::JoinHandle,
};

use crate::{
    auth::RegistryAuth,
    config::ImageConfig,
    digest::Digest,
    erofs,
    error::{ImageError, ImageResult},
    filetree::{FileTree, ResourceLimits},
    layer::Layer,
    lock::{flock_unlock, open_lock_file},
    manifest::OciManifest,
    platform::Platform,
    progress::{self, PullProgress, PullProgressHandle, PullProgressSender},
    pull::{PullOptions, PullPolicy, PullResult},
    store::{self, CachedImageMetadata, CachedLayerMetadata, GlobalCache},
    tar_ingest::{self, Compression},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Minimum byte delta between per-layer materialization progress updates.
const MATERIALIZE_PROGRESS_EMIT_BYTES: u64 = 256 * 1024;

/// Upper bound for concurrently active layer download/materialize tasks.
const MAX_LAYER_PIPELINE_CONCURRENCY: usize = 16;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// OCI registry client with platform resolution, caching, and progress reporting.
pub struct Registry {
    client: Client,
    auth: oci_client::secrets::RegistryAuth,
    platform: Platform,
    cache: GlobalCache,
}

/// Resolved manifest layer descriptor used during download/materialization.
#[derive(Debug, Clone)]
struct LayerDescriptor {
    digest: Digest,
    media_type: Option<String>,
    size: Option<u64>,
}

struct CachedPullInfo {
    result: PullResult,
    metadata: CachedImageMetadata,
}

struct LayerPipelineFailure {
    error: ImageError,
}

/// Per-layer pipeline success: EROFS image written, data-stripped tree + data map retained.
/// `tree` and `data_map` are `None` when the EROFS was already cached.
struct LayerPipelineTreeSuccess {
    layer_index: usize,
    tree: Option<FileTree>,
    data_map: Option<erofs::ErofsDataMap>,
}

/// Wraps an `AsyncRead` to emit `LayerMaterializeProgress` events as the
/// tar stream is read during EROFS materialization.
///
/// Progress events are throttled to avoid flooding the channel — an update
/// is sent only after at least `MATERIALIZE_PROGRESS_EMIT_BYTES` (256 KiB)
/// have been read since the last event.
struct MaterializeProgressReader<R> {
    inner: R,
    progress: Option<PullProgressSender>,
    layer_index: usize,
    total_bytes: u64,
    bytes_read: u64,
    last_emitted_bytes: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<R> MaterializeProgressReader<R> {
    fn new(
        inner: R,
        progress: Option<PullProgressSender>,
        layer_index: usize,
        total_bytes: u64,
    ) -> Self {
        Self {
            inner,
            progress,
            layer_index,
            total_bytes: total_bytes.max(1),
            bytes_read: 0,
            last_emitted_bytes: 0,
        }
    }
}

impl Registry {
    /// Create a registry client with anonymous authentication.
    pub fn new(platform: Platform, cache: GlobalCache) -> ImageResult<Self> {
        let client = build_client(&platform);

        Ok(Self {
            client,
            auth: oci_client::secrets::RegistryAuth::Anonymous,
            platform,
            cache,
        })
    }

    /// Create a registry client with explicit authentication.
    pub fn with_auth(
        platform: Platform,
        cache: GlobalCache,
        auth: RegistryAuth,
    ) -> ImageResult<Self> {
        let client = build_client(&platform);

        Ok(Self {
            client,
            auth: (&auth).into(),
            platform,
            cache,
        })
    }

    /// Resolve a pull directly from the on-disk cache without building a registry client.
    pub fn pull_cached(
        cache: &GlobalCache,
        reference: &oci_client::Reference,
        options: &PullOptions,
    ) -> ImageResult<Option<(PullResult, CachedImageMetadata)>> {
        Ok(resolve_cached_pull_result(cache, reference, options)?
            .map(|cached| (cached.result, cached.metadata)))
    }

    /// Pull an image. Downloads blobs and materializes EROFS layers concurrently.
    pub async fn pull(
        &self,
        reference: &oci_client::Reference,
        options: &PullOptions,
    ) -> ImageResult<PullResult> {
        self.pull_inner(reference, options, None).await
    }

    /// Pull with progress reporting.
    ///
    /// Creates a progress channel internally and returns both the receiver
    /// handle and the spawned pull task.
    pub fn pull_with_progress(
        &self,
        reference: &oci_client::Reference,
        options: &PullOptions,
    ) -> (PullProgressHandle, JoinHandle<ImageResult<PullResult>>)
    where
        Self: Send + Sync + 'static,
    {
        let (handle, sender) = progress::progress_channel();
        let task = self.spawn_pull_task(reference, options, sender);
        (handle, task)
    }

    /// Pull with an externally-provided progress sender.
    ///
    /// Use [`progress_channel()`](crate::progress_channel) to create the
    /// channel, keep the [`PullProgressHandle`] receiver, and pass the
    /// [`PullProgressSender`] here.
    pub fn pull_with_sender(
        &self,
        reference: &oci_client::Reference,
        options: &PullOptions,
        sender: PullProgressSender,
    ) -> JoinHandle<ImageResult<PullResult>>
    where
        Self: Send + Sync + 'static,
    {
        self.spawn_pull_task(reference, options, sender)
    }

    /// Spawn the pull task with a progress sender.
    fn spawn_pull_task(
        &self,
        reference: &oci_client::Reference,
        options: &PullOptions,
        sender: PullProgressSender,
    ) -> JoinHandle<ImageResult<PullResult>>
    where
        Self: Send + Sync + 'static,
    {
        let reference = reference.clone();
        let options = options.clone();
        let client = self.client.clone();
        let auth = self.auth.clone();
        let platform = self.platform.clone();

        let layers_dir = self.cache.layers_dir().to_path_buf();
        let cache_parent = layers_dir.parent().unwrap_or(&layers_dir).to_path_buf();

        tokio::spawn(async move {
            let cache = GlobalCache::new_async(&cache_parent).await?;
            let registry = Self {
                client,
                auth,
                platform,
                cache,
            };
            registry
                .pull_inner(&reference, &options, Some(sender))
                .await
        })
    }

    /// Core pull implementation.
    async fn pull_inner(
        &self,
        reference: &oci_client::Reference,
        options: &PullOptions,
        progress: Option<PullProgressSender>,
    ) -> ImageResult<PullResult> {
        let pull_started_at = Instant::now();
        let ref_str: Arc<str> = reference.to_string().into();
        let oci_ref = reference;
        let image_lock_path = self.cache.image_lock_path(reference);
        let image_lock_file = open_lock_file(&image_lock_path)?;
        {
            let fd = image_lock_file.as_raw_fd();
            tokio::task::spawn_blocking(move || {
                let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
                if ret != 0 {
                    return Err(ImageError::Io(io::Error::last_os_error()));
                }
                Ok(())
            })
            .await
            .map_err(|e| ImageError::Io(io::Error::other(e)))??;
        }
        // Lock files are intentionally never deleted — stable inodes prevent
        // TOCTOU races where two processes flock different inodes at the same path.
        let _image_lock_guard = scopeguard::guard(image_lock_file, |file| {
            let _ = flock_unlock(&file);
        });

        // Step 1: Early cache check using persisted image metadata.
        if let Some(cached) =
            resolve_cached_pull_result_async(&self.cache, reference, options).await?
        {
            tracing::debug!(
                reference = %reference,
                elapsed_ms = pull_started_at.elapsed().as_millis(),
                "pull resolved entirely from cached image metadata"
            );

            if let Some(ref p) = progress {
                p.send(PullProgress::Resolving {
                    reference: ref_str.clone(),
                });
                p.send(PullProgress::Resolved {
                    reference: ref_str.clone(),
                    manifest_digest: cached.metadata.manifest_digest.clone().into(),
                    layer_count: cached.metadata.layers.len(),
                    total_download_bytes: cached
                        .metadata
                        .layers
                        .iter()
                        .filter_map(|layer| layer.size_bytes)
                        .reduce(|a, b| a + b),
                });
                p.send(PullProgress::Complete {
                    reference: ref_str,
                    layer_count: cached.metadata.layers.len(),
                });
            }

            return Ok(cached.result);
        }

        if options.pull_policy == PullPolicy::Never {
            return Err(ImageError::NotCached {
                reference: reference.to_string(),
            });
        }

        // Step 2: Resolve manifest.
        if let Some(ref p) = progress {
            p.send(PullProgress::Resolving {
                reference: ref_str.clone(),
            });
        }

        let resolve_started_at = Instant::now();
        let (manifest_bytes, manifest_digest, config_bytes) =
            self.fetch_manifest_and_config(oci_ref).await?;

        let manifest_digest: Digest = manifest_digest.parse()?;

        // Determine media type from manifest bytes. For multi-platform images,
        // this also fetches the platform-specific config bytes.
        let (manifest, config_bytes) = self
            .parse_and_resolve_manifest(&manifest_bytes, config_bytes, oci_ref)
            .await?;

        // Step 3: Parse config.
        let (image_config, diff_ids) = ImageConfig::parse(&config_bytes)?;

        // Step 4: Get layer descriptors.
        let layer_descriptors = self.extract_layer_digests(&manifest)?;

        // OCI spec requires diff_ids and layer descriptors to have the same count.
        if diff_ids.len() != layer_descriptors.len() {
            return Err(ImageError::ManifestParse(format!(
                "layer count mismatch: config has {} diff_ids but manifest has {} layers",
                diff_ids.len(),
                layer_descriptors.len()
            )));
        }

        let layer_count = layer_descriptors.len();
        let total_bytes: Option<u64> = {
            let sum: u64 = layer_descriptors
                .iter()
                .filter_map(|layer| layer.size)
                .sum();
            if sum > 0 { Some(sum) } else { None }
        };

        tracing::debug!(
            reference = %reference,
            layer_count,
            elapsed_ms = resolve_started_at.elapsed().as_millis(),
            "pull resolved manifest and layer descriptors"
        );

        if let Some(ref p) = progress {
            p.send(PullProgress::Resolved {
                reference: ref_str.clone(),
                manifest_digest: manifest_digest.to_string().into(),
                layer_count,
                total_download_bytes: total_bytes,
            });
        }

        // Give the receiver a chance to render the resolved state before the
        // layer tasks begin flooding download events.
        tokio::task::yield_now().await;

        // Warn about duplicate layer digests — they can cause contention.
        {
            let mut seen = std::collections::HashSet::new();
            for desc in &layer_descriptors {
                if !seen.insert(&desc.digest) {
                    tracing::warn!(
                        digest = %desc.digest,
                        "manifest contains duplicate layer digest; \
                         per-layer processing will be serialized for this digest"
                    );
                }
            }
        }

        // Materialize per-layer EROFS images, then generate fsmeta + VMDK.
        self.materialize_layers_and_fsmeta(
            oci_ref,
            &manifest_digest,
            &layer_descriptors,
            &diff_ids,
            options.force,
            progress.clone(),
        )
        .await?;

        // Clean up compressed tarballs after all layer tasks complete.
        // Deferred from per-task cleanup to avoid races with duplicate layer digests.
        for layer_desc in &layer_descriptors {
            let layer = Layer::new(layer_desc.digest.clone(), &self.cache);
            let _ = tokio::fs::remove_file(&layer.tar_path_ref()).await;
        }

        let layer_diff_ids: Vec<Digest> = diff_ids
            .iter()
            .map(|diff_id| diff_id.parse())
            .collect::<ImageResult<Vec<Digest>>>()?;

        // Persist cached image metadata.
        let cached_image = CachedImageMetadata {
            manifest_digest: manifest_digest.to_string(),
            config_digest: manifest.config_digest().unwrap_or_default(),
            config: image_config.clone(),
            layers: layer_descriptors
                .iter()
                .enumerate()
                .map(|(i, layer)| CachedLayerMetadata {
                    digest: layer.digest.to_string(),
                    media_type: layer.media_type.clone(),
                    size_bytes: layer.size,
                    diff_id: diff_ids.get(i).cloned().unwrap_or_default(),
                })
                .collect(),
        };
        self.cache
            .write_image_metadata_async(reference, &cached_image)
            .await?;

        tracing::debug!(
            reference = %reference,
            layer_count,
            elapsed_ms = pull_started_at.elapsed().as_millis(),
            "pull completed and cached image metadata was persisted"
        );

        if let Some(ref p) = progress {
            p.send(PullProgress::Complete {
                reference: ref_str,
                layer_count,
            });
        }

        Ok(PullResult {
            layer_diff_ids,
            config: image_config,
            manifest_digest,
            cached: false,
        })
    }

    /// Fetch manifest and config from the registry.
    async fn fetch_manifest_and_config(
        &self,
        reference: &oci_client::Reference,
    ) -> ImageResult<(Vec<u8>, String, Vec<u8>)> {
        let (manifest, manifest_digest, config) = self
            .client
            .pull_manifest_and_config(reference, &self.auth)
            .await?;

        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|e| ImageError::ManifestParse(format!("failed to serialize manifest: {e}")))?;

        Ok((manifest_bytes, manifest_digest, config.into_bytes()))
    }

    /// Parse manifest, resolving multi-platform index if needed.
    ///
    /// Returns the manifest and the correct config bytes. For single-platform
    /// manifests, the config bytes are passed through unchanged. For multi-platform
    /// indexes, the platform-specific config bytes are fetched and returned.
    async fn parse_and_resolve_manifest(
        &self,
        manifest_bytes: &[u8],
        config_bytes: Vec<u8>,
        reference: &oci_client::Reference,
    ) -> ImageResult<(OciManifest, Vec<u8>)> {
        // Try to detect media type from the JSON.
        let media_type = detect_manifest_media_type(manifest_bytes);

        let manifest = OciManifest::parse(manifest_bytes, &media_type)?;

        if manifest.is_index() {
            // Resolve platform-specific manifest and fetch its config.
            self.resolve_platform_manifest(manifest_bytes, reference)
                .await
        } else {
            Ok((manifest, config_bytes))
        }
    }

    /// Resolve a platform-specific manifest from an OCI index.
    ///
    /// Returns the resolved manifest and its platform-specific config bytes.
    async fn resolve_platform_manifest(
        &self,
        index_bytes: &[u8],
        reference: &oci_client::Reference,
    ) -> ImageResult<(OciManifest, Vec<u8>)> {
        let index: oci_spec::image::ImageIndex = serde_json::from_slice(index_bytes)
            .map_err(|e| ImageError::ManifestParse(format!("failed to parse index: {e}")))?;

        let manifests = index.manifests();

        // Find matching platform.
        let mut best_match: Option<&oci_spec::image::Descriptor> = None;
        let mut exact_variant = false;

        for entry in manifests {
            // Skip attestation manifests.
            if entry.media_type().to_string().contains("attestation") {
                continue;
            }

            let platform = match entry.platform().as_ref() {
                Some(p) => p,
                None => continue,
            };

            // OS must match.
            if *platform.os() != self.platform.os {
                continue;
            }

            // Architecture must match.
            if *platform.architecture() != self.platform.arch {
                continue;
            }

            // Check variant.
            if let Some(ref target_variant) = self.platform.variant {
                if let Some(entry_variant) = platform.variant().as_ref()
                    && entry_variant == target_variant
                {
                    best_match = Some(entry);
                    exact_variant = true;
                    continue;
                }
                if !exact_variant {
                    best_match = Some(entry);
                }
            } else {
                best_match = Some(entry);
            }
        }

        let entry = best_match.ok_or_else(|| ImageError::PlatformNotFound {
            reference: reference.to_string(),
            os: self.platform.os.clone(),
            arch: self.platform.arch.clone(),
        })?;

        let digest = entry.digest();

        // Fetch the platform-specific manifest and config.
        let platform_ref = format!(
            "{}/{}@{}",
            reference.registry(),
            reference.repository(),
            digest
        );
        let platform_ref: oci_client::Reference = platform_ref.parse().map_err(|e| {
            ImageError::ManifestParse(format!("failed to parse platform reference: {e}"))
        })?;

        let (manifest_bytes, _digest, config_bytes) =
            self.fetch_manifest_and_config(&platform_ref).await?;

        let media_type = detect_manifest_media_type(&manifest_bytes);
        let manifest = OciManifest::parse(&manifest_bytes, &media_type)?;
        Ok((manifest, config_bytes))
    }

    /// Extract layer digests and sizes from a parsed manifest.
    fn extract_layer_digests(&self, manifest: &OciManifest) -> ImageResult<Vec<LayerDescriptor>> {
        match manifest {
            OciManifest::Image(m) => {
                let layers: Vec<LayerDescriptor> = m
                    .layers()
                    .iter()
                    .map(|desc| {
                        let digest: Digest = desc.digest().to_string().parse().map_err(|_| {
                            ImageError::ManifestParse(format!(
                                "invalid layer digest: {}",
                                desc.digest()
                            ))
                        })?;
                        let size = if desc.size() > 0 {
                            Some(desc.size())
                        } else {
                            None
                        };
                        Ok(LayerDescriptor {
                            digest,
                            media_type: Some(desc.media_type().to_string()),
                            size,
                        })
                    })
                    .collect::<ImageResult<Vec<_>>>()?;
                Ok(layers)
            }
            OciManifest::Index(_) => Err(ImageError::ManifestParse(
                "cannot extract layers from an index — resolve platform first".to_string(),
            )),
        }
    }

    /// Materialize per-layer EROFS images, then generate fsmeta + VMDK.
    async fn materialize_layers_and_fsmeta(
        &self,
        oci_ref: &oci_client::Reference,
        manifest_digest: &Digest,
        layer_descriptors: &[LayerDescriptor],
        diff_ids: &[String],
        force: bool,
        progress: Option<PullProgressSender>,
    ) -> ImageResult<()> {
        // Validate all diff_ids parse as digests before spawning layer tasks.
        // diff_ids come from the remote config blob (untrusted input).
        let validated_diff_ids: Vec<Digest> = diff_ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                id.parse::<Digest>().map_err(|_| {
                    ImageError::ManifestParse(format!("invalid diff_id at layer {i}: {id}"))
                })
            })
            .collect::<ImageResult<Vec<_>>>()?;

        // Phase-level idempotency: decide what actually needs regen based on
        // which artifacts already exist.
        //
        // - layers + fsmeta + VMDK all valid, not force: no-op.
        // - layers + fsmeta valid, only VMDK missing: re-stitch VMDK alone.
        // - fsmeta missing (regardless of VMDK): force layers to re-materialize
        //   so the pipeline produces fresh trees for fsmeta generation.
        // - layers missing (any subset): let the per-layer tasks re-materialize
        //   the missing ones; fsmeta/VMDK regen follows if needed.
        let fsmeta_path = self.cache.fsmeta_erofs_path(manifest_digest);
        let vmdk_path = self.cache.vmdk_path(manifest_digest);
        let fsmeta_valid = store::is_valid_erofs_artifact_async(&fsmeta_path).await;
        let vmdk_valid = path_exists_async(&vmdk_path).await;
        let all_layers_valid =
            all_layers_materialized_async(&self.cache, &validated_diff_ids).await;

        if all_layers_valid && fsmeta_valid && vmdk_valid && !force {
            return Ok(());
        }

        if all_layers_valid && fsmeta_valid && !vmdk_valid && !force {
            return self
                .regenerate_vmdk_only(manifest_digest, &validated_diff_ids, progress.as_ref())
                .await;
        }

        // fsmeta missing or force=true → layers must produce trees. The per-
        // layer cache check in the task body would otherwise short-circuit
        // with tree=None for cached layer EROFSes.
        //
        // This is scoped to MATERIALIZATION only. Downloads are already
        // idempotent (content-addressed, size-gated) and sharing the same
        // blob digest across duplicate layers means forcing re-download
        // would race: one task's `rm tar.gz` can run while another task has
        // finished its download and is about to read the tar.
        let layer_force = force || !fsmeta_valid;
        let has_duplicate_diff_ids = has_duplicate_entries(diff_ids);
        let layer_concurrency = layer_pipeline_concurrency(layer_descriptors.len());
        let semaphore = Arc::new(Semaphore::new(layer_concurrency));

        let layer_tasks: Vec<_> = layer_descriptors
            .iter()
            .enumerate()
            .map(|(i, layer_desc)| {
                let layer = Layer::new(layer_desc.digest.clone(), &self.cache);
                let client = self.client.clone();
                let oci_ref = oci_ref.clone();
                let size = layer_desc.size;
                let progress = progress.clone();
                let media_type = layer_desc.media_type.clone();
                let diff_id = diff_ids[i].clone();

                let diff_id_digest: Digest = validated_diff_ids[i].clone();
                let erofs_path = self.cache.layer_erofs_path(&diff_id_digest);
                let lock_path = self.cache.layer_erofs_lock_path(&diff_id_digest);
                let tmp_dir = self.cache.tmp_dir().to_path_buf();
                let semaphore = Arc::clone(&semaphore);

                tokio::spawn(async move {
                    let _permit =
                        semaphore
                            .acquire_owned()
                            .await
                            .map_err(|e| LayerPipelineFailure {
                                error: ImageError::Io(io::Error::other(format!(
                                    "layer pipeline semaphore closed: {e}"
                                ))),
                            })?;
                    let layer_started_at = Instant::now();

                    if store::is_valid_erofs_artifact_async(&erofs_path).await && !layer_force {
                        if let Some(ref p) = progress {
                            p.send(PullProgress::LayerMaterializeComplete {
                                layer_index: i,
                                diff_id: diff_id.clone().into(),
                            });
                        }

                        tracing::debug!(
                            layer_index = i,
                            diff_id = %diff_id,
                            elapsed_ms = layer_started_at.elapsed().as_millis(),
                            "layer reused existing EROFS image"
                        );

                        return Ok::<_, LayerPipelineFailure>(LayerPipelineTreeSuccess {
                            layer_index: i,
                            tree: None,
                            data_map: None,
                        });
                    }

                    if let Err(error) = layer
                        .download(&client, &oci_ref, size, force, progress.as_ref(), i)
                        .await
                    {
                        return Err(LayerPipelineFailure { error });
                    }

                    // Acquire per-layer flock to coordinate with concurrent pulls.
                    let lock_file = open_lock_file(&lock_path)
                        .map_err(|e| LayerPipelineFailure { error: e })?;
                    {
                        let fd = lock_file.as_raw_fd();
                        tokio::task::spawn_blocking(move || {
                            let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
                            if ret != 0 {
                                return Err(ImageError::Io(io::Error::last_os_error()));
                            }
                            Ok(())
                        })
                        .await
                        .map_err(|e| LayerPipelineFailure {
                            error: ImageError::Io(io::Error::other(e)),
                        })?
                        .map_err(|e| LayerPipelineFailure { error: e })?;
                    }
                    let _lock_guard = scopeguard::guard(lock_file, |file| {
                        let _ = flock_unlock(&file);
                    });

                    // Re-check after lock — another process may have materialized it.
                    if store::is_valid_erofs_artifact_async(&erofs_path).await && !layer_force {
                        if let Some(ref p) = progress {
                            p.send(PullProgress::LayerMaterializeComplete {
                                layer_index: i,
                                diff_id: diff_id.clone().into(),
                            });
                        }
                        return Ok::<_, LayerPipelineFailure>(LayerPipelineTreeSuccess {
                            layer_index: i,
                            tree: None,
                            data_map: None,
                        });
                    }

                    if let Some(ref p) = progress {
                        p.send(PullProgress::LayerMaterializeStarted {
                            layer_index: i,
                            diff_id: diff_id.clone().into(),
                        });
                    }

                    let tar_path = layer.tar_path_ref();
                    let tar_size =
                        tokio::fs::metadata(&tar_path)
                            .await
                            .map_err(|e| LayerPipelineFailure {
                                error: ImageError::Cache {
                                    path: tar_path.clone(),
                                    source: e,
                                },
                            })?;
                    let tar_file = tokio::fs::File::open(&tar_path).await.map_err(|e| {
                        LayerPipelineFailure {
                            error: ImageError::Cache {
                                path: tar_path.clone(),
                                source: e,
                            },
                        }
                    })?;

                    let compression =
                        Compression::from_media_type(media_type.as_deref().unwrap_or(""));
                    let limits = ResourceLimits::default();
                    let spool_path = tmp_dir.join(format!("{}.spool", diff_id));
                    let ingest_started_at = Instant::now();
                    let ingest_result = tar_ingest::ingest_compressed_tar(
                        MaterializeProgressReader::new(
                            tar_file,
                            progress.clone(),
                            i,
                            tar_size.len(),
                        ),
                        compression,
                        &limits,
                        Some(&spool_path),
                    )
                    .await
                    .map_err(|e| LayerPipelineFailure {
                        error: ImageError::Materialize {
                            digest: diff_id.clone(),
                            message: format!("tar ingestion failed: {e}"),
                            source: None,
                        },
                    })?;

                    // Verify the uncompressed digest matches the config's diff_id.
                    // This is the OCI content trust check — the diff_id is signed
                    // as part of the image config, so a tampered layer would be caught.
                    let expected_diff_hex = diff_id_digest.hex();
                    if ingest_result.uncompressed_digest != expected_diff_hex {
                        return Err(LayerPipelineFailure {
                            error: ImageError::DigestMismatch {
                                digest: diff_id.clone(),
                                expected: format!("sha256:{expected_diff_hex}"),
                                actual: format!("sha256:{}", ingest_result.uncompressed_digest),
                            },
                        });
                    }
                    let tree = ingest_result.tree;

                    tracing::debug!(
                        layer_index = i,
                        diff_id = %diff_id,
                        tar_bytes = tar_size.len(),
                        elapsed_ms = ingest_started_at.elapsed().as_millis(),
                        "layer tar ingestion completed (diff_id verified)"
                    );

                    if let Some(ref p) = progress {
                        p.send(PullProgress::LayerMaterializeWriting { layer_index: i });
                    }

                    // Write to a temp file, then atomic rename to the final path.
                    // This prevents partial files from being visible to concurrent readers.
                    let temp_path = tmp_dir.join(format!("{}.erofs.part", diff_id));
                    let erofs_final = erofs_path.clone();
                    let diff_id_for_join = diff_id.clone();
                    let write_started_at = Instant::now();
                    let (data_map, mut tree) = tokio::task::spawn_blocking(move || {
                        let data_map = erofs::write_erofs(&tree, &temp_path)?;
                        std::fs::rename(&temp_path, &erofs_final).map_err(erofs::ErofsError::Io)?;
                        Ok::<(erofs::ErofsDataMap, FileTree), erofs::ErofsError>((data_map, tree))
                    })
                    .await
                    .map_err(|e| LayerPipelineFailure {
                        error: ImageError::Materialize {
                            digest: diff_id_for_join.clone(),
                            message: format!("EROFS write task failed: {e}"),
                            source: None,
                        },
                    })?
                    .map_err(|e| LayerPipelineFailure {
                        error: ImageError::Materialize {
                            digest: diff_id.clone(),
                            message: format!("EROFS write failed: {e}"),
                            source: None,
                        },
                    })?;

                    // Strip file data from the retained tree to reduce memory.
                    // Only directory structure and metadata are needed for fsmeta merge.
                    tree.strip_file_data();

                    tracing::debug!(
                        layer_index = i,
                        diff_id = %diff_id,
                        elapsed_ms = write_started_at.elapsed().as_millis(),
                        total_elapsed_ms = layer_started_at.elapsed().as_millis(),
                        "layer EROFS image write completed"
                    );

                    // Tarball cleanup is deferred — with duplicate layer digests,
                    // another task may still need the same blob. Tarballs are cleaned
                    // up after all layer tasks complete.
                    let _ = tokio::fs::remove_file(&spool_path).await;

                    if let Some(ref p) = progress {
                        p.send(PullProgress::LayerMaterializeComplete {
                            layer_index: i,
                            diff_id: diff_id.clone().into(),
                        });
                    }

                    Ok::<_, LayerPipelineFailure>(LayerPipelineTreeSuccess {
                        layer_index: i,
                        tree: Some(tree),
                        data_map: Some(data_map),
                    })
                })
            })
            .collect();

        // Wait for all layer tasks to complete. Collect trees + data maps.
        let mut layer_results = wait_for_layer_tree_pipeline(layer_tasks).await?;
        layer_results.sort_by_key(|r| r.layer_index);

        // Generate fsmeta + VMDK if not already cached.
        let fsmeta_path = self.cache.fsmeta_erofs_path(manifest_digest);
        let vmdk_path = self.cache.vmdk_path(manifest_digest);

        if store::is_valid_erofs_artifact_async(&fsmeta_path).await
            && path_exists_async(&vmdk_path).await
            && !force
        {
            tracing::debug!(
                manifest_digest = %manifest_digest,
                "fsmeta + VMDK already cached, skipping generation"
            );
            return Ok(());
        }

        // Acquire flock for fsmeta/VMDK generation.
        let fsmeta_lock_path = self.cache.fsmeta_erofs_lock_path(manifest_digest);
        let fsmeta_lock_file = open_lock_file(&fsmeta_lock_path)?;
        {
            let fd = fsmeta_lock_file.as_raw_fd();
            tokio::task::spawn_blocking(move || {
                let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
                if ret != 0 {
                    return Err(ImageError::Io(io::Error::last_os_error()));
                }
                Ok(())
            })
            .await
            .map_err(|e| ImageError::Io(io::Error::other(e)))??;
        }
        let _fsmeta_lock_guard = scopeguard::guard(fsmeta_lock_file, |file| {
            let _ = flock_unlock(&file);
        });

        // Re-check after lock acquisition.
        if store::is_valid_erofs_artifact_async(&fsmeta_path).await
            && path_exists_async(&vmdk_path).await
            && !force
        {
            return Ok(());
        }

        // Extract trees and data maps from results.
        //
        // When an image contains duplicate layers (same diff_id at multiple
        // positions), only the first task actually builds the EROFS — the
        // others find the cached artifact and return tree=None. We handle
        // this by collecting produced trees keyed by diff_id, then cloning
        // for duplicate positions.
        //
        // If a diff_id has NO produced tree at all (every layer was already
        // cached from a prior pull), fsmeta generation was expected to be
        // cached too — but we checked above and it wasn't. This can happen
        // if the fsmeta cache was evicted while layer caches were kept.
        let (layer_trees, layer_data_maps) = if has_duplicate_diff_ids {
            let mut tree_by_diff_id: HashMap<String, (FileTree, erofs::ErofsDataMap)> =
                HashMap::new();
            for result in &mut layer_results {
                if let (Some(tree), Some(data_map)) = (result.tree.take(), result.data_map.take()) {
                    let diff_id = diff_ids[result.layer_index].clone();
                    tree_by_diff_id.entry(diff_id).or_insert((tree, data_map));
                }
            }

            let mut layer_trees: Vec<FileTree> = Vec::with_capacity(layer_results.len());
            let mut layer_data_maps: Vec<erofs::ErofsDataMap> =
                Vec::with_capacity(layer_results.len());
            for result in &layer_results {
                let diff_id = &diff_ids[result.layer_index];
                match tree_by_diff_id.get(diff_id) {
                    Some((tree, data_map)) => {
                        layer_trees.push(tree.clone());
                        layer_data_maps.push(data_map.clone());
                    }
                    None => {
                        return Err(ImageError::Materialize {
                            digest: manifest_digest.to_string(),
                            message: "fsmeta cache evicted but layer EROFS cached — \
                                      re-pull with force to regenerate"
                                .into(),
                            source: None,
                        });
                    }
                }
            }

            (layer_trees, layer_data_maps)
        } else {
            let mut layer_trees: Vec<FileTree> = Vec::with_capacity(layer_results.len());
            let mut layer_data_maps: Vec<erofs::ErofsDataMap> =
                Vec::with_capacity(layer_results.len());
            for result in layer_results {
                let tree = result.tree.ok_or_else(|| ImageError::Materialize {
                    digest: manifest_digest.to_string(),
                    message: "fsmeta generation expected uncached layer tree but found none".into(),
                    source: None,
                })?;
                let data_map = result.data_map.ok_or_else(|| ImageError::Materialize {
                    digest: manifest_digest.to_string(),
                    message: "fsmeta generation expected uncached layer data map but found none"
                        .into(),
                    source: None,
                })?;
                layer_trees.push(tree);
                layer_data_maps.push(data_map);
            }

            (layer_trees, layer_data_maps)
        };

        // Merge layer trees with provenance tracking.
        if let Some(ref p) = progress {
            p.send(PullProgress::StitchMergingTrees {
                layer_count: layer_trees.len(),
            });
        }
        let (merged_tree, provenance) = crate::filetree::merge_layers_with_provenance(layer_trees);

        // Generate fsmeta and VMDK.
        let fsmeta_path_for_write = fsmeta_path.clone();
        let vmdk_path_for_write = vmdk_path.clone();
        let work_dir = self.cache.work_dir(manifest_digest);
        let manifest_digest_str = manifest_digest.to_string();

        // Collect per-layer EROFS paths for the VMDK extents.
        let layer_erofs_paths: Vec<std::path::PathBuf> = validated_diff_ids
            .iter()
            .map(|d| self.cache.layer_erofs_path(d))
            .collect();

        let stitch_progress = progress.clone();
        tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&work_dir).map_err(|e| ImageError::Cache {
                path: work_dir.clone(),
                source: e,
            })?;
            let _work_guard = scopeguard::guard((), |_| {
                let _ = std::fs::remove_dir_all(&work_dir);
            });

            // Write fsmeta.
            if let Some(ref p) = stitch_progress {
                p.send(PullProgress::StitchWritingFsmeta);
            }
            let temp_fsmeta = work_dir.join("fsmeta.erofs");
            erofs::fsmeta::write_fsmeta(&merged_tree, &provenance, &layer_data_maps, &temp_fsmeta)
                .map_err(|e| ImageError::Materialize {
                    digest: manifest_digest_str.clone(),
                    message: format!("fsmeta write failed: {e}"),
                    source: None,
                })?;

            std::fs::rename(&temp_fsmeta, &fsmeta_path_for_write).map_err(|e| {
                ImageError::Cache {
                    path: fsmeta_path_for_write.clone(),
                    source: e,
                }
            })?;

            // Write VMDK descriptor.
            if let Some(ref p) = stitch_progress {
                p.send(PullProgress::StitchWritingVmdk);
            }
            let temp_vmdk = work_dir.join("rootfs.vmdk");
            let mut extents: Vec<&std::path::Path> = vec![&fsmeta_path_for_write];
            extents.extend(layer_erofs_paths.iter().map(|p| p.as_path()));

            crate::vmdk::write_vmdk_descriptor(&temp_vmdk, &extents).map_err(|e| {
                ImageError::Materialize {
                    digest: manifest_digest_str.clone(),
                    message: format!("VMDK write failed: {e}"),
                    source: None,
                }
            })?;

            std::fs::rename(&temp_vmdk, &vmdk_path_for_write).map_err(|e| ImageError::Cache {
                path: vmdk_path_for_write.clone(),
                source: e,
            })?;

            Ok::<(), ImageError>(())
        })
        .await
        .map_err(|e| ImageError::Io(io::Error::other(e)))??;

        if let Some(ref p) = progress {
            p.send(PullProgress::StitchComplete);
        }

        Ok(())
    }

    /// Re-stitch the VMDK descriptor from an existing fsmeta + layer EROFS files.
    ///
    /// Called when fsmeta and all layer EROFSes are present but only the VMDK
    /// descriptor is missing (e.g. the user deleted it manually, or a previous
    /// pull was interrupted between fsmeta rename and VMDK rename).
    async fn regenerate_vmdk_only(
        &self,
        manifest_digest: &Digest,
        validated_diff_ids: &[Digest],
        progress: Option<&PullProgressSender>,
    ) -> ImageResult<()> {
        let fsmeta_path = self.cache.fsmeta_erofs_path(manifest_digest);
        let vmdk_path = self.cache.vmdk_path(manifest_digest);

        let fsmeta_lock_path = self.cache.fsmeta_erofs_lock_path(manifest_digest);
        let fsmeta_lock_file = open_lock_file(&fsmeta_lock_path)?;
        {
            let fd = fsmeta_lock_file.as_raw_fd();
            tokio::task::spawn_blocking(move || {
                let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
                if ret != 0 {
                    return Err(ImageError::Io(io::Error::last_os_error()));
                }
                Ok(())
            })
            .await
            .map_err(|e| ImageError::Io(io::Error::other(e)))??;
        }
        let _fsmeta_lock_guard = scopeguard::guard(fsmeta_lock_file, |file| {
            let _ = flock_unlock(&file);
        });

        // Re-check under lock: a concurrent pull may have regenerated VMDK,
        // or the fsmeta may have been evicted while we waited.
        if path_exists_async(&vmdk_path).await {
            return Ok(());
        }
        if !store::is_valid_erofs_artifact_async(&fsmeta_path).await {
            return Err(ImageError::Materialize {
                digest: manifest_digest.to_string(),
                message: "fsmeta vanished while waiting for VMDK regen lock".into(),
                source: None,
            });
        }

        let layer_erofs_paths: Vec<std::path::PathBuf> = validated_diff_ids
            .iter()
            .map(|d| self.cache.layer_erofs_path(d))
            .collect();
        let work_dir = self.cache.work_dir(manifest_digest);
        let manifest_digest_str = manifest_digest.to_string();

        let stitch_progress = progress.cloned();
        tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&work_dir).map_err(|e| ImageError::Cache {
                path: work_dir.clone(),
                source: e,
            })?;
            let _work_guard = scopeguard::guard((), |_| {
                let _ = std::fs::remove_dir_all(&work_dir);
            });

            if let Some(ref p) = stitch_progress {
                p.send(PullProgress::StitchWritingVmdk);
            }
            let temp_vmdk = work_dir.join("rootfs.vmdk");
            let mut extents: Vec<&std::path::Path> = vec![&fsmeta_path];
            extents.extend(layer_erofs_paths.iter().map(|p| p.as_path()));

            crate::vmdk::write_vmdk_descriptor(&temp_vmdk, &extents).map_err(|e| {
                ImageError::Materialize {
                    digest: manifest_digest_str.clone(),
                    message: format!("VMDK write failed: {e}"),
                    source: None,
                }
            })?;

            std::fs::rename(&temp_vmdk, &vmdk_path).map_err(|e| ImageError::Cache {
                path: vmdk_path.clone(),
                source: e,
            })?;

            Ok::<(), ImageError>(())
        })
        .await
        .map_err(|e| ImageError::Io(io::Error::other(e)))??;

        if let Some(p) = progress {
            p.send(PullProgress::StitchComplete);
        }

        Ok(())
    }

    // NOTE: materialize_flat_image was removed — replaced by fsmeta + VMDK generation
    // in materialize_layers_and_fsmeta().
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<R: AsyncRead + Unpin> AsyncRead for MaterializeProgressReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                let bytes_read = (buf.filled().len() - before) as u64;
                if bytes_read > 0 {
                    self.bytes_read += bytes_read;
                    let should_emit_progress =
                        self.bytes_read.saturating_sub(self.last_emitted_bytes)
                            >= MATERIALIZE_PROGRESS_EMIT_BYTES
                            || self.bytes_read >= self.total_bytes;

                    if should_emit_progress {
                        if let Some(progress) = &self.progress {
                            progress.send(PullProgress::LayerMaterializeProgress {
                                layer_index: self.layer_index,
                                bytes_read: self.bytes_read.min(self.total_bytes),
                                total_bytes: self.total_bytes,
                            });
                        }
                        self.last_emitted_bytes = self.bytes_read;
                    }
                }

                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Detect the media type of a manifest from its JSON content.
fn detect_manifest_media_type(bytes: &[u8]) -> String {
    // Try to parse the mediaType field from JSON.
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(bytes) {
        if let Some(mt) = v.get("mediaType").and_then(|v| v.as_str()) {
            return mt.to_string();
        }

        // Heuristic: if it has "manifests" array, it's an index.
        if v.get("manifests").is_some() {
            return "application/vnd.oci.image.index.v1+json".to_string();
        }

        // If it has "layers" array, it's an image manifest.
        if v.get("layers").is_some() {
            return "application/vnd.oci.image.manifest.v1+json".to_string();
        }
    }

    // Default to OCI image manifest.
    "application/vnd.oci.image.manifest.v1+json".to_string()
}

/// Build an OCI client that resolves multi-platform manifests for the requested target.
fn build_client(platform: &Platform) -> Client {
    let platform = platform.clone();
    Client::new(ClientConfig {
        protocol: oci_client::client::ClientProtocol::Https,
        platform_resolver: Some(Box::new(move |manifests| {
            resolve_platform_digest(manifests, &platform)
        })),
        ..Default::default()
    })
}

/// Resolve the best matching platform-specific manifest digest.
fn resolve_platform_digest(manifests: &[ImageIndexEntry], target: &Platform) -> Option<String> {
    let mut arch_only_match: Option<String> = None;

    for entry in manifests {
        if entry.media_type.contains("attestation") {
            continue;
        }

        let Some(platform) = entry.platform.as_ref() else {
            continue;
        };
        if platform.os != target.os || platform.architecture != target.arch {
            continue;
        }

        match target.variant.as_deref() {
            Some(target_variant) if platform.variant.as_deref() == Some(target_variant) => {
                return Some(entry.digest.clone());
            }
            Some(_) => {
                if arch_only_match.is_none() {
                    arch_only_match = Some(entry.digest.clone());
                }
            }
            None => return Some(entry.digest.clone()),
        }
    }

    arch_only_match
}

/// Build a pull result from cached image metadata.
fn cached_pull_result(metadata: &CachedImageMetadata) -> ImageResult<PullResult> {
    let manifest_digest: Digest = metadata.manifest_digest.parse()?;
    let layer_diff_ids = metadata
        .layers
        .iter()
        .map(|layer| layer.diff_id.parse())
        .collect::<ImageResult<Vec<Digest>>>()?;

    Ok(PullResult {
        layer_diff_ids,
        config: metadata.config.clone(),
        manifest_digest,
        cached: true,
    })
}

fn resolve_cached_pull_result(
    cache: &GlobalCache,
    reference: &oci_client::Reference,
    options: &PullOptions,
) -> ImageResult<Option<CachedPullInfo>> {
    if options.force || options.pull_policy == PullPolicy::Always {
        return Ok(None);
    }

    let Some(metadata) = cache.read_image_metadata(reference)? else {
        return Ok(None);
    };

    // Check that all per-layer EROFS images exist.
    let cached_diff_ids = match metadata
        .layers
        .iter()
        .map(|layer| layer.diff_id.parse())
        .collect::<ImageResult<Vec<Digest>>>()
    {
        Ok(digests) => digests,
        Err(_) => return Ok(None),
    };
    if !cache.all_layers_materialized(&cached_diff_ids) {
        return Ok(None);
    }

    // Check that fsmeta + VMDK exist.
    let manifest_digest = match metadata.manifest_digest.parse::<Digest>() {
        Ok(digest) => digest,
        Err(_) => return Ok(None),
    };
    if !cache.is_fsmeta_materialized(&manifest_digest)
        || !cache.is_vmdk_materialized(&manifest_digest)
    {
        return Ok(None);
    }

    let result = match cached_pull_result(&metadata) {
        Ok(result) => result,
        Err(_) => return Ok(None),
    };

    Ok(Some(CachedPullInfo { result, metadata }))
}

async fn wait_for_layer_tree_pipeline(
    layer_tasks: Vec<JoinHandle<Result<LayerPipelineTreeSuccess, LayerPipelineFailure>>>,
) -> ImageResult<Vec<LayerPipelineTreeSuccess>> {
    let outcomes = futures::future::join_all(layer_tasks).await;
    let mut results = Vec::new();
    let mut first_error: Option<ImageError> = None;

    for outcome in outcomes {
        match outcome {
            Ok(Ok(result)) => results.push(result),
            Ok(Err(failure)) => {
                if first_error.is_none() {
                    first_error = Some(failure.error);
                }
            }
            Err(error) => {
                if first_error.is_none() {
                    first_error = Some(ImageError::Io(io::Error::other(format!(
                        "layer task failed: {error}"
                    ))));
                }
            }
        }
    }

    if let Some(error) = first_error {
        return Err(error);
    }

    Ok(results)
}

async fn resolve_cached_pull_result_async(
    cache: &GlobalCache,
    reference: &oci_client::Reference,
    options: &PullOptions,
) -> ImageResult<Option<CachedPullInfo>> {
    if options.force || options.pull_policy == PullPolicy::Always {
        return Ok(None);
    }

    let Some(metadata) = cache.read_image_metadata_async(reference).await? else {
        return Ok(None);
    };

    let cached_diff_ids = match metadata
        .layers
        .iter()
        .map(|layer| layer.diff_id.parse())
        .collect::<ImageResult<Vec<Digest>>>()
    {
        Ok(digests) => digests,
        Err(_) => return Ok(None),
    };
    if !all_layers_materialized_async(cache, &cached_diff_ids).await {
        return Ok(None);
    }

    let manifest_digest = match metadata.manifest_digest.parse::<Digest>() {
        Ok(digest) => digest,
        Err(_) => return Ok(None),
    };
    if !store::is_valid_erofs_artifact_async(&cache.fsmeta_erofs_path(&manifest_digest)).await
        || !path_exists_async(&cache.vmdk_path(&manifest_digest)).await
    {
        return Ok(None);
    }

    let result = match cached_pull_result(&metadata) {
        Ok(result) => result,
        Err(_) => return Ok(None),
    };

    Ok(Some(CachedPullInfo { result, metadata }))
}

async fn all_layers_materialized_async(cache: &GlobalCache, diff_ids: &[Digest]) -> bool {
    for diff_id in diff_ids {
        if !store::is_valid_erofs_artifact_async(&cache.layer_erofs_path(diff_id)).await {
            return false;
        }
    }

    true
}

async fn path_exists_async(path: &Path) -> bool {
    tokio::fs::metadata(path).await.is_ok()
}

fn has_duplicate_entries(entries: &[String]) -> bool {
    let mut seen = HashSet::with_capacity(entries.len());
    for entry in entries {
        if !seen.insert(entry.as_str()) {
            return true;
        }
    }

    false
}

fn layer_pipeline_concurrency(layer_count: usize) -> usize {
    let host_limit = std::thread::available_parallelism()
        .map(|n| n.get().saturating_mul(2))
        .unwrap_or(8)
        .clamp(4, MAX_LAYER_PIPELINE_CONCURRENCY);

    host_limit.min(layer_count.max(1))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use oci_client::manifest::{ImageIndexEntry, Platform as OciPlatform};

    use super::{Platform, resolve_cached_pull_result, resolve_platform_digest};
    use crate::{
        config::ImageConfig,
        error::ImageError,
        pull::{PullOptions, PullPolicy},
        store::{CachedImageMetadata, CachedLayerMetadata, GlobalCache},
    };

    #[test]
    fn test_platform_resolver_prefers_exact_variant() {
        let manifests = vec![
            ImageIndexEntry {
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                digest: "sha256:arch-only".into(),
                size: 1,
                platform: Some(OciPlatform {
                    architecture: "arm".into(),
                    os: "linux".into(),
                    os_version: None,
                    os_features: None,
                    variant: None,
                    features: None,
                }),
                annotations: None,
            },
            ImageIndexEntry {
                media_type: "application/vnd.oci.image.manifest.v1+json".into(),
                digest: "sha256:exact".into(),
                size: 1,
                platform: Some(OciPlatform {
                    architecture: "arm".into(),
                    os: "linux".into(),
                    os_version: None,
                    os_features: None,
                    variant: Some("v7".into()),
                    features: None,
                }),
                annotations: None,
            },
        ];

        let digest =
            resolve_platform_digest(&manifests, &Platform::with_variant("linux", "arm", "v7"));
        assert_eq!(digest.as_deref(), Some("sha256:exact"));
    }

    #[test]
    fn test_resolve_cached_pull_result_if_missing_uses_complete_cache() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/alpine".parse().unwrap();
        let metadata = write_cached_image_fixture(&cache, &reference, &[true, true]);

        let cached = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::IfMissing,
                force: false,
                ..Default::default()
            },
        )
        .unwrap()
        .expect("expected cached pull result");

        assert!(cached.result.cached);
        assert_eq!(cached.result.layer_diff_ids.len(), 2);
        assert_eq!(
            cached.result.manifest_digest.to_string(),
            metadata.manifest_digest
        );
        assert_eq!(cached.result.config.env, metadata.config.env);
        assert_eq!(
            cached.result.layer_diff_ids[0].to_string(),
            metadata.layers[0].diff_id
        );
        assert_eq!(
            cached.result.layer_diff_ids[1].to_string(),
            metadata.layers[1].diff_id
        );
    }

    #[test]
    fn test_resolve_cached_pull_result_never_uses_complete_cache() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/busybox:latest".parse().unwrap();
        write_cached_image_fixture(&cache, &reference, &[true]);

        let cached = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::Never,
                force: false,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(cached.is_some());
        assert!(cached.unwrap().result.cached);
    }

    #[test]
    fn test_pull_cached_uses_complete_cache() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/alpine".parse().unwrap();
        let metadata = write_cached_image_fixture(&cache, &reference, &[true]);

        let cached = super::Registry::pull_cached(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::IfMissing,
                force: false,
                ..Default::default()
            },
        )
        .unwrap()
        .expect("expected cached pull result");

        assert!(cached.0.cached);
        assert_eq!(
            cached.0.manifest_digest.to_string(),
            metadata.manifest_digest
        );
        assert_eq!(cached.1.manifest_digest, metadata.manifest_digest);
    }

    #[tokio::test]
    async fn test_pull_never_returns_not_cached_when_any_layer_is_missing() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/debian:stable".parse().unwrap();
        write_cached_image_fixture(&cache, &reference, &[true, false]);

        let cached = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::Never,
                force: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(cached.is_none());

        let registry = super::Registry::new(Platform::default(), cache).unwrap();
        let err = registry
            .pull(
                &reference,
                &PullOptions {
                    pull_policy: PullPolicy::Never,
                    force: false,
                    ..Default::default()
                },
            )
            .await;

        assert!(matches!(err, Err(ImageError::NotCached { .. })));
    }

    #[test]
    fn test_resolve_cached_pull_result_ignores_corrupt_metadata_file() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/ubuntu:latest".parse().unwrap();
        let metadata_path = image_metadata_path(temp.path(), &reference);
        std::fs::write(&metadata_path, b"{ definitely not json").unwrap();

        let cached = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::IfMissing,
                force: false,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(cached.is_none());
    }

    #[test]
    fn test_resolve_cached_pull_result_skips_cache_for_force_and_always() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/fedora:latest".parse().unwrap();
        write_cached_image_fixture(&cache, &reference, &[true]);

        let forced = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::IfMissing,
                force: true,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(forced.is_none());

        let always = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::Always,
                force: false,
                ..Default::default()
            },
        )
        .unwrap();
        assert!(always.is_none());
    }

    #[test]
    fn test_resolve_cached_pull_result_ignores_invalid_digest_metadata() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/redis:latest".parse().unwrap();
        let mut metadata = write_cached_image_fixture(&cache, &reference, &[true]);
        metadata.layers[0].diff_id = "not-a-digest".into();
        cache.write_image_metadata(&reference, &metadata).unwrap();

        let cached = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::IfMissing,
                force: false,
                ..Default::default()
            },
        )
        .unwrap();

        assert!(cached.is_none());
    }

    #[test]
    fn test_resolve_cached_pull_result_requires_fsmeta_and_vmdk() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/alpine:latest".parse().unwrap();
        // Create layers but no fsmeta/VMDK.
        let metadata = write_cached_image_fixture(&cache, &reference, &[false, false]);
        let manifest_digest = parse_digest(&metadata.manifest_digest);
        // Manually create layer files without fsmeta/VMDK.
        for (index, _) in metadata.layers.iter().enumerate() {
            let diff_id = parse_digest(&format!("sha256:{:064x}", index as u64 + 1000));
            std::fs::write(cache.layer_erofs_path(&diff_id), vec![0u8; 4096]).unwrap();
        }
        // Delete fsmeta/VMDK if they were created by the fixture.
        let _ = std::fs::remove_file(cache.fsmeta_erofs_path(&manifest_digest));
        let _ = std::fs::remove_file(cache.vmdk_path(&manifest_digest));

        let cached = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::IfMissing,
                force: false,
            },
        )
        .unwrap();

        assert!(cached.is_none(), "should not be cached without fsmeta+VMDK");
    }

    #[tokio::test]
    async fn test_pull_never_treats_invalid_digest_metadata_as_not_cached() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/httpd:latest".parse().unwrap();
        let mut metadata = write_cached_image_fixture(&cache, &reference, &[true]);
        metadata.layers[0].diff_id = "not-a-digest".into();
        cache.write_image_metadata(&reference, &metadata).unwrap();

        let registry = super::Registry::new(Platform::default(), cache).unwrap();
        let result = registry
            .pull(
                &reference,
                &PullOptions {
                    pull_policy: PullPolicy::Never,
                    force: false,
                    ..Default::default()
                },
            )
            .await;

        assert!(matches!(result, Err(ImageError::NotCached { .. })));
    }

    #[tokio::test]
    async fn test_pull_with_progress_cached_if_missing_emits_only_summary_events() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/nginx:latest".parse().unwrap();
        write_cached_image_fixture(&cache, &reference, &[true, true]);
        let registry = super::Registry::new(Platform::default(), cache).unwrap();

        let (mut handle, task) = registry.pull_with_progress(
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::IfMissing,
                force: false,
                ..Default::default()
            },
        );

        let result = task.await.unwrap().unwrap();
        let mut events = Vec::new();
        while let Some(event) = handle.recv().await {
            events.push(event);
        }

        assert!(result.cached);
        assert_eq!(events.len(), 3);
        assert!(matches!(
            &events[0],
            crate::progress::PullProgress::Resolving { reference: event_ref }
                if event_ref.as_ref() == reference.to_string()
        ));
        assert!(matches!(
            &events[1],
            crate::progress::PullProgress::Resolved {
                reference: event_ref,
                layer_count: 2,
                ..
            } if event_ref.as_ref() == reference.to_string()
        ));
        assert!(matches!(
            &events[2],
            crate::progress::PullProgress::Complete {
                reference: event_ref,
                layer_count: 2,
            } if event_ref.as_ref() == reference.to_string()
        ));
    }

    fn write_cached_image_fixture(
        cache: &GlobalCache,
        reference: &oci_client::Reference,
        materialized_layers: &[bool],
    ) -> CachedImageMetadata {
        let metadata = CachedImageMetadata {
            manifest_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            config_digest:
                "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
                    .to_string(),
            config: ImageConfig {
                env: vec!["PATH=/usr/bin".into()],
                ..Default::default()
            },
            layers: materialized_layers
                .iter()
                .enumerate()
                .map(|(index, _)| CachedLayerMetadata {
                    digest: layer_digest(index),
                    media_type: Some("application/vnd.oci.image.layer.v1.tar+gzip".into()),
                    size_bytes: Some((index as u64 + 1) * 100),
                    diff_id: format!("sha256:{:064x}", index as u64 + 1000),
                })
                .collect(),
        };

        cache.write_image_metadata(reference, &metadata).unwrap();

        // Create EROFS files keyed by diff_id for cache hit detection.
        let all_materialized = materialized_layers.iter().all(|m| *m);
        for (index, materialized) in materialized_layers.iter().copied().enumerate() {
            let diff_id = parse_digest(&format!("sha256:{:064x}", index as u64 + 1000));
            let erofs_path = cache.layer_erofs_path(&diff_id);
            if materialized {
                std::fs::write(&erofs_path, vec![0u8; 4096]).unwrap();
            }
        }

        // Create fsmeta + VMDK when all layers are present (fsmerge pipeline).
        if all_materialized && !materialized_layers.is_empty() {
            let manifest_digest = parse_digest(&metadata.manifest_digest);
            std::fs::write(cache.fsmeta_erofs_path(&manifest_digest), vec![0u8; 4096]).unwrap();
            std::fs::write(cache.vmdk_path(&manifest_digest), b"# VMDK fixture").unwrap();
        }

        metadata
    }

    fn layer_digest(index: usize) -> String {
        format!("sha256:{:064x}", index as u64 + 1)
    }

    fn parse_digest(digest: &str) -> crate::digest::Digest {
        digest.parse().unwrap()
    }

    fn image_metadata_path(
        cache_root: &std::path::Path,
        reference: &oci_client::Reference,
    ) -> std::path::PathBuf {
        use sha2::{Digest as Sha2Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(reference.to_string().as_bytes());
        cache_root
            .join("manifests")
            .join(format!("{}.json", hex::encode(hasher.finalize())))
    }
}
