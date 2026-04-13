//! OCI registry client.
//!
//! Wraps `oci-client` with platform resolution, caching, and progress reporting.

use std::{
    io,
    os::fd::AsRawFd,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::Instant,
};

use oci_client::{Client, client::ClientConfig, manifest::ImageIndexEntry};
use tokio::{
    io::{AsyncRead, ReadBuf},
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
    pull::{LayerMode, PullOptions, PullPolicy, PullResult},
    store::{self, CachedImageMetadata, CachedLayerMetadata, GlobalCache},
    tar_ingest::{self, Compression},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Minimum byte delta between per-layer materialization progress updates.
const MATERIALIZE_PROGRESS_EMIT_BYTES: u64 = 256 * 1024;

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

struct LayerPipelineSuccess;

struct LayerPipelineFailure {
    error: ImageError,
}

struct FlatLayerTreeSuccess {
    layer_index: usize,
    tree: FileTree,
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
            let cache = GlobalCache::new(&cache_parent)?;
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
        if let Some(cached) = resolve_cached_pull_result(&self.cache, reference, options)? {
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

        let effective_mode = select_layer_mode(options.layer_mode, layer_count);
        if effective_mode != options.layer_mode {
            tracing::debug!(
                reference = %reference,
                requested_mode = ?options.layer_mode,
                effective_mode = ?effective_mode,
                layer_count,
                "pull adjusted rootfs mode"
            );
        }

        match effective_mode {
            LayerMode::Layered => {
                self.materialize_layered_layers(
                    oci_ref,
                    &layer_descriptors,
                    &diff_ids,
                    options.force,
                    progress.clone(),
                )
                .await?;
            }
            LayerMode::Flat => {
                self.materialize_flat_image(
                    oci_ref,
                    &manifest_digest,
                    &layer_descriptors,
                    &diff_ids,
                    options.force,
                    progress.clone(),
                )
                .await?;
            }
        }

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
        self.cache.write_image_metadata(reference, &cached_image)?;

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
            mode: effective_mode,
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

    async fn materialize_layered_layers(
        &self,
        oci_ref: &oci_client::Reference,
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

                tokio::spawn(async move {
                    let layer_started_at = Instant::now();

                    if store::is_valid_erofs_artifact(&erofs_path) && !force {
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

                        return Ok::<_, LayerPipelineFailure>(LayerPipelineSuccess);
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
                    if store::is_valid_erofs_artifact(&erofs_path) && !force {
                        if let Some(ref p) = progress {
                            p.send(PullProgress::LayerMaterializeComplete {
                                layer_index: i,
                                diff_id: diff_id.clone().into(),
                            });
                        }
                        return Ok::<_, LayerPipelineFailure>(LayerPipelineSuccess);
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
                    tokio::task::spawn_blocking(move || {
                        erofs::write_erofs(&tree, &temp_path)?;
                        std::fs::rename(&temp_path, &erofs_final).map_err(erofs::ErofsError::Io)?;
                        Ok::<(), erofs::ErofsError>(())
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

                    Ok::<_, LayerPipelineFailure>(LayerPipelineSuccess)
                })
            })
            .collect();

        wait_for_layer_pipeline(layer_tasks).await
    }

    async fn materialize_flat_image(
        &self,
        oci_ref: &oci_client::Reference,
        manifest_digest: &Digest,
        layer_descriptors: &[LayerDescriptor],
        diff_ids: &[String],
        force: bool,
        progress: Option<PullProgressSender>,
    ) -> ImageResult<()> {
        let flat_path = self.cache.flat_erofs_path(manifest_digest);

        if store::is_valid_erofs_artifact(&flat_path) && !force {
            for (layer_index, diff_id) in diff_ids.iter().enumerate() {
                if let Some(ref p) = progress {
                    p.send(PullProgress::LayerMaterializeComplete {
                        layer_index,
                        diff_id: diff_id.clone().into(),
                    });
                }
            }

            if let Some(ref p) = progress {
                p.send(PullProgress::FlatMergeComplete {
                    manifest_digest: manifest_digest.to_string().into(),
                });
            }

            tracing::debug!(
                manifest_digest = %manifest_digest,
                "flat pull reused existing EROFS image"
            );
            return Ok(());
        }

        // Validate diff_ids before spawning (untrusted registry input).
        let validated_diff_ids: Vec<Digest> = diff_ids
            .iter()
            .enumerate()
            .map(|(i, id)| {
                id.parse::<Digest>().map_err(|_| {
                    ImageError::ManifestParse(format!("invalid diff_id at layer {i}: {id}"))
                })
            })
            .collect::<ImageResult<Vec<_>>>()?;

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
                let diff_id_digest = validated_diff_ids[i].clone();
                let tmp_dir = self.cache.tmp_dir().to_path_buf();

                tokio::spawn(async move {
                    if let Err(error) = layer
                        .download(&client, &oci_ref, size, force, progress.as_ref(), i)
                        .await
                    {
                        return Err(LayerPipelineFailure { error });
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

                    // Verify uncompressed digest (diff_id).
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

                    Ok::<_, LayerPipelineFailure>(FlatLayerTreeSuccess {
                        layer_index: i,
                        tree,
                    })
                })
            })
            .collect();

        let mut layer_trees = wait_for_flat_layer_pipeline(layer_tasks).await?;
        layer_trees.sort_by_key(|result| result.layer_index);

        if let Some(ref p) = progress {
            p.send(PullProgress::FlatMergeStarted {
                layer_count: layer_trees.len(),
            });
        }

        let flat_path_for_write = flat_path.clone();
        let manifest_digest_for_write = manifest_digest.clone();
        let work_dir = self.cache.work_dir(manifest_digest);
        let lock_path = self.cache.flat_erofs_lock_path(manifest_digest);
        let lock_file = open_lock_file(&lock_path)?;
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
            .map_err(|e| ImageError::Io(io::Error::other(e)))??;
        }
        let _lock_guard = scopeguard::guard(lock_file, |file| {
            let _ = flock_unlock(&file);
        });

        if store::is_valid_erofs_artifact(&flat_path) && !force {
            if let Some(ref p) = progress {
                p.send(PullProgress::FlatMergeComplete {
                    manifest_digest: manifest_digest.to_string().into(),
                });
            }
            return Ok(());
        }

        tokio::task::spawn_blocking(move || {
            std::fs::create_dir_all(&work_dir).map_err(|e| ImageError::Cache {
                path: work_dir.clone(),
                source: e,
            })?;

            // Clean up work_dir on both success and failure paths.
            let _work_guard = scopeguard::guard((), |_| {
                let _ = std::fs::remove_dir_all(&work_dir);
            });

            let temp_path = work_dir.join("flat.erofs");
            let mut merged = FileTree::new();
            for layer in layer_trees {
                merged.merge_layer(layer.tree);
            }

            erofs::write_erofs(&merged, &temp_path).map_err(|e| ImageError::Materialize {
                digest: manifest_digest_for_write.to_string(),
                message: format!("EROFS write failed: {e}"),
                source: None,
            })?;

            std::fs::rename(&temp_path, &flat_path_for_write).map_err(|e| ImageError::Cache {
                path: flat_path_for_write.clone(),
                source: e,
            })?;

            Ok::<(), ImageError>(())
        })
        .await
        .map_err(|e| ImageError::Io(io::Error::other(e)))??;

        if let Some(ref p) = progress {
            p.send(PullProgress::FlatMergeComplete {
                manifest_digest: manifest_digest.to_string().into(),
            });
        }

        Ok(())
    }
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
fn cached_pull_result(metadata: &CachedImageMetadata, mode: LayerMode) -> ImageResult<PullResult> {
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
        mode,
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

    let effective_mode = select_layer_mode(options.layer_mode, metadata.layers.len());
    let artifacts_ready = match effective_mode {
        LayerMode::Layered => {
            let cached_diff_ids = match metadata
                .layers
                .iter()
                .map(|layer| layer.diff_id.parse())
                .collect::<ImageResult<Vec<Digest>>>()
            {
                Ok(digests) => digests,
                Err(_) => return Ok(None),
            };
            cache.all_layers_materialized(&cached_diff_ids)
        }
        LayerMode::Flat => {
            let manifest_digest = match metadata.manifest_digest.parse::<Digest>() {
                Ok(digest) => digest,
                Err(_) => return Ok(None),
            };
            cache.is_flat_materialized(&manifest_digest)
        }
    };

    if !artifacts_ready {
        return Ok(None);
    }

    let result = match cached_pull_result(&metadata, effective_mode) {
        Ok(result) => result,
        Err(_) => return Ok(None),
    };

    Ok(Some(CachedPullInfo { result, metadata }))
}

fn select_layer_mode(requested: LayerMode, layer_count: usize) -> LayerMode {
    if layer_count == 0 {
        return LayerMode::Layered;
    }

    if requested == LayerMode::Layered && layer_count > 126 {
        LayerMode::Flat
    } else {
        requested
    }
}

async fn wait_for_layer_pipeline(
    layer_tasks: Vec<JoinHandle<Result<LayerPipelineSuccess, LayerPipelineFailure>>>,
) -> ImageResult<()> {
    let outcomes = futures::future::join_all(layer_tasks).await;
    let mut first_error: Option<ImageError> = None;

    for outcome in outcomes {
        match outcome {
            Ok(Ok(_)) => {}
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

    Ok(())
}

async fn wait_for_flat_layer_pipeline(
    layer_tasks: Vec<JoinHandle<Result<FlatLayerTreeSuccess, LayerPipelineFailure>>>,
) -> ImageResult<Vec<FlatLayerTreeSuccess>> {
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
        pull::{LayerMode, PullOptions, PullPolicy},
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
    fn test_resolve_cached_pull_result_flat_uses_flat_artifact() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/alpine:latest".parse().unwrap();
        let metadata = write_cached_image_fixture(&cache, &reference, &[false, false]);
        let manifest_digest = parse_digest(&metadata.manifest_digest);
        // EROFS validation checks size > 0 and 4 KiB alignment.
        std::fs::write(cache.flat_erofs_path(&manifest_digest), &[0u8; 4096]).unwrap();

        let cached = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::IfMissing,
                force: false,
                layer_mode: LayerMode::Flat,
            },
        )
        .unwrap()
        .expect("expected cached flat pull result");

        assert!(cached.result.cached);
        assert_eq!(cached.result.mode, LayerMode::Flat);
        assert_eq!(cached.result.layer_diff_ids.len(), 2);
    }

    #[test]
    fn test_resolve_cached_pull_result_flat_ignores_layer_only_cache() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/busybox:latest".parse().unwrap();
        write_cached_image_fixture(&cache, &reference, &[true, true]);

        let cached = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::IfMissing,
                force: false,
                layer_mode: LayerMode::Flat,
            },
        )
        .unwrap();

        assert!(cached.is_none());
    }

    #[test]
    fn test_resolve_cached_pull_result_auto_switches_large_images_to_flat() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/python:3.12".parse().unwrap();
        let metadata = write_cached_image_fixture(&cache, &reference, &vec![false; 127]);
        let manifest_digest = parse_digest(&metadata.manifest_digest);
        std::fs::write(cache.flat_erofs_path(&manifest_digest), vec![0u8; 4096]).unwrap();

        let cached = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::IfMissing,
                force: false,
                layer_mode: LayerMode::Layered,
            },
        )
        .unwrap()
        .expect("expected cached auto-flat pull result");

        assert_eq!(cached.result.mode, LayerMode::Flat);
        assert_eq!(cached.result.layer_diff_ids.len(), 127);
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
        for (index, materialized) in materialized_layers.iter().copied().enumerate() {
            let diff_id = parse_digest(&format!("sha256:{:064x}", index as u64 + 1000));
            let erofs_path = cache.layer_erofs_path(&diff_id);
            if materialized {
                std::fs::write(&erofs_path, vec![0u8; 4096]).unwrap();
            }
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
