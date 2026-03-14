//! OCI registry client.
//!
//! Wraps `oci-client` with platform resolution, caching, and progress reporting.

use std::{path::PathBuf, sync::Arc};

use oci_client::{Client, client::ClientConfig, manifest::ImageIndexEntry};
use tokio::task::JoinHandle;

use crate::{
    auth::RegistryAuth,
    config::ImageConfig,
    digest::Digest,
    error::{ImageError, ImageResult},
    layer::Layer,
    manifest::OciManifest,
    platform::Platform,
    progress::{self, PullProgress, PullProgressHandle, PullProgressSender},
    pull::{PullOptions, PullPolicy, PullResult},
    store::{CachedImageMetadata, CachedLayerMetadata, GlobalCache},
};

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

/// Resolved manifest layer descriptor used during download/extraction.
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

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

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

    /// Pull an image. Downloads layers concurrently, extracts sequentially.
    pub async fn pull(
        &self,
        reference: &oci_client::Reference,
        options: &PullOptions,
    ) -> ImageResult<PullResult> {
        self.pull_inner(reference, options, None).await
    }

    /// Pull with progress reporting.
    pub fn pull_with_progress(
        &self,
        reference: &oci_client::Reference,
        options: &PullOptions,
    ) -> (PullProgressHandle, JoinHandle<ImageResult<PullResult>>)
    where
        Self: Send + Sync + 'static,
    {
        // We can't move self into the task, so we need to do this differently.
        // Instead, we'll return the handle and the caller must drive the pull separately.
        let (handle, sender) = progress::progress_channel();

        // We need to clone the necessary state.
        let reference = reference.clone();
        let options = options.clone();
        let client = self.client.clone();
        let auth = self.auth.clone();
        let platform = self.platform.clone();

        // Create a new GlobalCache from the same directory.
        let layers_dir = self.cache.layers_dir().to_path_buf();
        let cache_parent = layers_dir.parent().unwrap_or(&layers_dir).to_path_buf();

        let task = tokio::spawn(async move {
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
        });

        (handle, task)
    }

    /// Core pull implementation.
    async fn pull_inner(
        &self,
        reference: &oci_client::Reference,
        options: &PullOptions,
        progress: Option<PullProgressSender>,
    ) -> ImageResult<PullResult> {
        let ref_str: Arc<str> = reference.to_string().into();
        let oci_ref = reference;

        // Step 1: Early cache check using persisted image metadata.
        if let Some(cached) = resolve_cached_pull_result(&self.cache, reference, options)? {
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

        let layer_count = layer_descriptors.len();
        let total_bytes: Option<u64> = {
            let sum: u64 = layer_descriptors
                .iter()
                .filter_map(|layer| layer.size)
                .sum();
            if sum > 0 { Some(sum) } else { None }
        };

        if let Some(ref p) = progress {
            p.send(PullProgress::Resolved {
                reference: ref_str.clone(),
                manifest_digest: manifest_digest.to_string().into(),
                layer_count,
                total_download_bytes: total_bytes,
            });
        }

        // Step 5: Download layers concurrently.
        let download_futures: Vec<_> = layer_descriptors
            .iter()
            .enumerate()
            .map(|(i, layer_desc)| {
                let layer = Layer::new(layer_desc.digest.clone(), &self.cache);
                let client = self.client.clone();
                let oci_ref = oci_ref.clone();
                let size = layer_desc.size;
                let progress = progress.clone();

                async move {
                    layer
                        .download(&client, &oci_ref, size, options.force, progress.as_ref(), i)
                        .await
                }
            })
            .collect();

        futures::future::try_join_all(download_futures).await?;

        // Step 6: Extract layers sequentially (bottom-to-top).
        let mut extracted_dirs: Vec<PathBuf> = Vec::with_capacity(layer_count);

        for (i, layer_desc) in layer_descriptors.iter().enumerate() {
            let layer = Layer::new(layer_desc.digest.clone(), &self.cache);

            let diff_id = diff_ids.get(i).map(String::as_str).unwrap_or("");

            if !layer.is_extracted() || options.force {
                layer
                    .extract(
                        &extracted_dirs,
                        progress.as_ref(),
                        i,
                        layer_desc.media_type.as_deref(),
                        diff_id,
                    )
                    .await?;

                // Build sidecar index if requested.
                if options.build_index {
                    if let Some(ref p) = progress {
                        p.send(PullProgress::LayerIndexStarted { layer_index: i });
                    }
                    layer.build_index().await?;
                    if let Some(ref p) = progress {
                        p.send(PullProgress::LayerIndexComplete { layer_index: i });
                    }
                }
            }

            extracted_dirs.push(layer.extracted_dir());
        }

        // Step 7: Return result.
        let layers: Vec<PathBuf> = layer_descriptors
            .iter()
            .map(|ld| self.cache.extracted_dir(&ld.digest))
            .collect();
        let cached_image = CachedImageMetadata {
            manifest_digest: manifest_digest.to_string(),
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

        if let Some(ref p) = progress {
            p.send(PullProgress::Complete {
                reference: ref_str,
                layer_count,
            });
        }

        Ok(PullResult {
            layers,
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
            if platform.os() != &oci_spec::image::Os::Other(self.platform.os.clone())
                && format!("{}", platform.os()) != self.platform.os
            {
                continue;
            }

            // Architecture must match.
            if platform.architecture() != &oci_spec::image::Arch::Other(self.platform.arch.clone())
                && format!("{}", platform.architecture()) != self.platform.arch
            {
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
fn cached_pull_result(
    cache: &GlobalCache,
    metadata: &CachedImageMetadata,
) -> ImageResult<PullResult> {
    let manifest_digest: Digest = metadata.manifest_digest.parse()?;
    let layer_digests = metadata
        .layers
        .iter()
        .map(|layer| layer.digest.parse())
        .collect::<ImageResult<Vec<Digest>>>()?;

    Ok(PullResult {
        layers: layer_digests
            .iter()
            .map(|digest| cache.extracted_dir(digest))
            .collect(),
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

    let cached_digests = match metadata
        .layers
        .iter()
        .map(|layer| layer.digest.parse())
        .collect::<ImageResult<Vec<Digest>>>()
    {
        Ok(digests) => digests,
        Err(_) => return Ok(None),
    };

    if !cache.all_layers_extracted(&cached_digests) {
        return Ok(None);
    }

    let result = match cached_pull_result(cache, &metadata) {
        Ok(result) => result,
        Err(_) => return Ok(None),
    };

    Ok(Some(CachedPullInfo { result, metadata }))
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
        store::{COMPLETE_MARKER, CachedImageMetadata, CachedLayerMetadata, GlobalCache},
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
        let reference: oci_client::Reference = "docker.io/library/alpine:latest".parse().unwrap();
        let metadata = write_cached_image_fixture(&cache, &reference, &[true, true]);

        let cached = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::IfMissing,
                force: false,
                build_index: true,
            },
        )
        .unwrap()
        .expect("expected cached pull result");

        assert!(cached.result.cached);
        assert_eq!(cached.result.layers.len(), 2);
        assert_eq!(
            cached.result.manifest_digest.to_string(),
            metadata.manifest_digest
        );
        assert_eq!(cached.result.config.env, metadata.config.env);
        assert_eq!(
            cached.result.layers[0],
            cache.extracted_dir(&parse_digest(&metadata.layers[0].digest))
        );
        assert_eq!(
            cached.result.layers[1],
            cache.extracted_dir(&parse_digest(&metadata.layers[1].digest))
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
                build_index: true,
            },
        )
        .unwrap();

        assert!(cached.is_some());
        assert!(cached.unwrap().result.cached);
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
                build_index: true,
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
                    build_index: true,
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
                build_index: true,
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
                build_index: true,
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
                build_index: true,
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
        metadata.layers[0].digest = "not-a-digest".into();
        cache.write_image_metadata(&reference, &metadata).unwrap();

        let cached = resolve_cached_pull_result(
            &cache,
            &reference,
            &PullOptions {
                pull_policy: PullPolicy::IfMissing,
                force: false,
                build_index: true,
            },
        )
        .unwrap();

        assert!(cached.is_none());
    }

    #[tokio::test]
    async fn test_pull_never_treats_invalid_digest_metadata_as_not_cached() {
        let temp = tempdir().unwrap();
        let cache = GlobalCache::new(temp.path()).unwrap();
        let reference: oci_client::Reference = "docker.io/library/httpd:latest".parse().unwrap();
        let mut metadata = write_cached_image_fixture(&cache, &reference, &[true]);
        metadata.layers[0].digest = "not-a-digest".into();
        cache.write_image_metadata(&reference, &metadata).unwrap();

        let registry = super::Registry::new(Platform::default(), cache).unwrap();
        let result = registry
            .pull(
                &reference,
                &PullOptions {
                    pull_policy: PullPolicy::Never,
                    force: false,
                    build_index: true,
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
                build_index: true,
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
        extracted_layers: &[bool],
    ) -> CachedImageMetadata {
        let metadata = CachedImageMetadata {
            manifest_digest:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                    .to_string(),
            config: ImageConfig {
                env: vec!["PATH=/usr/bin".into()],
                ..Default::default()
            },
            layers: extracted_layers
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

        for (index, extracted) in extracted_layers.iter().copied().enumerate() {
            let digest = parse_digest(&layer_digest(index));
            let extracted_dir = cache.extracted_dir(&digest);
            std::fs::create_dir_all(&extracted_dir).unwrap();
            if extracted {
                std::fs::write(extracted_dir.join(COMPLETE_MARKER), b"").unwrap();
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
            .join("images")
            .join(format!("{}.json", hex::encode(hasher.finalize())))
    }
}
