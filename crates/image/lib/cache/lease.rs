//! Operation-scoped protection spanning file access and catalog publication.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use crate::storage_lease::StorageLease;
use crate::{CachedImageMetadata, Digest, GlobalCache, ImageResult};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl GlobalCache {
    /// Start an operation scope. Its clones retain admitted entries until all clones are dropped.
    /// Keep this scope through publication of durable catalog ownership, including sandbox rows.
    pub fn operation(&self) -> Self {
        let mut cache = self.clone();
        cache.operation = Some(Arc::new(Mutex::new(BTreeMap::new())));
        cache
    }

    /// Retain an existing scope, or start one for a standalone image operation.
    pub(crate) fn operation_or_new(&self) -> Self {
        if self.operation.is_some() {
            self.clone()
        } else {
            self.operation()
        }
    }

    /// Protect entries in stable path order. The returned leases cover this call's reader;
    /// an operation scope additionally retains them through its caller's publication.
    pub fn lease_paths(&self, mut paths: Vec<PathBuf>) -> ImageResult<Vec<StorageLease>> {
        paths = paths
            .iter()
            .map(|path| StorageLease::key(path))
            .collect::<std::io::Result<_>>()?;
        paths.sort();
        paths.dedup();
        if let Some(operation) = &self.operation {
            let mut retained = operation
                .lock()
                .map_err(|_| std::io::Error::other("cache lease scope poisoned"))?;
            // Reopening a flock creates another open file description. Share the existing
            // guard instead, including across calls and aliases of the cache directory.
            return paths
                .into_iter()
                .map(|path| {
                    if let Some(lease) = retained.get(&path) {
                        return Ok(lease.clone());
                    }
                    let lease = StorageLease::shared(&path)?;
                    retained.insert(path, lease.clone());
                    Ok(lease)
                })
                .collect();
        }
        paths
            .iter()
            .map(|path| StorageLease::shared(path).map_err(Into::into))
            .collect()
    }

    /// Async counterpart of [`Self::lease_paths`].
    pub async fn lease_paths_async(&self, paths: Vec<PathBuf>) -> ImageResult<Vec<StorageLease>> {
        let cache = self.clone();
        tokio::task::spawn_blocking(move || cache.lease_paths(paths))
            .await
            .map_err(|error| std::io::Error::other(error.to_string()))?
    }

    /// All independently reclaimable entries belonging to this immutable manifest.
    pub fn metadata_paths(&self, metadata: &CachedImageMetadata) -> ImageResult<Vec<PathBuf>> {
        let digest: Digest = metadata.manifest_digest.parse()?;
        let mut paths = vec![self.fsmeta_erofs_path(&digest), self.vmdk_path(&digest)];
        for layer in &metadata.layers {
            paths.push(self.layer_erofs_path(&layer.diff_id.parse()?));
        }
        Ok(paths)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{CachedLayerMetadata, ImageConfig, Reference};

    fn metadata(id: char) -> CachedImageMetadata {
        CachedImageMetadata {
            manifest_digest: format!("sha256:{}", id.to_string().repeat(64)),
            config_digest: format!("sha256:{}", id.to_string().repeat(64)),
            raw_manifest_json: "{}".into(),
            raw_config_json: "{}".into(),
            config: ImageConfig::default(),
            layers: vec![CachedLayerMetadata {
                digest: format!("sha256:{}", id.to_string().repeat(64)),
                diff_id: format!("sha256:{}", id.to_string().repeat(64)),
                media_type: None,
                size_bytes: Some(1),
            }],
        }
    }

    #[test]
    fn scope_reuses_pins_across_calls() {
        let home = tempfile::tempdir().unwrap();
        let cache = GlobalCache::new(home.path()).unwrap().operation();
        let path = cache.layer_erofs_path(&metadata('a').manifest_digest.parse().unwrap());
        for _ in 0..500 {
            cache.lease_paths(vec![path.clone()]).unwrap();
        }
        assert_eq!(cache.operation.as_ref().unwrap().lock().unwrap().len(), 1);
        assert!(StorageLease::try_exclusive(&path).unwrap().is_none());
        drop(cache);
        assert!(StorageLease::try_exclusive(&path).unwrap().is_some());
    }

    #[test]
    fn retag_keeps_the_readers_original_dependencies_admitted() {
        let home = tempfile::tempdir().unwrap();
        let cache = GlobalCache::new(home.path()).unwrap();
        let reference: Reference = "example.com/test:latest".parse().unwrap();
        let original = metadata('a');
        cache.write_image_metadata(&reference, &original).unwrap();
        let reader = cache.operation();
        assert_eq!(
            reader
                .read_image_metadata(&reference)
                .unwrap()
                .unwrap()
                .manifest_digest,
            original.manifest_digest
        );
        // Readers no longer need the mutable tag once its exact generation is admitted.
        cache
            .write_image_metadata(&reference, &metadata('b'))
            .unwrap();
        for path in cache.metadata_paths(&original).unwrap() {
            assert!(StorageLease::try_exclusive(&path).unwrap().is_none());
        }
        drop(reader);
        for path in cache.metadata_paths(&original).unwrap() {
            assert!(StorageLease::try_exclusive(&path).unwrap().is_some());
        }
    }

    #[tokio::test]
    async fn digest_scan_retains_only_matching_images() {
        let home = tempfile::tempdir().unwrap();
        let cache = GlobalCache::new(home.path()).unwrap();
        let wanted = metadata('b');
        let reader = cache.operation();
        for index in 0..80 {
            let reference: Reference = format!("example.com/image-{index}:latest").parse().unwrap();
            cache
                .write_image_metadata(&reference, &metadata('a'))
                .unwrap();
            assert!(
                reader
                    .read_image_metadata_matching_async(
                        cache.image_metadata_path(&reference),
                        wanted.manifest_digest.clone(),
                    )
                    .await
                    .unwrap()
                    .is_none()
            );
        }
        assert!(
            reader
                .operation
                .as_ref()
                .unwrap()
                .lock()
                .unwrap()
                .is_empty()
        );
        let reference: Reference = "example.com/wanted:latest".parse().unwrap();
        cache.write_image_metadata(&reference, &wanted).unwrap();
        assert!(
            reader
                .read_image_metadata_matching_async(
                    cache.image_metadata_path(&reference),
                    wanted.manifest_digest.clone(),
                )
                .await
                .unwrap()
                .is_some()
        );
        for path in cache.metadata_paths(&wanted).unwrap() {
            assert!(StorageLease::try_exclusive(&path).unwrap().is_none());
        }
    }

    #[tokio::test]
    async fn cancelled_waiter_does_not_release_worker_pins() {
        let home = tempfile::tempdir().unwrap();
        let cache = GlobalCache::new(home.path()).unwrap().operation();
        let path = cache.layer_erofs_path(&metadata('a').manifest_digest.parse().unwrap());
        cache.lease_paths(vec![path.clone()]).unwrap();
        let (started, ready) = tokio::sync::oneshot::channel();
        let (release, wait) = std::sync::mpsc::channel();
        let task = tokio::spawn(async move {
            tokio::task::spawn_blocking(move || {
                let _cache = cache;
                started.send(()).unwrap();
                wait.recv().unwrap();
            })
            .await
            .unwrap();
        });
        ready.await.unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        assert!(StorageLease::try_exclusive(&path).unwrap().is_none());
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if StorageLease::try_exclusive(&path).unwrap().is_some() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
    }
}
