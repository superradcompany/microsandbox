//! Operation-scoped protection spanning file access and catalog publication.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
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

    /// Transfer a lease already admitted under a publication gate into the operation scope.
    /// The key must be canonical; callers without a scope retain their own lease instead.
    pub(crate) fn retain_lease(&self, key: PathBuf, lease: StorageLease) -> ImageResult<()> {
        if let Some(operation) = &self.operation {
            let mut retained = operation
                .lock()
                .map_err(|_| std::io::Error::other("cache lease scope poisoned"))?;
            retained.entry(key).or_insert(lease);
        }

        Ok(())
    }

    /// Reuse a canonical entry already owned by this operation without waiting behind a writer.
    pub(crate) fn retained_lease(&self, key: &Path) -> ImageResult<Option<StorageLease>> {
        let Some(operation) = &self.operation else {
            return Ok(None);
        };
        let retained = operation
            .lock()
            .map_err(|_| std::io::Error::other("cache lease scope poisoned"))?;

        Ok(retained.get(key).cloned())
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
        let mut leases = Vec::with_capacity(paths.len());
        for path in paths {
            if let Some(lease) = self.retained_lease(&path)? {
                leases.push(lease);
                continue;
            }

            // Waiting never holds the scope mutex. The shared pool deduplicates
            // descriptors if another caller admits this key concurrently.
            let lease = StorageLease::shared_keyed(&path)?;
            self.retain_lease(path, lease.clone())?;
            leases.push(lease);
        }

        Ok(leases)
    }

    /// Async counterpart of [`Self::lease_paths`].
    pub async fn lease_paths_async(
        &self,
        mut paths: Vec<PathBuf>,
    ) -> ImageResult<Vec<StorageLease>> {
        paths = tokio::task::spawn_blocking(move || {
            paths
                .iter()
                .map(|path| StorageLease::key(path))
                .collect::<std::io::Result<Vec<_>>>()
        })
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))??;
        paths.sort();
        paths.dedup();

        let mut leases = Vec::with_capacity(paths.len());
        for path in paths {
            if let Some(lease) = self.retained_lease(&path)? {
                leases.push(lease);
                continue;
            }

            let lease = StorageLease::shared_async_keyed(path.clone()).await?;
            self.retain_lease(path, lease.clone())?;
            leases.push(lease);
        }
        Ok(leases)
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
    fn blocked_sync_acquisition_does_not_block_async_scope_access() {
        let home = tempfile::tempdir().unwrap();
        let cache = GlobalCache::new(home.path()).unwrap().operation();
        let busy = cache.layer_erofs_path(&metadata('a').manifest_digest.parse().unwrap());
        let available = cache.layer_erofs_path(&metadata('b').manifest_digest.parse().unwrap());
        let held = StorageLease::try_exclusive(&busy).unwrap().unwrap();
        let sync_cache = cache.clone();
        let (started, ready) = std::sync::mpsc::channel();
        let sync_reader = std::thread::spawn(move || {
            started.send(()).unwrap();
            sync_cache.lease_paths(vec![busy]).unwrap()
        });
        ready.recv().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(50));

        let (finished, result) = std::sync::mpsc::channel();
        let async_reader = std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .unwrap();
            let leases = runtime
                .block_on(cache.lease_paths_async(vec![available]))
                .unwrap();
            finished.send(()).unwrap();
            leases
        });
        let completed_before_release = result
            .recv_timeout(std::time::Duration::from_secs(1))
            .is_ok();

        // Always release and join before asserting, including on the pre-fix failure path.
        drop(held);
        drop(sync_reader.join().unwrap());
        drop(async_reader.join().unwrap());
        assert!(
            completed_before_release,
            "an unrelated async lease must not wait for the busy key"
        );
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

    #[test]
    fn async_lease_wait_does_not_occupy_the_blocking_pool() {
        let home = tempfile::tempdir().unwrap();
        let cache = GlobalCache::new(home.path()).unwrap().operation();
        let path = cache.layer_erofs_path(&metadata('a').manifest_digest.parse().unwrap());
        let held = StorageLease::try_exclusive(&path).unwrap().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async move {
            let waiter_cache = cache.clone();
            let waiter_path = path.clone();
            let waiter =
                tokio::spawn(
                    async move { waiter_cache.lease_paths_async(vec![waiter_path]).await },
                );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;

            let marker = tokio::time::timeout(
                std::time::Duration::from_secs(1),
                tokio::task::spawn_blocking(|| 42),
            )
            .await
            .expect("a lease waiter must not monopolize the only blocking thread")
            .unwrap();
            assert_eq!(marker, 42);

            drop(held);
            let _lease = tokio::time::timeout(std::time::Duration::from_secs(1), waiter)
                .await
                .expect("the waiter should acquire the released lease")
                .unwrap()
                .unwrap();
            assert_eq!(cache.operation.as_ref().unwrap().lock().unwrap().len(), 1);
        });
    }

    #[cfg(unix)]
    #[test]
    fn concurrent_operations_share_lease_descriptors() {
        const CHILD: &str = "MSB_TEST_SHARED_LEASE_FD_LIMIT";
        if std::env::var_os(CHILD).is_none() {
            use std::os::unix::process::CommandExt;

            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "cache::lease::tests::concurrent_operations_share_lease_descriptors",
                    "--nocapture",
                ])
                .env(CHILD, "1");
            // SAFETY: the callback only changes the child descriptor limit before exec.
            unsafe {
                child.pre_exec(|| {
                    let mut limit = std::mem::zeroed::<libc::rlimit>();
                    if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    limit.rlim_cur = limit.rlim_max.min(64);
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "shared lease child failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            return;
        }

        let home = tempfile::tempdir().unwrap();
        let cache = GlobalCache::new(home.path()).unwrap();
        let paths = (0_u32..24)
            .map(|index| {
                let digest: Digest = format!("sha256:{index:064x}").parse().unwrap();
                cache.layer_erofs_path(&digest)
            })
            .collect::<Vec<_>>();
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(4)
            .enable_all()
            .build()
            .unwrap();
        let operations = runtime.block_on(async {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..512 {
                let operation = cache.operation();
                let paths = paths.clone();
                tasks.spawn(async move {
                    operation.lease_paths_async(paths).await.unwrap();
                    operation
                });
            }
            let mut operations = Vec::with_capacity(512);
            while let Some(operation) = tasks.join_next().await {
                operations.push(operation.unwrap());
            }
            operations
        });

        for path in &paths {
            assert!(StorageLease::try_exclusive(path).unwrap().is_none());
        }
        drop(operations);
        for path in &paths {
            assert!(StorageLease::try_exclusive(path).unwrap().is_some());
        }
    }
}
