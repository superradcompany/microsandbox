//! Paginated ReadDir cache for one RPC connection (mirrors Go `readDirCache`).

use std::{
    collections::HashMap,
    ffi::OsStr,
    io,
    os::unix::ffi::OsStrExt,
    path::Path,
    sync::{Arc, Mutex},
};

use super::super::{PathFs, VDirEntry};
use super::protocol::{MAX_READDIR_CACHE_PATHS, MAX_READDIR_FETCH_RETRIES, MAX_READDIR_TOTAL};
use crate::backends::shared::{name_validation, platform};

type InflightWaiter = Arc<(Mutex<InflightReadDir>, std::sync::Condvar)>;

struct InflightEntry {
    waiter: InflightWaiter,
    fetch_id: u64,
}

struct DirCacheEntry {
    entries: Vec<VDirEntry>,
    fetched_generation: u64,
}

#[derive(Default)]
struct ReadDirCacheInner {
    generation: u64,
    dirs: HashMap<Vec<u8>, DirCacheEntry>,
    dir_order: Vec<Vec<u8>>,
    inflight: HashMap<Vec<u8>, InflightEntry>,
    next_fetch_id: u64,
}

struct InflightReadDir {
    done: bool,
}

struct InflightGuard<'a> {
    cache: &'a ReadDirCache,
    path: Vec<u8>,
    fetch_id: u64,
}

impl Drop for InflightGuard<'_> {
    fn drop(&mut self) {
        self.cache.finish_inflight(&self.path, self.fetch_id);
    }
}

/// Paginated ReadDir cache shared by one RPC connection.
pub struct ReadDirCache {
    inner: Mutex<ReadDirCacheInner>,
}

impl Default for ReadDirCache {
    fn default() -> Self {
        Self {
            inner: Mutex::new(ReadDirCacheInner::default()),
        }
    }
}

fn path_from_bytes(bytes: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(bytes))
}

impl ReadDirCache {
    pub(crate) fn invalidate(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.generation = inner.generation.saturating_add(1);
        inner.dirs.clear();
        inner.dir_order.clear();
        self.finish_all_inflight_locked(&mut inner);
    }

    fn finish_all_inflight_locked(&self, inner: &mut ReadDirCacheInner) {
        for (_, entry) in inner.inflight.drain() {
            let (state, cvar) = (&entry.waiter.0, &entry.waiter.1);
            let mut guard = state.lock().unwrap();
            guard.done = true;
            cvar.notify_all();
        }
    }

    fn finish_inflight(&self, path: &[u8], fetch_id: u64) {
        let mut inner = self.inner.lock().unwrap();
        if inner
            .inflight
            .get(path)
            .is_some_and(|entry| entry.fetch_id == fetch_id)
            && let Some(entry) = inner.inflight.remove(path)
        {
            let (state, cvar) = (&entry.waiter.0, &entry.waiter.1);
            let mut guard = state.lock().unwrap();
            guard.done = true;
            cvar.notify_all();
        }
    }

    pub(crate) fn page(
        &self,
        provider: &dyn PathFs,
        path: &[u8],
        offset: u64,
        limit: usize,
    ) -> io::Result<Vec<VDirEntry>> {
        for _attempt in 0..MAX_READDIR_FETCH_RETRIES {
            if let Some(page) = self.page_from_cache(path, offset, limit)? {
                return Ok(page);
            }

            let Some((fetch_gen, fetch_id)) = self.begin_fetch(path) else {
                continue;
            };

            if let Some(page) =
                self.fetch_and_store(provider, path, fetch_gen, fetch_id, offset, limit)?
            {
                return Ok(page);
            }
        }
        Err(platform::eagain())
    }

    fn fetch_and_store(
        &self,
        provider: &dyn PathFs,
        path: &[u8],
        fetch_gen: u64,
        fetch_id: u64,
        offset: u64,
        limit: usize,
    ) -> io::Result<Option<Vec<VDirEntry>>> {
        let _inflight = InflightGuard {
            cache: self,
            path: path.to_vec(),
            fetch_id,
        };
        let raw_entries = provider.readdir(path_from_bytes(path))?;
        let entries = raw_entries
            .into_iter()
            .filter(|e| {
                if name_validation::validate_readdir_name(&e.name).is_ok() {
                    true
                } else {
                    tracing::warn!(
                        name = ?e.name,
                        "vfs: dropping invalid readdir name from provider"
                    );
                    false
                }
            })
            .collect::<Vec<_>>();
        if entries.len() > MAX_READDIR_TOTAL {
            return Err(platform::einval());
        }

        let mut inner = self.inner.lock().unwrap();
        if inner.generation != fetch_gen {
            return Ok(None);
        }
        let generation = inner.generation;
        inner.dirs.insert(
            path.to_vec(),
            DirCacheEntry {
                entries,
                fetched_generation: generation,
            },
        );
        Self::touch_dir_locked(path, &mut inner);
        Self::evict_dirs_locked(&mut inner);
        Ok(Some(self.slice_entries(
            inner.dirs.get(path).expect("dir cache entry"),
            offset,
            limit,
        )))
    }

    fn begin_fetch(&self, path: &[u8]) -> Option<(u64, u64)> {
        loop {
            let mut inner = self.inner.lock().unwrap();
            if inner
                .dirs
                .get(path)
                .is_some_and(|ent| ent.fetched_generation == inner.generation)
            {
                return None;
            }
            if let Some(entry) = inner.inflight.get(path) {
                let waiter = Arc::clone(&entry.waiter);
                drop(inner);
                let (state, cvar) = (&waiter.0, &waiter.1);
                let mut guard = state.lock().unwrap();
                while !guard.done {
                    guard = cvar.wait(guard).unwrap();
                }
                continue;
            }
            let fetch_id = inner.next_fetch_id;
            inner.next_fetch_id = inner.next_fetch_id.saturating_add(1);
            let waiter = Arc::new((
                Mutex::new(InflightReadDir { done: false }),
                std::sync::Condvar::new(),
            ));
            inner.inflight.insert(
                path.to_vec(),
                InflightEntry {
                    waiter: Arc::clone(&waiter),
                    fetch_id,
                },
            );
            return Some((inner.generation, fetch_id));
        }
    }

    fn page_from_cache(
        &self,
        path: &[u8],
        offset: u64,
        limit: usize,
    ) -> io::Result<Option<Vec<VDirEntry>>> {
        let mut inner = self.inner.lock().unwrap();
        let page = match inner
            .dirs
            .get(path)
            .filter(|ent| ent.fetched_generation == inner.generation)
        {
            Some(ent) => self.slice_entries(ent, offset, limit),
            None => {
                if offset > 0 {
                    return Err(platform::eagain());
                }
                return Ok(None);
            }
        };
        Self::touch_dir_locked(path, &mut inner);
        Ok(Some(page))
    }

    fn touch_dir_locked(path: &[u8], inner: &mut ReadDirCacheInner) {
        if let Some(pos) = inner.dir_order.iter().position(|p| p == path) {
            let key = inner.dir_order.remove(pos);
            inner.dir_order.push(key);
        } else {
            inner.dir_order.push(path.to_vec());
        }
    }

    fn evict_dirs_locked(inner: &mut ReadDirCacheInner) {
        while inner.dirs.len() > MAX_READDIR_CACHE_PATHS {
            let Some(evict) = inner.dir_order.first().cloned() else {
                break;
            };
            inner.dir_order.remove(0);
            inner.dirs.remove(&evict);
        }
    }

    fn slice_entries(&self, ent: &DirCacheEntry, offset: u64, limit: usize) -> Vec<VDirEntry> {
        let off = offset.min(usize::MAX as u64) as usize;
        if off >= ent.entries.len() {
            return Vec::new();
        }
        let end = off.saturating_add(limit).min(ent.entries.len());
        ent.entries[off..end].to_vec()
    }
}

#[cfg(test)]
mod read_dir_cache_tests {
    use std::path::Path;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Barrier};

    use super::super::super::path_fs::NodeKind;
    use super::super::super::{PathFs, VAttr, VDirEntry};
    use super::ReadDirCache;

    fn path_matches(path: &Path, want: &[u8]) -> bool {
        path == Path::new(std::str::from_utf8(want).expect("utf-8 test path"))
    }

    struct CountingProvider {
        calls: AtomicUsize,
        path: Vec<u8>,
    }

    impl PathFs for CountingProvider {
        fn getattr(&self, path: &Path) -> std::io::Result<VAttr> {
            if path_matches(path, &self.path) {
                Ok(VAttr::dir(0o755))
            } else {
                Err(std::io::Error::from_raw_os_error(libc::ENOENT))
            }
        }

        fn readdir(&self, path: &Path) -> std::io::Result<Vec<VDirEntry>> {
            if !path_matches(path, &self.path) {
                return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(vec![VDirEntry {
                name: b"a".to_vec(),
                kind: NodeKind::File,
            }])
        }

        fn read(&self, _path: &Path, _offset: u64, _size: u32) -> std::io::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn concurrent_offset_zero_refetch_is_single_flight() {
        let cache = Arc::new(ReadDirCache::default());
        let provider = Arc::new(CountingProvider {
            calls: AtomicUsize::new(0),
            path: b"/".to_vec(),
        });
        let barrier = Arc::new(Barrier::new(9));
        let mut handles = Vec::new();
        for _ in 0..8 {
            let barrier = Arc::clone(&barrier);
            let provider = Arc::clone(&provider);
            let cache = Arc::clone(&cache);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                cache
                    .page(provider.as_ref(), b"/", 0, 64)
                    .expect("page should succeed")
            }));
        }
        barrier.wait();
        for h in handles {
            h.join().expect("worker panicked");
        }
        assert_eq!(
            provider.calls.load(Ordering::SeqCst),
            1,
            "expected a single provider readdir for concurrent offset-0 misses"
        );
    }

    #[test]
    fn concurrent_offset_zero_refetch_is_single_flight_per_path() {
        let cache = Arc::new(ReadDirCache::default());
        let root = Arc::new(CountingProvider {
            calls: AtomicUsize::new(0),
            path: b"/".to_vec(),
        });
        let other = Arc::new(CountingProvider {
            calls: AtomicUsize::new(0),
            path: b"/other".to_vec(),
        });
        let barrier = Arc::new(Barrier::new(9));
        let mut handles = Vec::new();
        for _ in 0..4 {
            let barrier = Arc::clone(&barrier);
            let provider = Arc::clone(&root);
            let cache = Arc::clone(&cache);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                cache
                    .page(provider.as_ref(), b"/", 0, 64)
                    .expect("page / should succeed")
            }));
        }
        for _ in 0..4 {
            let barrier = Arc::clone(&barrier);
            let provider = Arc::clone(&other);
            let cache = Arc::clone(&cache);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                cache
                    .page(provider.as_ref(), b"/other", 0, 64)
                    .expect("page /other should succeed")
            }));
        }
        barrier.wait();
        for h in handles {
            h.join().expect("worker panicked");
        }
        assert_eq!(root.calls.load(Ordering::SeqCst), 1);
        assert_eq!(other.calls.load(Ordering::SeqCst), 1);
    }

    struct ErrOnceProvider {
        calls: AtomicUsize,
    }

    impl PathFs for ErrOnceProvider {
        fn getattr(&self, path: &Path) -> std::io::Result<VAttr> {
            if path == Path::new("/") {
                Ok(VAttr::dir(0o755))
            } else {
                Err(std::io::Error::from_raw_os_error(libc::ENOENT))
            }
        }

        fn readdir(&self, path: &Path) -> std::io::Result<Vec<VDirEntry>> {
            if path != Path::new("/") {
                return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
            }
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(std::io::Error::from_raw_os_error(libc::EIO));
            }
            Ok(vec![VDirEntry {
                name: b"a".to_vec(),
                kind: NodeKind::File,
            }])
        }

        fn read(&self, _path: &Path, _offset: u64, _size: u32) -> std::io::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn readdir_error_finishes_inflight() {
        let cache = ReadDirCache::default();
        let provider = ErrOnceProvider {
            calls: AtomicUsize::new(0),
        };
        let err = cache
            .page(&provider, b"/", 0, 64)
            .expect_err("first page should fail");
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
        cache
            .page(&provider, b"/", 0, 64)
            .expect("second page should succeed after inflight cleared");
        assert_eq!(provider.calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn oversized_listing_finishes_inflight() {
        use super::super::protocol::MAX_READDIR_TOTAL;

        struct HugeListingProvider;

        impl PathFs for HugeListingProvider {
            fn getattr(&self, path: &Path) -> std::io::Result<VAttr> {
                if path == Path::new("/") {
                    Ok(VAttr::dir(0o755))
                } else {
                    Err(std::io::Error::from_raw_os_error(libc::ENOENT))
                }
            }

            fn readdir(&self, _path: &Path) -> std::io::Result<Vec<VDirEntry>> {
                Ok((0..=MAX_READDIR_TOTAL)
                    .map(|_| VDirEntry {
                        name: b"x".to_vec(),
                        kind: NodeKind::File,
                    })
                    .collect())
            }

            fn read(&self, _path: &Path, _offset: u64, _size: u32) -> std::io::Result<Vec<u8>> {
                Ok(Vec::new())
            }
        }

        let cache = Arc::new(ReadDirCache::default());
        let provider = HugeListingProvider;
        let err = cache
            .page(&provider, b"/", 0, 64)
            .expect_err("oversized listing should fail");
        assert_eq!(err.raw_os_error(), Some(libc::EINVAL));
        let (tx, rx) = std::sync::mpsc::sync_channel(0);
        let cache_wait = Arc::clone(&cache);
        std::thread::spawn(move || {
            let _ = cache_wait.page(&provider, b"/", 0, 64);
            let _ = tx.send(());
        });
        rx.recv_timeout(std::time::Duration::from_secs(2))
            .expect("second oversized listing attempt should not hang");
    }

    struct BlockingProvider {
        started: std::sync::mpsc::SyncSender<()>,
        unblocked: Arc<std::sync::atomic::AtomicBool>,
    }

    impl PathFs for BlockingProvider {
        fn getattr(&self, path: &Path) -> std::io::Result<VAttr> {
            if path == Path::new("/") {
                Ok(VAttr::dir(0o755))
            } else {
                Err(std::io::Error::from_raw_os_error(libc::ENOENT))
            }
        }

        fn readdir(&self, _path: &Path) -> std::io::Result<Vec<VDirEntry>> {
            let _ = self.started.try_send(());
            while !self.unblocked.load(std::sync::atomic::Ordering::Acquire) {
                std::thread::yield_now();
            }
            Ok(vec![VDirEntry {
                name: b"a".to_vec(),
                kind: NodeKind::File,
            }])
        }

        fn read(&self, _path: &Path, _offset: u64, _size: u32) -> std::io::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn invalidate_unblocks_inflight_waiters() {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(1);
        let unblocked = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let provider = Arc::new(BlockingProvider {
            started: started_tx,
            unblocked: Arc::clone(&unblocked),
        });
        let cache = Arc::new(ReadDirCache::default());
        let (fetch_tx, fetch_rx) = std::sync::mpsc::sync_channel(0);
        {
            let cache = Arc::clone(&cache);
            let provider = Arc::clone(&provider);
            std::thread::spawn(move || {
                let _ = cache.page(provider.as_ref(), b"/", 0, 64);
                let _ = fetch_tx.send(());
            });
        }
        started_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("timed out waiting for readdir to start");
        let (wait_tx, wait_rx) = std::sync::mpsc::sync_channel(0);
        {
            let cache = Arc::clone(&cache);
            let provider = Arc::clone(&provider);
            std::thread::spawn(move || {
                let _ = cache.page(provider.as_ref(), b"/", 0, 64);
                let _ = wait_tx.send(());
            });
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
        cache.invalidate();
        unblocked.store(true, std::sync::atomic::Ordering::Release);
        wait_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("waiter blocked after invalidate during inflight fetch");
        let _ = fetch_rx.recv_timeout(std::time::Duration::from_secs(1));
    }

    struct PathOnlyProvider {
        path: Vec<u8>,
        calls: Arc<AtomicUsize>,
    }

    impl PathFs for PathOnlyProvider {
        fn getattr(&self, path: &Path) -> std::io::Result<VAttr> {
            if path_matches(path, &self.path) {
                Ok(VAttr::dir(0o755))
            } else {
                Err(std::io::Error::from_raw_os_error(libc::ENOENT))
            }
        }

        fn readdir(&self, path: &Path) -> std::io::Result<Vec<VDirEntry>> {
            if !path_matches(path, &self.path) {
                return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
            }
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(Vec::new())
        }

        fn read(&self, _path: &Path, _offset: u64, _size: u32) -> std::io::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn cache_evicts_oldest_path_beyond_limit() {
        use super::super::protocol::MAX_READDIR_CACHE_PATHS;

        let cache = ReadDirCache::default();
        let dir0_calls = Arc::new(AtomicUsize::new(0));
        for i in 0..MAX_READDIR_CACHE_PATHS {
            let path = format!("/dir{i}");
            let calls = if i == 0 {
                Arc::clone(&dir0_calls)
            } else {
                Arc::new(AtomicUsize::new(0))
            };
            let provider = PathOnlyProvider {
                path: path.into_bytes(),
                calls,
            };
            cache
                .page(&provider, provider.path.as_slice(), 0, 64)
                .expect("seed cache");
        }
        assert_eq!(dir0_calls.load(Ordering::SeqCst), 1);
        let overflow = format!("/dir{}", MAX_READDIR_CACHE_PATHS);
        let provider = PathOnlyProvider {
            path: overflow.into_bytes(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        cache
            .page(&provider, provider.path.as_slice(), 0, 64)
            .expect("insert overflow path");
        let dir0 = PathOnlyProvider {
            path: b"/dir0".to_vec(),
            calls: Arc::clone(&dir0_calls),
        };
        cache
            .page(&dir0, b"/dir0", 0, 64)
            .expect("refetch evicted path");
        assert_eq!(
            dir0_calls.load(Ordering::SeqCst),
            2,
            "oldest cached path should have been evicted and refetched"
        );
    }

    struct PanicOnceProvider {
        calls: AtomicUsize,
        path: Vec<u8>,
    }

    impl PathFs for PanicOnceProvider {
        fn getattr(&self, path: &Path) -> std::io::Result<VAttr> {
            if path_matches(path, &self.path) {
                Ok(VAttr::dir(0o755))
            } else {
                Err(std::io::Error::from_raw_os_error(libc::ENOENT))
            }
        }

        fn readdir(&self, path: &Path) -> std::io::Result<Vec<VDirEntry>> {
            if !path_matches(path, &self.path) {
                return Err(std::io::Error::from_raw_os_error(libc::ENOENT));
            }
            if self.calls.fetch_add(1, Ordering::SeqCst) == 0 {
                panic!("provider bug");
            }
            Ok(vec![VDirEntry {
                name: b"a".to_vec(),
                kind: NodeKind::File,
            }])
        }

        fn read(&self, _path: &Path, _offset: u64, _size: u32) -> std::io::Result<Vec<u8>> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn finishes_inflight_on_provider_panic() {
        let cache = ReadDirCache::default();
        let provider = PanicOnceProvider {
            calls: AtomicUsize::new(0),
            path: b"/".to_vec(),
        };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            cache.page(&provider, b"/", 0, 64)
        }));
        assert!(result.is_err());

        let (done_tx, done_rx) = std::sync::mpsc::sync_channel(0);
        std::thread::spawn(move || {
            let _ = cache.page(&provider, b"/", 0, 64);
            let _ = done_tx.send(());
        });
        done_rx
            .recv_timeout(std::time::Duration::from_secs(1))
            .expect("waiter blocked after provider panic during readdir");
    }
}
