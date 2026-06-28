//! Shared helpers for serving snapshot-backed directory entries.

use std::io;

use crate::DirEntry;
use crate::backends::shared::platform;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// View over a backend-owned directory snapshot entry.
pub(crate) trait SnapshotEntry {
    /// Guest-visible inode number.
    fn inode(&self) -> u64;

    /// Stable offset cookie.
    fn offset(&self) -> u64;

    /// Guest-visible directory entry type.
    fn file_type(&self) -> u32;

    /// Entry name bytes.
    fn name(&self) -> &[u8];
}

/// Metadata for one cached FUSE directory entry; name bytes live in `names_buf`.
struct FuseDirEntryMeta {
    ino: u64,
    offset: u64,
    type_: u32,
    name_start: usize,
    name_len: usize,
}

/// Owned storage for one cached FUSE directory listing.
///
/// `entries` index into `names_buf`. The name buffer is leaked once when the
/// cache is built so paginated `readdir` replies can hand out `'static` name
/// subslices without per-entry allocations. The leaked buffer is reclaimed only
/// at process exit (same contract as the prior per-page leak, but bounded to one
/// buffer per open-handle cache generation).
struct FuseDirCacheStorage {
    names_buf: &'static [u8],
    entries: Vec<FuseDirEntryMeta>,
}

/// Cached FUSE directory entries for one open directory handle.
///
/// Built once from a snapshot (with a single names-buffer allocation) and
/// reused for subsequent `readdir` calls at different offsets. Prior
/// generations' leaked name buffers are retained until the handle is released
/// so in-flight FUSE `DirEntry` name subslices stay valid; the RPC/readDir
/// layer forces clients to restart pagination after a mutation (`EAGAIN`).
/// Each rebuild leaks one new name buffer (FUSE requires `'static` names);
/// pagination does not add further leaks within a generation.
pub(crate) struct FuseDirCache {
    storage: Option<FuseDirCacheStorage>,
    /// Leaked name buffers from prior generations (kept for in-flight entries).
    retired_buffers: Vec<&'static [u8]>,
    /// Scratch space reused across rebuilds to avoid extra allocations before leak.
    build_scratch: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FuseDirCache {
    /// Create an empty cache.
    pub(crate) fn new() -> Self {
        Self {
            storage: None,
            retired_buffers: Vec::new(),
            build_scratch: Vec::new(),
        }
    }

    /// Drop any cached FUSE entries (e.g. after a directory mutation).
    ///
    /// Prior generations' leaked name buffers are retained until
    /// [`clear_on_release`](Self::clear_on_release) so in-flight FUSE `DirEntry`
    /// name subslices stay valid for the lifetime of the open handle.
    pub(crate) fn invalidate(&mut self) {
        if let Some(storage) = self.storage.take() {
            self.retired_buffers.push(storage.names_buf);
        }
    }

    /// Reclaim all cached storage when the directory handle is released.
    pub(crate) fn clear_on_release(&mut self) {
        self.storage = None;
        self.retired_buffers.clear();
        self.build_scratch.clear();
    }

    /// Serve directory entries from `snapshot`, building the FUSE cache on
    /// first use.
    pub(crate) fn serve<T: SnapshotEntry>(
        &mut self,
        snapshot: &[T],
        offset: u64,
        max_bytes: u32,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        if self.storage.is_none() {
            self.storage = Some(build_fuse_dir_storage(snapshot, &mut self.build_scratch));
        }
        paginate_fuse_dir_entries(self.storage.as_ref().unwrap(), offset, max_bytes)
    }

    #[cfg(test)]
    fn generation_count(&self) -> usize {
        self.retired_buffers.len() + usize::from(self.storage.is_some())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Guest-visible size of one `fuse_dirent` (fixed header + name, 8-byte aligned).
fn fuse_dirent_size(name_len: usize) -> usize {
    const FUSE_DIRENT_FIXED: usize = 24;
    let len = FUSE_DIRENT_FIXED + name_len;
    (len + 7) & !7
}

/// Build the full FUSE directory-entry list for a snapshot.
fn build_fuse_dir_storage<T: SnapshotEntry>(
    entries: &[T],
    scratch: &mut Vec<u8>,
) -> FuseDirCacheStorage {
    if entries.is_empty() {
        return FuseDirCacheStorage {
            names_buf: &[],
            entries: Vec::new(),
        };
    }

    scratch.clear();
    let mut raw_entries = Vec::with_capacity(entries.len());

    for entry in entries {
        let name_len = entry.name().len();
        let name_offset = scratch.len();
        scratch.extend_from_slice(entry.name());
        raw_entries.push((
            entry.inode(),
            entry.offset(),
            entry.file_type(),
            name_offset,
            name_len,
        ));
    }

    let names_buf: &'static [u8] = Box::leak(scratch.clone().into_boxed_slice());

    FuseDirCacheStorage {
        names_buf,
        entries: raw_entries
            .into_iter()
            .map(|(ino, off, typ, start, len)| FuseDirEntryMeta {
                ino,
                offset: off,
                type_: typ,
                name_start: start,
                name_len: len,
            })
            .collect(),
    }
}

/// Paginate pre-built FUSE entries starting strictly after `offset`.
///
/// When `max_bytes` is zero, return every entry from `offset` through the end
/// of the snapshot (callers that omit a byte limit, including unit tests).
/// When non-zero, stop once the encoded reply would exceed the FUSE buffer
/// size the kernel requested.
fn paginate_fuse_dir_entries(
    storage: &FuseDirCacheStorage,
    offset: u64,
    max_bytes: u32,
) -> io::Result<Vec<DirEntry<'static>>> {
    let entries = &storage.entries;
    let start = entries
        .iter()
        .position(|entry| entry.offset > offset)
        .unwrap_or(entries.len());

    let slice = &entries[start..];
    if slice.is_empty() {
        return Ok(Vec::new());
    }

    if max_bytes == 0 {
        return Ok(slice
            .iter()
            .map(|entry| dir_entry_from_storage(storage, entry))
            .collect());
    }

    let mut out = Vec::new();
    let mut used_bytes = 0usize;
    let byte_limit = max_bytes as usize;

    for entry in slice {
        let entry_bytes = fuse_dirent_size(entry.name_len);
        if used_bytes + entry_bytes > byte_limit {
            break;
        }
        used_bytes += entry_bytes;
        out.push(dir_entry_from_storage(storage, entry));
    }

    if out.is_empty() {
        // Returning zero entries while the snapshot still has data would look
        // like EOF to FUSE. Ask the caller to retry with a larger buffer.
        return Err(platform::eagain());
    }

    Ok(out)
}

/// Build one `DirEntry` whose name borrows the cache's single leaked buffer.
fn dir_entry_from_storage(
    storage: &FuseDirCacheStorage,
    entry: &FuseDirEntryMeta,
) -> DirEntry<'static> {
    let name = &storage.names_buf[entry.name_start..entry.name_start + entry.name_len];
    DirEntry {
        ino: entry.ino,
        offset: entry.offset,
        type_: entry.type_,
        name,
    }
}

/// Serve directory entries from a snapshot starting strictly after `offset`.
///
/// Prefer [`FuseDirCache::serve`] when serving multiple pages from the same
/// open directory handle.
#[allow(dead_code)]
pub(crate) fn serve_snapshot_entries<T: SnapshotEntry>(
    entries: &[T],
    offset: u64,
    max_bytes: u32,
) -> io::Result<Vec<DirEntry<'static>>> {
    let mut cache = FuseDirCache::new();
    cache.serve(entries, offset, max_bytes)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    struct TestEntry {
        ino: u64,
        off: u64,
        typ: u32,
        name: Vec<u8>,
    }

    impl SnapshotEntry for TestEntry {
        fn inode(&self) -> u64 {
            self.ino
        }
        fn offset(&self) -> u64 {
            self.off
        }
        fn file_type(&self) -> u32 {
            self.typ
        }
        fn name(&self) -> &[u8] {
            &self.name
        }
    }

    #[test]
    fn serve_snapshot_returns_eagain_when_buffer_too_small_for_first_entry() {
        let entries = vec![TestEntry {
            ino: 1,
            off: 1,
            typ: 0,
            name: b"a".to_vec(),
        }];
        let mut cache = FuseDirCache::new();
        // One dirent needs 32 bytes; a 16-byte buffer cannot fit any entry.
        match cache.serve(&entries, 0, 16) {
            Err(err) => assert_eq!(
                err.raw_os_error(),
                platform::eagain().raw_os_error(),
                "got: {err:?}"
            ),
            Ok(out) => panic!("expected EAGAIN, got {} entries", out.len()),
        }
    }

    #[test]
    fn serve_snapshot_returns_eagain_when_first_entry_exceeds_buffer() {
        let long_name = vec![b'x'; 200];
        let entries = vec![TestEntry {
            ino: 1,
            off: 1,
            typ: 0,
            name: long_name,
        }];
        let mut cache = FuseDirCache::new();
        // One dirent needs 224 bytes (24 + 200, 8-byte aligned); 64-byte buffer cannot fit it.
        match cache.serve(&entries, 0, 64) {
            Err(err) => assert_eq!(
                err.raw_os_error(),
                platform::eagain().raw_os_error(),
                "got: {err:?}"
            ),
            Ok(out) => panic!("expected EAGAIN, got {} entries", out.len()),
        }
    }

    #[test]
    fn serve_snapshot_returns_one_entry_when_buffer_fits_single_dirent() {
        let entries = vec![
            TestEntry {
                ino: 1,
                off: 1,
                typ: 0,
                name: b"a".to_vec(),
            },
            TestEntry {
                ino: 2,
                off: 2,
                typ: 0,
                name: b"b".to_vec(),
            },
        ];
        let mut cache = FuseDirCache::new();
        // One dirent needs 32 bytes; a 16-byte buffer cannot fit two.
        let out = cache.serve(&entries, 0, 32).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, b"a");
    }

    #[test]
    fn serve_snapshot_respects_byte_limit_after_first_entry() {
        let entries = vec![
            TestEntry {
                ino: 1,
                off: 1,
                typ: 0,
                name: b"a".to_vec(),
            },
            TestEntry {
                ino: 2,
                off: 2,
                typ: 0,
                name: b"b".to_vec(),
            },
        ];
        let mut cache = FuseDirCache::new();
        let out = cache.serve(&entries, 0, 64).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn serve_snapshot_zero_size_returns_all_entries() {
        let entries = vec![
            TestEntry {
                ino: 1,
                off: 1,
                typ: 0,
                name: b"a".to_vec(),
            },
            TestEntry {
                ino: 2,
                off: 2,
                typ: 0,
                name: b"b".to_vec(),
            },
        ];
        let mut cache = FuseDirCache::new();
        let out = cache.serve(&entries, 0, 0).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn fuse_dir_cache_reuses_single_allocation_across_pages() {
        let entries = vec![
            TestEntry {
                ino: 1,
                off: 1,
                typ: 0,
                name: b"a".to_vec(),
            },
            TestEntry {
                ino: 2,
                off: 2,
                typ: 0,
                name: b"b".to_vec(),
            },
        ];
        let mut cache = FuseDirCache::new();
        let first = cache.serve(&entries, 0, 32).unwrap();
        let second = cache.serve(&entries, first[0].offset, 64).unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].name, b"b");
    }

    #[test]
    fn fuse_dir_cache_invalidate_drops_storage() {
        let entries = vec![TestEntry {
            ino: 1,
            off: 1,
            typ: 0,
            name: b"a".to_vec(),
        }];
        let mut cache = FuseDirCache::new();
        let _ = cache.serve(&entries, 0, 0).unwrap();
        assert!(cache.storage.is_some());
        assert_eq!(cache.generation_count(), 1);
        cache.invalidate();
        assert!(cache.storage.is_none());
        assert_eq!(cache.generation_count(), 1);
        let out = cache.serve(&entries, 0, 0).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].name, b"a");
        assert_eq!(cache.generation_count(), 2);
    }

    #[test]
    fn fuse_dir_cache_retains_all_retired_generations_until_release() {
        let entries = vec![TestEntry {
            ino: 1,
            off: 1,
            typ: 0,
            name: b"a".to_vec(),
        }];
        let mut cache = FuseDirCache::new();
        const GENERATIONS: usize = 72;
        for _ in 0..GENERATIONS {
            let _ = cache.serve(&entries, 0, 0).unwrap();
            cache.invalidate();
        }
        assert_eq!(
            cache.retired_buffers.len(),
            GENERATIONS,
            "retired buffers must not be evicted while the handle stays open"
        );
    }

    #[test]
    fn fuse_dir_cache_retains_retired_buffers_until_release() {
        let entries = vec![TestEntry {
            ino: 1,
            off: 1,
            typ: 0,
            name: b"a".to_vec(),
        }];
        let mut cache = FuseDirCache::new();
        for generation in 0..12 {
            let _ = cache.serve(&entries, 0, 0).unwrap();
            cache.invalidate();
            assert_eq!(
                cache.retired_buffers.len(),
                generation + 1,
                "generation {generation}"
            );
        }
        cache.clear_on_release();
        assert!(cache.retired_buffers.is_empty());
    }

    #[test]
    fn fuse_dir_cache_clear_on_release_drops_all_generations() {
        let entries = vec![TestEntry {
            ino: 1,
            off: 1,
            typ: 0,
            name: b"a".to_vec(),
        }];
        let mut cache = FuseDirCache::new();
        let _ = cache.serve(&entries, 0, 0).unwrap();
        cache.invalidate();
        cache.clear_on_release();
        assert!(cache.storage.is_none());
        assert!(cache.retired_buffers.is_empty());
    }

    #[test]
    fn fuse_dir_cache_many_pages_share_one_generation() {
        let entries = vec![
            TestEntry {
                ino: 1,
                off: 1,
                typ: 0,
                name: b"a".to_vec(),
            },
            TestEntry {
                ino: 2,
                off: 2,
                typ: 0,
                name: b"b".to_vec(),
            },
        ];
        let mut cache = FuseDirCache::new();
        for _ in 0..20 {
            let _ = cache.serve(&entries, 0, 32).unwrap();
        }
        assert_eq!(cache.generation_count(), 1);
    }

    #[test]
    fn paginated_readdir_names_share_one_leaked_buffer() {
        let entries = vec![
            TestEntry {
                ino: 1,
                off: 1,
                typ: 0,
                name: b"a".to_vec(),
            },
            TestEntry {
                ino: 2,
                off: 2,
                typ: 0,
                name: b"b".to_vec(),
            },
        ];
        let mut cache = FuseDirCache::new();
        let first = cache.serve(&entries, 0, 32).unwrap();
        let second = cache.serve(&entries, first[0].offset, 64).unwrap();
        assert_eq!(first.len(), 1);
        assert_eq!(second.len(), 1);
        let base = first[0].name.as_ptr();
        let end = unsafe { base.add(first[0].name.len() + second[0].name.len()) };
        assert!(second[0].name.as_ptr() >= base);
        assert!(second[0].name.as_ptr() < end);
    }
}
