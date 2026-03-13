//! Sidecar index reader for lower layer acceleration.
//!
//! Provides zero-copy, mmap-based access to the binary layer index generated at
//! OCI layer extraction time. See `layer-index-format.md` for the wire format.
//!
//! The index is an optimization — if missing or corrupt, the overlay falls back
//! to live syscalls. `MmapIndex::open()` returns `None` on any validation failure.

use std::path::Path;

use super::{
    DIR_FLAG_OPAQUE, DirRecord, ENTRY_FLAG_WHITEOUT, EntryRecord, HardlinkRef, INDEX_MAGIC,
    INDEX_VERSION, IndexHeader,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Zero-copy reader for a mmap'd layer sidecar index.
///
/// Immutable after construction. The mmap region is `PROT_READ | MAP_PRIVATE`,
/// so this is `Send + Sync`.
pub struct MmapIndex {
    /// Pointer to the start of the mmap'd region.
    ptr: *const u8,
    /// Total length of the mmap'd region in bytes.
    len: usize,
    /// Byte offset of the string pool within the mmap'd region.
    pool_offset: usize,
}

/// Iterator over tombstone names packed in the string pool.
///
/// Format: `[u16 len][name bytes]` repeated `count` times.
pub struct TombstoneIter<'a> {
    data: &'a [u8],
    remaining: u16,
}

// SAFETY: The mmap'd region is read-only and never modified after construction.
unsafe impl Send for MmapIndex {}
unsafe impl Sync for MmapIndex {}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MmapIndex {
    /// Open and validate a sidecar index file.
    ///
    /// Returns `None` if the file doesn't exist, is too small, or fails any
    /// validation check (magic, version, checksum, size consistency).
    pub fn open(path: &Path) -> Option<Self> {
        use scopeguard::ScopeGuard;

        let file = std::fs::File::open(path).ok()?;
        let metadata = file.metadata().ok()?;
        let file_len = metadata.len() as usize;

        // Must be at least as large as the header.
        if file_len < size_of::<IndexHeader>() {
            return None;
        }

        // mmap the file read-only.
        use std::os::fd::AsRawFd;
        let raw = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                file_len,
                libc::PROT_READ,
                libc::MAP_PRIVATE,
                file.as_raw_fd(),
                0,
            )
        };
        if raw == libc::MAP_FAILED {
            return None;
        }
        let ptr = raw as *const u8;

        // Auto-unmap on early return; defused on success.
        let guard = scopeguard::guard((ptr, file_len), |(p, len)| unsafe {
            libc::munmap(p as *mut libc::c_void, len);
        });

        // Validate header.
        let header = unsafe { &*(ptr as *const IndexHeader) };
        if header.magic != INDEX_MAGIC || header.version != INDEX_VERSION {
            return None;
        }

        // Compute pool offset and verify total size matches file size.
        let header_size = size_of::<IndexHeader>();
        let pool_offset = header_size
            + (header.dir_count as usize) * size_of::<DirRecord>()
            + (header.entry_count as usize) * size_of::<EntryRecord>()
            + (header.hardlink_ref_count as usize) * size_of::<HardlinkRef>();
        let expected_size = pool_offset + header.string_pool_size as usize;
        if expected_size != file_len {
            return None;
        }

        // Verify CRC32C checksum incrementally without heap allocation.
        // The checksum field (bytes 28..32) is treated as zeroed for computation.
        let data = unsafe { std::slice::from_raw_parts(ptr, file_len) };
        let crc = crc32c::crc32c(&data[..28]);
        let crc = crc32c::crc32c_append(crc, &[0u8; 4]);
        let crc = crc32c::crc32c_append(crc, &data[header_size..]);
        if crc != header.checksum {
            return None;
        }

        // Defuse the guard — ownership transfers to Self.
        ScopeGuard::into_inner(guard);

        Some(Self {
            ptr,
            len: file_len,
            pool_offset,
        })
    }

    /// Get the header.
    fn header(&self) -> &IndexHeader {
        unsafe { &*(self.ptr as *const IndexHeader) }
    }

    /// Get the directory records table (sorted by path).
    pub fn dir_records(&self) -> &[DirRecord] {
        let header = self.header();
        let offset = size_of::<IndexHeader>();
        let count = header.dir_count as usize;
        unsafe { std::slice::from_raw_parts(self.ptr.add(offset) as *const DirRecord, count) }
    }

    /// Get the entry records table.
    fn entry_records(&self) -> &[EntryRecord] {
        let header = self.header();
        let offset =
            size_of::<IndexHeader>() + (header.dir_count as usize) * size_of::<DirRecord>();
        let count = header.entry_count as usize;
        unsafe { std::slice::from_raw_parts(self.ptr.add(offset) as *const EntryRecord, count) }
    }

    /// Get a string from the string pool by offset and length.
    pub fn get_str(&self, off: u32, len: u16) -> &[u8] {
        self.pool_slice(off as usize, len as usize)
    }

    /// Get a string from the string pool by u32 offset and u32 length.
    fn get_str_u32(&self, off: u32, len: u32) -> &[u8] {
        self.pool_slice(off as usize, len as usize)
    }

    /// Get a slice from the string pool by offset and length.
    fn pool_slice(&self, off: usize, len: usize) -> &[u8] {
        let start = self.pool_offset + off;
        let end = start + len;
        if end > self.len {
            return b"";
        }
        unsafe { std::slice::from_raw_parts(self.ptr.add(start), len) }
    }

    /// Find a directory by path. Returns `(index, &DirRecord)`.
    ///
    /// Binary search on the sorted directory table.
    pub fn find_dir(&self, path: &[u8]) -> Option<(usize, &DirRecord)> {
        let dirs = self.dir_records();
        let idx = dirs
            .binary_search_by(|rec| self.get_str(rec.path_off, rec.path_len).cmp(path))
            .ok()?;
        Some((idx, &dirs[idx]))
    }

    /// Find an entry within a directory by name.
    ///
    /// Binary search on the entry slice for this directory.
    pub fn find_entry<'a>(&'a self, dir: &DirRecord, name: &[u8]) -> Option<&'a EntryRecord> {
        let entries = self.dir_entries(dir);
        let idx = entries
            .binary_search_by(|rec| self.get_str(rec.name_off, rec.name_len).cmp(name))
            .ok()?;
        Some(&entries[idx])
    }

    /// Get the contiguous entry slice for a directory.
    pub fn dir_entries(&self, dir: &DirRecord) -> &[EntryRecord] {
        let all = self.entry_records();
        let start = dir.first_entry as usize;
        let end = start + dir.entry_count as usize;
        if end > all.len() {
            return &[];
        }
        &all[start..end]
    }

    /// Check if a directory is opaque.
    pub fn is_opaque(&self, dir: &DirRecord) -> bool {
        dir.flags & DIR_FLAG_OPAQUE != 0
    }

    /// Check if a name is whited out in a directory.
    pub fn has_whiteout(&self, dir: &DirRecord, name: &[u8]) -> bool {
        if let Some(entry) = self.find_entry(dir, name) {
            entry.flags & ENTRY_FLAG_WHITEOUT != 0
        } else {
            false
        }
    }

    /// Iterate overflow tombstone names for a directory.
    pub fn tombstone_names<'a>(&'a self, dir: &DirRecord) -> TombstoneIter<'a> {
        if dir.tombstone_count == 0 {
            return TombstoneIter {
                data: &[],
                remaining: 0,
            };
        }

        // Tombstone data is in the string pool: packed [u16 len][name bytes]...
        let start = self.pool_offset + dir.tombstone_off as usize;
        // We don't know the exact end, but it's bounded by the file length.
        let data = if start < self.len {
            unsafe { std::slice::from_raw_parts(self.ptr.add(start), self.len - start) }
        } else {
            &[]
        };

        TombstoneIter {
            data,
            remaining: dir.tombstone_count,
        }
    }

    /// Get the hardlink reference table.
    pub fn hardlink_refs(&self) -> &[HardlinkRef] {
        let header = self.header();
        let count = header.hardlink_ref_count as usize;
        let offset = self.pool_offset - count * size_of::<HardlinkRef>();
        unsafe { std::slice::from_raw_parts(self.ptr.add(offset) as *const HardlinkRef, count) }
    }

    /// Find all aliases of a hardlinked file by host inode number.
    pub fn find_aliases(&self, ino: u64) -> &[HardlinkRef] {
        let refs = self.hardlink_refs();
        let start = refs.partition_point(|r| r.host_ino < ino);
        let end = start
            + refs[start..]
                .iter()
                .take_while(|r| r.host_ino == ino)
                .count();
        &refs[start..end]
    }

    /// Get a hardlink ref's path string.
    pub fn hardlink_path(&self, href: &HardlinkRef) -> &[u8] {
        self.get_str_u32(href.path_off, href.path_len)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'a> Iterator for TombstoneIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<Self::Item> {
        if self.remaining == 0 || self.data.len() < 2 {
            return None;
        }
        let len = u16::from_le_bytes([self.data[0], self.data[1]]) as usize;
        self.data = &self.data[2..];
        if self.data.len() < len {
            self.remaining = 0;
            return None;
        }
        let name = &self.data[..len];
        self.data = &self.data[len..];
        self.remaining -= 1;
        Some(name)
    }
}

impl Drop for MmapIndex {
    fn drop(&mut self) {
        if !self.ptr.is_null() && self.len > 0 {
            unsafe {
                libc::munmap(self.ptr as *mut libc::c_void, self.len);
            }
        }
    }
}
