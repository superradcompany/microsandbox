//! Sidecar index writer.
//!
//! Builds binary index files from high-level calls. Used by OCI layer extraction
//! to generate per-layer sidecar indexes, and by tests to construct valid/corrupt
//! index data.

use std::{io, path::Path};

use super::{
    DIR_FLAG_OPAQUE, DIR_RECORD_IDX_NONE, DirRecord, ENTRY_FLAG_WHITEOUT, EntryRecord, HardlinkRef,
    INDEX_MAGIC, INDEX_VERSION, IndexHeader,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Specification for a directory in the index.
struct DirBuildSpec {
    /// Directory path (`""` for root, `"etc"`, `"usr/bin"`).
    path: String,
    /// Flags (bit 0 = opaque).
    flags: u8,
    /// Child entries.
    entries: Vec<EntryBuildSpec>,
    /// Overflow tombstone names.
    tombstones: Vec<String>,
}

/// Specification for an entry in the index.
struct EntryBuildSpec {
    /// Entry name (basename only, e.g. `"hosts"`).
    name: String,
    /// Host inode number.
    host_ino: u64,
    /// File size in bytes.
    size: u64,
    /// Full stat mode including `S_IFMT` type bits.
    mode: u32,
    /// Guest-visible uid.
    uid: u32,
    /// Guest-visible gid.
    gid: u32,
    /// Flags (bit 0 = whiteout).
    flags: u8,
}

/// Builds valid sidecar index files from high-level calls.
///
/// # Example
/// ```ignore
/// let data = IndexBuilder::new()
///     .dir("")
///     .file("", "hello.txt", 0o644)
///     .build();
/// ```
pub struct IndexBuilder {
    dirs: Vec<DirBuildSpec>,
    hardlinks: Vec<(u64, String)>,
    /// Synthetic host_ino counter for convenience methods.
    /// Not used by lookup (lookup stats the real file).
    next_ino: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl IndexBuilder {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self {
            dirs: Vec::new(),
            hardlinks: Vec::new(),
            next_ino: 1000,
        }
    }

    /// Add a directory to the index.
    pub fn dir(mut self, path: &str) -> Self {
        self.dirs.push(DirBuildSpec {
            path: path.to_string(),
            flags: 0,
            entries: Vec::new(),
            tombstones: Vec::new(),
        });
        self
    }

    /// Add an opaque directory to the index.
    pub fn opaque_dir(mut self, path: &str) -> Self {
        self.dirs.push(DirBuildSpec {
            path: path.to_string(),
            flags: DIR_FLAG_OPAQUE,
            entries: Vec::new(),
            tombstones: Vec::new(),
        });
        self
    }

    /// Add a regular file entry. Mode permissions only (S_IFREG is added automatically).
    pub fn file(mut self, dir: &str, name: &str, mode: u32) -> Self {
        let ino = self.next_ino;
        self.next_ino += 1;
        let dir_spec = self
            .dirs
            .iter_mut()
            .find(|d| d.path == dir)
            .unwrap_or_else(|| panic!("dir '{}' not found, add with .dir() first", dir));
        dir_spec.entries.push(EntryBuildSpec {
            name: name.to_string(),
            host_ino: ino,
            size: 0,
            mode: u32::from(libc::S_IFREG) | (mode & 0o7777),
            uid: 0,
            gid: 0,
            flags: 0,
        });
        self
    }

    /// Add a subdirectory entry. Mode permissions only (S_IFDIR is added automatically).
    pub fn subdir(mut self, dir: &str, name: &str, mode: u32) -> Self {
        let ino = self.next_ino;
        self.next_ino += 1;
        let dir_spec = self
            .dirs
            .iter_mut()
            .find(|d| d.path == dir)
            .unwrap_or_else(|| panic!("dir '{}' not found", dir));
        dir_spec.entries.push(EntryBuildSpec {
            name: name.to_string(),
            host_ino: ino,
            size: 0,
            mode: u32::from(libc::S_IFDIR) | (mode & 0o7777),
            uid: 0,
            gid: 0,
            flags: 0,
        });
        self
    }

    /// Add a symlink entry.
    pub fn symlink(mut self, dir: &str, name: &str) -> Self {
        let ino = self.next_ino;
        self.next_ino += 1;
        let dir_spec = self.dirs.iter_mut().find(|d| d.path == dir).unwrap();
        dir_spec.entries.push(EntryBuildSpec {
            name: name.to_string(),
            host_ino: ino,
            size: 0,
            mode: u32::from(libc::S_IFLNK) | 0o777,
            uid: 0,
            gid: 0,
            flags: 0,
        });
        self
    }

    /// Add a whiteout entry (masks a name from lower layers).
    pub fn whiteout(mut self, dir: &str, name: &str) -> Self {
        let dir_spec = self.dirs.iter_mut().find(|d| d.path == dir).unwrap();
        dir_spec.entries.push(EntryBuildSpec {
            name: name.to_string(),
            host_ino: 0,
            size: 0,
            mode: u32::from(libc::S_IFREG),
            uid: 0,
            gid: 0,
            flags: ENTRY_FLAG_WHITEOUT,
        });
        self
    }

    /// Add an overflow tombstone name for a directory.
    pub fn tombstone(mut self, dir: &str, name: &str) -> Self {
        let dir_spec = self.dirs.iter_mut().find(|d| d.path == dir).unwrap();
        dir_spec.tombstones.push(name.to_string());
        self
    }

    /// Add a hardlink reference entry.
    pub fn hardlink(mut self, ino: u64, path: &str) -> Self {
        self.hardlinks.push((ino, path.to_string()));
        self
    }

    /// Build valid index bytes.
    pub fn build(mut self) -> Vec<u8> {
        // Sort dirs by path (lexicographic byte comparison).
        self.dirs
            .sort_by(|a, b| a.path.as_bytes().cmp(b.path.as_bytes()));

        // Sort entries within each dir by name.
        for dir in &mut self.dirs {
            dir.entries
                .sort_by(|a, b| a.name.as_bytes().cmp(b.name.as_bytes()));
        }

        // Sort hardlinks by ino, then path.
        self.hardlinks
            .sort_by(|a, b| a.0.cmp(&b.0).then_with(|| a.1.cmp(&b.1)));

        // Build string pool.
        let mut pool = Vec::new();

        // Dir paths.
        let dir_path_offsets: Vec<(u32, u16)> = self
            .dirs
            .iter()
            .map(|d| {
                let off = pool.len() as u32;
                let len = d.path.len() as u16;
                pool.extend_from_slice(d.path.as_bytes());
                (off, len)
            })
            .collect();

        // Entry names.
        let entry_name_offsets: Vec<Vec<(u32, u16)>> = self
            .dirs
            .iter()
            .map(|d| {
                d.entries
                    .iter()
                    .map(|e| {
                        let off = pool.len() as u32;
                        let len = e.name.len() as u16;
                        pool.extend_from_slice(e.name.as_bytes());
                        (off, len)
                    })
                    .collect()
            })
            .collect();

        // Hardlink paths.
        let hardlink_offsets: Vec<(u32, u32)> = self
            .hardlinks
            .iter()
            .map(|(_, path)| {
                let off = pool.len() as u32;
                let len = path.len() as u32;
                pool.extend_from_slice(path.as_bytes());
                (off, len)
            })
            .collect();

        // Tombstone data.
        let tombstone_offsets: Vec<(u32, u16)> = self
            .dirs
            .iter()
            .map(|d| {
                if d.tombstones.is_empty() {
                    (0, 0)
                } else {
                    let off = pool.len() as u32;
                    for name in &d.tombstones {
                        let len = name.len() as u16;
                        pool.extend_from_slice(&len.to_le_bytes());
                        pool.extend_from_slice(name.as_bytes());
                    }
                    (off, d.tombstones.len() as u16)
                }
            })
            .collect();

        // Sorted dir paths for dir_record_idx resolution.
        let sorted_paths: Vec<&str> = self.dirs.iter().map(|d| d.path.as_str()).collect();

        // Compute first_entry offsets.
        let mut first_entries: Vec<u32> = Vec::new();
        let mut offset = 0u32;
        for dir in &self.dirs {
            first_entries.push(offset);
            offset += dir.entries.len() as u32;
        }

        let dir_count = self.dirs.len() as u32;
        let entry_count: u32 = self.dirs.iter().map(|d| d.entries.len() as u32).sum();
        let hardlink_ref_count = self.hardlinks.len() as u32;
        let string_pool_size = pool.len() as u32;

        let mut buf = Vec::with_capacity(
            size_of::<IndexHeader>()
                + dir_count as usize * size_of::<DirRecord>()
                + entry_count as usize * size_of::<EntryRecord>()
                + hardlink_ref_count as usize * size_of::<HardlinkRef>()
                + string_pool_size as usize,
        );

        // Header (32 bytes).
        buf.extend_from_slice(&INDEX_MAGIC.to_le_bytes());
        buf.extend_from_slice(&INDEX_VERSION.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // flags
        buf.extend_from_slice(&dir_count.to_le_bytes());
        buf.extend_from_slice(&entry_count.to_le_bytes());
        buf.extend_from_slice(&hardlink_ref_count.to_le_bytes());
        buf.extend_from_slice(&string_pool_size.to_le_bytes());
        buf.extend_from_slice(&0u32.to_le_bytes()); // checksum placeholder
        assert_eq!(buf.len(), 32);

        // DirRecords (24 bytes each).
        for (i, dir) in self.dirs.iter().enumerate() {
            let (path_off, path_len) = dir_path_offsets[i];
            let (tomb_off, tomb_count) = tombstone_offsets[i];
            buf.extend_from_slice(&path_off.to_le_bytes());
            buf.extend_from_slice(&path_len.to_le_bytes());
            buf.push(dir.flags);
            buf.push(0); // _pad
            buf.extend_from_slice(&first_entries[i].to_le_bytes());
            buf.extend_from_slice(&(dir.entries.len() as u32).to_le_bytes());
            buf.extend_from_slice(&tomb_off.to_le_bytes());
            buf.extend_from_slice(&tomb_count.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes()); // _pad2
        }

        // EntryRecords (40 bytes each).
        for (dir_idx, dir) in self.dirs.iter().enumerate() {
            for (entry_idx, entry) in dir.entries.iter().enumerate() {
                let (name_off, name_len) = entry_name_offsets[dir_idx][entry_idx];

                // Auto-compute dir_record_idx for directory entries.
                let dir_record_idx =
                    if entry.mode & u32::from(libc::S_IFMT) == u32::from(libc::S_IFDIR) {
                        let child_path = if dir.path.is_empty() {
                            entry.name.clone()
                        } else {
                            format!("{}/{}", dir.path, entry.name)
                        };
                        sorted_paths
                            .binary_search(&child_path.as_str())
                            .map(|i| i as u32)
                            .unwrap_or(DIR_RECORD_IDX_NONE)
                    } else {
                        DIR_RECORD_IDX_NONE
                    };

                buf.extend_from_slice(&entry.host_ino.to_le_bytes());
                buf.extend_from_slice(&entry.size.to_le_bytes());
                buf.extend_from_slice(&name_off.to_le_bytes());
                buf.extend_from_slice(&entry.mode.to_le_bytes());
                buf.extend_from_slice(&entry.uid.to_le_bytes());
                buf.extend_from_slice(&entry.gid.to_le_bytes());
                buf.extend_from_slice(&name_len.to_le_bytes());
                buf.push(entry.flags);
                buf.push(0); // _pad
                buf.extend_from_slice(&dir_record_idx.to_le_bytes());
            }
        }

        // HardlinkRefs (16 bytes each).
        for (i, (ino, _)) in self.hardlinks.iter().enumerate() {
            let (path_off, path_len) = hardlink_offsets[i];
            buf.extend_from_slice(&ino.to_le_bytes());
            buf.extend_from_slice(&path_off.to_le_bytes());
            buf.extend_from_slice(&path_len.to_le_bytes());
        }

        // String pool.
        buf.append(&mut pool);

        // Compute CRC32C incrementally (checksum field at bytes 28..32 treated as zeroed).
        let crc = crc32c::crc32c(&buf[..28]);
        let crc = crc32c::crc32c_append(crc, &[0u8; 4]);
        let crc = crc32c::crc32c_append(crc, &buf[32..]);
        buf[28..32].copy_from_slice(&crc.to_le_bytes());

        buf
    }

    /// Write valid index to a file.
    pub fn build_to_file(self, path: &Path) -> io::Result<()> {
        std::fs::write(path, self.build())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for IndexBuilder {
    fn default() -> Self {
        Self::new()
    }
}
