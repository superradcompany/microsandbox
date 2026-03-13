//! Wire format types for the layer sidecar index.
//!
//! Binary mmap-friendly index generated at OCI layer extraction time and consumed
//! by OverlayFs at runtime. See `layer-index-format.md` for the full specification.
//!
//! All types are `#[repr(C)]` with natural alignment for zero-copy mmap access on
//! little-endian targets (x86_64, aarch64).

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Magic bytes: "MSBi" in little-endian.
pub const INDEX_MAGIC: u32 = 0x6942_534D;

/// Current wire format version.
pub const INDEX_VERSION: u32 = 1;

/// DirRecord flag: directory is opaque (hides all lower entries).
pub const DIR_FLAG_OPAQUE: u8 = 0x01;

/// EntryRecord flag: entry is a whiteout (masks a lower entry).
pub const ENTRY_FLAG_WHITEOUT: u8 = 0x01;

/// Sentinel value for `EntryRecord.dir_record_idx` on non-directory entries.
pub const DIR_RECORD_IDX_NONE: u32 = 0xFFFF_FFFF;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Index file header (32 bytes, offset 0).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct IndexHeader {
    /// Magic bytes (`INDEX_MAGIC`).
    pub magic: u32,
    /// Wire format version (`INDEX_VERSION`).
    pub version: u32,
    /// Reserved flags (must be 0).
    pub flags: u32,
    /// Number of `DirRecord` entries.
    pub dir_count: u32,
    /// Total number of `EntryRecord` entries across all directories.
    pub entry_count: u32,
    /// Number of `HardlinkRef` entries.
    pub hardlink_ref_count: u32,
    /// Total bytes in the string pool.
    pub string_pool_size: u32,
    /// CRC32C of entire file with this field zeroed.
    pub checksum: u32,
}

/// A directory in the index (24 bytes). Sorted by path (lexicographic).
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DirRecord {
    /// String pool offset for directory path.
    pub path_off: u32,
    /// Byte length of path (`""` for root, `"etc"`, `"usr/bin"`).
    pub path_len: u16,
    /// Flags (bit 0 = `DIR_FLAG_OPAQUE`).
    pub flags: u8,
    /// Padding.
    pub _pad: u8,
    /// Index of first child in the entry table.
    pub first_entry: u32,
    /// Number of children in this directory.
    pub entry_count: u32,
    /// String pool offset for overflow tombstone data (0 = none).
    pub tombstone_off: u32,
    /// Number of overflow tombstoned names.
    pub tombstone_count: u16,
    /// Padding.
    pub _pad2: u16,
}

/// A filesystem entry in the index (40 bytes, 8-byte aligned).
/// Grouped by parent directory (contiguous), sorted by name within each group.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct EntryRecord {
    /// Host inode number (`LowerOriginId.object_id`).
    pub host_ino: u64,
    /// File size in bytes.
    pub size: u64,
    /// String pool offset for entry name.
    pub name_off: u32,
    /// Full stat mode including `S_IFMT` type bits.
    pub mode: u32,
    /// Guest-visible uid (from `override_stat` xattr).
    pub uid: u32,
    /// Guest-visible gid (from `override_stat` xattr).
    pub gid: u32,
    /// Byte length of name.
    pub name_len: u16,
    /// Flags (bit 0 = `ENTRY_FLAG_WHITEOUT`).
    pub flags: u8,
    /// Padding.
    pub _pad: u8,
    /// `DirRecord` index for directory entries; `DIR_RECORD_IDX_NONE` for non-dirs.
    pub dir_record_idx: u32,
}

/// A hardlink reference (16 bytes, 8-byte aligned).
/// Sorted by `host_ino`, then by path. Only entries with nlink > 1 within the layer.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct HardlinkRef {
    /// Shared host inode number.
    pub host_ino: u64,
    /// String pool offset for full path (e.g. `"usr/bin/tool"`).
    pub path_off: u32,
    /// Byte length of path.
    pub path_len: u32,
}

// Compile-time size assertions.
const _: () = assert!(size_of::<IndexHeader>() == 32);
const _: () = assert!(size_of::<DirRecord>() == 24);
const _: () = assert!(size_of::<EntryRecord>() == 40);
const _: () = assert!(size_of::<HardlinkRef>() == 16);
