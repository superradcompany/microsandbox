//! Type definitions for the in-memory filesystem backend.

use std::collections::BTreeMap;
use std::sync::atomic::AtomicU64;
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Root inode number (FUSE convention).
pub(crate) const ROOT_INODE: u64 = 1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for the in-memory filesystem.
pub struct MemFsConfig {
    /// Maximum total bytes for file data (None = unlimited).
    pub capacity: Option<u64>,

    /// Maximum number of inodes (None = unlimited).
    pub max_inodes: Option<u64>,

    /// FUSE entry cache timeout (default: 5s).
    pub entry_timeout: Duration,

    /// FUSE attribute cache timeout (default: 5s).
    pub attr_timeout: Duration,

    /// Cache policy (default: Auto).
    pub cache_policy: CachePolicy,

    /// Enable writeback caching (default: false).
    pub writeback: bool,
}

/// Cache policy for FUSE open options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    /// No caching — sets DIRECT_IO.
    Never,
    /// Let the kernel decide.
    Auto,
    /// Aggressive caching — sets KEEP_CACHE.
    Always,
}

/// A filesystem node in the in-memory filesystem.
pub(crate) struct MemNode {
    /// FUSE inode number.
    pub inode: u64,

    /// File type (S_IFREG, S_IFDIR, S_IFLNK, etc).
    pub kind: u32,

    /// FUSE lookup reference count.
    pub lookup_refs: AtomicU64,

    /// Metadata (uid, gid, mode, timestamps, etc).
    pub meta: RwLock<InodeMeta>,

    /// Content data.
    pub content: InodeContent,

    /// Extended attributes.
    pub xattrs: RwLock<BTreeMap<Vec<u8>, Vec<u8>>>,
}

/// Metadata for an in-memory inode.
pub(crate) struct InodeMeta {
    /// Owner user ID.
    pub uid: u32,

    /// Owner group ID.
    pub gid: u32,

    /// File mode (includes type bits).
    pub mode: u32,

    /// Device number (for special files).
    pub rdev: u32,

    /// Number of hard links.
    pub nlink: u64,

    /// File size in bytes.
    pub size: u64,

    /// Last access time.
    pub atime: Timespec,

    /// Last modification time.
    pub mtime: Timespec,

    /// Last status change time.
    pub ctime: Timespec,
}

/// Content stored in an inode.
pub(crate) enum InodeContent {
    /// Regular file with in-memory data.
    RegularFile {
        /// File data bytes.
        data: RwLock<Vec<u8>>,
    },

    /// Directory with child entries.
    Directory {
        /// Map from child name to child inode number.
        children: RwLock<BTreeMap<Vec<u8>, u64>>,

        /// Parent inode number.
        parent: AtomicU64,
    },

    /// Symbolic link.
    Symlink {
        /// Link target path.
        target: Vec<u8>,
    },

    /// Special file (socket, char device, block device, fifo).
    Special,
}

/// Open file handle.
pub(crate) struct FileHandle {
    /// Inode this handle refers to.
    pub inode: u64,

    /// Reference to the node (keeps it alive after unlink).
    pub node: Arc<MemNode>,

    /// Open flags.
    pub flags: u32,
}

/// Open directory handle.
pub(crate) struct DirHandle {
    /// Inode this handle refers to.
    pub inode: u64,

    /// Reference to the node (keeps it alive after rmdir).
    pub node: Arc<MemNode>,

    /// Merged entry snapshot, built on first readdir call.
    pub snapshot: Mutex<Option<DirSnapshot>>,
}

/// A point-in-time snapshot of a directory's entries.
pub(crate) struct DirSnapshot {
    /// Directory entries.
    pub entries: Vec<MemDirEntry>,
}

/// A single entry in a directory snapshot.
pub(crate) struct MemDirEntry {
    /// Entry name.
    pub name: Vec<u8>,

    /// Inode number.
    pub inode: u64,

    /// Stable offset cookie (1-based).
    pub offset: u64,

    /// File type (d_type).
    pub file_type: u32,
}

/// Timestamp with second and nanosecond precision.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Timespec {
    /// Seconds since epoch.
    pub sec: i64,

    /// Nanoseconds.
    pub nsec: i64,
}
