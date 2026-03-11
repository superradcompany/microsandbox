//! Type definitions for the overlay filesystem backend.
//!
//! All core types used across overlay modules are defined here to avoid
//! circular dependencies between modules.

use std::collections::HashMap;
use std::fs::File;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::{Mutex, RwLock};
use std::time::Duration;

use super::origin::LowerOriginId;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Root inode number (FUSE convention).
pub(crate) const ROOT_INODE: u64 = 1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for the overlay filesystem.
pub struct OverlayConfig {
    /// Lower layers in bottom-to-top order. All treated as read-only.
    pub lowers: Vec<PathBuf>,

    /// Writable upper layer directory.
    pub upper_dir: PathBuf,

    /// Private same-filesystem staging area for atomic operations.
    /// Must be on the same filesystem as upper_dir.
    pub state_dir: PathBuf,

    /// Enable xattr-based stat virtualization (default: true).
    pub xattr: bool,

    /// Fail mount if required primitives are unavailable (default: true).
    pub strict: bool,

    /// FUSE entry cache timeout (default: 5s).
    pub entry_timeout: Duration,

    /// FUSE attribute cache timeout (default: 5s).
    pub attr_timeout: Duration,

    /// Cache policy (default: Auto).
    pub cache_policy: CachePolicy,

    /// Enable writeback caching (default: false).
    pub writeback: bool,

    /// Metadata-only copy-up (default: false, V1 always off).
    pub metacopy: bool,
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

/// A filesystem object in the overlay.
pub(crate) struct OverlayNode {
    /// Synthetic FUSE inode number (monotonically increasing, never reused).
    pub inode: u64,

    /// File type (cached from virtualized stat).
    pub kind: u32,

    /// FUSE lookup reference count.
    pub lookup_refs: AtomicU64,

    /// Current backing state (changes on copy-up).
    pub state: RwLock<NodeState>,

    /// True if this directory is opaque (has .wh..wh..opq).
    pub opaque: AtomicBool,

    /// Copy-up lock. Acquired exclusively during copy-up to prevent races.
    pub copy_up_lock: Mutex<()>,

    /// Lower-layer origin identity for hardlink unification.
    pub origin: Option<LowerOriginId>,

    /// Redirect state for renamed directories (Phase 2).
    pub redirect: RwLock<Option<RedirectState>>,

    /// Primary parent inode for reverse lookup (inode-only FUSE ops).
    pub primary_parent: AtomicU64,

    /// Primary name for reverse lookup.
    pub primary_name: RwLock<NameId>,
}

/// Backing state for an overlay node.
pub(crate) enum NodeState {
    /// The overlay root directory.
    Root {
        /// Fd to the upper layer's root directory.
        upper_fd: File,
    },

    /// The virtual init.krun binary.
    Init,

    /// Entry lives on a read-only lower layer.
    Lower {
        /// Which lower layer (index into OverlayFs::lowers).
        layer_idx: usize,

        /// O_PATH fd pinning the inode.
        #[cfg(target_os = "linux")]
        file: File,

        /// Mount ID from statx.
        #[cfg(target_os = "linux")]
        mnt_id: u64,

        /// Host inode number (macOS — no O_PATH fds).
        #[cfg(target_os = "macos")]
        ino: u64,

        /// Host device number.
        #[cfg(target_os = "macos")]
        dev: u64,
    },

    /// Entry has been copied up to the upper layer.
    Upper {
        /// O_PATH fd pinning the inode.
        #[cfg(target_os = "linux")]
        file: File,

        /// Mount ID from statx.
        #[cfg(target_os = "linux")]
        mnt_id: u64,

        /// Host inode number (macOS).
        #[cfg(target_os = "macos")]
        ino: u64,

        /// Host device number.
        #[cfg(target_os = "macos")]
        dev: u64,
    },
}

/// A single filesystem layer in the overlay stack.
pub(crate) struct Layer {
    /// Root directory fd (O_RDONLY | O_DIRECTORY | O_CLOEXEC).
    pub root_fd: File,

    /// Whether this layer is writable (only the topmost layer).
    pub writable: bool,

    /// Index in the layer stack (0 = bottommost lower).
    pub index: usize,

    /// Linux: /proc/self/fd handle for secure inode reopening.
    #[cfg(target_os = "linux")]
    pub proc_self_fd: File,

    /// Linux: whether openat2/RESOLVE_BENEATH is available.
    #[cfg(target_os = "linux")]
    pub has_openat2: bool,
}

/// A directory entry linking a name to a node within a parent.
pub(crate) struct Dentry {
    /// Parent node's inode number (0 for root's parent).
    pub parent: u64,

    /// Interned name of this entry.
    pub name: NameId,

    /// Node (inode) this entry points to.
    pub node: u64,

    /// Dentry flags.
    pub flags: DentryFlags,
}

/// Dentry flags (manual bitflags — no bitflags dep in workspace).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DentryFlags(u8);

impl DentryFlags {
    /// Empty flags.
    pub const EMPTY: Self = Self(0);
    /// This dentry represents a whiteout (.wh.<name>).
    pub const WHITEOUT: Self = Self(0x01);
    /// This dentry is a negative cache entry (known not to exist).
    pub const NEGATIVE: Self = Self(0x02);

    /// Check if a flag is set.
    pub fn contains(self, flag: Self) -> bool {
        self.0 & flag.0 == flag.0
    }
}

/// File handle for open regular files.
pub(crate) struct FileHandle {
    /// The overlay inode this handle belongs to.
    pub inode: u64,

    /// Real open fd for I/O.
    pub file: RwLock<File>,

    /// Whether this handle was opened for writing.
    pub writable: bool,
}

/// Directory handle with lazy merged snapshot.
pub(crate) struct DirHandle {
    /// The overlay inode this handle belongs to.
    pub inode: u64,

    /// Merged entry snapshot, built on first readdir call.
    pub snapshot: Mutex<Option<DirSnapshot>>,
}

/// A point-in-time snapshot of a merged directory's entries.
pub(crate) struct DirSnapshot {
    /// Merged entries across all layers.
    pub entries: Vec<MergedDirEntry>,
}

/// A single entry in a merged directory snapshot.
pub(crate) struct MergedDirEntry {
    /// Entry name (owned bytes — snapshot is per-handle, short-lived).
    pub name: Vec<u8>,

    /// Stable offset cookie (1-based, monotonically increasing).
    pub offset: u64,

    /// File type (d_type).
    pub file_type: u32,
}

/// Interned name ID. Path components are interned to reduce memory usage
/// across thousands of inodes sharing common names (usr, bin, lib, etc).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct NameId(pub u32);

/// Symbol interning table for path components.
pub(crate) struct NameTable {
    /// Forward map: raw name bytes → interned ID.
    names: RwLock<HashMap<Vec<u8>, NameId>>,

    /// Reverse map: interned ID → raw name bytes.
    reverse: RwLock<Vec<Vec<u8>>>,
}

/// Redirect state for renamed directories.
///
/// When a directory is renamed, this records the path to the original lower-layer
/// location so lookups through the renamed directory can still find lower entries.
pub(crate) struct RedirectState {
    /// Path components from root to the original lower directory.
    pub lower_path: Vec<Vec<u8>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Default for OverlayConfig {
    fn default() -> Self {
        Self {
            lowers: Vec::new(),
            upper_dir: PathBuf::new(),
            state_dir: PathBuf::new(),
            xattr: true,
            strict: true,
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: CachePolicy::Auto,
            writeback: false,
            metacopy: false,
        }
    }
}

impl NameTable {
    /// Create a new empty name table.
    pub fn new() -> Self {
        Self {
            names: RwLock::new(HashMap::new()),
            reverse: RwLock::new(Vec::new()),
        }
    }

    /// Intern a name, returning its NameId. If already interned, returns existing ID.
    pub fn intern(&self, name: &[u8]) -> NameId {
        // Fast path: check read lock first.
        {
            let names = self.names.read().unwrap();
            if let Some(&id) = names.get(name) {
                return id;
            }
        }

        // Slow path: acquire write lock and insert.
        let mut names = self.names.write().unwrap();
        // Double-check after acquiring write lock.
        if let Some(&id) = names.get(name) {
            return id;
        }

        let mut reverse = self.reverse.write().unwrap();
        let id = NameId(reverse.len() as u32);
        reverse.push(name.to_vec());
        names.insert(name.to_vec(), id);
        id
    }

    /// Resolve a NameId back to raw name bytes.
    pub fn resolve(&self, id: NameId) -> Vec<u8> {
        let reverse = self.reverse.read().unwrap();
        reverse[id.0 as usize].clone()
    }
}
