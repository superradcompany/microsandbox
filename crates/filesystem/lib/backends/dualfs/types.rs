//! Core type definitions for the DualFs backend.
//!
//! Defines guest-visible inode state, handle types, namespace tables,
//! and configuration. DualFs owns no storage — all data lives in child backends.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use super::policy::DualDispatchPlan;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Root inode number (FUSE convention).
pub(crate) const ROOT_INODE: u64 = 1;

/// Default materialization chunk size (1 MiB).
const DEFAULT_COPY_CHUNK_SIZE: usize = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Identifies one of the two child backends.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BackendId {
    /// The first backend slot.
    BackendA,
    /// The second backend slot.
    BackendB,
}

/// Atomic storage for a `BackendId` value.
pub(crate) struct AtomicBackendId(AtomicU8);

/// File type cached from child stat on first discovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum FileKind {
    RegularFile,
    Directory,
    Symlink,
    /// FIFO, socket, block device, char device.
    Special,
}

/// A guest-visible filesystem object tracked by DualFs.
///
/// The core owns the guest identity; child backends own the storage.
#[allow(dead_code)]
pub(crate) struct GuestNode {
    /// Synthetic FUSE inode number.
    pub guest_inode: u64,

    /// File type (cached from child stat on first discovery).
    pub kind: FileKind,

    /// FUSE lookup reference count.
    pub lookup_refs: AtomicU64,

    /// Stable guest alias for reverse lookup (used by materialization).
    pub anchor_parent: AtomicU64,
    /// Stable name for the anchor alias.
    pub anchor_name: RwLock<Vec<u8>>,

    /// Which backend currently supplies authoritative metadata.
    pub metadata_backend: AtomicBackendId,

    /// Which child backend(s) currently back this object.
    pub state: RwLock<NodeState>,

    /// Serializes materialization of this node.
    pub copy_up_lock: Mutex<()>,
}

/// Tracks which child backend(s) back a guest-visible object.
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum NodeState {
    /// The synthetic DualFs root directory.
    Root {
        backend_a_root: u64,
        backend_b_root: u64,
    },

    /// Entry lives exclusively in backend_a.
    BackendA {
        backend_a_inode: u64,
        /// If materialized from backend_b, the original backend_b inode.
        former_backend_b_inode: Option<u64>,
    },

    /// Entry lives exclusively in backend_b.
    BackendB {
        backend_b_inode: u64,
        /// If materialized from backend_a, the original backend_a inode.
        former_backend_a_inode: Option<u64>,
    },

    /// Directory exists in both backends (for readdir merging).
    MergedDir {
        backend_a_inode: u64,
        backend_b_inode: u64,
    },

    /// The virtual init.krun binary.
    Init,
}

/// File handle for regular files.
#[derive(Debug)]
#[allow(dead_code)]
pub(crate) enum DualHandle {
    /// Handle to a backend_a file.
    BackendA {
        guest_inode: u64,
        backend_a_inode: u64,
        backend_a_handle: u64,
    },
    /// Handle to a backend_b file.
    BackendB {
        guest_inode: u64,
        backend_b_inode: u64,
        backend_b_handle: u64,
    },
}

/// Directory handle.
pub(crate) struct DualDirHandle {
    /// Guest inode this handle refers to.
    pub guest_inode: u64,
    /// Backend_a inode (if dir has backend_a presence).
    pub backend_a_inode: Option<u64>,
    /// Backend_b inode (if dir has backend_b presence).
    pub backend_b_inode: Option<u64>,
    /// Readdir plan chosen at opendir time.
    pub readdir_plan: DualDispatchPlan,
    /// Merged snapshot, built on first readdir.
    pub snapshot: Mutex<Option<DirSnapshot>>,
}

/// Point-in-time snapshot of a directory's merged entries.
pub(crate) struct DirSnapshot {
    pub entries: Vec<MergedDirEntry>,
}

/// A single entry in a merged directory snapshot.
pub(crate) struct MergedDirEntry {
    pub name: Vec<u8>,
    /// Stable guest inode.
    pub inode: u64,
    /// 1-based monotonically increasing offset.
    pub offset: u64,
    /// d_type value.
    pub file_type: u32,
}

/// All mutable namespace state for DualFs.
pub(crate) struct DualState {
    /// Node table: guest inode -> GuestNode.
    pub nodes: RwLock<BTreeMap<u64, Arc<GuestNode>>>,

    /// Dentry table: (parent_inode, name) -> guest inode.
    pub dentries: RwLock<BTreeMap<(u64, Vec<u8>), u64>>,

    /// Reverse dentry index: guest_inode -> { (parent, name), ... }
    pub alias_index: RwLock<BTreeMap<u64, BTreeSet<(u64, Vec<u8>)>>>,

    /// Backend_a inode -> guest inode dedup map.
    pub backend_a_inode_map: RwLock<BTreeMap<u64, u64>>,

    /// Backend_b inode -> guest inode dedup map.
    pub backend_b_inode_map: RwLock<BTreeMap<u64, u64>>,

    /// In-memory whiteouts: (parent_guest_inode, name, hidden_backend).
    pub whiteouts: RwLock<HashSet<(u64, Vec<u8>, BackendId)>>,

    /// Directories marked opaque against a specific backend.
    pub opaque_dirs: RwLock<HashSet<(u64, BackendId)>>,

    /// Next guest inode number.
    pub next_inode: AtomicU64,

    /// File handle table.
    pub file_handles: RwLock<BTreeMap<u64, Arc<DualHandle>>>,

    /// Directory handle table.
    pub dir_handles: RwLock<BTreeMap<u64, Arc<DualDirHandle>>>,

    /// Hidden per-backend staging directories for materialization.
    pub staging_dirs: RwLock<BTreeMap<BackendId, u64>>,

    /// Next handle number.
    pub next_handle: AtomicU64,

    /// Whether writeback caching is negotiated.
    pub writeback: AtomicBool,
}

/// Cache policy for FUSE caching.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    /// Never cache.
    Never,
    /// Cache based on FUSE defaults.
    Auto,
    /// Always cache.
    Always,
}

/// Configuration for DualFs.
pub struct DualFsConfig {
    /// FUSE entry cache timeout.
    pub entry_timeout: Duration,
    /// FUSE attribute cache timeout.
    pub attr_timeout: Duration,
    /// Cache policy.
    pub cache_policy: CachePolicy,
    /// Enable writeback caching.
    pub writeback: bool,
    /// Chunk size for materialization data streaming.
    pub copy_chunk_size: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AtomicBackendId {
    pub(crate) fn new(id: BackendId) -> Self {
        AtomicBackendId(AtomicU8::new(id.to_u8()))
    }

    pub(crate) fn load(&self, ordering: Ordering) -> BackendId {
        BackendId::from_u8(self.0.load(ordering))
    }

    pub(crate) fn store(&self, id: BackendId, ordering: Ordering) {
        self.0.store(id.to_u8(), ordering);
    }
}

impl BackendId {
    fn to_u8(self) -> u8 {
        match self {
            BackendId::BackendA => 0,
            BackendId::BackendB => 1,
        }
    }

    fn from_u8(v: u8) -> Self {
        match v {
            0 => BackendId::BackendA,
            _ => BackendId::BackendB,
        }
    }

    /// Return the other backend.
    pub(crate) fn other(self) -> Self {
        match self {
            BackendId::BackendA => BackendId::BackendB,
            BackendId::BackendB => BackendId::BackendA,
        }
    }
}

impl DualHandle {
    /// Return which backend this handle is bound to.
    pub(crate) fn backend_id(&self) -> BackendId {
        match self {
            DualHandle::BackendA { .. } => BackendId::BackendA,
            DualHandle::BackendB { .. } => BackendId::BackendB,
        }
    }

    /// Return the guest inode for this handle.
    #[allow(dead_code)]
    pub(crate) fn guest_inode(&self) -> u64 {
        match self {
            DualHandle::BackendA { guest_inode, .. }
            | DualHandle::BackendB { guest_inode, .. } => *guest_inode,
        }
    }

    /// Return the child backend inode for this handle.
    pub(crate) fn child_inode(&self) -> u64 {
        match self {
            DualHandle::BackendA {
                backend_a_inode, ..
            } => *backend_a_inode,
            DualHandle::BackendB {
                backend_b_inode, ..
            } => *backend_b_inode,
        }
    }

    /// Return the child backend handle for this handle.
    pub(crate) fn child_handle(&self) -> u64 {
        match self {
            DualHandle::BackendA {
                backend_a_handle, ..
            } => *backend_a_handle,
            DualHandle::BackendB {
                backend_b_handle, ..
            } => *backend_b_handle,
        }
    }
}

impl DualState {
    /// Create a new empty DualState.
    pub(crate) fn new() -> Self {
        DualState {
            nodes: RwLock::new(BTreeMap::new()),
            dentries: RwLock::new(BTreeMap::new()),
            alias_index: RwLock::new(BTreeMap::new()),
            backend_a_inode_map: RwLock::new(BTreeMap::new()),
            backend_b_inode_map: RwLock::new(BTreeMap::new()),
            whiteouts: RwLock::new(HashSet::new()),
            opaque_dirs: RwLock::new(HashSet::new()),
            next_inode: AtomicU64::new(3), // 1=root, 2=init
            file_handles: RwLock::new(BTreeMap::new()),
            dir_handles: RwLock::new(BTreeMap::new()),
            staging_dirs: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1), // 0=init handle
            writeback: AtomicBool::new(false),
        }
    }

    /// Get the inode map for a given backend.
    pub(crate) fn inode_map(
        &self,
        backend: BackendId,
    ) -> &RwLock<BTreeMap<u64, u64>> {
        match backend {
            BackendId::BackendA => &self.backend_a_inode_map,
            BackendId::BackendB => &self.backend_b_inode_map,
        }
    }

    /// Check if a name is hidden for a specific backend.
    pub(crate) fn is_whited_out(&self, parent: u64, name: &[u8], hidden_backend: BackendId) -> bool {
        self.whiteouts
            .read()
            .unwrap()
            .contains(&(parent, name.to_vec(), hidden_backend))
    }

    /// Check if a directory is opaque against a specific backend.
    pub(crate) fn is_opaque(&self, dir_inode: u64, hidden_backend: BackendId) -> bool {
        self.opaque_dirs
            .read()
            .unwrap()
            .contains(&(dir_inode, hidden_backend))
    }
}

impl FileKind {
    /// Convert from stat st_mode to FileKind.
    pub(crate) fn from_mode(mode: u32) -> Self {
        let fmt = mode & libc::S_IFMT as u32;
        if fmt == libc::S_IFREG as u32 {
            FileKind::RegularFile
        } else if fmt == libc::S_IFDIR as u32 {
            FileKind::Directory
        } else if fmt == libc::S_IFLNK as u32 {
            FileKind::Symlink
        } else {
            FileKind::Special
        }
    }

    /// Convert to d_type value.
    pub(crate) fn to_dtype(self) -> u32 {
        match self {
            FileKind::RegularFile => libc::DT_REG as u32,
            FileKind::Directory => libc::DT_DIR as u32,
            FileKind::Symlink => libc::DT_LNK as u32,
            FileKind::Special => libc::DT_UNKNOWN as u32,
        }
    }

    /// Convert from d_type to FileKind.
    pub(crate) fn from_dtype(dtype: u32) -> Self {
        if dtype == libc::DT_REG as u32 {
            FileKind::RegularFile
        } else if dtype == libc::DT_DIR as u32 {
            FileKind::Directory
        } else if dtype == libc::DT_LNK as u32 {
            FileKind::Symlink
        } else {
            FileKind::Special
        }
    }
}

impl NodeState {
    /// Resolve the child backend inode for a given backend, if present.
    pub(crate) fn backend_inode(&self, backend: BackendId) -> Option<u64> {
        match (self, backend) {
            (NodeState::Root { backend_a_root, .. }, BackendId::BackendA) => Some(*backend_a_root),
            (NodeState::Root { backend_b_root, .. }, BackendId::BackendB) => Some(*backend_b_root),
            (NodeState::BackendA { backend_a_inode, .. }, BackendId::BackendA) => {
                Some(*backend_a_inode)
            }
            (NodeState::BackendB { backend_b_inode, .. }, BackendId::BackendB) => {
                Some(*backend_b_inode)
            }
            (NodeState::MergedDir { backend_a_inode, .. }, BackendId::BackendA) => {
                Some(*backend_a_inode)
            }
            (NodeState::MergedDir { backend_b_inode, .. }, BackendId::BackendB) => {
                Some(*backend_b_inode)
            }
            _ => None,
        }
    }

    /// Return the single active backend for a single-backed node.
    pub(crate) fn current_backend(&self) -> Option<BackendId> {
        match self {
            NodeState::BackendA { .. } => Some(BackendId::BackendA),
            NodeState::BackendB { .. } => Some(BackendId::BackendB),
            _ => None,
        }
    }

    /// Check if this is a pure single-backed directory on the given backend.
    pub(crate) fn is_pure_on(&self, backend: BackendId) -> bool {
        match (self, backend) {
            (NodeState::BackendA { .. }, BackendId::BackendA) => true,
            (NodeState::BackendB { .. }, BackendId::BackendB) => true,
            _ => false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for CachePolicy {
    fn default() -> Self {
        CachePolicy::Auto
    }
}

impl Default for DualFsConfig {
    fn default() -> Self {
        DualFsConfig {
            entry_timeout: Duration::from_secs(5),
            attr_timeout: Duration::from_secs(5),
            cache_policy: CachePolicy::default(),
            writeback: false,
            copy_chunk_size: DEFAULT_COPY_CHUNK_SIZE,
        }
    }
}
