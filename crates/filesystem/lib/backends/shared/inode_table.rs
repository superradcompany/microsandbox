//! Inode table with dual-key lookup for filesystem backends.
//!
//! Provides [`MultikeyBTreeMap`] (a BTreeMap with two key types), [`InodeData`]
//! for per-inode state, and [`InodeAltKey`] for host-identity-based deduplication.

#[cfg(target_os = "macos")]
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::{
    borrow::Borrow,
    collections::{BTreeMap, BTreeSet},
    sync::{RwLock, atomic::AtomicU64},
};
#[cfg(target_os = "linux")]
use std::{fs::File, sync::Mutex};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A BTreeMap that supports 2 types of keys per value.
///
/// There is a 1:1 relationship between the two key types: for each `K1` in the
/// map there is exactly one `K2` and vice versa.
///
/// Copied from msb_krun's `src/devices/src/virtio/fs/multikey.rs` to avoid
/// depending on msb_krun internals.
#[derive(Default)]
pub(crate) struct MultikeyBTreeMap<K1, K2, V>
where
    K1: Ord,
    K2: Ord,
{
    main: BTreeMap<K1, (K2, V)>,
    alt: BTreeMap<K2, K1>,
}

/// Alternate key for inode lookup based on host filesystem identity.
///
/// On Linux, includes `mnt_id` from `statx` to prevent cross-mount collisions.
/// On macOS, uses `(ino, dev)` which is sufficient since there are no bind mounts.
#[derive(Clone, Copy, PartialOrd, Ord, PartialEq, Eq, Debug)]
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(crate) struct InodeAltKey {
    pub ino: u64,
    pub dev: u64,
    #[cfg(target_os = "linux")]
    pub mnt_id: u64,
}

/// One namespace alias for a tracked passthrough inode.
#[derive(Clone, PartialOrd, Ord, PartialEq, Eq, Debug)]
pub(crate) struct NamespaceAlias {
    pub parent: u64,
    pub name: Vec<u8>,
}

/// Per-inode data tracked by the filesystem backend.
#[cfg_attr(target_os = "linux", allow(dead_code))]
pub(crate) struct InodeData {
    /// Synthetic FUSE inode number (monotonically increasing, never reused).
    pub inode: u64,

    /// Host inode number.
    #[cfg(target_os = "linux")]
    pub ino: u64,

    /// Host inode number. Read it with [`InodeData::host_ino`].
    ///
    /// Atomic on macOS because it is not fixed there on every filesystem: see
    /// `ino_unstable`.
    #[cfg(target_os = "macos")]
    pub ino: AtomicU64,

    /// Host device ID.
    pub dev: u64,

    /// FUSE lookup reference count. When this reaches 0, the inode is removed.
    pub refcount: AtomicU64,

    /// Mount ID from statx (Linux only, for cross-mount deduplication).
    #[cfg(target_os = "linux")]
    pub mnt_id: u64,

    /// Current anchor parent inode for secure reopen-from-root.
    ///
    /// Tracked on both platforms; on macOS populated only for shares in
    /// anchor mode.
    pub anchor_parent: AtomicU64,

    /// Current anchor name under `anchor_parent`.
    ///
    /// Tracked on both platforms; on macOS populated only for shares in
    /// anchor mode.
    pub anchor_name: RwLock<Vec<u8>>,

    /// All known live aliases for this inode within the exported namespace.
    ///
    /// Tracked on both platforms; on macOS populated only for shares in
    /// anchor mode.
    pub aliases: RwLock<BTreeSet<NamespaceAlias>>,

    /// Number of descendant anchors that currently depend on this inode.
    ///
    /// Tracked on both platforms; on macOS populated only for shares in
    /// anchor mode.
    pub anchor_children: AtomicU64,

    /// Retained fd for detached objects that lost their last visible alias.
    #[cfg(target_os = "linux")]
    pub retained_fd: Mutex<Option<File>>,

    /// Fd grabbed before unlink, keeping the file accessible after deletion.
    ///
    /// On macOS, `/.vol/<dev>/<ino>` may become invalid after unlink. This fd
    /// (set by `do_unlink`) keeps the file data alive for open handles. -1 means
    /// the file has not been unlinked.
    #[cfg(target_os = "macos")]
    pub unlinked_fd: AtomicI64,

    /// Whether the host may give this file a different inode number.
    ///
    /// Set only for a share in anchor mode, while `ino` was read from a
    /// regular file that holds no data. FSKit exFAT numbers a regular file by
    /// its first data cluster, and a file without data gets a placeholder that
    /// is replaced by any change to the file. The backend reads the number
    /// again after each operation that makes one.
    #[cfg(target_os = "macos")]
    pub ino_unstable: AtomicBool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<K1, K2, V> MultikeyBTreeMap<K1, K2, V>
where
    K1: Clone + Ord,
    K2: Clone + Ord,
{
    /// Create a new empty MultikeyBTreeMap.
    pub fn new() -> Self {
        MultikeyBTreeMap {
            main: BTreeMap::default(),
            alt: BTreeMap::default(),
        }
    }

    /// Returns a reference to the value corresponding to the primary key.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K1: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.main.get(key).map(|(_, v)| v)
    }

    /// Returns a reference to the value corresponding to the alternate key.
    ///
    /// Performs 2 lookups: alt → primary key, then primary key → value.
    pub fn get_alt<Q2>(&self, key: &Q2) -> Option<&V>
    where
        K2: Borrow<Q2>,
        Q2: Ord + ?Sized,
    {
        if let Some(k) = self.alt.get(key) {
            self.get(k)
        } else {
            None
        }
    }

    /// Insert a new entry with both keys. Returns the old value if either key
    /// was already present.
    pub fn insert(&mut self, k1: K1, k2: K2, v: V) -> Option<V> {
        let oldval = if let Some(oldkey) = self.alt.insert(k2.clone(), k1.clone()) {
            self.main.remove(&oldkey)
        } else {
            None
        };
        self.main
            .insert(k1, (k2.clone(), v))
            .or(oldval)
            .map(|(oldk2, v)| {
                if oldk2 != k2 {
                    self.alt.remove(&oldk2);
                }
                v
            })
    }

    /// Remove an entry by its primary key.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K1: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.main.remove(key).map(|(k2, v)| {
            self.alt.remove(&k2);
            v
        })
    }

    /// Clear all entries.
    pub fn clear(&mut self) {
        self.alt.clear();
        self.main.clear();
    }

    /// Iterate primary keys and values in deterministic key order.
    pub fn iter(&self) -> impl Iterator<Item = (&K1, &V)> {
        self.main.iter().map(|(key, (_, value))| (key, value))
    }
}

impl InodeData {
    /// The host inode number currently recorded for this inode.
    #[cfg(target_os = "linux")]
    pub fn host_ino(&self) -> u64 {
        self.ino
    }

    /// The host inode number currently recorded for this inode.
    #[cfg(target_os = "macos")]
    pub fn host_ino(&self) -> u64 {
        self.ino.load(Ordering::Acquire)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "macos")]
impl Drop for InodeData {
    fn drop(&mut self) {
        // A prepared restore may be validated and discarded without receiving a guest
        // FORGET. The inode must release its retained descriptor in that path as well.
        let fd = self
            .unlinked_fd
            .swap(-1, std::sync::atomic::Ordering::AcqRel);
        if fd >= 0 {
            unsafe { libc::close(fd as i32) };
        }
    }
}

impl InodeAltKey {
    /// Create a new alternate key from stat fields.
    #[cfg(target_os = "linux")]
    pub fn new(ino: u64, dev: u64, mnt_id: u64) -> Self {
        Self { ino, dev, mnt_id }
    }

    /// Create a new alternate key from stat fields.
    #[cfg(target_os = "macos")]
    pub fn new(ino: u64, dev: u64) -> Self {
        Self { ino, dev }
    }
}

impl NamespaceAlias {
    pub fn new(parent: u64, name: &[u8]) -> Self {
        Self {
            parent,
            name: name.to_vec(),
        }
    }
}
