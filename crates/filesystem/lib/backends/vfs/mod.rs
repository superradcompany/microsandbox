//! Path-based programmable virtual filesystem.
//!
//! `VirtualFs<P>` is a [`DynFileSystem`] scaffold that owns every FUSE-shaped
//! concern — inode allocation, the inode↔path map, open-handle tables, lookup
//! reference counting, `stat64`/`Entry` construction, readdir cookie paging,
//! and zero-copy I/O — and delegates the *semantics* of each operation to a
//! user-supplied [`PathFs`] provider keyed by absolute guest path.
//!
//! This realizes the "filesystem as a UI layer for the agent" pattern: a
//! provider maps `read`/`readdir`/`write`/`create`/`rename`/… directly onto a
//! backend (an in-memory map, a database, an object store, a remote API),
//! while the scaffold handles all the kernel-facing bookkeeping that would
//! otherwise have to be reimplemented for every backend.
//!
//! ## Scope
//!
//! `VirtualFs` is intentionally simpler than [`MemFs`](super::memfs::MemFs):
//! it is keyed purely by path, so **hard links are not supported** (a path
//! API cannot express two names sharing one inode), and there is no embedded
//! boot-init binary. It is meant for mounting data sources as a subtree, not
//! as a bootable rootfs.

mod config;
mod path_fs;
pub mod rpc;

#[cfg(test)]
mod test_backend;
#[cfg(test)]
mod tests;

pub use config::{CachePolicy, VirtualFsConfig, VirtualFsMountConfig};
pub use path_fs::{NodeKind, PathFs, VAttr, VDirEntry};

use std::{
    cell::RefCell,
    collections::{BTreeMap, HashSet},
    ffi::{CStr, OsStr},
    fs::File,
    io,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    path::Path,
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use crate::{
    Context, DirEntry, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
    backends::shared::{
        dir_snapshot::{FuseDirCache, SnapshotEntry},
        inode_table::MultikeyBTreeMap,
        name_validation, platform,
    },
    stat64, statvfs64,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Root inode number (FUSE convention).
const ROOT_INODE: u64 = 1;

/// Guest Linux open flags. `VirtualFs` interprets these directly, so it must
/// use guest values on every host platform.
const GUEST_O_TRUNC: u32 = 0x200;

/// `SEEK_DATA` — seek to next data region.
const SEEK_DATA: u32 = 3;

/// `SEEK_HOLE` — seek to next hole region.
const SEEK_HOLE: u32 = 4;

/// XATTR_CREATE flag (Linux value).
const XATTR_CREATE: u32 = 1;

/// XATTR_REPLACE flag (Linux value).
const XATTR_REPLACE: u32 = 2;

/// Linux `RENAME_NOREPLACE` flag.
const RENAME_NOREPLACE: u32 = 1;

/// Linux `RENAME_EXCHANGE` flag.
const RENAME_EXCHANGE: u32 = 2;

const KNOWN_RENAME_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;

/// Maximum bytes per read/write (matches [`rpc::protocol::MAX_IO_SIZE`]).
const MAX_IO_SIZE: u32 = rpc::protocol::MAX_IO_SIZE;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A live inode: the scaffold's record of a path that the guest is referencing.
struct VNode {
    /// FUSE inode number.
    inode: u64,
    /// Absolute guest path (mutated on rename). Begins with `/`.
    path: RwLock<Vec<u8>>,
    /// FUSE lookup reference count.
    lookup_refs: AtomicU64,
}

/// An open file handle.
struct VFileHandle {
    /// The node, kept alive for the handle's lifetime (survives unlink).
    node: Arc<VNode>,
    /// Guest path captured at open time for provider I/O after unlink.
    path: Vec<u8>,
}

/// An open directory handle.
struct VDirHandle {
    /// The node, kept alive for the handle's lifetime.
    node: Arc<VNode>,
    /// Entry snapshot, built lazily on first readdir.
    snapshot: Mutex<Option<Vec<VSnapEntry>>>,
    /// Cached FUSE entries for this handle (one names-buffer allocation).
    fuse_cache: Mutex<FuseDirCache>,
}

/// A single entry in a directory snapshot.
struct VSnapEntry {
    name: Vec<u8>,
    inode: u64,
    offset: u64,
    file_type: u32,
}

impl SnapshotEntry for VSnapEntry {
    fn inode(&self) -> u64 {
        self.inode
    }
    fn offset(&self) -> u64 {
        self.offset
    }
    fn file_type(&self) -> u32 {
        self.file_type
    }
    fn name(&self) -> &[u8] {
        &self.name
    }
}

/// Path-based programmable virtual filesystem.
///
/// Construct with [`VirtualFs::new`] (default config) or
/// [`VirtualFs::with_config`], passing any [`PathFs`] provider.
pub struct VirtualFs<P: PathFs> {
    /// The semantic backend.
    provider: P,
    /// Inode table with both keys (inode → node and absolute path → inode) in
    /// one structure, so the two indexes can never disagree and there is no
    /// lock-ordering to maintain between them.
    inodes: RwLock<MultikeyBTreeMap<u64, Vec<u8>, Arc<VNode>>>,
    /// Open file handle table.
    file_handles: RwLock<BTreeMap<u64, Arc<VFileHandle>>>,
    /// Open directory handle table.
    dir_handles: RwLock<BTreeMap<u64, Arc<VDirHandle>>>,
    /// Next inode to allocate (1 = root).
    next_inode: AtomicU64,
    /// Next handle to allocate.
    next_handle: AtomicU64,
    /// Configuration.
    cfg: VirtualFsConfig,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<P: PathFs> VirtualFs<P> {
    /// Create a `VirtualFs` over `provider` with default configuration.
    pub fn new(provider: P) -> io::Result<Self> {
        Self::with_config(provider, VirtualFsConfig::default())
    }

    /// Create a `VirtualFs` over `provider` with the given configuration.
    pub fn with_config(provider: P, cfg: VirtualFsConfig) -> io::Result<Self> {
        let root = Arc::new(VNode {
            inode: ROOT_INODE,
            path: RwLock::new(b"/".to_vec()),
            // Pin the root so it is never evicted.
            lookup_refs: AtomicU64::new(u64::MAX / 2),
        });

        let mut inodes = MultikeyBTreeMap::new();
        inodes.insert(ROOT_INODE, b"/".to_vec(), root);

        Ok(Self {
            provider,
            inodes: RwLock::new(inodes),
            file_handles: RwLock::new(BTreeMap::new()),
            dir_handles: RwLock::new(BTreeMap::new()),
            next_inode: AtomicU64::new(ROOT_INODE + 1),
            next_handle: AtomicU64::new(1),
            cfg,
        })
    }

    /// Borrow the underlying provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }

    // ---- bookkeeping helpers -------------------------------------------------------------------

    fn cache_open_options(&self) -> OpenOptions {
        match self.cfg.cache_policy {
            CachePolicy::Never => OpenOptions::DIRECT_IO,
            CachePolicy::Auto => OpenOptions::empty(),
            CachePolicy::Always => OpenOptions::KEEP_CACHE,
        }
    }

    fn cache_dir_options(&self) -> OpenOptions {
        match self.cfg.cache_policy {
            CachePolicy::Never => OpenOptions::DIRECT_IO,
            CachePolicy::Auto => OpenOptions::empty(),
            CachePolicy::Always => OpenOptions::CACHE_DIR,
        }
    }

    /// Look up a node by inode, or `EBADF` if unknown.
    fn get_node(&self, ino: u64) -> io::Result<Arc<VNode>> {
        self.inodes
            .read()
            .unwrap()
            .get(&ino)
            .cloned()
            .ok_or_else(platform::ebadf)
    }

    /// The current absolute path of an inode.
    ///
    /// An inode the kernel still references after its name was removed or taken
    /// over by a rename is kept resolvable (so FORGET can clean it up) but holds
    /// a tombstone key instead of a guest path; resolving it to a path is
    /// `ESTALE` because it no longer names anything the provider can serve.
    fn path_of(&self, ino: u64) -> io::Result<Vec<u8>> {
        let node = self.get_node(ino)?;
        let path = node.path.read().unwrap().clone();
        if is_tombstone(&path) {
            return Err(platform::estale());
        }
        Ok(path)
    }

    /// Get or allocate the inode for `path` and take one FUSE lookup reference
    /// for it, returning the node.
    ///
    /// The get-or-insert and the reference bump happen together under the write
    /// lock. This is what closes the lookup/forget race: `forget_one` evicts a
    /// node only while holding the same write lock and only when its refs are
    /// `0`, so it can never observe a node mid-intern. Either it runs fully
    /// before us (the node is gone, we re-create it with `refs == 1`) or fully
    /// after (it sees the reference we just took and skips eviction). Bumping
    /// the count *after* releasing the lock — as a separate `fetch_add` — would
    /// reopen that window and hand the kernel an inode already removed from the
    /// table.
    fn intern_and_reference(&self, path: Vec<u8>) -> Arc<VNode> {
        let mut inodes = self.inodes.write().unwrap();
        if let Some(node) = inodes.get_alt(&path).cloned() {
            node.lookup_refs.fetch_add(1, Ordering::Relaxed);
            return node;
        }

        let ino = self.next_inode.fetch_add(1, Ordering::Relaxed);
        let node = Arc::new(VNode {
            inode: ino,
            path: RwLock::new(path.clone()),
            lookup_refs: AtomicU64::new(1),
        });
        inodes.insert(ino, path, Arc::clone(&node));
        node
    }

    /// Decrement an inode's lookup refs, evicting it when it reaches zero.
    fn forget_one(&self, ino: u64, count: u64) {
        if ino == ROOT_INODE {
            return;
        }
        let drop_to_zero = {
            let inodes = self.inodes.read().unwrap();
            match inodes.get(&ino) {
                Some(node) => {
                    // Saturating decrement via CAS. A plain `fetch_sub` followed
                    // by a clamping `store(0)` is not atomic: a concurrent
                    // `lookup` `fetch_add` could land between the two and be
                    // clobbered by the store, evicting a node the kernel still
                    // references. Folding the clamp into the CAS never loses an
                    // increment, so the write-locked re-check below reliably
                    // sees a live ref and skips eviction.
                    let mut cur = node.lookup_refs.load(Ordering::Relaxed);
                    loop {
                        let new = cur.saturating_sub(count);
                        match node.lookup_refs.compare_exchange_weak(
                            cur,
                            new,
                            Ordering::Relaxed,
                            Ordering::Relaxed,
                        ) {
                            Ok(_) => break new == 0,
                            Err(actual) => cur = actual,
                        }
                    }
                }
                None => false,
            }
        };

        if drop_to_zero {
            let mut inodes = self.inodes.write().unwrap();
            if let Some(node) = inodes.get(&ino)
                && node.lookup_refs.load(Ordering::Relaxed) == 0
            {
                // `remove` drops both the inode and its current path key, so a
                // path that was re-pointed to a different inode (via a rename
                // remap) is left untouched — only this inode's own entry goes.
                inodes.remove(&ino);
            }
        }
    }

    /// Detach the scaffold's record of `path` after the object behind it is
    /// gone (unlink/rmdir) or its name was taken over by a rename.
    fn invalidate_path(&self, path: &[u8]) {
        detach_path(&mut self.inodes.write().unwrap(), path);
    }

    /// Drop cached directory snapshots after a mutation that may change listings.
    ///
    /// Unlike fixed tree backends (memfs/dualfs/passthrough), programmable
    /// providers may change directory contents at any time, so open handles
    /// observe fresh listings after mutations. Only handles whose directory
    /// path is listed in `dirs` are refreshed.
    fn invalidate_dir_listings(&self, dirs: &[Vec<u8>]) {
        if dirs.is_empty() {
            return;
        }
        let targets: HashSet<Vec<u8>> = dirs.iter().cloned().collect();
        for dh in self.dir_handles.read().unwrap().values() {
            let path = dh.node.path.read().unwrap().clone();
            if is_tombstone(&path) || !targets.contains(&path) {
                continue;
            }
            *dh.snapshot.lock().unwrap() = None;
            dh.fuse_cache.lock().unwrap().invalidate();
        }
    }

    /// Parent listings (and any open handles on a renamed subtree) that must
    /// refresh after `rename`.
    fn invalidate_after_rename(&self, from: &[u8], to: &[u8]) {
        let parent_from = parent_path(from);
        let parent_to = parent_path(to);
        for dh in self.dir_handles.read().unwrap().values() {
            let path = dh.node.path.read().unwrap().clone();
            if is_tombstone(&path) {
                continue;
            }
            if path == parent_from || path == parent_to || is_at_or_under(&path, to) {
                *dh.snapshot.lock().unwrap() = None;
                dh.fuse_cache.lock().unwrap().invalidate();
            }
        }
    }

    /// Resolve the guest path for an open file handle, or the appropriate
    /// errno if the handle or path is stale.
    fn file_handle_path(&self, handle: u64) -> io::Result<Vec<u8>> {
        let handles = self.file_handles.read().unwrap();
        let fh = handles.get(&handle).ok_or_else(platform::ebadf)?;
        let live = fh.node.path.read().unwrap().clone();
        if !is_tombstone(&live) {
            return Ok(live);
        }
        Ok(fh.path.clone())
    }

    /// Build a FUSE `Entry` for an interned node from provider attributes.
    fn build_entry(&self, ino: u64, attr: &VAttr) -> Entry {
        Entry {
            inode: ino,
            generation: 0,
            attr: vattr_to_stat(ino, attr),
            attr_flags: 0,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        }
    }

    /// Validate `name` and resolve the absolute path of `parent`'s child named
    /// `name`. Shared by every operation that addresses a named child of a
    /// directory (lookup, create, unlink, ...).
    fn child_path(&self, parent: u64, name: &CStr) -> io::Result<Vec<u8>> {
        name_validation::validate_memfs_name(name)?;
        let path = join(&self.path_of(parent)?, name.to_bytes());
        name_validation::validate_provider_path_bytes(&path)?;
        Ok(path)
    }

    /// Intern a freshly created child `path`, take one FUSE lookup reference,
    /// and build its `Entry`.
    fn intern_entry(&self, path: Vec<u8>, attr: &VAttr) -> Entry {
        let node = self.intern_and_reference(path);
        self.build_entry(node.inode, attr)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: path utilities
//--------------------------------------------------------------------------------------------------

/// View a byte path as a `&Path` (byte-safe on unix).
fn as_path(bytes: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(bytes))
}

/// Join a directory path and a single child name into an absolute path.
///
/// `name` is always a single, already-validated path component: the guest
/// navigates by `lookup(parent_inode, name)` and `validate_name` rejects empty,
/// `..`, and any name containing `/` before it reaches here. So every path built
/// from a known-good parent stays within the mount — a provider never receives a
/// `..` traversal it must defend against, and paths cannot escape the subtree.
fn join(parent: &[u8], name: &[u8]) -> Vec<u8> {
    if parent == b"/" {
        let mut p = Vec::with_capacity(1 + name.len());
        p.push(b'/');
        p.extend_from_slice(name);
        p
    } else {
        let mut p = Vec::with_capacity(parent.len() + 1 + name.len());
        p.extend_from_slice(parent);
        p.push(b'/');
        p.extend_from_slice(name);
        p
    }
}

/// Whether `path` is `base` itself or a descendant of `base`.
fn is_at_or_under(path: &[u8], base: &[u8]) -> bool {
    path == base || (path.len() > base.len() && path.starts_with(base) && path[base.len()] == b'/')
}

/// The parent directory of an absolute path. The parent of `/` is `/`.
fn parent_path(path: &[u8]) -> Vec<u8> {
    match path.iter().rposition(|&b| b == b'/') {
        Some(0) | None => b"/".to_vec(),
        Some(idx) => path[..idx].to_vec(),
    }
}

/// A private inode-table key for a node whose name is gone but which the kernel
/// still references. Guest paths always begin with `/` (every path is built by
/// [`join`] from the `/` root), so a leading NUL can never collide with one.
fn tombstone_key(inode: u64) -> Vec<u8> {
    let mut key = Vec::with_capacity(1 + 8);
    key.push(0);
    key.extend_from_slice(&inode.to_be_bytes());
    key
}

/// Whether `path` is a tombstone key produced by [`tombstone_key`].
fn is_tombstone(path: &[u8]) -> bool {
    path.first() == Some(&0)
}

/// A stable provisional inode for a directory entry that is not yet interned.
///
/// Derived deterministically from the path (64-bit FNV-1a) so repeated listings
/// of an unchanged entry report the same `d_ino`. The top bit is set so a
/// provisional number can never collide with the sequential inodes [`intern`]
/// hands out — those start at [`ROOT_INODE`] + 1 and increment, so they stay
/// well below `2^63` in any realistic run.
///
/// [`intern`]: VirtualFs::intern_and_reference
fn provisional_inode(path: &[u8]) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in path {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash | (1 << 63)
}

/// Like [`provisional_inode`] with extra mixing when two paths collide in one
/// directory listing.
fn provisional_inode_salted(path: &[u8], salt: u64) -> u64 {
    let mut hash = provisional_inode(path) ^ salt;
    hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    hash | (1 << 63)
}

/// Assign a unique `d_ino` for one `readdir` entry within a single listing.
fn unique_dirent_inode(base: u64, path: &[u8], seen: &mut HashSet<u64>) -> u64 {
    if seen.insert(base) {
        return base;
    }
    let mut salt = 1u64;
    loop {
        let ino = provisional_inode_salted(path, salt);
        if seen.insert(ino) {
            return ino;
        }
        salt += 1;
    }
}

/// Detach `path` from the inode table after the object behind it is gone
/// (unlink/rmdir) or its name was taken over by a rename.
///
/// A node the kernel has already forgotten (`lookup_refs == 0`) is removed
/// outright. A node the kernel still references is re-keyed to a private
/// tombstone instead: it keeps its inode so `get_node`/FORGET stay valid until
/// the kernel releases it, but it no longer occupies any guest path, freeing
/// that path for whatever now lives there. Resolving a tombstoned inode to a
/// path is `ESTALE` (see [`VirtualFs::path_of`]).
fn detach_path(inodes: &mut MultikeyBTreeMap<u64, Vec<u8>, Arc<VNode>>, path: &[u8]) {
    let Some(node) = inodes.get_alt(path).cloned() else {
        return;
    };
    if node.lookup_refs.load(Ordering::Relaxed) == 0 {
        inodes.remove_alt(path);
    } else {
        let tombstone = tombstone_key(node.inode);
        *node.path.write().unwrap() = tombstone.clone();
        // `insert` re-keys the inode to the tombstone and drops its old path
        // key in one step.
        inodes.insert(node.inode, tombstone, node);
    }
}

/// Split a `SystemTime` into `(seconds, nanos)`, defaulting `None` to now.
fn time_parts(t: Option<SystemTime>) -> (i64, i64) {
    match t {
        Some(t) => match t.duration_since(UNIX_EPOCH) {
            Ok(d) => (d.as_secs() as i64, d.subsec_nanos() as i64),
            Err(_) => (0, 0),
        },
        None => current_timespec(),
    }
}

/// Current wall-clock time as `(seconds, nanos)`.
fn current_timespec() -> (i64, i64) {
    let mut tp = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    unsafe { libc::clock_gettime(libc::CLOCK_REALTIME, &mut tp) };
    (tp.tv_sec, tp.tv_nsec)
}

/// Build a `stat64` from an inode number and portable attributes.
fn vattr_to_stat(ino: u64, attr: &VAttr) -> stat64 {
    let mut st: stat64 = unsafe { std::mem::zeroed() };

    let mode = attr.kind.type_bits() | (attr.mode & 0o7777);
    let nlink = attr
        .nlink
        .unwrap_or(if attr.kind == NodeKind::Dir { 2 } else { 1 });

    st.st_ino = ino;

    #[cfg(target_os = "linux")]
    {
        st.st_mode = mode as _;
        st.st_nlink = nlink as _;
        st.st_rdev = attr.rdev as _;
    }

    #[cfg(target_os = "macos")]
    {
        st.st_mode = mode as u16;
        st.st_nlink = nlink as u16;
        st.st_rdev = attr.rdev as i32;
    }

    st.st_uid = attr.uid;
    st.st_gid = attr.gid;
    // `size` is u64 but the stat fields are i64. Saturate rather than wrap so a
    // provider reporting a very large (or sentinel) size can't surface a
    // negative st_size/st_blocks. Round blocks up in u64 to avoid the `+ 511`
    // overflow near i64::MAX.
    st.st_size = attr.size.min(i64::MAX as u64) as i64;
    st.st_blksize = 4096;
    st.st_blocks = attr.size.div_ceil(512).min(i64::MAX as u64) as i64;

    let (asec, ansec) = time_parts(attr.atime);
    let (msec, mnsec) = time_parts(attr.mtime);
    let (csec, cnsec) = time_parts(attr.ctime);
    st.st_atime = asec;
    st.st_atime_nsec = ansec;
    st.st_mtime = msec;
    st.st_mtime_nsec = mnsec;
    st.st_ctime = csec;
    st.st_ctime_nsec = cnsec;

    st
}

/// Create a staging file for ZeroCopy I/O data transfer.
fn create_staging_file() -> io::Result<File> {
    #[cfg(target_os = "linux")]
    {
        use std::os::fd::FromRawFd;
        let name = std::ffi::CString::new("virtual-mount-staging").unwrap();
        let fd = unsafe { libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    #[cfg(target_os = "macos")]
    {
        tempfile::tempfile()
    }
}

thread_local! {
    static STAGING_FILE: RefCell<Option<File>> = const { RefCell::new(None) };
}

/// Run a closure against this thread's staging file (one per FUSE worker).
fn with_staging_file<R>(f: impl FnOnce(&File) -> io::Result<R>) -> io::Result<R> {
    STAGING_FILE.with(|slot| {
        let mut file = slot.borrow_mut();
        if file.is_none() {
            *file = Some(create_staging_file()?);
        }
        f(file.as_ref().unwrap())
    })
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<P: PathFs> DynFileSystem for VirtualFs<P> {
    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        let mut opts = FsOptions::empty();
        let wanted = FsOptions::DONT_MASK
            | FsOptions::BIG_WRITES
            | FsOptions::ASYNC_READ
            | FsOptions::PARALLEL_DIROPS
            | FsOptions::MAX_PAGES;
        opts |= capable & wanted;

        if capable.contains(FsOptions::DO_READDIRPLUS) {
            opts |= FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO;
        }

        if self.cfg.writeback && capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
        }

        Ok(opts)
    }

    /// Tear down inode and handle tables. The FUSE session must be quiesced
    /// (no in-flight ops) before this is called; concurrent workers may see
    /// `EBADF`/`ESTALE` if tables are cleared while ops are still running.
    fn destroy(&self) {
        self.file_handles.write().unwrap().clear();
        self.dir_handles.write().unwrap().clear();
        self.inodes.write().unwrap().clear();
    }

    fn lookup(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        name_validation::validate_name(name)?;
        let name_bytes = name.to_bytes();
        if name_bytes == b"." {
            let path = self.path_of(parent)?;
            let attr = self.provider.getattr(as_path(&path))?;
            let node = self.intern_and_reference(path);
            return Ok(self.build_entry(node.inode, &attr));
        }
        let child = self.child_path(parent, name)?;
        let attr = self.provider.getattr(as_path(&child))?;
        Ok(self.intern_entry(child, &attr))
    }

    fn forget(&self, _ctx: Context, ino: u64, count: u64) {
        self.forget_one(ino, count);
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(u64, u64)>) {
        for (ino, count) in requests {
            self.forget_one(ino, count);
        }
    }

    fn getattr(
        &self,
        _ctx: Context,
        ino: u64,
        _handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        let path = self.path_of(ino)?;
        let attr = self.provider.getattr(as_path(&path))?;
        Ok((vattr_to_stat(ino, &attr), self.cfg.attr_timeout))
    }

    fn setattr(
        &self,
        _ctx: Context,
        ino: u64,
        attr: stat64,
        _handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        let path = self.path_of(ino)?;
        // Start from current attributes, overlay the requested fields.
        let mut target = self.provider.getattr(as_path(&path))?;

        if valid.contains(SetattrValid::SIZE) {
            if attr.st_size < 0 {
                return Err(platform::einval());
            }
            target.size = attr.st_size as u64;
        }
        if valid.contains(SetattrValid::MODE) {
            target.mode = (attr.st_mode as u32) & 0o7777;
        }
        if valid.contains(SetattrValid::UID) {
            target.uid = attr.st_uid;
        }
        if valid.contains(SetattrValid::GID) {
            target.gid = attr.st_gid;
        }
        if valid.contains(SetattrValid::ATIME) {
            target.atime = Some(if valid.contains(SetattrValid::ATIME_NOW) {
                SystemTime::now()
            } else {
                systime(attr.st_atime, attr.st_atime_nsec)
            });
        }
        if valid.contains(SetattrValid::MTIME) {
            target.mtime = Some(if valid.contains(SetattrValid::MTIME_NOW) {
                SystemTime::now()
            } else {
                systime(attr.st_mtime, attr.st_mtime_nsec)
            });
        }
        if valid.contains(SetattrValid::CTIME) {
            target.ctime = Some(systime(attr.st_ctime, attr.st_ctime_nsec));
        }

        let result = self.provider.setattr(as_path(&path), &target, valid)?;
        Ok((vattr_to_stat(ino, &result), self.cfg.attr_timeout))
    }

    fn readlink(&self, _ctx: Context, ino: u64) -> io::Result<Vec<u8>> {
        let path = self.path_of(ino)?;
        let target = self.provider.readlink(as_path(&path))?;
        name_validation::validate_symlink_target_bytes(&target)?;
        Ok(target)
    }

    fn symlink(
        &self,
        _ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        let child = self.child_path(parent, name)?;
        name_validation::validate_symlink_target_bytes(linkname.to_bytes())?;
        let attr = self
            .provider
            .symlink(as_path(&child), linkname.to_bytes())?;
        self.invalidate_dir_listings(&[parent_path(&child)]);
        Ok(self.intern_entry(child, &attr))
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        _ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        let child = self.child_path(parent, name)?;
        let Some(kind) = NodeKind::from_mode(mode) else {
            return Err(platform::einval());
        };
        let mut attr = VAttr::new(kind, (mode & 0o7777) & !(umask & 0o7777), 0);
        attr.rdev = rdev;
        let attr = self.provider.create(as_path(&child), &attr)?;
        self.invalidate_dir_listings(&[parent_path(&child)]);
        Ok(self.intern_entry(child, &attr))
    }

    fn mkdir(
        &self,
        _ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        let child = self.child_path(parent, name)?;
        let attr = self
            .provider
            .mkdir(as_path(&child), (mode & 0o7777) & !(umask & 0o7777))?;
        self.invalidate_dir_listings(&[parent_path(&child)]);
        Ok(self.intern_entry(child, &attr))
    }

    fn unlink(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        let child = self.child_path(parent, name)?;
        let attr = self.provider.getattr(as_path(&child))?;
        if attr.kind == NodeKind::Dir {
            return Err(platform::eisdir());
        }
        self.provider.remove(as_path(&child))?;
        self.invalidate_path(&child);
        self.invalidate_dir_listings(&[parent_path(&child)]);
        Ok(())
    }

    fn rmdir(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        let child = self.child_path(parent, name)?;
        self.provider.rmdir(as_path(&child))?;
        // Drop cached listings on the removed directory before tombstoning its
        // path — tombstoned handles are skipped by invalidate_dir_listings.
        self.invalidate_dir_listings(&[child.clone(), parent_path(&child)]);
        self.invalidate_path(&child);
        Ok(())
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        if flags & !KNOWN_RENAME_FLAGS != 0 {
            return Err(platform::einval());
        }
        if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
            return Err(platform::einval());
        }
        if flags & RENAME_EXCHANGE != 0 {
            return Err(platform::enosys());
        }

        name_validation::validate_memfs_name(oldname)?;
        name_validation::validate_memfs_name(newname)?;
        let from = join(&self.path_of(olddir)?, oldname.to_bytes());
        let to = join(&self.path_of(newdir)?, newname.to_bytes());
        name_validation::validate_provider_path_bytes(&from)?;
        name_validation::validate_provider_path_bytes(&to)?;
        if from == to {
            return Ok(());
        }
        if is_at_or_under(&to, &from) {
            return Err(platform::einval());
        }
        self.provider
            .rename_with_flags(as_path(&from), as_path(&to), flags)?;
        let mut inodes = self.inodes.write().unwrap();
        Self::remap_subtree_inodes(&mut inodes, &from, &to);
        drop(inodes);
        self.invalidate_after_rename(&from, &to);
        Ok(())
    }

    fn link(
        &self,
        _ctx: Context,
        _ino: u64,
        _newparent: u64,
        _newname: &CStr,
    ) -> io::Result<Entry> {
        // Hard links cannot be expressed by a path-keyed provider.
        Err(platform::enosys())
    }

    fn open(
        &self,
        _ctx: Context,
        ino: u64,
        _kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        // Consult the provider for the live kind: a programmable backend can
        // turn a path from file to dir (or back), so a cached kind would go
        // stale and produce wrong EISDIR/ENOTDIR decisions.
        let path = self.path_of(ino)?;
        let node = self.get_node(ino)?;
        let mut attr = self.provider.getattr(as_path(&path))?;
        if attr.kind == NodeKind::Dir {
            return Err(platform::eisdir());
        }

        // Honor O_TRUNC by asking the provider to zero the file.
        if flags & GUEST_O_TRUNC != 0 {
            attr.size = 0;
            match self
                .provider
                .setattr(as_path(&path), &attr, SetattrValid::SIZE)
            {
                Ok(_) => {}
                // The provider's error already carries a Linux errno (the wire
                // and guest both speak Linux errno), so compare against the
                // Linux constant — `libc::ENOSYS` is the *host* value and
                // differs on macOS (78 vs 38).
                Err(e) if e.raw_os_error() == Some(platform::LINUX_ENOSYS) => {
                    return Err(platform::eopnotsupp());
                }
                Err(e) => return Err(e),
            }
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.file_handles
            .write()
            .unwrap()
            .insert(handle, Arc::new(VFileHandle { node, path }));
        Ok((Some(handle), self.cache_open_options()))
    }

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        _ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        _kill_priv: bool,
        _flags: u32,
        umask: u32,
        _extensions: Extensions,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        let child = self.child_path(parent, name)?;
        let req = VAttr::file((mode & 0o7777) & !(umask & 0o7777), 0);
        let attr = self.provider.create(as_path(&child), &req)?;
        self.invalidate_dir_listings(&[parent_path(&child)]);
        let node = self.intern_and_reference(child.clone());
        let entry = self.build_entry(node.inode, &attr);

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.file_handles
            .write()
            .unwrap()
            .insert(handle, Arc::new(VFileHandle { node, path: child }));
        Ok((entry, Some(handle), self.cache_open_options()))
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        _ctx: Context,
        _ino: u64,
        handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        let path = self.file_handle_path(handle)?;
        let req_size = size.min(MAX_IO_SIZE);
        let data = self.provider.read(as_path(&path), offset, req_size)?;
        // A provider returning more than requested must not be silently
        // truncated: the kernel would treat the clamped-to-`size` result as a
        // full (non-EOF) read and never re-request the dropped tail, corrupting
        // the file. Reject it instead.
        if data.len() > req_size as usize {
            return Err(platform::eio());
        }
        let count = data.len();
        if count == 0 {
            return Ok(0);
        }

        with_staging_file(|staging| {
            let written = unsafe {
                libc::pwrite(
                    staging.as_raw_fd(),
                    data.as_ptr() as *const libc::c_void,
                    count,
                    0,
                )
            };
            if written < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            let written = written as usize;
            if written == 0 {
                return Ok(0);
            }
            w.write_from(staging, written, 0)
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        _ctx: Context,
        _ino: u64,
        handle: u64,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        let path = self.file_handle_path(handle)?;

        // Drain the guest's data into the staging file, then read it back.
        let buf = with_staging_file(|staging| {
            let count = r.read_to(staging, size as usize, 0)?;
            if count == 0 {
                return Ok(Vec::new());
            }
            let mut buf = vec![0u8; count];
            let read_back = unsafe {
                libc::pread(
                    staging.as_raw_fd(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    count,
                    0,
                )
            };
            if read_back < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            buf.truncate(read_back as usize);
            Ok(buf)
        })?;

        if buf.is_empty() {
            return Ok(0);
        }

        let count = self.provider.write(as_path(&path), offset, &buf)?;
        if count > buf.len() {
            return Err(platform::eio());
        }
        Ok(count)
    }

    fn flush(&self, _ctx: Context, _ino: u64, handle: u64, _lock_owner: u64) -> io::Result<()> {
        let path = self.file_handle_path(handle)?;
        self.provider.flush(as_path(&path))
    }

    fn fsync(&self, _ctx: Context, _ino: u64, datasync: bool, handle: u64) -> io::Result<()> {
        let path = self.file_handle_path(handle)?;
        self.provider.fsync(as_path(&path), datasync)
    }

    fn fallocate(
        &self,
        _ctx: Context,
        ino: u64,
        _handle: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        if mode != 0 {
            return Err(platform::eopnotsupp());
        }
        let path = self.path_of(ino)?;
        let new_end = offset.checked_add(length).ok_or_else(platform::einval)?;
        if new_end > i64::MAX as u64 {
            return Err(platform::efbig());
        }
        let mut target = self.provider.getattr(as_path(&path))?;
        if new_end > target.size {
            target.size = new_end;
            self.provider
                .setattr(as_path(&path), &target, SetattrValid::SIZE)?;
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn release(
        &self,
        _ctx: Context,
        _ino: u64,
        _flags: u32,
        handle: u64,
        flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        if flush {
            let path = self.file_handle_path(handle)?;
            self.provider.flush(as_path(&path))?;
        }
        self.file_handles.write().unwrap().remove(&handle);
        Ok(())
    }

    fn statfs(&self, _ctx: Context, _ino: u64) -> io::Result<statvfs64> {
        self.provider.statfs()
    }

    fn setxattr(
        &self,
        _ctx: Context,
        ino: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        let path = self.path_of(ino)?;
        let name = name.to_bytes();
        name_validation::validate_xattr_name_bytes(name)?;

        // Enforce XATTR_CREATE/REPLACE semantics against the provider's view.
        // Only a genuine ENODATA means "absent"; any other error (EACCES, EIO,
        // …) must propagate rather than be misread as a missing attribute.
        if flags & (XATTR_CREATE | XATTR_REPLACE) != 0 {
            let exists = match self.provider.getxattr(as_path(&path), name) {
                Ok(_) => true,
                // Compare against the Linux errno the provider actually returns;
                // `libc::ENODATA` is the host value (96 on macOS, 61 on Linux).
                Err(e) if e.raw_os_error() == Some(platform::LINUX_ENODATA) => false,
                Err(e) => return Err(e),
            };
            if flags & XATTR_CREATE != 0 && exists {
                return Err(platform::eexist());
            }
            if flags & XATTR_REPLACE != 0 && !exists {
                return Err(platform::enodata());
            }
        }

        self.provider.setxattr(as_path(&path), name, value, flags)
    }

    fn getxattr(
        &self,
        _ctx: Context,
        ino: u64,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        let path = self.path_of(ino)?;
        let name = name.to_bytes();
        name_validation::validate_xattr_name_bytes(name)?;
        let value = self.provider.getxattr(as_path(&path), name)?;
        if size == 0 {
            Ok(GetxattrReply::Count(value.len() as u32))
        } else if value.len() > size as usize {
            Err(platform::erange())
        } else {
            Ok(GetxattrReply::Value(value))
        }
    }

    fn listxattr(&self, _ctx: Context, ino: u64, size: u32) -> io::Result<ListxattrReply> {
        let path = self.path_of(ino)?;
        let names = self.provider.listxattr(as_path(&path))?;

        let mut buf = Vec::new();
        for name in names {
            name_validation::validate_xattr_name_bytes(&name)?;
            buf.extend_from_slice(&name);
            buf.push(0);
        }

        if size == 0 {
            Ok(ListxattrReply::Count(buf.len() as u32))
        } else if buf.len() > size as usize {
            Err(platform::erange())
        } else {
            Ok(ListxattrReply::Names(buf))
        }
    }

    fn removexattr(&self, _ctx: Context, ino: u64, name: &CStr) -> io::Result<()> {
        let path = self.path_of(ino)?;
        let name = name.to_bytes();
        name_validation::validate_xattr_name_bytes(name)?;
        self.provider.removexattr(as_path(&path), name)
    }

    fn opendir(
        &self,
        _ctx: Context,
        ino: u64,
        _flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        // Consult the provider for the live kind (see `open`): the cached kind
        // could be stale for a programmable backend.
        let path = self.path_of(ino)?;
        let node = self.get_node(ino)?;
        if self.provider.getattr(as_path(&path))?.kind != NodeKind::Dir {
            return Err(platform::enotdir());
        }
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.dir_handles.write().unwrap().insert(
            handle,
            Arc::new(VDirHandle {
                node,
                snapshot: Mutex::new(None),
                fuse_cache: Mutex::new(FuseDirCache::new()),
            }),
        );
        Ok((Some(handle), self.cache_dir_options()))
    }

    fn readdir(
        &self,
        _ctx: Context,
        ino: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        self.serve_dir(ino, handle, size, offset)
    }

    fn readdirplus(
        &self,
        _ctx: Context,
        ino: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        let dir_path = self.path_of(ino)?;
        let entries = self.serve_dir(ino, handle, size, offset)?;

        // Fetch every child's attributes in one batched provider call rather
        // than a getattr round-trip per entry. `.`/`..` are synthesized and
        // carry no plus-attrs, so they are excluded from the batch. Large
        // directories are fetched in chunks bounded by MAX_BATCH_PATHS.
        let children: Vec<Vec<u8>> = entries
            .iter()
            .filter(|de| de.name != b"." && de.name != b"..")
            .map(|de| join(&dir_path, de.name))
            .collect();
        let attrs = self.getattr_many_batched(&children)?;
        if attrs.len() != children.len() {
            return Err(platform::eio());
        }

        let mut children = children.into_iter();
        let mut attrs = attrs.into_iter();
        let mut result = Vec::with_capacity(entries.len());
        for de in entries {
            if de.name == b"." || de.name == b".." {
                continue;
            }
            let child = children.next().expect("one child path per non-dot entry");
            let attr = match attrs.next().expect("one attr result per child path") {
                Ok(attr) => attr,
                Err(_) => return Err(platform::eio()),
            };
            // readdirplus *does* take a lookup reference, so intern a real
            // node here and advertise its inode so the readdir cookie and
            // the entry agree.
            let node = self.intern_and_reference(child);
            let entry = self.build_entry(node.inode, &attr);
            let mut de = de;
            de.ino = node.inode;
            result.push((de, entry));
        }
        Ok(result)
    }

    fn fsyncdir(&self, _ctx: Context, ino: u64, _datasync: bool, handle: u64) -> io::Result<()> {
        let dh = self
            .dir_handles
            .read()
            .unwrap()
            .get(&handle)
            .cloned()
            .ok_or_else(platform::ebadf)?;
        if dh.node.inode != ino {
            return Err(platform::ebadf());
        }
        // Refresh the listing so providers that mutate outside scaffold ops
        // (database/API backends) can expose updates via fsyncdir. RPC-backed
        // providers drop their paginated ReadDir cache on this hook.
        let path = self.path_of(ino)?;
        self.provider.fsyncdir(as_path(&path))?;
        *dh.snapshot.lock().unwrap() = None;
        dh.fuse_cache.lock().unwrap().invalidate();
        Ok(())
    }

    fn releasedir(&self, _ctx: Context, _ino: u64, _flags: u32, handle: u64) -> io::Result<()> {
        if let Some(dh) = self.dir_handles.write().unwrap().remove(&handle) {
            dh.fuse_cache.lock().unwrap().clear_on_release();
        }
        Ok(())
    }

    fn access(&self, ctx: Context, ino: u64, mask: u32) -> io::Result<()> {
        // Permission check uses the caller's uid and primary gid only. FUSE does
        // not pass supplementary groups through Context, so group membership
        // beyond the primary gid is not consulted.
        let path = self.path_of(ino)?;
        let attr = self.provider.getattr(as_path(&path))?;

        if mask == platform::ACCESS_F_OK {
            return Ok(());
        }
        let perm = attr.mode & 0o7777;
        if ctx.uid == 0 {
            if mask & platform::ACCESS_X_OK != 0 && perm & 0o111 == 0 {
                return Err(platform::eacces());
            }
            return Ok(());
        }
        let bits = if attr.uid == ctx.uid {
            (perm >> 6) & 0o7
        } else if attr.gid == ctx.gid {
            (perm >> 3) & 0o7
        } else {
            perm & 0o7
        };
        if mask & platform::ACCESS_R_OK != 0 && bits & 0o4 == 0 {
            return Err(platform::eacces());
        }
        if mask & platform::ACCESS_W_OK != 0 && bits & 0o2 == 0 {
            return Err(platform::eacces());
        }
        if mask & platform::ACCESS_X_OK != 0 && bits & 0o1 == 0 {
            return Err(platform::eacces());
        }
        Ok(())
    }

    fn lseek(
        &self,
        _ctx: Context,
        ino: u64,
        _handle: u64,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        let path = self.path_of(ino)?;
        let size = self.provider.getattr(as_path(&path))?.size;
        match whence {
            w if w == libc::SEEK_SET as u32 => Ok(offset),
            w if w == libc::SEEK_END as u32 => {
                let pos = (size as i64)
                    .checked_add(offset as i64)
                    .ok_or_else(platform::einval)?;
                if pos < 0 {
                    return Err(platform::einval());
                }
                Ok(pos as u64)
            }
            SEEK_DATA => {
                if offset >= size {
                    Err(platform::enxio())
                } else {
                    Ok(offset)
                }
            }
            SEEK_HOLE => {
                if offset >= size {
                    Err(platform::enxio())
                } else {
                    Ok(size)
                }
            }
            _ => Err(platform::einval()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: dir + rename helpers
//--------------------------------------------------------------------------------------------------

impl<P: PathFs> VirtualFs<P> {
    /// Build (on first call) and serve a directory handle's entry snapshot.
    fn serve_dir(
        &self,
        ino: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        let dh = self
            .dir_handles
            .read()
            .unwrap()
            .get(&handle)
            .cloned()
            .ok_or_else(platform::ebadf)?;

        let mut snapshot = dh.snapshot.lock().unwrap();
        if snapshot.is_none() {
            if offset > 0 {
                return Err(platform::eagain());
            }
            *snapshot = Some(self.build_snapshot(ino, &dh.node)?);
        }
        dh.fuse_cache
            .lock()
            .unwrap()
            .serve(snapshot.as_ref().unwrap(), offset, size)
    }

    /// Fetch attributes for many paths, chunking at [`rpc::protocol::MAX_BATCH_PATHS`].
    fn getattr_many_batched(&self, paths: &[Vec<u8>]) -> io::Result<Vec<io::Result<VAttr>>> {
        if paths.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::with_capacity(paths.len());
        for chunk in paths.chunks(rpc::protocol::MAX_BATCH_PATHS) {
            let refs: Vec<&Path> = chunk.iter().map(|p| as_path(p)).collect();
            let mut partial = self.provider.getattr_many(&refs)?;
            out.append(&mut partial);
        }
        Ok(out)
    }

    /// Build a point-in-time directory snapshot from the provider.
    fn build_snapshot(&self, ino: u64, node: &VNode) -> io::Result<Vec<VSnapEntry>> {
        let _ = node;
        let dir_path = self.path_of(ino)?;
        let children = self.provider.readdir(as_path(&dir_path))?;

        let parent = parent_path(&dir_path);
        let parent_ino = self.dirent_inode(&parent);

        let mut entries = Vec::with_capacity(children.len() + 2);
        let mut seen_inodes = HashSet::new();
        entries.push(VSnapEntry {
            name: b".".to_vec(),
            inode: unique_dirent_inode(ino, &dir_path, &mut seen_inodes),
            offset: 0,
            file_type: platform::DIRENT_DIR,
        });
        entries.push(VSnapEntry {
            name: b"..".to_vec(),
            inode: unique_dirent_inode(parent_ino, &parent, &mut seen_inodes),
            offset: 0,
            file_type: platform::DIRENT_DIR,
        });

        for child in children {
            // Skip — rather than reject the whole listing for — any entry whose
            // name the scaffold cannot represent (empty, `.`/`..`, contains `/`,
            // or over NAME_MAX). One malformed name from a provider should hide
            // only that entry, not make the entire directory unlistable.
            if name_validation::validate_readdir_name(&child.name).is_err() {
                tracing::debug!(
                    path = ?String::from_utf8_lossy(&dir_path),
                    name = ?String::from_utf8_lossy(&child.name),
                    "vfs: skipping unrepresentable readdir name from provider"
                );
                continue;
            }
            let child_path = join(&dir_path, &child.name);
            let inode = unique_dirent_inode(
                self.dirent_inode(&child_path),
                &child_path,
                &mut seen_inodes,
            );
            entries.push(VSnapEntry {
                name: child.name,
                inode,
                offset: 0,
                file_type: child.kind.dirent_type(),
            });
        }

        for (i, entry) in entries.iter_mut().enumerate() {
            entry.offset = (i + 1) as u64;
        }

        Ok(entries)
    }

    /// The inode number to advertise for a `readdir` entry at `path`.
    ///
    /// Reuses the interned inode when the path is already known so the cookie
    /// stays stable across a later `lookup`; otherwise returns a deterministic
    /// [`provisional_inode`] *without* interning a permanent node. Plain
    /// `readdir` does not take a FUSE lookup reference, so interning here would
    /// create nodes the kernel never `FORGET`s — an unbounded `nodes`/`by_path`
    /// leak. Deriving the provisional number from the path (rather than burning
    /// a fresh `next_inode` each call) keeps an unchanged entry's `d_ino` stable
    /// across repeated listings, which tools like `find`/`tar` rely on; the
    /// authoritative inode is still established on the subsequent `lookup`.
    fn dirent_inode(&self, path: &[u8]) -> u64 {
        match self.inodes.read().unwrap().get_alt(path) {
            Some(node) => node.inode,
            None => provisional_inode(path),
        }
    }

    /// After a provider rename, rewrite the inode↔path map for the moved
    /// subtree so open handles and cached inodes follow the move.
    fn remap_subtree_inodes(
        inodes: &mut MultikeyBTreeMap<u64, Vec<u8>, Arc<VNode>>,
        from: &[u8],
        to: &[u8],
    ) {
        // The rename replaces whatever lived at the destination, so any node
        // interned at or under `to` (but not part of the moved subtree) now
        // names a path that no longer exists — detach it so it doesn't dangle.
        // `detach_path` evicts a forgotten node outright but keeps one the
        // kernel still references resolvable (under a tombstone key) until its
        // FORGET, so the moved node can take the freed path without leaving the
        // kernel pointing at an inode missing from the table.
        let dest_stale: Vec<Vec<u8>> = inodes
            .iter_alt()
            .map(|(path, _)| path)
            .filter(|path| is_at_or_under(path, to) && !is_at_or_under(path, from))
            .cloned()
            .collect();
        for path in dest_stale {
            detach_path(inodes, &path);
        }

        // Collect every interned path at or under `from`.
        let moved: Vec<(Vec<u8>, u64)> = inodes
            .iter_alt()
            .filter(|(path, _)| is_at_or_under(path, from))
            .map(|(path, &ino)| (path.clone(), ino))
            .collect();

        for (old_path, ino) in moved {
            let mut new_path = to.to_vec();
            new_path.extend_from_slice(&old_path[from.len()..]);

            // Re-key the node to its new path: `insert` overwrites the inode's
            // entry and drops the old path key in one step.
            if let Some(node) = inodes.get(&ino).cloned() {
                *node.path.write().unwrap() = new_path.clone();
                inodes.insert(ino, new_path, node);
            }
        }
    }
}

/// Build a `SystemTime` from seconds + nanoseconds since the epoch.
///
/// Uses the same pre-epoch floor convention as the VFS RPC wire codec so guest
/// timestamps round-trip consistently across setattr and provider calls.
fn systime(sec: i64, nsec: i64) -> SystemTime {
    let nsec = nsec.max(0) as u32;
    if sec >= 0 {
        UNIX_EPOCH + Duration::new(sec as u64, nsec)
    } else {
        UNIX_EPOCH - (Duration::new((-sec) as u64, 0) - Duration::new(0, nsec))
    }
}
