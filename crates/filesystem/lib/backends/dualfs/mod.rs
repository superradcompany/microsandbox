//! Two-backend compositional filesystem with programmable dispatch policies.
//!
//! `DualFs` presents a single merged filesystem to the guest through exactly
//! two child `DynFileSystem` backends — a **backend_a** and a **backend_b** —
//! with a programmable dispatch policy and lifecycle hooks.

pub(crate) mod builder;
mod create_ops;
mod dir_ops;
mod file_ops;
/// Lifecycle hooks for observing and influencing dispatch.
pub mod hooks;
mod lookup;
mod materialize;
mod metadata;
/// Built-in dispatch policies.
pub mod policies;
/// Dispatch policy traits and plan types.
pub mod policy;
mod remove_ops;
mod special;
/// Core type definitions.
pub mod types;
mod xattr_ops;

use std::{
    ffi::CStr,
    fs::File,
    io,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use hooks::DualDispatchHook;
use policy::DualDispatchPolicy;
use types::{AtomicBackendId, BackendId, DualState, FileKind, GuestNode, NodeState, ROOT_INODE};

use crate::{
    Context, DirEntry, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter, backends::shared::init_binary,
    stat64, statvfs64,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Name of the hidden staging directory.
const STAGING_DIR_NAME: &str = ".dualfs_staging";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Two-backend compositional filesystem with programmable dispatch policies
/// and lifecycle hooks.
pub struct DualFs {
    /// The backend_a backend.
    backend_a: Box<dyn DynFileSystem>,

    /// The backend_b backend.
    backend_b: Box<dyn DynFileSystem>,

    /// Dispatch policy.
    policy: Arc<dyn DualDispatchPolicy>,

    /// Lifecycle hooks.
    hooks: Vec<Arc<dyn DualDispatchHook>>,

    /// All mutable namespace state.
    state: DualState,

    /// File containing the init binary bytes.
    init_file: File,

    /// Configuration.
    cfg: DualFsConfig,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DualFs {
    /// Create a builder for constructing a DualFs.
    pub fn builder() -> builder::DualFsBuilder {
        builder::DualFsBuilder::new()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DynFileSystem for DualFs {
    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        // Initialize both child backends.
        let ba_supported = self.backend_a.init(capable)?;
        let bb_supported = self.backend_b.init(capable)?;
        let child_support = ba_supported & bb_supported;

        let mut opts = FsOptions::empty();

        let wanted = FsOptions::DONT_MASK
            | FsOptions::BIG_WRITES
            | FsOptions::ASYNC_READ
            | FsOptions::PARALLEL_DIROPS
            | FsOptions::MAX_PAGES
            | FsOptions::HANDLE_KILLPRIV_V2;
        opts |= capable & child_support & wanted;

        if capable.contains(FsOptions::DO_READDIRPLUS)
            && child_support.contains(FsOptions::DO_READDIRPLUS)
        {
            opts |= FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO;
        }

        if self.cfg.writeback
            && capable.contains(FsOptions::WRITEBACK_CACHE)
            && child_support.contains(FsOptions::WRITEBACK_CACHE)
        {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.state.writeback.store(true, Ordering::Relaxed);
        }

        // Create staging directories in both backends.
        let staging_name = std::ffi::CString::new(STAGING_DIR_NAME).unwrap();

        // Get root inodes from both backends.
        let ba_root_entry = self
            .backend_a
            .lookup(
                Context {
                    uid: 0,
                    gid: 0,
                    pid: 0,
                },
                1,
                &staging_name,
            )
            .or_else(|_| {
                self.backend_a.mkdir(
                    Context {
                        uid: 0,
                        gid: 0,
                        pid: 0,
                    },
                    1,
                    &staging_name,
                    0o700,
                    0,
                    Extensions::default(),
                )
            })?;

        let bb_root_entry = self
            .backend_b
            .lookup(
                Context {
                    uid: 0,
                    gid: 0,
                    pid: 0,
                },
                1,
                &staging_name,
            )
            .or_else(|_| {
                self.backend_b.mkdir(
                    Context {
                        uid: 0,
                        gid: 0,
                        pid: 0,
                    },
                    1,
                    &staging_name,
                    0o700,
                    0,
                    Extensions::default(),
                )
            })?;

        // Store staging dir inodes.
        {
            let mut staging_dirs = self.state.staging_dirs.write().unwrap();
            staging_dirs.insert(BackendId::BackendA, ba_root_entry.inode);
            staging_dirs.insert(BackendId::BackendB, bb_root_entry.inode);
        }

        // Register root node: root always has both backends.
        // Backend_a root = 1, backend_b root = 1 (FUSE convention).
        let root_node = Arc::new(GuestNode {
            guest_inode: ROOT_INODE,
            kind: FileKind::Directory,
            lookup_refs: AtomicU64::new(u64::MAX / 2),
            anchor_parent: AtomicU64::new(ROOT_INODE),
            anchor_name: std::sync::RwLock::new(Vec::new()),
            metadata_backend: AtomicBackendId::new(BackendId::BackendA),
            state: std::sync::RwLock::new(NodeState::Root {
                backend_a_root: 1,
                backend_b_root: 1,
            }),
            copy_up_lock: Mutex::new(()),
        });
        self.state
            .nodes
            .write()
            .unwrap()
            .insert(ROOT_INODE, root_node);

        // Register init node.
        let init_node = Arc::new(GuestNode {
            guest_inode: init_binary::INIT_INODE,
            kind: FileKind::RegularFile,
            lookup_refs: AtomicU64::new(u64::MAX / 2),
            anchor_parent: AtomicU64::new(ROOT_INODE),
            anchor_name: std::sync::RwLock::new(init_binary::INIT_FILENAME.to_vec()),
            metadata_backend: AtomicBackendId::new(BackendId::BackendA),
            state: std::sync::RwLock::new(NodeState::Init),
            copy_up_lock: Mutex::new(()),
        });
        self.state
            .nodes
            .write()
            .unwrap()
            .insert(init_binary::INIT_INODE, init_node);

        Ok(opts)
    }

    fn destroy(&self) {
        self.state.file_handles.write().unwrap().clear();
        self.state.dir_handles.write().unwrap().clear();
        self.backend_a.destroy();
        self.backend_b.destroy();
    }

    fn lookup(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        lookup::do_lookup(self, ctx, parent, name)
    }

    fn forget(&self, ctx: Context, ino: u64, count: u64) {
        lookup::do_forget(self, ctx, ino, count);
    }

    fn batch_forget(&self, ctx: Context, requests: Vec<(u64, u64)>) {
        lookup::do_batch_forget(self, ctx, requests);
    }

    fn getattr(
        &self,
        ctx: Context,
        ino: u64,
        handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        metadata::do_getattr(self, ctx, ino, handle)
    }

    fn setattr(
        &self,
        ctx: Context,
        ino: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        metadata::do_setattr(self, ctx, ino, attr, handle, valid)
    }

    fn readlink(&self, ctx: Context, ino: u64) -> io::Result<Vec<u8>> {
        file_ops::do_readlink(self, ctx, ino)
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        create_ops::do_symlink(self, ctx, linkname, parent, name, extensions)
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        create_ops::do_mknod(self, ctx, parent, name, mode, rdev, umask, extensions)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        create_ops::do_mkdir(self, ctx, parent, name, mode, umask, extensions)
    }

    fn unlink(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        remove_ops::do_unlink(self, ctx, parent, name)
    }

    fn rmdir(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        remove_ops::do_rmdir(self, ctx, parent, name)
    }

    fn rename(
        &self,
        ctx: Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        remove_ops::do_rename(self, ctx, olddir, oldname, newdir, newname, flags)
    }

    fn link(&self, ctx: Context, ino: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        create_ops::do_link(self, ctx, ino, newparent, newname)
    }

    fn open(
        &self,
        ctx: Context,
        ino: u64,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        file_ops::do_open(self, ctx, ino, kill_priv, flags)
    }

    #[allow(clippy::too_many_arguments)]
    fn create(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        kill_priv: bool,
        flags: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        create_ops::do_create(
            self, ctx, parent, name, mode, kill_priv, flags, umask, extensions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        ctx: Context,
        ino: u64,
        handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        file_ops::do_read(self, ctx, ino, handle, w, size, offset, lock_owner, flags)
    }

    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        ctx: Context,
        ino: u64,
        handle: u64,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<usize> {
        file_ops::do_write(
            self,
            ctx,
            ino,
            handle,
            r,
            size,
            offset,
            lock_owner,
            delayed_write,
            kill_priv,
            flags,
        )
    }

    fn flush(&self, ctx: Context, ino: u64, handle: u64, lock_owner: u64) -> io::Result<()> {
        file_ops::do_flush(self, ctx, ino, handle, lock_owner)
    }

    fn fsync(&self, ctx: Context, ino: u64, datasync: bool, handle: u64) -> io::Result<()> {
        special::do_fsync(self, ctx, ino, datasync, handle)
    }

    fn fallocate(
        &self,
        ctx: Context,
        ino: u64,
        handle: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        special::do_fallocate(self, ctx, ino, handle, mode, offset, length)
    }

    #[allow(clippy::too_many_arguments)]
    fn release(
        &self,
        ctx: Context,
        ino: u64,
        flags: u32,
        handle: u64,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        file_ops::do_release(
            self,
            ctx,
            ino,
            flags,
            handle,
            flush,
            flock_release,
            lock_owner,
        )
    }

    fn statfs(&self, ctx: Context, ino: u64) -> io::Result<statvfs64> {
        special::do_statfs(self, ctx, ino)
    }

    fn setxattr(
        &self,
        ctx: Context,
        ino: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        xattr_ops::do_setxattr(self, ctx, ino, name, value, flags)
    }

    fn getxattr(
        &self,
        ctx: Context,
        ino: u64,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        xattr_ops::do_getxattr(self, ctx, ino, name, size)
    }

    fn listxattr(&self, ctx: Context, ino: u64, size: u32) -> io::Result<ListxattrReply> {
        xattr_ops::do_listxattr(self, ctx, ino, size)
    }

    fn removexattr(&self, ctx: Context, ino: u64, name: &CStr) -> io::Result<()> {
        xattr_ops::do_removexattr(self, ctx, ino, name)
    }

    fn opendir(
        &self,
        ctx: Context,
        ino: u64,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        dir_ops::do_opendir(self, ctx, ino, flags)
    }

    fn readdir(
        &self,
        ctx: Context,
        ino: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        dir_ops::do_readdir(self, ctx, ino, handle, size, offset)
    }

    fn readdirplus(
        &self,
        ctx: Context,
        ino: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        dir_ops::do_readdirplus(self, ctx, ino, handle, size, offset)
    }

    fn fsyncdir(&self, ctx: Context, ino: u64, datasync: bool, handle: u64) -> io::Result<()> {
        special::do_fsyncdir(self, ctx, ino, datasync, handle)
    }

    fn releasedir(&self, ctx: Context, ino: u64, flags: u32, handle: u64) -> io::Result<()> {
        dir_ops::do_releasedir(self, ctx, ino, flags, handle)
    }

    fn access(&self, ctx: Context, ino: u64, mask: u32) -> io::Result<()> {
        metadata::do_access(self, ctx, ino, mask)
    }

    fn lseek(
        &self,
        ctx: Context,
        ino: u64,
        handle: u64,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        special::do_lseek(self, ctx, ino, handle, offset, whence)
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use policies::{
    BackendAFallbackToBackendBRead, BackendAOnly, MergeReadsBackendAPrecedence,
    ReadBackendBWriteBackendA,
};
pub use types::{CachePolicy, DualFsConfig};

#[cfg(test)]
mod tests;
