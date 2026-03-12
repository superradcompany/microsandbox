//! Overlay filesystem backend.
//!
//! Presents multiple read-only lower layers and one writable upper layer as a
//! single merged filesystem via virtio-fs. Whiteout and opaque markers implement
//! deletion semantics; stat virtualization via xattr provides correct uid/gid/mode.
//!
//! Mutation operations trigger copy-up of lower-layer entries to the upper layer
//! before applying changes. Deletions create whiteout markers to mask lower entries.

pub(crate) mod builder;
mod copy_up;
mod create_ops;
mod dir_ops;
mod file_ops;
pub(crate) mod inode;
pub(crate) mod layer;
mod metadata;
mod origin;
mod remove_ops;
mod special;
/// Type definitions for the overlay filesystem.
pub mod types;
mod whiteout;
mod xattr_ops;

use std::collections::BTreeMap;
use std::ffi::CStr;
use std::fs::File;
use std::io;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use origin::LowerOriginId;
use types::{Dentry, DirHandle, FileHandle, Layer, NameTable, OverlayNode, ROOT_INODE};

use crate::backends::shared::inode_table::InodeAltKey;
use crate::backends::shared::init_binary;
use crate::{
    Context, DirEntry, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter, stat64, statvfs64,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Overlay filesystem backend.
///
/// Implements [`DynFileSystem`] by merging multiple read-only lower layers with
/// one writable upper layer, using whiteout markers for deletion and xattr-based
/// stat virtualization for correct permissions.
pub struct OverlayFs {
    /// Read-only lower layers (bottom-to-top order, index 0 = bottommost).
    pub(crate) lowers: Vec<Layer>,

    /// Writable upper layer.
    pub(crate) upper: Layer,

    /// Staging directory fd (same filesystem as upper, for atomic copy-up).
    pub(crate) staging_fd: File,

    /// Inode table: FUSE inode → OverlayNode.
    pub(crate) nodes: RwLock<BTreeMap<u64, Arc<OverlayNode>>>,

    /// Dentry table: (parent_inode, name_id) → Dentry.
    pub(crate) dentries: RwLock<BTreeMap<(u64, types::NameId), Dentry>>,

    /// Upper-layer dedup: host identity → FUSE inode (same entry seen via different names).
    pub(crate) upper_alt_keys: RwLock<BTreeMap<InodeAltKey, u64>>,

    /// Lower-layer hardlink unification: LowerOriginId → FUSE inode.
    pub(crate) lower_origin_keys: RwLock<BTreeMap<LowerOriginId, u64>>,

    /// Origin index: LowerOriginId → upper FUSE inode (for cross-copy-up dedup, Phase 2).
    pub(crate) origin_index: RwLock<BTreeMap<LowerOriginId, u64>>,

    /// Next FUSE inode number to allocate (starts at 3: 1=root, 2=init).
    pub(crate) next_inode: AtomicU64,

    /// Open file handle table.
    pub(crate) file_handles: RwLock<BTreeMap<u64, Arc<FileHandle>>>,

    /// Open directory handle table.
    pub(crate) dir_handles: RwLock<BTreeMap<u64, Arc<DirHandle>>>,

    /// Next handle number to allocate (starts at 1: 0=init handle).
    pub(crate) next_handle: AtomicU64,

    /// Whether writeback caching is negotiated.
    pub(crate) writeback: AtomicBool,

    /// File containing the init binary bytes (memfd on Linux, tmpfile on macOS).
    pub(crate) init_file: File,

    /// Name interning table for path components.
    pub(crate) names: NameTable,

    /// Configuration.
    pub(crate) cfg: OverlayConfig,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OverlayFs {
    /// Create a builder for constructing an OverlayFs.
    pub fn builder() -> builder::OverlayFsBuilder {
        builder::OverlayFsBuilder::new()
    }

    /// Get the `OpenOptions` for file opens based on cache policy.
    pub(crate) fn cache_open_options(&self) -> OpenOptions {
        match self.cfg.cache_policy {
            types::CachePolicy::Never => OpenOptions::DIRECT_IO,
            types::CachePolicy::Auto => OpenOptions::empty(),
            types::CachePolicy::Always => OpenOptions::KEEP_CACHE,
        }
    }

    /// Get the `OpenOptions` for directory opens based on cache policy.
    pub(crate) fn cache_dir_options(&self) -> OpenOptions {
        match self.cfg.cache_policy {
            types::CachePolicy::Never => OpenOptions::DIRECT_IO,
            types::CachePolicy::Auto => OpenOptions::empty(),
            types::CachePolicy::Always => OpenOptions::CACHE_DIR,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DynFileSystem for OverlayFs {
    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        // Register root inode (inode 1).
        inode::register_root_inode(self)?;

        let mut opts = FsOptions::empty();

        let wanted = FsOptions::DONT_MASK
            | FsOptions::BIG_WRITES
            | FsOptions::ASYNC_READ
            | FsOptions::PARALLEL_DIROPS
            | FsOptions::MAX_PAGES
            | FsOptions::HANDLE_KILLPRIV_V2;
        opts |= capable & wanted;

        if capable.contains(FsOptions::DO_READDIRPLUS) {
            opts |= FsOptions::DO_READDIRPLUS | FsOptions::READDIRPLUS_AUTO;
        }

        if self.cfg.writeback && capable.contains(FsOptions::WRITEBACK_CACHE) {
            opts |= FsOptions::WRITEBACK_CACHE;
            self.writeback.store(true, Ordering::Relaxed);
        }

        // Clear umask so the client can set all mode bits.
        unsafe { libc::umask(0o000) };

        Ok(opts)
    }

    fn destroy(&self) {
        self.file_handles.write().unwrap().clear();
        self.dir_handles.write().unwrap().clear();
        self.nodes.write().unwrap().clear();
        self.dentries.write().unwrap().clear();
        self.upper_alt_keys.write().unwrap().clear();
        self.lower_origin_keys.write().unwrap().clear();
        self.origin_index.write().unwrap().clear();
    }

    fn lookup(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        if parent == ROOT_INODE && init_binary::is_init_name(name.to_bytes()) {
            return Ok(init_binary::init_entry(
                self.cfg.entry_timeout,
                self.cfg.attr_timeout,
            ));
        }
        inode::do_lookup(self, parent, name)
    }

    fn forget(&self, _ctx: Context, ino: u64, count: u64) {
        if ino == init_binary::INIT_INODE {
            return;
        }
        inode::forget_one(self, ino, count);
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(u64, u64)>) {
        let removed = {
            let mut nodes = self.nodes.write().unwrap();
            let mut dentries = self.dentries.write().unwrap();
            let mut removed = Vec::new();
            for (ino, count) in requests {
                if ino == init_binary::INIT_INODE {
                    continue;
                }
                if let Some(origin) = inode::forget_one_locked(&mut nodes, &mut dentries, ino, count) {
                    removed.push((ino, origin));
                }
            }
            removed
        };

        if !removed.is_empty() {
            inode::cleanup_dedup_maps_batch(self, &removed);
        }
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

    fn link(
        &self,
        ctx: Context,
        ino: u64,
        newparent: u64,
        newname: &CStr,
    ) -> io::Result<Entry> {
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
        create_ops::do_create(self, ctx, parent, name, mode, kill_priv, flags, umask, extensions)
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
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        file_ops::do_read(self, ctx, ino, handle, w, size, offset)
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
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        file_ops::do_write(self, ctx, ino, handle, r, size, offset, kill_priv)
    }

    fn flush(&self, ctx: Context, ino: u64, handle: u64, _lock_owner: u64) -> io::Result<()> {
        file_ops::do_flush(self, ctx, ino, handle)
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
        _flags: u32,
        handle: u64,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        file_ops::do_release(self, ctx, ino, handle)
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

    #[allow(clippy::too_many_arguments)]
    fn copyfilerange(
        &self,
        ctx: Context,
        inode_in: u64,
        handle_in: u64,
        offset_in: u64,
        inode_out: u64,
        handle_out: u64,
        offset_out: u64,
        len: u64,
        flags: u64,
    ) -> io::Result<usize> {
        special::do_copyfilerange(
            self, ctx, inode_in, handle_in, offset_in, inode_out, handle_out, offset_out, len,
            flags,
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use types::{CachePolicy, OverlayConfig};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests;
