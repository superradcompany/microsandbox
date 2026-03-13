//! Proxy filesystem backend.
//!
//! Decorator wrapping any [`DynFileSystem`] with hooks for access control,
//! read/write interception, and path tracking. Non-intercepted operations
//! are delegated transparently to the inner backend.
//!
//! When no hooks are set, ProxyFs adds zero overhead beyond cheap path tracking.
//! When hooks are set, the zero-copy FUSE path is broken and data flows through
//! memory for transformation.

pub(crate) mod adapters;
pub(crate) mod builder;
mod hooks;
mod path_tracking;

use std::{
    collections::HashMap,
    ffi::CStr,
    fs::File,
    io,
    sync::{Mutex, RwLock},
};

use crate::{
    Context, DirEntry, DynFileSystem, Entry, Extensions, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter, stat64, statvfs64,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Proxy filesystem backend.
///
/// Wraps any [`DynFileSystem`] and intercepts specific FUSE operations for
/// user-supplied hooks. All non-intercepted operations are delegated
/// transparently to the inner backend.
#[allow(clippy::type_complexity)]
pub struct ProxyFs {
    /// The wrapped filesystem backend.
    inner: Box<dyn DynFileSystem>,

    /// Access control hook, called before open/create/opendir.
    on_access: Option<Box<dyn Fn(&str, AccessMode) -> Result<(), io::Error> + Send + Sync>>,

    /// Read interception hook, called after inner.read() succeeds.
    on_read: Option<Box<dyn Fn(&str, &[u8]) -> Vec<u8> + Send + Sync>>,

    /// Write interception hook, called before inner.write().
    on_write: Option<Box<dyn Fn(&str, &[u8]) -> Vec<u8> + Send + Sync>>,

    /// Inode-to-path table (relative to mount root).
    paths: RwLock<HashMap<u64, String>>,

    /// Handle-to-path table for O(1) lookup during read/write.
    handle_paths: RwLock<HashMap<u64, String>>,

    /// Staging file for buffered hook interception (created only when hooks need it).
    staging_file: Option<Mutex<File>>,
}

/// Access modes passed to the on_access hook.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessMode {
    /// Read access (e.g. O_RDONLY open, opendir).
    Read,
    /// Write access (e.g. O_WRONLY open, create).
    Write,
    /// Execute access.
    Execute,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProxyFs {
    /// Create a builder for constructing a ProxyFs wrapping the given backend.
    pub fn builder(inner: Box<dyn DynFileSystem>) -> builder::ProxyFsBuilder {
        builder::ProxyFsBuilder::new(inner)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DynFileSystem for ProxyFs {
    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        self.inner.init(capable)
    }

    fn destroy(&self) {
        self.inner.destroy()
    }

    fn lookup(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        let entry = self.inner.lookup(ctx, parent, name)?;
        let path = path_tracking::build_path(self, parent, name);
        path_tracking::register_path(self, entry.inode, path);
        Ok(entry)
    }

    fn forget(&self, ctx: Context, ino: u64, count: u64) {
        self.inner.forget(ctx, ino, count);
        self.paths.write().unwrap().remove(&ino);
    }

    fn batch_forget(&self, ctx: Context, requests: Vec<(u64, u64)>) {
        let inodes: Vec<u64> = requests.iter().map(|&(ino, _)| ino).collect();
        self.inner.batch_forget(ctx, requests);
        let mut paths = self.paths.write().unwrap();
        for ino in inodes {
            paths.remove(&ino);
        }
    }

    fn getattr(
        &self,
        ctx: Context,
        ino: u64,
        handle: Option<u64>,
    ) -> io::Result<(stat64, std::time::Duration)> {
        self.inner.getattr(ctx, ino, handle)
    }

    fn setattr(
        &self,
        ctx: Context,
        ino: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, std::time::Duration)> {
        self.inner.setattr(ctx, ino, attr, handle, valid)
    }

    fn readlink(&self, ctx: Context, ino: u64) -> io::Result<Vec<u8>> {
        self.inner.readlink(ctx, ino)
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        let entry = self
            .inner
            .symlink(ctx, linkname, parent, name, extensions)?;
        let path = path_tracking::build_path(self, parent, name);
        path_tracking::register_path(self, entry.inode, path);
        Ok(entry)
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
        let entry = self
            .inner
            .mknod(ctx, parent, name, mode, rdev, umask, extensions)?;
        let path = path_tracking::build_path(self, parent, name);
        path_tracking::register_path(self, entry.inode, path);
        Ok(entry)
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
        let entry = self
            .inner
            .mkdir(ctx, parent, name, mode, umask, extensions)?;
        let path = path_tracking::build_path(self, parent, name);
        path_tracking::register_path(self, entry.inode, path);
        Ok(entry)
    }

    fn unlink(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.inner.unlink(ctx, parent, name)
    }

    fn rmdir(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.inner.rmdir(ctx, parent, name)
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
        let renamed_inode = path_tracking::resolve_inode(self, olddir, oldname);
        self.inner
            .rename(ctx, olddir, oldname, newdir, newname, flags)?;
        if let Some(ino) = renamed_inode {
            path_tracking::update_paths_after_rename(self, olddir, oldname, newdir, newname, ino);
        }
        Ok(())
    }

    fn link(&self, ctx: Context, ino: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        let entry = self.inner.link(ctx, ino, newparent, newname)?;
        let path = path_tracking::build_path(self, newparent, newname);
        path_tracking::register_path(self, entry.inode, path);
        Ok(entry)
    }

    fn open(
        &self,
        ctx: Context,
        ino: u64,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        hooks::check_access(self, ino, flags)?;
        let (handle, opts) = self.inner.open(ctx, ino, kill_priv, flags)?;
        if let Some(h) = handle {
            path_tracking::register_handle_path(self, ino, h);
        }
        Ok((handle, opts))
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
        let path = path_tracking::build_path(self, parent, name);
        hooks::check_access_by_path(self, &path, AccessMode::Write)?;

        let (entry, handle, opts) = self
            .inner
            .create(ctx, parent, name, mode, kill_priv, flags, umask, extensions)?;

        path_tracking::register_path(self, entry.inode, path.clone());
        if let Some(h) = handle {
            self.handle_paths.write().unwrap().insert(h, path);
        }

        Ok((entry, handle, opts))
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
        if self.on_read.is_none() {
            return self
                .inner
                .read(ctx, ino, handle, w, size, offset, lock_owner, flags);
        }
        hooks::do_intercepted_read(self, ctx, ino, handle, w, size, offset, lock_owner, flags)
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
        if self.on_write.is_none() {
            return self.inner.write(
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
            );
        }
        hooks::do_intercepted_write(
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
        self.inner.flush(ctx, ino, handle, lock_owner)
    }

    fn fsync(&self, ctx: Context, ino: u64, datasync: bool, handle: u64) -> io::Result<()> {
        self.inner.fsync(ctx, ino, datasync, handle)
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
        self.inner.fallocate(ctx, ino, handle, mode, offset, length)
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
        self.inner
            .release(ctx, ino, flags, handle, flush, flock_release, lock_owner)?;
        path_tracking::remove_handle_path(self, handle);
        Ok(())
    }

    fn statfs(&self, ctx: Context, ino: u64) -> io::Result<statvfs64> {
        self.inner.statfs(ctx, ino)
    }

    fn setxattr(
        &self,
        ctx: Context,
        ino: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        self.inner.setxattr(ctx, ino, name, value, flags)
    }

    fn getxattr(
        &self,
        ctx: Context,
        ino: u64,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        self.inner.getxattr(ctx, ino, name, size)
    }

    fn listxattr(&self, ctx: Context, ino: u64, size: u32) -> io::Result<ListxattrReply> {
        self.inner.listxattr(ctx, ino, size)
    }

    fn removexattr(&self, ctx: Context, ino: u64, name: &CStr) -> io::Result<()> {
        self.inner.removexattr(ctx, ino, name)
    }

    fn opendir(
        &self,
        ctx: Context,
        ino: u64,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if let Some(ref on_access) = self.on_access {
            let path = self
                .paths
                .read()
                .unwrap()
                .get(&ino)
                .cloned()
                .unwrap_or_default();
            on_access(&path, AccessMode::Read)?;
        }

        let (handle, opts) = self.inner.opendir(ctx, ino, flags)?;
        if let Some(h) = handle {
            path_tracking::register_handle_path(self, ino, h);
        }
        Ok((handle, opts))
    }

    fn readdir(
        &self,
        ctx: Context,
        ino: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        self.inner.readdir(ctx, ino, handle, size, offset)
    }

    fn readdirplus(
        &self,
        ctx: Context,
        ino: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        self.inner.readdirplus(ctx, ino, handle, size, offset)
    }

    fn fsyncdir(&self, ctx: Context, ino: u64, datasync: bool, handle: u64) -> io::Result<()> {
        self.inner.fsyncdir(ctx, ino, datasync, handle)
    }

    fn releasedir(&self, ctx: Context, ino: u64, flags: u32, handle: u64) -> io::Result<()> {
        self.inner.releasedir(ctx, ino, flags, handle)?;
        path_tracking::remove_handle_path(self, handle);
        Ok(())
    }

    fn access(&self, ctx: Context, ino: u64, mask: u32) -> io::Result<()> {
        self.inner.access(ctx, ino, mask)
    }

    fn lseek(
        &self,
        ctx: Context,
        ino: u64,
        handle: u64,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        self.inner.lseek(ctx, ino, handle, offset, whence)
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use builder::ProxyFsBuilder;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests;
