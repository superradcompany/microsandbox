//! Object-safe filesystem trait and adapter for dynamic dispatch.
//!
//! This module provides `DynFileSystem`, an object-safe version of `FileSystem`
//! that uses `u64` directly for `Inode` and `Handle` instead of associated types,
//! and `DynFileSystemAdapter` which bridges `DynFileSystem` back to `FileSystem`.

#[cfg(any(target_os = "macos", target_os = "windows"))]
use crossbeam_channel::Sender;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use utils::worker_message::WorkerMessage;

use std::ffi::CStr;
use std::io;
use std::sync::atomic::AtomicI32;
use std::sync::Arc;
use std::time::Duration;

use super::filesystem::{
    Context, DirEntry, Entry, Extensions, FileSystem, FsOptions, GetxattrReply, ListxattrReply,
    OpenOptions, RemovemappingOne, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use crate::virtio::bindings::{stat64, statvfs64, LINUX_ENOSYS};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Object-safe callback used by dynamic filesystem backends to stream directory
/// entries into the FUSE response buffer.
pub type AddDirEntry<'a> = dyn for<'name> FnMut(DirEntry<'name>) -> io::Result<usize> + 'a;

/// Object-safe callback used by dynamic filesystem backends to stream directory
/// entries with attributes into the FUSE response buffer.
pub type AddDirEntryPlus<'a> =
    dyn for<'name> FnMut(DirEntry<'name>, Entry) -> io::Result<usize> + 'a;

/// Object-safe filesystem trait for dynamic dispatch.
///
/// This trait mirrors the `FileSystem` trait but uses `u64` directly for `Inode`
/// and `Handle` instead of associated types, enabling object safety.
///
/// Most methods have default implementations that return `ENOSYS`, allowing
/// implementations to only override the methods they need.
#[allow(unused_variables)]
pub trait DynFileSystem: Send + Sync {
    /// Initialize the file system.
    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        Ok(FsOptions::empty())
    }

    /// Clean up the file system.
    fn destroy(&self) {}

    /// Look up a directory entry by name and get its attributes.
    fn lookup(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Forget about an inode.
    fn forget(&self, ctx: Context, inode: u64, count: u64) {}

    /// Forget about multiple inodes.
    fn batch_forget(&self, ctx: Context, requests: Vec<(u64, u64)>) {
        for (inode, count) in requests {
            self.forget(ctx, inode, count);
        }
    }

    /// Get attributes for a file / directory.
    fn getattr(
        &self,
        ctx: Context,
        inode: u64,
        handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Set attributes for a file / directory.
    fn setattr(
        &self,
        ctx: Context,
        inode: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Read a symbolic link.
    fn readlink(&self, ctx: Context, inode: u64) -> io::Result<Vec<u8>> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Create a symbolic link.
    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Create a file node.
    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Create a directory.
    fn mkdir(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Remove a file.
    fn unlink(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Remove a directory.
    fn rmdir(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Rename a file / directory.
    fn rename(
        &self,
        ctx: Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Create a hard link.
    fn link(&self, ctx: Context, inode: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Open a file.
    fn open(
        &self,
        ctx: Context,
        inode: u64,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        Ok((None, OpenOptions::empty()))
    }

    /// Create and open a file.
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
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Read data from a file.
    #[allow(clippy::too_many_arguments)]
    fn read(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Write data to a file.
    #[allow(clippy::too_many_arguments)]
    fn write(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<usize> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Flush the contents of a file.
    fn flush(&self, ctx: Context, inode: u64, handle: u64, lock_owner: u64) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Synchronize file contents.
    fn fsync(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Allocate requested space for file data.
    fn fallocate(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Release an open file.
    #[allow(clippy::too_many_arguments)]
    fn release(
        &self,
        ctx: Context,
        inode: u64,
        flags: u32,
        handle: u64,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Get information about the file system.
    fn statfs(&self, ctx: Context, inode: u64) -> io::Result<statvfs64> {
        // Safe because we are zero-initializing a struct with only POD fields.
        let mut st: statvfs64 = unsafe { std::mem::zeroed() };
        st.f_namemax = 255;
        st.f_bsize = 512;
        Ok(st)
    }

    /// Set an extended attribute.
    fn setxattr(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Get an extended attribute.
    fn getxattr(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// List extended attribute names.
    fn listxattr(&self, ctx: Context, inode: u64, size: u32) -> io::Result<ListxattrReply> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Remove an extended attribute.
    fn removexattr(&self, ctx: Context, inode: u64, name: &CStr) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Open a directory for reading.
    fn opendir(
        &self,
        ctx: Context,
        inode: u64,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        Ok((None, OpenOptions::empty()))
    }

    /// Read a directory.
    ///
    /// Returns a vector of directory entries. Unlike the original FileSystem trait
    /// which uses a callback, this returns entries directly for object safety.
    fn readdir(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Read a directory by streaming entries into `add_entry`.
    ///
    /// Backends should prefer overriding this method when entry names are owned
    /// by per-handle snapshots or other non-static storage. The vector-returning
    /// `readdir` method remains as a compatibility fallback for older custom
    /// backends.
    fn readdir_for_each(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut AddDirEntry<'_>,
    ) -> io::Result<()> {
        let entries = self.readdir(ctx, inode, handle, size, offset)?;
        for entry in entries {
            match add_entry(entry) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Read a directory with entry attributes.
    ///
    /// Returns a vector of (DirEntry, Entry) pairs. Unlike the original FileSystem
    /// trait which uses a callback, this returns entries directly for object safety.
    fn readdirplus(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
    ) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Read a directory with attributes by streaming entries into `add_entry`.
    ///
    /// This avoids forcing custom backends to allocate or leak `'static` entry
    /// names. Existing vector-returning implementations continue to work via the
    /// default compatibility bridge.
    fn readdirplus_for_each(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        add_entry: &mut AddDirEntryPlus<'_>,
    ) -> io::Result<()> {
        let entries = self.readdirplus(ctx, inode, handle, size, offset)?;
        for (dir_entry, entry) in entries {
            match add_entry(dir_entry, entry) {
                Ok(0) => break,
                Ok(_) => {}
                Err(e) => return Err(e),
            }
        }
        Ok(())
    }

    /// Synchronize the contents of a directory.
    fn fsyncdir(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Release an open directory.
    fn releasedir(&self, ctx: Context, inode: u64, flags: u32, handle: u64) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Check file access permissions.
    fn access(&self, ctx: Context, inode: u64, mask: u32) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Reposition read/write file offset.
    fn lseek(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Copy a range of data from one file to another.
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
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Setup a mapping for DAX.
    #[allow(clippy::too_many_arguments)]
    fn setupmapping(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        host_shm_base: u64,
        shm_size: u64,
        #[cfg(any(target_os = "macos", target_os = "windows"))] map_sender: &Option<
            Sender<WorkerMessage>,
        >,
    ) -> io::Result<()> {
        // Dynamic backends return guest-facing errors, so keep this in the Linux namespace.
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Remove a DAX mapping.
    fn removemapping(
        &self,
        ctx: Context,
        requests: Vec<RemovemappingOne>,
        host_shm_base: u64,
        shm_size: u64,
        #[cfg(any(target_os = "macos", target_os = "windows"))] map_sender: &Option<
            Sender<WorkerMessage>,
        >,
    ) -> io::Result<()> {
        // `reply_error` serializes this value directly into the Linux FUSE ABI.
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Perform an ioctl on a file.
    #[allow(clippy::too_many_arguments)]
    fn ioctl(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        flags: u32,
        cmd: u32,
        arg: u64,
        in_size: u32,
        out_size: u32,
        exit_code: &Arc<AtomicI32>,
    ) -> io::Result<Vec<u8>> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Get file lock (not yet supported).
    fn getlk(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Set file lock (not yet supported).
    fn setlk(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Set file lock and wait (not yet supported).
    fn setlkw(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Map block index to block number (not yet supported).
    fn bmap(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Poll for events (not yet supported).
    fn poll(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }

    /// Reply to a notification (not yet supported).
    fn notify_reply(&self) -> io::Result<()> {
        Err(io::Error::from_raw_os_error(LINUX_ENOSYS))
    }
}

/// Adapter that implements `FileSystem` by delegating to a `dyn DynFileSystem`.
pub struct DynFileSystemAdapter(Arc<dyn DynFileSystem>);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DynFileSystemAdapter {
    /// Create a new adapter wrapping a `DynFileSystem` trait object.
    pub fn new(inner: Arc<dyn DynFileSystem>) -> Self {
        Self(inner)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FileSystem for DynFileSystemAdapter {
    type Inode = u64;
    type Handle = u64;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        self.0.init(capable)
    }

    fn destroy(&self) {
        self.0.destroy()
    }

    fn lookup(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        self.0.lookup(ctx, parent, name)
    }

    fn forget(&self, ctx: Context, inode: u64, count: u64) {
        self.0.forget(ctx, inode, count)
    }

    fn batch_forget(&self, ctx: Context, requests: Vec<(u64, u64)>) {
        self.0.batch_forget(ctx, requests)
    }

    fn getattr(
        &self,
        ctx: Context,
        inode: u64,
        handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        self.0.getattr(ctx, inode, handle)
    }

    fn setattr(
        &self,
        ctx: Context,
        inode: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        self.0.setattr(ctx, inode, attr, handle, valid)
    }

    fn readlink(&self, ctx: Context, inode: u64) -> io::Result<Vec<u8>> {
        self.0.readlink(ctx, inode)
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.0.symlink(ctx, linkname, parent, name, extensions)
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        extensions: Extensions,
    ) -> io::Result<Entry> {
        self.0
            .mknod(ctx, inode, name, mode, rdev, umask, extensions)
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
        self.0.mkdir(ctx, parent, name, mode, umask, extensions)
    }

    fn unlink(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.0.unlink(ctx, parent, name)
    }

    fn rmdir(&self, ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.0.rmdir(ctx, parent, name)
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
        self.0.rename(ctx, olddir, oldname, newdir, newname, flags)
    }

    fn link(&self, ctx: Context, inode: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        self.0.link(ctx, inode, newparent, newname)
    }

    fn open(
        &self,
        ctx: Context,
        inode: u64,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        self.0.open(ctx, inode, kill_priv, flags)
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
        self.0
            .create(ctx, parent, name, mode, kill_priv, flags, umask, extensions)
    }

    #[allow(clippy::too_many_arguments)]
    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        mut w: W,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        flags: u32,
    ) -> io::Result<usize> {
        self.0
            .read(ctx, inode, handle, &mut w, size, offset, lock_owner, flags)
    }

    #[allow(clippy::too_many_arguments)]
    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        mut r: R,
        size: u32,
        offset: u64,
        lock_owner: Option<u64>,
        delayed_write: bool,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<usize> {
        self.0.write(
            ctx,
            inode,
            handle,
            &mut r,
            size,
            offset,
            lock_owner,
            delayed_write,
            kill_priv,
            flags,
        )
    }

    fn flush(&self, ctx: Context, inode: u64, handle: u64, lock_owner: u64) -> io::Result<()> {
        self.0.flush(ctx, inode, handle, lock_owner)
    }

    fn fsync(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        self.0.fsync(ctx, inode, datasync, handle)
    }

    fn fallocate(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        self.0.fallocate(ctx, inode, handle, mode, offset, length)
    }

    #[allow(clippy::too_many_arguments)]
    fn release(
        &self,
        ctx: Context,
        inode: u64,
        flags: u32,
        handle: u64,
        flush: bool,
        flock_release: bool,
        lock_owner: Option<u64>,
    ) -> io::Result<()> {
        self.0
            .release(ctx, inode, flags, handle, flush, flock_release, lock_owner)
    }

    fn statfs(&self, ctx: Context, inode: u64) -> io::Result<statvfs64> {
        self.0.statfs(ctx, inode)
    }

    fn setxattr(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        value: &[u8],
        flags: u32,
    ) -> io::Result<()> {
        self.0.setxattr(ctx, inode, name, value, flags)
    }

    fn getxattr(
        &self,
        ctx: Context,
        inode: u64,
        name: &CStr,
        size: u32,
    ) -> io::Result<GetxattrReply> {
        self.0.getxattr(ctx, inode, name, size)
    }

    fn listxattr(&self, ctx: Context, inode: u64, size: u32) -> io::Result<ListxattrReply> {
        self.0.listxattr(ctx, inode, size)
    }

    fn removexattr(&self, ctx: Context, inode: u64, name: &CStr) -> io::Result<()> {
        self.0.removexattr(ctx, inode, name)
    }

    fn opendir(
        &self,
        ctx: Context,
        inode: u64,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        self.0.opendir(ctx, inode, flags)
    }

    fn readdir<F>(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        self.0
            .readdir_for_each(ctx, inode, handle, size, offset, &mut add_entry)
    }

    fn readdirplus<F>(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        size: u32,
        offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry, Entry) -> io::Result<usize>,
    {
        self.0
            .readdirplus_for_each(ctx, inode, handle, size, offset, &mut add_entry)
    }

    fn fsyncdir(&self, ctx: Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        self.0.fsyncdir(ctx, inode, datasync, handle)
    }

    fn releasedir(&self, ctx: Context, inode: u64, flags: u32, handle: u64) -> io::Result<()> {
        self.0.releasedir(ctx, inode, flags, handle)
    }

    fn access(&self, ctx: Context, inode: u64, mask: u32) -> io::Result<()> {
        self.0.access(ctx, inode, mask)
    }

    fn lseek(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        offset: u64,
        whence: u32,
    ) -> io::Result<u64> {
        self.0.lseek(ctx, inode, handle, offset, whence)
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
        self.0.copyfilerange(
            ctx, inode_in, handle_in, offset_in, inode_out, handle_out, offset_out, len, flags,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn setupmapping(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        host_shm_base: u64,
        shm_size: u64,
        #[cfg(any(target_os = "macos", target_os = "windows"))] map_sender: &Option<
            Sender<WorkerMessage>,
        >,
    ) -> io::Result<()> {
        self.0.setupmapping(
            ctx,
            inode,
            handle,
            foffset,
            len,
            flags,
            moffset,
            host_shm_base,
            shm_size,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            map_sender,
        )
    }

    fn removemapping(
        &self,
        ctx: Context,
        requests: Vec<RemovemappingOne>,
        host_shm_base: u64,
        shm_size: u64,
        #[cfg(any(target_os = "macos", target_os = "windows"))] map_sender: &Option<
            Sender<WorkerMessage>,
        >,
    ) -> io::Result<()> {
        self.0.removemapping(
            ctx,
            requests,
            host_shm_base,
            shm_size,
            #[cfg(any(target_os = "macos", target_os = "windows"))]
            map_sender,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn ioctl(
        &self,
        ctx: Context,
        inode: u64,
        handle: u64,
        flags: u32,
        cmd: u32,
        arg: u64,
        in_size: u32,
        out_size: u32,
        exit_code: &Arc<AtomicI32>,
    ) -> io::Result<Vec<u8>> {
        self.0.ioctl(
            ctx, inode, handle, flags, cmd, arg, in_size, out_size, exit_code,
        )
    }

    fn getlk(&self) -> io::Result<()> {
        self.0.getlk()
    }

    fn setlk(&self) -> io::Result<()> {
        self.0.setlk()
    }

    fn setlkw(&self) -> io::Result<()> {
        self.0.setlkw()
    }

    fn bmap(&self) -> io::Result<()> {
        self.0.bmap()
    }

    fn poll(&self) -> io::Result<()> {
        self.0.poll()
    }

    fn notify_reply(&self) -> io::Result<()> {
        self.0.notify_reply()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, target_os = "windows"))]
mod tests {
    use super::*;

    struct DefaultFileSystem;
    struct DefaultDynFileSystem;

    impl FileSystem for DefaultFileSystem {
        type Inode = u64;
        type Handle = u64;
    }

    impl DynFileSystem for DefaultDynFileSystem {}

    fn context() -> Context {
        Context {
            uid: 0,
            gid: 0,
            pid: 0,
        }
    }

    fn assert_linux_enosys(error: io::Error) {
        assert_eq!(error.raw_os_error(), Some(LINUX_ENOSYS));
    }

    #[test]
    fn dax_defaults_return_linux_enosys() {
        let map_sender: Option<Sender<WorkerMessage>> = None;

        assert_linux_enosys(
            DefaultFileSystem
                .setupmapping(context(), 0, 0, 0, 0, 0, 0, 0, 0, &map_sender)
                .unwrap_err(),
        );
        assert_linux_enosys(
            DefaultFileSystem
                .removemapping(context(), Vec::new(), 0, 0, &map_sender)
                .unwrap_err(),
        );
        assert_linux_enosys(
            DefaultDynFileSystem
                .setupmapping(context(), 0, 0, 0, 0, 0, 0, 0, 0, &map_sender)
                .unwrap_err(),
        );
        assert_linux_enosys(
            DefaultDynFileSystem
                .removemapping(context(), Vec::new(), 0, 0, &map_sender)
                .unwrap_err(),
        );
    }
}
