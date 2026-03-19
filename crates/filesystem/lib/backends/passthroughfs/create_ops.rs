//! Creation operations: create, mkdir, mknod, symlink, link.
//!
//! ## Creation Pattern
//!
//! All create-type operations follow: validate name → host syscall → set override xattr →
//! do_lookup. On partial failure (xattr set fails after file creation), the backing file is
//! unlinked before returning the error to avoid dangling files that could be misinterpreted.
//!
//! ## Special File Virtualization
//!
//! `mknod` always creates a regular file on the host regardless of requested type. The actual
//! file type (S_IFBLK, S_IFCHR, S_IFIFO, S_IFSOCK) is stored in the override xattr and
//! reported to the guest via `patched_stat`. The host process lacks `CAP_MKNOD`.
//!
//! ## Symlinks
//!
//! On Linux, symlinks are stored as regular files with the target as content and S_IFLNK in
//! xattr mode (file-backed symlinks), because Linux `user.*` xattrs cannot be set on symlinks.
//! On macOS, real symlinks are used with `XATTR_NOFOLLOW` for xattr operations.

use std::{
    ffi::CStr,
    io,
    os::fd::FromRawFd,
    sync::{Arc, RwLock, atomic::Ordering},
};

use super::{PassthroughFs, inode};
use crate::{
    Context, Entry, Extensions, OpenOptions,
    backends::shared::{
        handle_table::HandleData, init_binary, name_validation, platform, stat_override,
    },
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create and open a regular file.
///
/// The host file is created with `S_IRUSR | S_IWUSR` (0o600) regardless of the
/// requested mode — the guest-visible permissions are stored in the override xattr.
/// This ensures the host process can always read/write the file for I/O operations.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_create(
    fs: &PassthroughFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    mode: u32,
    kill_priv: bool,
    flags: u32,
    umask: u32,
    _extensions: Extensions,
) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
    name_validation::validate_name(name)?;

    if init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    let parent_fd = inode::get_inode_fd(fs, parent)?;

    // Apply umask.
    let file_mode = mode & !umask & 0o7777;

    let mut open_flags = inode::translate_open_flags(flags as i32);
    open_flags |= libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW;

    let fd = unsafe {
        libc::openat(
            parent_fd.raw(),
            name.as_ptr(),
            open_flags,
            (libc::S_IRUSR | libc::S_IWUSR) as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    // Set override xattr with requested permissions.
    let full_mode = libc::S_IFREG as u32 | file_mode;
    if let Err(e) = stat_override::set_override(fd, ctx.uid, ctx.gid, full_mode, 0) {
        unsafe { libc::close(fd) };
        unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), 0) };
        return Err(e);
    }

    // Close the fd we used for xattr, then do a proper lookup.
    unsafe { libc::close(fd) };

    let entry = inode::do_lookup(fs, parent, name)?;

    // Reopen for the handle — strip O_CREAT since the file already exists.
    // open_inode_fd adds O_CLOEXEC itself and rejects real host symlinks.
    let open_fd = inode::open_inode_fd(fs, entry.inode, open_flags & !libc::O_CREAT)?;

    // Clear SUID/SGID on create+truncate of existing file (HANDLE_KILLPRIV_V2).
    if kill_priv
        && (open_flags & libc::O_TRUNC != 0)
        && let Ok(Some(ovr)) = stat_override::get_override(open_fd)
    {
        let new_mode = ovr.mode & !(libc::S_ISUID as u32 | libc::S_ISGID as u32);
        if new_mode != ovr.mode {
            let _ = stat_override::set_override(open_fd, ovr.uid, ovr.gid, new_mode, ovr.rdev);
        }
    }

    let file = unsafe { std::fs::File::from_raw_fd(open_fd) };

    let handle = fs.next_handle.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(HandleData {
        file: RwLock::new(file),
    });
    fs.handles.write().unwrap().insert(handle, data);

    Ok((entry, Some(handle), fs.cache_open_options()))
}

/// Create a directory.
pub(crate) fn do_mkdir(
    fs: &PassthroughFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    mode: u32,
    umask: u32,
    _extensions: Extensions,
) -> io::Result<Entry> {
    name_validation::validate_name(name)?;

    if init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    let parent_fd = inode::get_inode_fd(fs, parent)?;
    let dir_mode = mode & !umask & 0o7777;

    let ret = unsafe {
        libc::mkdirat(
            parent_fd.raw(),
            name.as_ptr(),
            (libc::S_IRWXU) as libc::mode_t,
        )
    };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    // Set override xattr.
    let full_mode = libc::S_IFDIR as u32 | dir_mode;
    if let Err(e) =
        stat_override::set_override_at(parent_fd.raw(), name, ctx.uid, ctx.gid, full_mode, 0)
    {
        unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), libc::AT_REMOVEDIR) };
        return Err(e);
    }

    inode::do_lookup(fs, parent, name)
}

/// Create a file node (regular file, device, fifo, socket).
///
/// On the host, always creates a regular file. The actual file type is stored
/// in the override xattr mode bits.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_mknod(
    fs: &PassthroughFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    mode: u32,
    rdev: u32,
    umask: u32,
    _extensions: Extensions,
) -> io::Result<Entry> {
    name_validation::validate_name(name)?;

    if init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    let parent_fd = inode::get_inode_fd(fs, parent)?;
    let perm_mode = mode & !umask & 0o7777;
    let file_type = mode & libc::S_IFMT as u32;

    // Always create a regular file on host.
    let fd = unsafe {
        libc::openat(
            parent_fd.raw(),
            name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
            (libc::S_IRUSR | libc::S_IWUSR) as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    // Store the requested type and permissions in xattr.
    let full_mode = file_type | perm_mode;
    if let Err(e) = stat_override::set_override(fd, ctx.uid, ctx.gid, full_mode, rdev) {
        unsafe { libc::close(fd) };
        unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), 0) };
        return Err(e);
    }
    unsafe { libc::close(fd) };

    inode::do_lookup(fs, parent, name)
}

/// Create a symbolic link.
///
/// On Linux, creates a file-backed symlink (regular file with target as content
/// and S_IFLNK in xattr mode) because Linux cannot set user xattrs on symlinks.
/// On macOS, creates a real symlink and sets xattr with XATTR_NOFOLLOW.
pub(crate) fn do_symlink(
    fs: &PassthroughFs,
    ctx: Context,
    linkname: &CStr,
    parent: u64,
    name: &CStr,
    _extensions: Extensions,
) -> io::Result<Entry> {
    name_validation::validate_name(name)?;

    if init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    let parent_fd = inode::get_inode_fd(fs, parent)?;

    #[cfg(target_os = "linux")]
    {
        // File-backed symlink: create a regular file with the target as content.
        let fd = unsafe {
            libc::openat(
                parent_fd.raw(),
                name.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
                (libc::S_IRUSR | libc::S_IWUSR) as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }

        // Write the symlink target as file content.
        let target = linkname.to_bytes();
        let written =
            unsafe { libc::write(fd, target.as_ptr() as *const libc::c_void, target.len()) };
        if written < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), 0) };
            return Err(platform::linux_error(err));
        }
        if (written as usize) != target.len() {
            unsafe { libc::close(fd) };
            unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), 0) };
            return Err(platform::eio());
        }

        // Set override xattr with S_IFLNK.
        let mode = libc::S_IFLNK as u32 | 0o777;
        if let Err(e) = stat_override::set_override(fd, ctx.uid, ctx.gid, mode, 0) {
            unsafe { libc::close(fd) };
            unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), 0) };
            return Err(e);
        }
        unsafe { libc::close(fd) };
    }

    #[cfg(target_os = "macos")]
    {
        // Real symlink on macOS.
        let ret = unsafe { libc::symlinkat(linkname.as_ptr(), parent_fd.raw(), name.as_ptr()) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }

        // Set override metadata on the symlink itself by opening it with
        // O_SYMLINK and writing the xattr through that fd.
        let mode = libc::S_IFLNK as u32 | 0o777;
        let fd = unsafe {
            libc::openat(
                parent_fd.raw(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_SYMLINK,
            )
        };
        if fd < 0 {
            unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), 0) };
            return Err(platform::linux_error(io::Error::last_os_error()));
        }

        let xattr_result = stat_override::set_override(fd, ctx.uid, ctx.gid, mode, 0);
        unsafe { libc::close(fd) };

        if let Err(err) = xattr_result {
            unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), 0) };
            return Err(err);
        }
    }

    inode::do_lookup(fs, parent, name)
}

/// Create a hard link.
///
/// On Linux, uses `/proc/self/fd/N` with `AT_SYMLINK_FOLLOW` to link by fd reference.
/// On macOS, uses `/.vol/dev/ino` to reference the source inode by identity.
pub(crate) fn do_link(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    newparent: u64,
    newname: &CStr,
) -> io::Result<Entry> {
    name_validation::validate_name(newname)?;

    if init_binary::is_init_name(newname.to_bytes()) {
        return Err(platform::eacces());
    }

    if inode == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    #[cfg(target_os = "linux")]
    {
        let inode_fd = inode::get_inode_fd(fs, inode)?;
        let newparent_fd = inode::get_inode_fd(fs, newparent)?;

        let path = format!("/proc/self/fd/{}\0", inode_fd.raw());
        let ret = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                path.as_ptr() as *const libc::c_char,
                newparent_fd.raw(),
                newname.as_ptr(),
                libc::AT_SYMLINK_FOLLOW,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let inodes = fs.inodes.read().unwrap();
        let data = inodes.get(&inode).ok_or_else(platform::ebadf)?;
        let src_path = format!("/.vol/{}/{}\0", data.dev, data.ino);
        let newparent_fd = inode::get_inode_fd(fs, newparent)?;

        let ret = unsafe {
            libc::linkat(
                libc::AT_FDCWD,
                src_path.as_ptr() as *const libc::c_char,
                newparent_fd.raw(),
                newname.as_ptr(),
                0,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    inode::do_lookup(fs, newparent, newname)
}

/// Read the target of a symbolic link.
///
/// On Linux, first checks if the inode is a real host symlink (rare — only if symlinks
/// preexist in the exported directory). For file-backed symlinks, verifies the override
/// xattr has S_IFLNK before reading file content. This type guard prevents a guest from
/// reading arbitrary file content via readlink on a regular file.
///
/// On macOS, verifies the inode is actually a symlink via `stat_inode` (which applies
/// xattr patching) before calling readlinkat.
pub(crate) fn do_readlink(fs: &PassthroughFs, _ctx: Context, ino: u64) -> io::Result<Vec<u8>> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::einval());
    }

    #[cfg(target_os = "linux")]
    {
        let inode_fd = inode::get_inode_fd(fs, ino)?;
        let st = platform::fstat(inode_fd.raw())?;

        // Real symlink on host — use readlinkat.
        if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
            let mut buf = vec![0u8; libc::PATH_MAX as usize];
            let path = format!("/proc/self/fd/{}\0", inode_fd.raw());
            let ret = unsafe {
                libc::readlinkat(
                    libc::AT_FDCWD,
                    path.as_ptr() as *const libc::c_char,
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            buf.truncate(ret as usize);
            return Ok(buf);
        }

        // Verify override xattr says S_IFLNK before reading file content.
        // Without this check, a guest could read any regular file's content via readlink.
        match stat_override::get_override(inode_fd.raw())? {
            Some(ovr) if ovr.mode & libc::S_IFMT as u32 == libc::S_IFLNK as u32 => {}
            _ => return Err(platform::einval()),
        }

        // File-backed symlink — read the file content.
        let fd = inode::open_inode_fd(fs, ino, libc::O_RDONLY)?;
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let ret = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        let read_err = (ret < 0).then(io::Error::last_os_error);
        unsafe { libc::close(fd) };
        if ret < 0 {
            return Err(platform::linux_error(
                read_err.unwrap_or_else(io::Error::last_os_error),
            ));
        }
        buf.truncate(ret as usize);
        Ok(buf)
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS we create real symlinks, so verify it's actually a symlink first.
        let st = inode::stat_inode(fs, ino)?;
        if st.st_mode as u32 & libc::S_IFMT as u32 != libc::S_IFLNK as u32 {
            return Err(platform::einval());
        }

        let inodes = fs.inodes.read().unwrap();
        let data = inodes.get(&ino).ok_or_else(platform::ebadf)?;
        let path = format!("/.vol/{}/{}\0", data.dev, data.ino);

        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let ret = unsafe {
            libc::readlinkat(
                libc::AT_FDCWD,
                path.as_ptr() as *const libc::c_char,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        buf.truncate(ret as usize);
        Ok(buf)
    }
}
