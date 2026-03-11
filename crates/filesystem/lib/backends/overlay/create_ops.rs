//! Creation operations: create, mkdir, mknod, symlink, link.
//!
//! All create-type operations follow: validate name → ensure parent upper →
//! remove existing whiteout → create on upper → set override xattr → do_lookup.
//! On partial failure (xattr set fails after file creation), the backing file is
//! unlinked before returning the error.
//!
//! ## Special File Virtualization
//!
//! `mknod` always creates a regular file on the host. The actual file type is
//! stored in the override xattr.
//!
//! ## Symlinks
//!
//! On Linux, symlinks are file-backed (regular file with S_IFLNK in xattr).
//! On macOS, real symlinks are used with xattr via O_SYMLINK.

use std::ffi::CStr;
use std::io;
use std::os::fd::FromRawFd;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};

use super::OverlayFs;
use super::copy_up;
use super::inode;
use super::types::FileHandle;
use super::whiteout;
use crate::backends::shared::init_binary;
use crate::backends::shared::name_validation;
use crate::backends::shared::platform;
use crate::backends::shared::stat_override;
use crate::{Context, Entry, Extensions, OpenOptions};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create and open a regular file.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_create(
    fs: &OverlayFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    mode: u32,
    kill_priv: bool,
    flags: u32,
    umask: u32,
    _extensions: Extensions,
) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
    name_validation::validate_overlay_name(name)?;

    if init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    // Ensure parent is on upper layer.
    copy_up::ensure_upper(fs, parent)?;

    let upper_parent_fd = copy_up::open_upper_parent_fd(fs, parent)?;
    let _close_parent = scopeguard::guard(upper_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Remove existing whiteout.
    whiteout::remove_whiteout(upper_parent_fd, name.to_bytes())?;

    // Apply umask.
    let file_mode = mode & !umask & 0o7777;

    let mut open_flags = inode::translate_open_flags(flags as i32);
    open_flags |= libc::O_CREAT | libc::O_CLOEXEC | libc::O_NOFOLLOW;

    let fd = unsafe {
        libc::openat(
            upper_parent_fd,
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
        unsafe { libc::unlinkat(upper_parent_fd, name.as_ptr(), 0) };
        return Err(e);
    }

    unsafe { libc::close(fd) };

    let entry = inode::do_lookup(fs, parent, name)?;

    // Reopen for the handle — strip O_CREAT since the file already exists.
    let open_fd = inode::open_node_fd(fs, entry.inode, open_flags & !libc::O_CREAT)?;

    // kill_priv handling.
    if kill_priv && (open_flags & libc::O_TRUNC != 0) {
        if let Ok(Some(ovr)) = stat_override::get_override(open_fd) {
            let new_mode = ovr.mode & !(libc::S_ISUID as u32 | libc::S_ISGID as u32);
            if new_mode != ovr.mode {
                let _ = stat_override::set_override(open_fd, ovr.uid, ovr.gid, new_mode, ovr.rdev);
            }
        }
    }

    let file = unsafe { std::fs::File::from_raw_fd(open_fd) };

    let handle = fs.next_handle.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(FileHandle {
        inode: entry.inode,
        file: RwLock::new(file),
        writable: true,
    });
    fs.file_handles.write().unwrap().insert(handle, data);

    Ok((entry, Some(handle), fs.cache_open_options()))
}

/// Create a directory.
pub(crate) fn do_mkdir(
    fs: &OverlayFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    mode: u32,
    umask: u32,
    _extensions: Extensions,
) -> io::Result<Entry> {
    name_validation::validate_overlay_name(name)?;

    if init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    copy_up::ensure_upper(fs, parent)?;

    let upper_parent_fd = copy_up::open_upper_parent_fd(fs, parent)?;
    let _close_parent = scopeguard::guard(upper_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    whiteout::remove_whiteout(upper_parent_fd, name.to_bytes())?;

    let dir_mode = mode & !umask & 0o7777;

    let ret = unsafe {
        libc::mkdirat(
            upper_parent_fd,
            name.as_ptr(),
            libc::S_IRWXU as libc::mode_t,
        )
    };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    // Set override xattr.
    let full_mode = libc::S_IFDIR as u32 | dir_mode;
    if let Err(e) =
        stat_override::set_override_at(upper_parent_fd, name, ctx.uid, ctx.gid, full_mode, 0)
    {
        unsafe { libc::unlinkat(upper_parent_fd, name.as_ptr(), libc::AT_REMOVEDIR) };
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
    fs: &OverlayFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    mode: u32,
    rdev: u32,
    umask: u32,
    _extensions: Extensions,
) -> io::Result<Entry> {
    name_validation::validate_overlay_name(name)?;

    if init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    copy_up::ensure_upper(fs, parent)?;

    let upper_parent_fd = copy_up::open_upper_parent_fd(fs, parent)?;
    let _close_parent = scopeguard::guard(upper_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    whiteout::remove_whiteout(upper_parent_fd, name.to_bytes())?;

    let perm_mode = mode & !umask & 0o7777;
    let file_type = mode & libc::S_IFMT as u32;

    // Always create a regular file on host.
    let fd = unsafe {
        libc::openat(
            upper_parent_fd,
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
        unsafe { libc::unlinkat(upper_parent_fd, name.as_ptr(), 0) };
        return Err(e);
    }
    unsafe { libc::close(fd) };

    inode::do_lookup(fs, parent, name)
}

/// Create a symbolic link.
///
/// On Linux, creates a file-backed symlink. On macOS, creates a real symlink.
pub(crate) fn do_symlink(
    fs: &OverlayFs,
    ctx: Context,
    linkname: &CStr,
    parent: u64,
    name: &CStr,
    _extensions: Extensions,
) -> io::Result<Entry> {
    name_validation::validate_overlay_name(name)?;

    if init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    copy_up::ensure_upper(fs, parent)?;

    let upper_parent_fd = copy_up::open_upper_parent_fd(fs, parent)?;
    let _close_parent = scopeguard::guard(upper_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    whiteout::remove_whiteout(upper_parent_fd, name.to_bytes())?;

    #[cfg(target_os = "linux")]
    {
        // File-backed symlink: create a regular file with the target as content.
        let fd = unsafe {
            libc::openat(
                upper_parent_fd,
                name.as_ptr(),
                libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
                (libc::S_IRUSR | libc::S_IWUSR) as libc::c_uint,
            )
        };
        if fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }

        let target = linkname.to_bytes();
        let written =
            unsafe { libc::write(fd, target.as_ptr() as *const libc::c_void, target.len()) };
        if written < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            unsafe { libc::unlinkat(upper_parent_fd, name.as_ptr(), 0) };
            return Err(platform::linux_error(err));
        }
        if (written as usize) != target.len() {
            unsafe { libc::close(fd) };
            unsafe { libc::unlinkat(upper_parent_fd, name.as_ptr(), 0) };
            return Err(platform::eio());
        }

        let mode = libc::S_IFLNK as u32 | 0o777;
        if let Err(e) = stat_override::set_override(fd, ctx.uid, ctx.gid, mode, 0) {
            unsafe { libc::close(fd) };
            unsafe { libc::unlinkat(upper_parent_fd, name.as_ptr(), 0) };
            return Err(e);
        }
        unsafe { libc::close(fd) };
    }

    #[cfg(target_os = "macos")]
    {
        let ret = unsafe { libc::symlinkat(linkname.as_ptr(), upper_parent_fd, name.as_ptr()) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }

        let mode = libc::S_IFLNK as u32 | 0o777;
        let fd = unsafe {
            libc::openat(
                upper_parent_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_SYMLINK,
            )
        };
        if fd < 0 {
            unsafe { libc::unlinkat(upper_parent_fd, name.as_ptr(), 0) };
            return Err(platform::linux_error(io::Error::last_os_error()));
        }

        let xattr_result = stat_override::set_override(fd, ctx.uid, ctx.gid, mode, 0);
        unsafe { libc::close(fd) };

        if let Err(err) = xattr_result {
            unsafe { libc::unlinkat(upper_parent_fd, name.as_ptr(), 0) };
            return Err(err);
        }
    }

    inode::do_lookup(fs, parent, name)
}

/// Create a hard link.
///
/// Ensures both source inode and target parent are on the upper layer.
pub(crate) fn do_link(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    newparent: u64,
    newname: &CStr,
) -> io::Result<Entry> {
    name_validation::validate_overlay_name(newname)?;

    if init_binary::is_init_name(newname.to_bytes()) {
        return Err(platform::eacces());
    }

    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    // Ensure source and target parent are on upper.
    copy_up::ensure_upper(fs, ino)?;
    copy_up::ensure_upper(fs, newparent)?;

    let newparent_fd = copy_up::open_upper_parent_fd(fs, newparent)?;
    let _close_parent = scopeguard::guard(newparent_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Remove existing whiteout at target name.
    whiteout::remove_whiteout(newparent_fd, newname.to_bytes())?;

    #[cfg(target_os = "linux")]
    {
        let node = {
            let nodes = fs.nodes.read().unwrap();
            nodes.get(&ino).cloned().ok_or_else(platform::enoent)?
        };
        let state = node.state.read().unwrap();
        if let super::types::NodeState::Upper { file, .. } = &*state {
            let path = format!("/proc/self/fd/{}\0", file.as_raw_fd());
            let ret = unsafe {
                libc::linkat(
                    libc::AT_FDCWD,
                    path.as_ptr() as *const libc::c_char,
                    newparent_fd,
                    newname.as_ptr(),
                    libc::AT_SYMLINK_FOLLOW,
                )
            };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
        } else {
            return Err(platform::einval());
        }
    }

    #[cfg(target_os = "macos")]
    {
        let node = {
            let nodes = fs.nodes.read().unwrap();
            nodes.get(&ino).cloned().ok_or_else(platform::enoent)?
        };
        let state = node.state.read().unwrap();
        if let super::types::NodeState::Upper { ino: node_ino, dev, .. } = &*state {
            let src_path = format!("/.vol/{dev}/{node_ino}\0");
            let ret = unsafe {
                libc::linkat(
                    libc::AT_FDCWD,
                    src_path.as_ptr() as *const libc::c_char,
                    newparent_fd,
                    newname.as_ptr(),
                    0,
                )
            };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
        } else {
            return Err(platform::einval());
        }
    }

    inode::do_lookup(fs, newparent, newname)
}
