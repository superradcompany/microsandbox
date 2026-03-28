//! Removal operations: unlink, rmdir, rename.
//!
//! All operations validate names and protect `init.krun` from deletion/renaming.
//! On Linux, `renameat2` is used for flag support (RENAME_NOREPLACE, RENAME_EXCHANGE).
//! On macOS, `renameatx_np` is used with translated flag values.

use std::{ffi::CStr, io};

use super::{PassthroughFs, inode};
use crate::{
    Context,
    backends::shared::{init_binary, name_validation, platform},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Remove a file.
///
/// On macOS, opens an fd to the file before unlinking so that open handles
/// can still access the data after the directory entry is removed (the
/// `/.vol/<dev>/<ino>` path becomes invalid after unlink).
pub(crate) fn do_unlink(
    fs: &PassthroughFs,
    _ctx: Context,
    parent: u64,
    name: &CStr,
) -> io::Result<()> {
    name_validation::validate_name(name)?;

    // Protect init.krun from deletion.
    if init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    let parent_fd = inode::get_inode_fd(fs, parent)?;

    // On macOS, grab an fd before unlink to keep the file data alive.
    #[cfg(target_os = "macos")]
    let pre_unlink_fd = {
        let fd = unsafe {
            libc::openat(
                parent_fd.raw(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd >= 0 { Some(fd) } else { None }
    };

    let ret = unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), 0) };
    if ret < 0 {
        #[cfg(target_os = "macos")]
        if let Some(fd) = pre_unlink_fd {
            unsafe { libc::close(fd) };
        }
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    // Store the fd in InodeData so open_inode_fd can use it.
    #[cfg(target_os = "macos")]
    if let Some(fd) = pre_unlink_fd {
        // Look up the inode by stat identity from the pre-unlink fd.
        let st = platform::fstat(fd);
        if let Ok(st) = st {
            let alt_key = crate::backends::shared::inode_table::InodeAltKey::new(
                st.st_ino,
                platform::stat_dev(&st),
            );
            let inodes = fs.inodes.read().unwrap();
            if let Some(data) = inodes.get_alt(&alt_key) {
                inode::store_unlinked_fd(data, fd);
            } else {
                // No tracked inode — close the fd.
                unsafe { libc::close(fd) };
            }
        } else {
            unsafe { libc::close(fd) };
        }
    }

    Ok(())
}

/// Remove a directory.
pub(crate) fn do_rmdir(
    fs: &PassthroughFs,
    _ctx: Context,
    parent: u64,
    name: &CStr,
) -> io::Result<()> {
    name_validation::validate_name(name)?;

    if init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    let parent_fd = inode::get_inode_fd(fs, parent)?;
    let ret = unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(())
}

/// Rename a file or directory.
pub(crate) fn do_rename(
    fs: &PassthroughFs,
    _ctx: Context,
    olddir: u64,
    oldname: &CStr,
    newdir: u64,
    newname: &CStr,
    flags: u32,
) -> io::Result<()> {
    name_validation::validate_name(oldname)?;
    name_validation::validate_name(newname)?;

    // Protect init.krun from being renamed or overwritten.
    if init_binary::is_init_name(oldname.to_bytes())
        || init_binary::is_init_name(newname.to_bytes())
    {
        return Err(platform::eacces());
    }

    let old_fd = inode::get_inode_fd(fs, olddir)?;
    let new_fd = inode::get_inode_fd(fs, newdir)?;

    #[cfg(target_os = "linux")]
    {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                old_fd.raw(),
                oldname.as_ptr(),
                new_fd.raw(),
                newname.as_ptr(),
                flags,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if flags == 0 {
            let ret = unsafe {
                libc::renameat(
                    old_fd.raw(),
                    oldname.as_ptr(),
                    new_fd.raw(),
                    newname.as_ptr(),
                )
            };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
        } else {
            // macOS uses renamex_np for RENAME_SWAP and RENAME_EXCL.
            // Map Linux flags to macOS equivalents.
            let mut macos_flags: libc::c_uint = 0;

            // Linux RENAME_NOREPLACE = 1, macOS RENAME_EXCL = 0x00000004
            if flags & 1 != 0 {
                macos_flags |= 0x00000004; // RENAME_EXCL
            }
            // Linux RENAME_EXCHANGE = 2, macOS RENAME_SWAP = 0x00000002
            if flags & 2 != 0 {
                macos_flags |= 0x00000002; // RENAME_SWAP
            }

            let ret = unsafe {
                libc::renameatx_np(
                    old_fd.raw(),
                    oldname.as_ptr(),
                    new_fd.raw(),
                    newname.as_ptr(),
                    macos_flags,
                )
            };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
        }
    }

    Ok(())
}
