//! Extended attribute operations: setxattr, getxattr, listxattr, removexattr.
//!
//! The `user.containers.override_stat` xattr is hidden from the guest: get/set/remove
//! return `EACCES`, and it is filtered from listxattr results. This is secure because the
//! FUSE protocol guarantees ALL guest xattr operations go through these handlers — there is
//! no direct path from the guest to the host filesystem.
//!
//! ## Errno Safety
//!
//! All error paths capture `io::Error::last_os_error()` *before* calling `libc::close(fd)`,
//! since `close()` may clobber errno on some systems. The captured error is then returned.
//!
//! ## listxattr size=0
//!
//! When `size=0` (query byte count), the response is computed by doing a full listxattr,
//! filtering out the hidden key, and returning the filtered byte count. Returning the raw
//! kernel count would leak the hidden xattr's existence (the guest could compare the
//! unfiltered count with the filtered list to infer the xattr exists).

use std::{ffi::CStr, io};

use super::{PassthroughFs, inode, metadata};
use crate::{
    Context, GetxattrReply, ListxattrReply,
    backends::shared::{init_binary, platform, stat_override},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Set an extended attribute.
pub(crate) fn do_setxattr(
    fs: &PassthroughFs,
    _ctx: Context,
    ino: u64,
    name: &CStr,
    value: &[u8],
    flags: u32,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    // Block writes to the override xattr.
    if name == stat_override::OVERRIDE_XATTR_KEY {
        return Err(platform::eacces());
    }

    let fd = open_xattr_fd(fs, ino)?;

    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/self/fd/{fd}\0");
        let ret = unsafe {
            libc::setxattr(
                path.as_ptr() as *const libc::c_char,
                name.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                flags as i32,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(platform::linux_error(err));
        }
        unsafe { libc::close(fd) };
    }

    #[cfg(target_os = "macos")]
    {
        let ret = unsafe {
            libc::fsetxattr(
                fd,
                name.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
                flags as i32,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(platform::linux_error(err));
        }
        unsafe { libc::close(fd) };
    }

    Ok(())
}

/// Get an extended attribute.
pub(crate) fn do_getxattr(
    fs: &PassthroughFs,
    _ctx: Context,
    ino: u64,
    name: &CStr,
    size: u32,
) -> io::Result<GetxattrReply> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::enodata());
    }

    // Block reads of the override xattr.
    if name == stat_override::OVERRIDE_XATTR_KEY {
        return Err(platform::eacces());
    }

    let fd = open_xattr_fd(fs, ino)?;

    if size == 0 {
        // Query size.
        #[cfg(target_os = "linux")]
        let ret = {
            let path = format!("/proc/self/fd/{fd}\0");
            unsafe {
                libc::getxattr(
                    path.as_ptr() as *const libc::c_char,
                    name.as_ptr(),
                    std::ptr::null_mut(),
                    0,
                )
            }
        };

        #[cfg(target_os = "macos")]
        let ret = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };

        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(platform::linux_error(err));
        }
        unsafe { libc::close(fd) };
        Ok(GetxattrReply::Count(ret as u32))
    } else {
        let mut buf = vec![0u8; size as usize];

        #[cfg(target_os = "linux")]
        let ret = {
            let path = format!("/proc/self/fd/{fd}\0");
            unsafe {
                libc::getxattr(
                    path.as_ptr() as *const libc::c_char,
                    name.as_ptr(),
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                )
            }
        };

        #[cfg(target_os = "macos")]
        let ret = unsafe {
            libc::fgetxattr(
                fd,
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                0,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(platform::linux_error(err));
        }
        unsafe { libc::close(fd) };
        buf.truncate(ret as usize);
        Ok(GetxattrReply::Value(buf))
    }
}

/// List extended attribute names.
///
/// Filters out the `user.containers.override_stat` key from the returned list.
pub(crate) fn do_listxattr(
    fs: &PassthroughFs,
    _ctx: Context,
    ino: u64,
    size: u32,
) -> io::Result<ListxattrReply> {
    if ino == init_binary::INIT_INODE {
        if size == 0 {
            return Ok(ListxattrReply::Count(0));
        }
        return Ok(ListxattrReply::Names(Vec::new()));
    }

    let fd = open_xattr_fd(fs, ino)?;

    if size == 0 {
        // Do a full listxattr, filter, and return the filtered byte count.
        // Returning the raw kernel count would leak the hidden xattr's existence.
        #[cfg(target_os = "linux")]
        let raw_size = {
            let path = format!("/proc/self/fd/{fd}\0");
            unsafe {
                libc::listxattr(
                    path.as_ptr() as *const libc::c_char,
                    std::ptr::null_mut(),
                    0,
                )
            }
        };

        #[cfg(target_os = "macos")]
        let raw_size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0, 0) };

        if raw_size < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(platform::linux_error(err));
        }

        if raw_size == 0 {
            unsafe { libc::close(fd) };
            return Ok(ListxattrReply::Count(0));
        }

        // Read the full list to compute filtered size.
        let mut buf = vec![0u8; raw_size as usize];

        #[cfg(target_os = "linux")]
        let ret = {
            let path = format!("/proc/self/fd/{fd}\0");
            unsafe {
                libc::listxattr(
                    path.as_ptr() as *const libc::c_char,
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            }
        };

        #[cfg(target_os = "macos")]
        let ret =
            unsafe { libc::flistxattr(fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), 0) };

        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(platform::linux_error(err));
        }
        unsafe { libc::close(fd) };
        buf.truncate(ret as usize);

        let hidden_key = stat_override::OVERRIDE_XATTR_KEY.to_bytes_with_nul();
        let filtered = filter_xattr_names(&buf, hidden_key);
        Ok(ListxattrReply::Count(filtered.len() as u32))
    } else {
        let mut buf = vec![0u8; size as usize];

        #[cfg(target_os = "linux")]
        let ret = {
            let path = format!("/proc/self/fd/{fd}\0");
            unsafe {
                libc::listxattr(
                    path.as_ptr() as *const libc::c_char,
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            }
        };

        #[cfg(target_os = "macos")]
        let ret =
            unsafe { libc::flistxattr(fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), 0) };

        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(platform::linux_error(err));
        }
        unsafe { libc::close(fd) };
        buf.truncate(ret as usize);

        // Filter out the override xattr key from the list.
        let hidden_key = stat_override::OVERRIDE_XATTR_KEY.to_bytes_with_nul();
        let filtered = filter_xattr_names(&buf, hidden_key);

        Ok(ListxattrReply::Names(filtered))
    }
}

/// Remove an extended attribute.
pub(crate) fn do_removexattr(
    fs: &PassthroughFs,
    _ctx: Context,
    ino: u64,
    name: &CStr,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    // Block removal of the override xattr.
    if name == stat_override::OVERRIDE_XATTR_KEY {
        return Err(platform::eacces());
    }

    let fd = open_xattr_fd(fs, ino)?;

    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/self/fd/{fd}\0");
        let ret = unsafe { libc::removexattr(path.as_ptr() as *const libc::c_char, name.as_ptr()) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(platform::linux_error(err));
        }
        unsafe { libc::close(fd) };
    }

    #[cfg(target_os = "macos")]
    {
        let ret = unsafe { libc::fremovexattr(fd, name.as_ptr(), 0) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            unsafe { libc::close(fd) };
            return Err(platform::linux_error(err));
        }
        unsafe { libc::close(fd) };
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Filter a nul-separated xattr name list, removing any entry matching `hidden`.
fn filter_xattr_names(names: &[u8], hidden: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(names.len());

    for entry in names.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        // Compare entry + nul against hidden.
        let mut with_nul = entry.to_vec();
        with_nul.push(0);
        if with_nul != hidden {
            result.extend_from_slice(&with_nul);
        }
    }

    result
}

fn open_xattr_fd(fs: &PassthroughFs, ino: u64) -> io::Result<i32> {
    #[cfg(target_os = "macos")]
    {
        let guest_file_type = platform::mode_file_type(inode::stat_inode(fs, ino)?.st_mode);
        if guest_file_type == platform::MODE_LNK {
            return metadata::open_symlink_inode_fd_macos(fs, ino);
        }
    }

    inode::open_inode_fd(fs, ino, libc::O_RDONLY)
}
