//! Extended attribute operations: getxattr, listxattr, setxattr, removexattr.
//!
//! ## Internal xattr filtering
//!
//! The overlay uses several internal xattrs for stat virtualization, origin
//! tracking, redirect paths, and tombstones. These are hidden from the guest:
//! - `user.containers.override_stat` — stat virtualization
//! - `user.containers.overlay_origin` — lower-layer origin identity
//! - `user.containers.overlay_redirect` — renamed directory lower path
//! - `user.containers.overlay_tombstones` — overflow whiteout names
//!
//! getxattr/setxattr/removexattr return EACCES for internal keys.
//! listxattr filters them from the returned list.
//!
//! setxattr and removexattr trigger copy-up before modification.

use std::{ffi::CStr, io};

use super::{OverlayFs, copy_up, inode};
use crate::{
    Context, GetxattrReply, ListxattrReply,
    backends::shared::{init_binary, platform, stat_override},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

use super::{
    origin::{ORIGIN_XATTR_KEY, REDIRECT_XATTR_KEY},
    whiteout::TOMBSTONES_XATTR_KEY,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Check if an xattr name is an internal overlay key that should be hidden.
fn is_internal_xattr(name: &CStr) -> bool {
    name == stat_override::OVERRIDE_XATTR_KEY
        || name == ORIGIN_XATTR_KEY
        || name == REDIRECT_XATTR_KEY
        || name == TOMBSTONES_XATTR_KEY
}

/// Check if a raw xattr name matches any internal key.
fn is_internal_xattr_bytes(name: &[u8]) -> bool {
    name == stat_override::OVERRIDE_XATTR_KEY.to_bytes()
        || name == ORIGIN_XATTR_KEY.to_bytes()
        || name == REDIRECT_XATTR_KEY.to_bytes()
        || name == TOMBSTONES_XATTR_KEY.to_bytes()
}

/// Get an extended attribute.
pub(crate) fn do_getxattr(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    name: &CStr,
    size: u32,
) -> io::Result<GetxattrReply> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::enodata());
    }

    // Block reads of internal xattrs.
    if is_internal_xattr(name) {
        return Err(platform::eacces());
    }

    let fd = inode::open_node_fd(fs, ino, libc::O_RDONLY)?;
    let _close = scopeguard::guard(fd, |fd| unsafe {
        libc::close(fd);
    });

    // Build /proc/self/fd path once for all reads (Linux).
    #[cfg(target_os = "linux")]
    let path = format!("/proc/self/fd/{fd}\0");

    if size == 0 {
        // Query size.
        #[cfg(target_os = "linux")]
        let ret = unsafe {
            libc::getxattr(
                path.as_ptr() as *const libc::c_char,
                name.as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };

        #[cfg(target_os = "macos")]
        let ret = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };

        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        Ok(GetxattrReply::Count(ret as u32))
    } else {
        let mut buf = vec![0u8; size as usize];

        #[cfg(target_os = "linux")]
        let ret = unsafe {
            libc::getxattr(
                path.as_ptr() as *const libc::c_char,
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
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
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        buf.truncate(ret as usize);
        Ok(GetxattrReply::Value(buf))
    }
}

/// List extended attribute names, filtering out internal overlay keys.
pub(crate) fn do_listxattr(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    size: u32,
) -> io::Result<ListxattrReply> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::enodata());
    }

    let fd = inode::open_node_fd(fs, ino, libc::O_RDONLY)?;
    let _close = scopeguard::guard(fd, |fd| unsafe {
        libc::close(fd);
    });

    // Build /proc/self/fd path once for all reads (Linux).
    #[cfg(target_os = "linux")]
    let path = format!("/proc/self/fd/{fd}\0");

    if size == 0 {
        // Do a full listxattr, filter, and return the filtered byte count.
        // Returning the raw kernel count would leak internal xattrs' existence.
        // Retry loop: the xattr list may change between sizing and reading (TOCTOU).
        // Bounded to 3 attempts to prevent infinite loops.
        for _ in 0..3 {
            #[cfg(target_os = "linux")]
            let raw_size = unsafe {
                libc::listxattr(
                    path.as_ptr() as *const libc::c_char,
                    std::ptr::null_mut(),
                    0,
                )
            };

            #[cfg(target_os = "macos")]
            let raw_size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0, 0) };

            if raw_size < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }

            if raw_size == 0 {
                return Ok(ListxattrReply::Count(0));
            }

            // Read full list to compute filtered size.
            let mut buf = vec![0u8; raw_size as usize];

            #[cfg(target_os = "linux")]
            let ret = unsafe {
                libc::listxattr(
                    path.as_ptr() as *const libc::c_char,
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            };

            #[cfg(target_os = "macos")]
            let ret = unsafe {
                libc::flistxattr(fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), 0)
            };

            if ret < 0 {
                let err = io::Error::last_os_error();
                // ERANGE means the xattr list grew between sizing and reading — retry.
                if err.raw_os_error() == Some(libc::ERANGE) {
                    continue;
                }
                return Err(platform::linux_error(err));
            }
            buf.truncate(ret as usize);

            let filtered = filter_internal_xattrs(&buf);
            return Ok(ListxattrReply::Count(filtered.len() as u32));
        }

        // Exhausted retries — the xattr list keeps changing.
        Err(platform::eio())
    } else {
        let mut buf = vec![0u8; size as usize];

        #[cfg(target_os = "linux")]
        let ret = unsafe {
            libc::listxattr(
                path.as_ptr() as *const libc::c_char,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };

        #[cfg(target_os = "macos")]
        let ret =
            unsafe { libc::flistxattr(fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), 0) };

        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        buf.truncate(ret as usize);

        let filtered = filter_internal_xattrs(&buf);
        Ok(ListxattrReply::Names(filtered))
    }
}

/// Set an extended attribute.
///
/// Triggers copy-up for lower-layer files before setting the xattr.
pub(crate) fn do_setxattr(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    name: &CStr,
    value: &[u8],
    flags: u32,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }
    if is_internal_xattr(name) {
        return Err(platform::eacces());
    }

    // Copy-up before mutation.
    copy_up::ensure_upper(fs, ino)?;

    let fd = inode::open_node_fd(fs, ino, libc::O_RDONLY)?;
    let _close = scopeguard::guard(fd, |fd| unsafe {
        libc::close(fd);
    });

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
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let mac_flags = translate_xattr_flags(flags);
        let ret = unsafe {
            libc::fsetxattr(
                fd,
                name.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
                mac_flags,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Remove an extended attribute.
///
/// Triggers copy-up for lower-layer files before removing the xattr.
pub(crate) fn do_removexattr(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    name: &CStr,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }
    if is_internal_xattr(name) {
        return Err(platform::eacces());
    }

    // Copy-up before mutation.
    copy_up::ensure_upper(fs, ino)?;

    let fd = inode::open_node_fd(fs, ino, libc::O_RDONLY)?;
    let _close = scopeguard::guard(fd, |fd| unsafe {
        libc::close(fd);
    });

    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/self/fd/{fd}\0");
        let ret = unsafe { libc::removexattr(path.as_ptr() as *const libc::c_char, name.as_ptr()) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let ret = unsafe { libc::fremovexattr(fd, name.as_ptr(), 0) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Translate Linux xattr flags to macOS xattr options.
///
/// Linux: `XATTR_CREATE = 1`, `XATTR_REPLACE = 2`
/// macOS: `XATTR_CREATE = 0x0002`, `XATTR_REPLACE = 0x0004`
///
/// The FUSE guest sends Linux flag values, which must be translated for macOS.
#[cfg(target_os = "macos")]
fn translate_xattr_flags(linux_flags: u32) -> i32 {
    const LINUX_XATTR_CREATE: u32 = 1;
    const LINUX_XATTR_REPLACE: u32 = 2;

    let mut mac_flags: i32 = 0;
    if linux_flags & LINUX_XATTR_CREATE != 0 {
        mac_flags |= libc::XATTR_CREATE;
    }
    if linux_flags & LINUX_XATTR_REPLACE != 0 {
        mac_flags |= libc::XATTR_REPLACE;
    }
    mac_flags
}

/// Filter a NUL-separated xattr name list, removing all internal overlay keys.
fn filter_internal_xattrs(names: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(names.len());

    for entry in names.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }
        if !is_internal_xattr_bytes(entry) {
            result.extend_from_slice(entry);
            result.push(0);
        }
    }

    result
}
