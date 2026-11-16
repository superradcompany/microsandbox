//! Extended attribute operations: setxattr, getxattr, listxattr, removexattr.
//!
//! Guest xattr access is limited to user.* attributes, except the reserved
//! user.msb and user.overlay namespaces. This keeps host-controlled metadata
//! namespaces from reaching the backing filesystem through guest requests.
//!
//! The same policy applies in every stat-virtualization mode. That setting
//! controls Microsandbox's own stat overlay, not access to arbitrary host xattrs.
//!
//! ## listxattr sizing
//!
//! The host list is filtered before either reporting its size or comparing it with the
//! guest's output buffer. This avoids leaking host-only names through the count and avoids
//! returning ERANGE just because filtered-out names made the host list larger.

use std::{
    ffi::CStr,
    fs::File,
    io,
    os::fd::{AsRawFd, FromRawFd},
};

#[cfg(target_os = "macos")]
use super::metadata;
use super::{PassthroughFs, inode};
use crate::{Context, GetxattrReply, ListxattrReply, backends::shared::platform};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const USER_XATTR_PREFIX: &[u8] = b"user.";
const INTERNAL_XATTR_NAMESPACE: &[u8] = b"user.msb";
const INTERNAL_XATTR_PREFIX: &[u8] = b"user.msb.";
const OVERLAYFS_XATTR_NAMESPACE: &[u8] = b"user.overlay";
const OVERLAYFS_XATTR_PREFIX: &[u8] = b"user.overlay.";
const MAX_XATTR_LIST_ATTEMPTS: usize = 3;

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
    if fs.is_virtual_init_inode(ino) {
        return Err(platform::eacces());
    }
    if fs.cfg.readonly() {
        return Err(platform::erofs());
    }

    if !guest_xattr_name_allowed(name.to_bytes()) {
        return Err(platform::eacces());
    }

    with_xattr_fd(fs, ino, |fd| {
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
                return Err(platform::linux_error(err));
            }
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
                return Err(platform::linux_error(err));
            }
        }

        Ok(())
    })
}

/// Get an extended attribute.
pub(crate) fn do_getxattr(
    fs: &PassthroughFs,
    _ctx: Context,
    ino: u64,
    name: &CStr,
    size: u32,
) -> io::Result<GetxattrReply> {
    if fs.is_virtual_init_inode(ino) {
        return Err(platform::enodata());
    }

    if !guest_xattr_name_allowed(name.to_bytes()) {
        return Err(platform::eacces());
    }

    with_xattr_fd(fs, ino, |fd| {
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
                return Err(platform::linux_error(err));
            }
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
                return Err(platform::linux_error(err));
            }
            buf.truncate(ret as usize);
            Ok(GetxattrReply::Value(buf))
        }
    })
}

/// List extended attribute names visible to the guest.
pub(crate) fn do_listxattr(
    fs: &PassthroughFs,
    _ctx: Context,
    ino: u64,
    size: u32,
) -> io::Result<ListxattrReply> {
    if fs.is_virtual_init_inode(ino) {
        if size == 0 {
            return Ok(ListxattrReply::Count(0));
        }
        return Ok(ListxattrReply::Names(Vec::new()));
    }

    with_xattr_fd(fs, ino, |fd| {
        let raw_names = list_raw_xattr_names(fd)?;
        let names = filter_xattr_names(&raw_names);

        if size == 0 {
            return Ok(ListxattrReply::Count(names.len() as u32));
        }

        // Host names rejected by the guest policy can make the raw list larger
        // than the guest buffer even when the filtered result fits. Filter first.
        if names.len() > size as usize {
            return Err(platform::erange());
        }

        Ok(ListxattrReply::Names(names))
    })
}

/// Remove an extended attribute.
pub(crate) fn do_removexattr(
    fs: &PassthroughFs,
    _ctx: Context,
    ino: u64,
    name: &CStr,
) -> io::Result<()> {
    if fs.is_virtual_init_inode(ino) {
        return Err(platform::eacces());
    }
    if fs.cfg.readonly() {
        return Err(platform::erofs());
    }

    if !guest_xattr_name_allowed(name.to_bytes()) {
        return Err(platform::eacces());
    }

    with_xattr_fd(fs, ino, |fd| {
        #[cfg(target_os = "linux")]
        {
            let path = format!("/proc/self/fd/{fd}\0");
            let ret =
                unsafe { libc::removexattr(path.as_ptr() as *const libc::c_char, name.as_ptr()) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                return Err(platform::linux_error(err));
            }
        }

        #[cfg(target_os = "macos")]
        {
            let ret = unsafe { libc::fremovexattr(fd, name.as_ptr(), 0) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                return Err(platform::linux_error(err));
            }
        }

        Ok(())
    })
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Whether a host xattr name is visible and mutable from the guest.
fn guest_xattr_name_allowed(name: &[u8]) -> bool {
    name.starts_with(USER_XATTR_PREFIX)
        && name.len() > USER_XATTR_PREFIX.len()
        && name != INTERNAL_XATTR_NAMESPACE
        && !name.starts_with(INTERNAL_XATTR_PREFIX)
        && name != OVERLAYFS_XATTR_NAMESPACE
        && !name.starts_with(OVERLAYFS_XATTR_PREFIX)
}

/// Filter a nul-separated host xattr list to names allowed for guest access.
fn filter_xattr_names(names: &[u8]) -> Vec<u8> {
    let mut result = Vec::with_capacity(names.len());

    for entry in names.split(|&b| b == 0) {
        if guest_xattr_name_allowed(entry) {
            result.extend_from_slice(entry);
            result.push(0);
        }
    }

    result
}

/// Read the complete host list so filtering never depends on a guest buffer size.
fn list_raw_xattr_names(fd: i32) -> io::Result<Vec<u8>> {
    // A concurrent xattr add can invalidate the queried size; bound retries so
    // continuous mutation cannot keep the guest request spinning indefinitely.
    for _ in 0..MAX_XATTR_LIST_ATTEMPTS {
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
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        if raw_size == 0 {
            return Ok(Vec::new());
        }

        let mut names = vec![0u8; raw_size as usize];

        #[cfg(target_os = "linux")]
        let ret = {
            let path = format!("/proc/self/fd/{fd}\0");
            unsafe {
                libc::listxattr(
                    path.as_ptr() as *const libc::c_char,
                    names.as_mut_ptr() as *mut libc::c_char,
                    names.len(),
                )
            }
        };

        #[cfg(target_os = "macos")]
        let ret = unsafe {
            libc::flistxattr(fd, names.as_mut_ptr() as *mut libc::c_char, names.len(), 0)
        };

        if ret < 0 {
            let error = io::Error::last_os_error();
            if error.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            return Err(platform::linux_error(error));
        }

        names.truncate(ret as usize);
        return Ok(names);
    }

    Err(platform::erange())
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

/// Borrow a pinned guest handle when available; otherwise open read-only.
/// Holding the file lock keeps checkpoint handle replacement from closing it.
fn with_xattr_fd<T>(
    fs: &PassthroughFs,
    ino: u64,
    operation: impl FnOnce(i32) -> io::Result<T>,
) -> io::Result<T> {
    let data = fs.handles.read().unwrap().for_inode(ino).cloned();
    if let Some(data) = data {
        let file = data.file.read().unwrap();
        return operation(file.as_raw_fd());
    }

    let file = unsafe { File::from_raw_fd(open_xattr_fd(fs, ino)?) };
    operation(file.as_raw_fd())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_xattr_policy_only_exposes_non_internal_user_names() {
        let names = b"user.notes\0user.\0user.msb\0user.msb.override_stat\0user.overlay\0user.overlay.redirect\0system.posix_acl_access\0security.selinux\0trusted.example\0com.apple.quarantine\0";

        assert_eq!(filter_xattr_names(names), b"user.notes\0");
    }

    #[test]
    fn guest_xattr_policy_rejects_host_namespaces() {
        for name in [
            b"system.posix_acl_access".as_slice(),
            b"system.posix_acl_default".as_slice(),
            b"security.selinux".as_slice(),
            b"security.capability".as_slice(),
            b"trusted.example".as_slice(),
            b"com.apple.quarantine".as_slice(),
            b"user.msb".as_slice(),
            b"user.msb.future".as_slice(),
            b"user.overlay".as_slice(),
            b"user.overlay.redirect".as_slice(),
        ] {
            assert!(!guest_xattr_name_allowed(name), "allowed {name:?}");
        }

        assert!(guest_xattr_name_allowed(b"user.app_metadata"));
    }
}
