//! Stat virtualization via the `user.containers.override_stat` extended attribute.
//!
//! The host process runs unprivileged and cannot `chown`, create device nodes,
//! or set xattrs on symlinks (Linux). All ownership/permissions/type information
//! is stored in a 20-byte binary xattr that [`patched_stat`] applies on top of
//! the real host `stat`.
//!
//! ## Format
//!
//! The xattr stores a fixed-size 20-byte `#[repr(C, packed)]` struct with version byte,
//! uid, gid, mode (including file type bits S_IFMT), and rdev. Reading/writing is a single
//! `memcpy` — no text parsing needed. Unknown version bytes trigger `EIO` (hard fail).
//!
//! ## Linux Symlink Exception
//!
//! Real symlinks on Linux cannot have `user.*` xattrs on most filesystems. `patched_stat`
//! skips the xattr read for real host symlinks (detected via `S_IFLNK` in the unpatched stat).
//! File-backed symlinks (regular files with S_IFLNK in xattr) are handled normally.

use std::{ffi::CStr, io, os::fd::RawFd};

use crate::stat64;

use super::platform;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Xattr key for the override stat, as a null-terminated C string.
pub(crate) const OVERRIDE_XATTR_KEY: &CStr = c"user.containers.override_stat";

/// Current version of the binary override format.
const OVERRIDE_VERSION: u8 = 1;

/// Size of the binary override struct.
const OVERRIDE_SIZE: usize = std::mem::size_of::<OverrideStat>();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Binary layout of the override xattr value (20 bytes).
#[repr(C, packed)]
#[derive(Clone, Copy)]
pub(crate) struct OverrideStat {
    pub version: u8,
    pub _pad: [u8; 3],
    pub uid: u32,
    pub gid: u32,
    pub mode: u32,
    pub rdev: u32,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read the override xattr and patch the given stat with virtualized fields.
///
/// If no override xattr is present, returns the stat unmodified.
/// Returns `EIO` if the xattr is corrupt (wrong version, short read).
pub(crate) fn patched_stat(fd: RawFd, mut st: stat64) -> io::Result<stat64> {
    // Real symlinks on host cannot have user xattrs on Linux.
    #[cfg(target_os = "linux")]
    if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
        return Ok(st);
    }

    match read_override(fd) {
        Ok(Some(ovr)) => {
            st.st_uid = ovr.uid;
            st.st_gid = ovr.gid;

            #[cfg(target_os = "linux")]
            {
                st.st_mode = ovr.mode;
            }
            #[cfg(target_os = "macos")]
            {
                st.st_mode = ovr.mode as u16;
            }

            if ovr.mode & platform::MODE_TYPE_MASK == platform::MODE_BLK
                || ovr.mode & platform::MODE_TYPE_MASK == platform::MODE_CHR
            {
                #[cfg(target_os = "linux")]
                {
                    st.st_rdev = u64::from(ovr.rdev);
                }
                #[cfg(target_os = "macos")]
                {
                    st.st_rdev = ovr.rdev as i32;
                }
            }
            Ok(st)
        }
        Ok(None) => Ok(st), // No override xattr
        Err(e) => Err(e),
    }
}

/// Read the override xattr from a file descriptor.
///
/// Returns `None` if the xattr does not exist (ENODATA/ENOATTR).
/// Returns `Err(EIO)` for corrupt data.
fn read_override(fd: RawFd) -> io::Result<Option<OverrideStat>> {
    let mut buf = [0u8; OVERRIDE_SIZE];

    #[cfg(target_os = "linux")]
    let path = format!("/proc/self/fd/{fd}");

    #[cfg(target_os = "linux")]
    let path_cstr = std::ffi::CString::new(path).map_err(|_| platform::eio())?;

    #[cfg(target_os = "linux")]
    let ret = unsafe {
        libc::getxattr(
            path_cstr.as_ptr(),
            OVERRIDE_XATTR_KEY.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            OVERRIDE_SIZE,
        )
    };

    #[cfg(target_os = "macos")]
    let ret = unsafe {
        libc::fgetxattr(
            fd,
            OVERRIDE_XATTR_KEY.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            OVERRIDE_SIZE,
            0,
            0,
        )
    };

    if ret < 0 {
        let err = io::Error::last_os_error();
        let errno = err.raw_os_error().unwrap_or(0);

        // ENODATA (Linux) or ENOATTR (macOS) means no xattr set.
        #[cfg(target_os = "linux")]
        if errno == libc::ENODATA {
            return Ok(None);
        }
        #[cfg(target_os = "macos")]
        if errno == libc::ENOATTR {
            return Ok(None);
        }

        // EOPNOTSUPP means the filesystem doesn't support xattrs.
        if errno == libc::EOPNOTSUPP {
            return Ok(None);
        }

        return Err(platform::linux_error(err));
    }

    let size = ret as usize;
    if size < OVERRIDE_SIZE {
        return Err(platform::eio());
    }

    // SAFETY: buf is fully initialized and OVERRIDE_SIZE bytes long.
    let ovr: OverrideStat =
        unsafe { std::ptr::read_unaligned(buf.as_ptr() as *const OverrideStat) };

    if ovr.version != OVERRIDE_VERSION {
        return Err(platform::eio());
    }

    Ok(Some(ovr))
}

/// Set the override xattr on a file descriptor.
pub(crate) fn set_override(fd: RawFd, uid: u32, gid: u32, mode: u32, rdev: u32) -> io::Result<()> {
    let ovr = OverrideStat {
        version: OVERRIDE_VERSION,
        _pad: [0; 3],
        uid,
        gid,
        mode,
        rdev,
    };

    let buf = unsafe {
        std::slice::from_raw_parts(&ovr as *const OverrideStat as *const u8, OVERRIDE_SIZE)
    };

    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/self/fd/{fd}");
        let path_cstr = std::ffi::CString::new(path).map_err(|_| platform::eio())?;
        let ret = unsafe {
            libc::setxattr(
                path_cstr.as_ptr(),
                OVERRIDE_XATTR_KEY.as_ptr(),
                buf.as_ptr() as *const libc::c_void,
                OVERRIDE_SIZE,
                0,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let ret = unsafe {
            libc::fsetxattr(
                fd,
                OVERRIDE_XATTR_KEY.as_ptr(),
                buf.as_ptr() as *const libc::c_void,
                OVERRIDE_SIZE,
                0,
                0,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Set the override xattr on a path (for use when we don't have an fd).
pub(crate) fn set_override_at(
    dirfd: RawFd,
    name: &CStr,
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: u32,
) -> io::Result<()> {
    // Open the file to get an fd, then delegate.
    let fd = unsafe {
        libc::openat(
            dirfd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        // For directories, use O_RDONLY | O_DIRECTORY.
        let fd = unsafe {
            libc::openat(
                dirfd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        if fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        let result = set_override(fd, uid, gid, mode, rdev);
        unsafe { libc::close(fd) };
        return result;
    }
    let result = set_override(fd, uid, gid, mode, rdev);
    unsafe { libc::close(fd) };
    result
}

/// Read the current override xattr values from a file descriptor.
///
/// Returns `None` if no override is set.
pub(crate) fn get_override(fd: RawFd) -> io::Result<Option<OverrideStat>> {
    read_override(fd)
}

/// Check if the xattr system is functional by probing the given directory.
///
/// Returns `Ok(true)` if xattrs work, `Ok(false)` if not supported.
pub(crate) fn probe_xattr_support(dirfd: RawFd) -> io::Result<bool> {
    let probe_key = c"user.containers._probe";
    let probe_val: [u8; 1] = [1];

    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/self/fd/{dirfd}");
        let path_cstr = std::ffi::CString::new(path).map_err(|_| platform::eio())?;
        let ret = unsafe {
            libc::setxattr(
                path_cstr.as_ptr(),
                probe_key.as_ptr(),
                probe_val.as_ptr() as *const libc::c_void,
                1,
                0,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(0);
            if errno == libc::EOPNOTSUPP || errno == libc::ENOTSUP {
                return Ok(false);
            }
            return Err(platform::linux_error(err));
        }
        // Clean up the probe xattr.
        unsafe {
            libc::removexattr(path_cstr.as_ptr(), probe_key.as_ptr());
        }
    }

    #[cfg(target_os = "macos")]
    {
        let ret = unsafe {
            libc::fsetxattr(
                dirfd,
                probe_key.as_ptr(),
                probe_val.as_ptr() as *const libc::c_void,
                1,
                0,
                0,
            )
        };
        if ret < 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(0);
            if errno == libc::EOPNOTSUPP || errno == libc::ENOTSUP {
                return Ok(false);
            }
            return Err(platform::linux_error(err));
        }
        // Clean up the probe xattr.
        unsafe {
            libc::fremovexattr(dirfd, probe_key.as_ptr(), 0);
        }
    }

    Ok(true)
}
