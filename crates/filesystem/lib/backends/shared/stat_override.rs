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

use std::{
    ffi::CStr,
    io,
    os::fd::RawFd,
    sync::{Arc, OnceLock},
};

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

/// Maximum length of `/proc/self/fd/{fd}\0` for any non-negative i32 fd.
#[cfg(target_os = "linux")]
const PROC_SELF_FD_PATH_BUF_LEN: usize = 32;

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

/// Guest-visible ownership mapping for host-backed user volume files.
///
/// The map is applied only when stat virtualization is enabled and no
/// per-file override xattr exists. Files owned by the host user running
/// microsandbox appear as the sandbox's effective guest user; files owned by
/// other host users appear as the overflow identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BindIdentityMap {
    /// Host uid that owns ordinary caller-created files.
    pub host_owner_uid: u32,

    /// Guest uid to show for host-owner files.
    pub guest_uid: u32,

    /// Guest gid to show for host-owner files.
    pub guest_gid: u32,

    /// Guest uid to show for files not owned by [`host_owner_uid`](Self::host_owner_uid).
    pub overflow_uid: u32,

    /// Guest gid to show for files not owned by [`host_owner_uid`](Self::host_owner_uid).
    pub overflow_gid: u32,
}

/// Shared bind identity map that can be installed after guest user resolution.
pub type BindIdentityMapHandle = Arc<OnceLock<BindIdentityMap>>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BindIdentityMap {
    /// Create a map from one host owner uid to one guest uid/gid pair.
    pub fn new(host_owner_uid: u32, guest_uid: u32, guest_gid: u32) -> Self {
        Self {
            host_owner_uid,
            guest_uid,
            guest_gid,
            overflow_uid: 65534,
            overflow_gid: 65534,
        }
    }

    /// Apply this map to a stat result in place.
    pub fn apply(&self, st: &mut stat64) {
        if st.st_uid == self.host_owner_uid {
            st.st_uid = self.guest_uid;
            st.st_gid = self.guest_gid;
        } else {
            st.st_uid = self.overflow_uid;
            st.st_gid = self.overflow_gid;
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read the override xattr and patch the given stat with virtualized fields.
///
/// If no override xattr is present, returns the stat unmodified.
/// Returns `EIO` if the xattr is corrupt (wrong version, short read).
pub(crate) fn patched_stat(
    fd: RawFd,
    mut st: stat64,
    xattr_enabled: bool,
    strict: bool,
    bind_identity_map: Option<&BindIdentityMapHandle>,
) -> io::Result<stat64> {
    if !xattr_enabled {
        return Ok(st);
    }

    // Real symlinks on host cannot have user xattrs on Linux.
    #[cfg(target_os = "linux")]
    if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
        apply_bind_identity_map(&mut st, bind_identity_map);
        return Ok(st);
    }

    match read_override(fd, strict) {
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
        Ok(None) => {
            apply_bind_identity_map(&mut st, bind_identity_map);
            Ok(st)
        } // No override xattr
        Err(e) => Err(e),
    }
}

/// Read the override xattr from a file descriptor.
///
/// Returns `None` if the xattr does not exist (ENODATA/ENOATTR).
/// Returns `Err(EIO)` for corrupt data.
fn read_override(fd: RawFd, strict: bool) -> io::Result<Option<OverrideStat>> {
    let mut buf = [0u8; OVERRIDE_SIZE];

    #[cfg(target_os = "linux")]
    let mut path_buf = [0u8; PROC_SELF_FD_PATH_BUF_LEN];

    #[cfg(target_os = "linux")]
    let path = format_proc_self_fd_path(fd, &mut path_buf)?;

    #[cfg(target_os = "linux")]
    let ret = unsafe {
        libc::getxattr(
            path,
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

        // EOPNOTSUPP / ENOTSUP means the filesystem doesn't support xattrs.
        if errno == libc::EOPNOTSUPP || errno == libc::ENOTSUP {
            return handle_unsupported_xattr(strict);
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

fn handle_unsupported_xattr(strict: bool) -> io::Result<Option<OverrideStat>> {
    if strict {
        return Err(platform::eio());
    }

    Ok(None)
}

#[cfg(target_os = "linux")]
fn format_proc_self_fd_path(
    fd: RawFd,
    buf: &mut [u8; PROC_SELF_FD_PATH_BUF_LEN],
) -> io::Result<*const libc::c_char> {
    if fd < 0 {
        return Err(platform::eio());
    }

    let prefix = b"/proc/self/fd/";
    buf[..prefix.len()].copy_from_slice(prefix);

    let mut digits = [0u8; 10];
    let mut value = fd as u32;
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (value % 10) as u8;
        value /= 10;
        if value == 0 {
            break;
        }
    }

    let digits = &digits[start..];
    let end = prefix.len() + digits.len();
    if end + 1 > buf.len() {
        return Err(platform::eio());
    }

    buf[prefix.len()..end].copy_from_slice(digits);
    buf[end] = 0;
    Ok(buf.as_ptr().cast())
}

pub(crate) fn apply_bind_identity_map(
    st: &mut stat64,
    bind_identity_map: Option<&BindIdentityMapHandle>,
) {
    if let Some(map) = bind_identity_map.and_then(|handle| handle.get().copied()) {
        map.apply(st);
    }
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
        let mut path_buf = [0u8; PROC_SELF_FD_PATH_BUF_LEN];
        let path = format_proc_self_fd_path(fd, &mut path_buf)?;
        let ret = unsafe {
            libc::setxattr(
                path,
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
pub(crate) fn get_override(
    fd: RawFd,
    xattr_enabled: bool,
    strict: bool,
) -> io::Result<Option<OverrideStat>> {
    if !xattr_enabled {
        return Ok(None);
    }

    read_override(fd, strict)
}

/// Check if the xattr system is functional by probing the given directory.
///
/// Returns `Ok(true)` if xattrs work, `Ok(false)` if not supported.
pub(crate) fn probe_xattr_support(dirfd: RawFd) -> io::Result<bool> {
    let probe_key = c"user.containers._probe";
    let probe_val: [u8; 1] = [1];

    #[cfg(target_os = "linux")]
    {
        let mut path_buf = [0u8; PROC_SELF_FD_PATH_BUF_LEN];
        let path = format_proc_self_fd_path(dirfd, &mut path_buf)?;
        let ret = unsafe {
            libc::setxattr(
                path,
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
            libc::removexattr(path, probe_key.as_ptr());
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::handle_unsupported_xattr;

    #[test]
    fn test_unsupported_xattr_is_eio_in_strict_mode() {
        let err = match handle_unsupported_xattr(true) {
            Ok(_) => panic!("strict mode must hard-fail on unsupported xattrs"),
            Err(err) => err,
        };
        assert_eq!(err.raw_os_error(), Some(libc::EIO));
    }

    #[test]
    fn test_unsupported_xattr_is_none_in_non_strict_mode() {
        assert!(handle_unsupported_xattr(false).unwrap().is_none());
    }
}
