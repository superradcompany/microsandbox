//! Layer resolution helpers: whiteout detection, opaque detection, and child opening.
//!
//! These functions operate on individual layer directories and are used by the
//! lookup and readdir algorithms to implement overlay merge semantics.

use std::ffi::CStr;
use std::io;
use std::os::fd::RawFd;

use crate::backends::shared::platform;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Check whether a whiteout exists for the given name in a parent directory.
///
/// Looks for a file named `.wh.<name>` in the parent directory. Returns true
/// if the whiteout file exists, false if it doesn't, and propagates errors
/// other than ENOENT.
pub(crate) fn check_whiteout(parent_fd: RawFd, name: &[u8]) -> io::Result<bool> {
    if name.len() > 251 {
        // Name too long for inline whiteout — check overflow tombstone xattr.
        return super::whiteout::check_overflow_whiteout(parent_fd, name);
    }

    let mut wh_buf = [0u8; 260];
    let wh_name = super::whiteout::build_whiteout_cstr(name, &mut wh_buf);

    match platform::fstatat_nofollow(parent_fd, wh_name) {
        Ok(_) => Ok(true),
        Err(e) if platform::is_enoent(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Check whether a directory is opaque (has `.wh..wh..opq` marker).
pub(crate) fn check_opaque(dir_fd: RawFd) -> io::Result<bool> {
    match platform::fstatat_nofollow(dir_fd, c".wh..wh..opq") {
        Ok(_) => Ok(true),
        Err(e) if platform::is_enoent(&e) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Open a child entry in a layer directory with containment.
///
/// On Linux, uses RESOLVE_BENEATH for kernel-enforced path containment.
/// On macOS, uses O_NOFOLLOW.
#[cfg(target_os = "linux")]
pub(crate) fn open_child_beneath(
    parent_fd: RawFd,
    name: &CStr,
    flags: i32,
    has_openat2: bool,
) -> io::Result<RawFd> {
    let fd = platform::open_beneath(parent_fd, name.as_ptr(), flags, has_openat2);
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(fd)
}

/// Open a child entry in a layer directory with containment.
#[cfg(target_os = "macos")]
pub(crate) fn open_child_beneath(
    parent_fd: RawFd,
    name: &CStr,
    flags: i32,
    _has_openat2: bool,
) -> io::Result<RawFd> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(fd)
}

/// Open a subdirectory within a parent directory fd.
///
/// Returns the fd for the subdirectory, or an error if it doesn't exist or
/// is not a directory.
pub(crate) fn open_subdir(parent_fd: RawFd, name: &CStr) -> io::Result<RawFd> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(fd)
}

/// Read all directory entries from an fd, returning (name, d_type) pairs.
///
/// Used by the readdir merge algorithm to enumerate entries in a single layer.
/// Filters out `.` and `..`.
#[cfg(target_os = "linux")]
pub(crate) fn read_dir_entries_raw(fd: RawFd) -> io::Result<Vec<(Vec<u8>, u32)>> {
    // Seek to beginning.
    let ret = unsafe { libc::lseek64(fd, 0, libc::SEEK_SET) };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    let mut buf = [0u8; 8192];
    let mut entries = Vec::new();

    loop {
        let nread = unsafe { libc::syscall(libc::SYS_getdents64, fd, buf.as_mut_ptr(), buf.len()) };
        if nread < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        if nread == 0 {
            break;
        }

        let mut pos = 0usize;
        while pos < nread as usize {
            let d_reclen = u16::from_ne_bytes(buf[pos + 16..pos + 18].try_into().unwrap());
            let d_type = buf[pos + 18];

            let name_start = pos + 19;
            let name_end = pos + d_reclen as usize;
            let name_slice = &buf[name_start..name_end];
            let name_len = name_slice
                .iter()
                .position(|&b| b == 0)
                .unwrap_or(name_slice.len());
            let name_bytes = &name_slice[..name_len];

            // Filter . and ..
            if name_bytes != b"." && name_bytes != b".." {
                entries.push((name_bytes.to_vec(), d_type as u32));
            }

            pos += d_reclen as usize;
        }
    }

    Ok(entries)
}

/// Read all directory entries from an fd, returning (name, d_type) pairs.
#[cfg(target_os = "macos")]
pub(crate) fn read_dir_entries_raw(fd: RawFd) -> io::Result<Vec<(Vec<u8>, u32)>> {
    let dup_fd = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
    if dup_fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    let dirp = unsafe { libc::fdopendir(dup_fd) };
    if dirp.is_null() {
        unsafe { libc::close(dup_fd) };
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    // Rewind to beginning (seekdir(0) is not guaranteed to reset on macOS).
    unsafe { libc::rewinddir(dirp) };

    let mut entries = Vec::new();

    loop {
        unsafe { *libc::__error() = 0 };
        let ent = unsafe { libc::readdir(dirp) };
        if ent.is_null() {
            let errno = unsafe { *libc::__error() };
            if errno != 0 {
                unsafe { libc::closedir(dirp) };
                return Err(platform::linux_error(io::Error::from_raw_os_error(errno)));
            }
            break;
        }

        let d = unsafe { &*ent };
        let name_len = d.d_namlen as usize;
        let name_bytes =
            unsafe { std::slice::from_raw_parts(d.d_name.as_ptr() as *const u8, name_len) };

        // Filter . and ..
        if name_bytes != b"." && name_bytes != b".." {
            entries.push((name_bytes.to_vec(), d.d_type as u32));
        }
    }

    unsafe { libc::closedir(dirp) };
    Ok(entries)
}
