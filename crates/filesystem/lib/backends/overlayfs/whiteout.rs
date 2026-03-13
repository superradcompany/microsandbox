//! Whiteout creation and removal.
//!
//! Whiteouts are marker files (`.wh.<name>`) on the upper layer that mask
//! entries from lower layers. When an entry is deleted from the overlay,
//! the upper entry (if any) is removed and a whiteout is created if the
//! name exists on any lower layer.
//!
//! ## Overflow whiteouts
//!
//! Names longer than 251 bytes cannot use the inline `.wh.<name>` format
//! because the resulting filename would exceed `NAME_MAX` (255). Instead,
//! these names are stored in the `user.containers.overlay_tombstones` xattr
//! on the parent directory as a length-prefixed binary blob.

use std::{ffi::CStr, io, os::fd::RawFd};

use super::{OverlayFs, inode, layer};
use crate::backends::shared::platform;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Xattr key for overflow whiteout tombstones on parent directories.
pub(crate) const TOMBSTONES_XATTR_KEY: &CStr = c"user.containers.overlay_tombstones";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a `.wh.<name>\0` CStr in a caller-provided stack buffer.
///
/// Requires `name.len() <= 251` (caller must check) and `buf.len() >= 260`.
/// Returns a borrowed CStr referencing the buffer.
pub(crate) fn build_whiteout_cstr<'a>(name: &[u8], buf: &'a mut [u8; 260]) -> &'a CStr {
    debug_assert!(name.len() <= 251, "name too long for inline whiteout");
    buf[..4].copy_from_slice(b".wh.");
    buf[4..4 + name.len()].copy_from_slice(name);
    buf[4 + name.len()] = 0;
    unsafe { CStr::from_bytes_with_nul_unchecked(&buf[..4 + name.len() + 1]) }
}

/// Create a whiteout for a name in the upper parent directory.
///
/// For names up to 251 bytes, creates an inline `.wh.<name>` file.
/// For longer names, stores the name in the parent's overflow tombstone xattr.
pub(crate) fn create_whiteout(upper_parent_fd: RawFd, name: &[u8]) -> io::Result<()> {
    if name.len() > 251 {
        return create_overflow_whiteout(upper_parent_fd, name);
    }

    let mut wh_buf = [0u8; 260];
    let wh_name = build_whiteout_cstr(name, &mut wh_buf);

    let fd = unsafe {
        libc::openat(
            upper_parent_fd,
            wh_name.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
            0o000 as libc::c_uint,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        // EEXIST is fine — whiteout already present.
        if err.raw_os_error() == Some(libc::EEXIST) {
            return Ok(());
        }
        return Err(platform::linux_error(err));
    }
    unsafe { libc::close(fd) };

    Ok(())
}

/// Remove a whiteout for a name from the upper parent directory.
///
/// For names up to 251 bytes, removes the inline `.wh.<name>` file.
/// For longer names, removes the name from the parent's overflow tombstone xattr.
/// Returns `true` if the whiteout existed and was removed, `false` if not.
pub(crate) fn remove_whiteout(upper_parent_fd: RawFd, name: &[u8]) -> io::Result<bool> {
    if name.len() > 251 {
        return remove_overflow_whiteout(upper_parent_fd, name);
    }

    let mut wh_buf = [0u8; 260];
    let wh_name = build_whiteout_cstr(name, &mut wh_buf);

    let ret = unsafe { libc::unlinkat(upper_parent_fd, wh_name.as_ptr(), 0) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() == Some(libc::ENOENT) {
            return Ok(false);
        }
        return Err(platform::linux_error(err));
    }

    Ok(true)
}

/// Check if a name exists on any lower layer beneath the given parent.
///
/// Used to decide whether to create a whiteout during unlink/rmdir — if the
/// name only exists on the upper layer, no whiteout is needed.
pub(crate) fn has_lower_entry(fs: &OverlayFs, parent_inode: u64, name: &[u8]) -> io::Result<bool> {
    let parent_node = {
        let nodes = fs.nodes.read().unwrap();
        nodes
            .get(&parent_inode)
            .cloned()
            .ok_or_else(platform::enoent)?
    };

    // If parent is opaque, no lower entries are visible.
    if parent_node
        .opaque
        .load(std::sync::atomic::Ordering::Acquire)
    {
        return Ok(false);
    }

    let name_cstr = std::ffi::CString::new(name).map_err(|_| platform::einval())?;

    // Precompute the path once — it depends only on parent_node, not the layer.
    let path_components = match inode::get_parent_lower_path(fs, &parent_node) {
        Ok(p) => p,
        Err(_) => return Ok(false),
    };

    // Check each lower layer (top-down).
    for lower in fs.lowers.iter().rev() {
        let lower_parent_fd = match inode::open_lower_parent(lower, &parent_node, &path_components)
        {
            Some(fd) => fd,
            None => continue,
        };

        // Check if whiteout exists on this layer (blocks further searching).
        if layer::check_whiteout(lower_parent_fd.raw(), name)? {
            return Ok(false);
        }

        // Check if entry exists on this layer.
        match platform::fstatat_nofollow(lower_parent_fd.raw(), &name_cstr) {
            Ok(_) => return Ok(true),
            Err(e) if platform::is_enoent(&e) => {}
            Err(e) => return Err(e),
        }

        // Check if this layer's directory is opaque (blocks further searching).
        if layer::check_opaque(lower_parent_fd.raw())? {
            return Ok(false);
        }
    }

    Ok(false)
}

//--------------------------------------------------------------------------------------------------
// Functions: Overflow Whiteouts
//--------------------------------------------------------------------------------------------------

/// Check if a long name is tombstoned in the parent's overflow xattr.
///
/// Reads `user.containers.overlay_tombstones` from `parent_fd` and searches
/// the length-prefixed list for `name`.
pub(crate) fn check_overflow_whiteout(parent_fd: RawFd, name: &[u8]) -> io::Result<bool> {
    let blob = match read_tombstone_xattr(parent_fd)? {
        Some(blob) => blob,
        None => return Ok(false),
    };

    let entries = parse_tombstone_blob(&blob)?;
    Ok(entries.contains(&name))
}

/// Add a long name to the parent's overflow tombstone xattr.
///
/// Reads existing tombstone blob (if any), validates it, checks for
/// duplicates, appends the new entry, and writes the blob back.
fn create_overflow_whiteout(parent_fd: RawFd, name: &[u8]) -> io::Result<()> {
    if name.len() > u16::MAX as usize {
        return Err(platform::enametoolong());
    }

    let mut blob = match read_tombstone_xattr(parent_fd) {
        Ok(Some(existing)) => {
            // Validate existing blob and check for duplicates.
            let entries = parse_tombstone_blob(&existing)?;
            if entries.contains(&name) {
                return Ok(()); // Already tombstoned.
            }
            existing
        }
        Ok(None) => Vec::new(),
        Err(e) => return Err(e),
    };

    // Append [u16_le len][name bytes].
    blob.extend_from_slice(&(name.len() as u16).to_le_bytes());
    blob.extend_from_slice(name);

    write_tombstone_xattr(parent_fd, &blob)
}

/// Remove a long name from the parent's overflow tombstone xattr.
///
/// Reads existing blob, removes the matching entry, writes back.
/// If the resulting blob is empty, removes the xattr entirely.
/// Returns `true` if the name was found and removed.
fn remove_overflow_whiteout(parent_fd: RawFd, name: &[u8]) -> io::Result<bool> {
    let blob = match read_tombstone_xattr(parent_fd)? {
        Some(existing) => existing,
        None => return Ok(false),
    };

    let entries = parse_tombstone_blob(&blob)?;
    let mut found = false;
    let mut compacted = Vec::with_capacity(blob.len());

    for entry in &entries {
        if *entry == name {
            found = true;
        } else {
            compacted.extend_from_slice(&(entry.len() as u16).to_le_bytes());
            compacted.extend_from_slice(entry);
        }
    }

    if !found {
        return Ok(false);
    }

    if compacted.is_empty() {
        remove_tombstone_xattr(parent_fd)?;
    } else {
        write_tombstone_xattr(parent_fd, &compacted)?;
    }

    Ok(true)
}

/// Get all tombstoned names from a parent directory's overflow xattr.
///
/// Returns an empty Vec if no tombstone xattr is present.
/// Used by readdir to bulk-add overflow-whiteout names to the `seen` set.
pub(crate) fn get_tombstoned_names(parent_fd: RawFd) -> io::Result<Vec<Vec<u8>>> {
    let blob = match read_tombstone_xattr(parent_fd)? {
        Some(blob) => blob,
        None => return Ok(Vec::new()),
    };

    let entries = parse_tombstone_blob(&blob)?;
    Ok(entries.into_iter().map(|e| e.to_vec()).collect())
}

/// Parse all tombstoned names from a raw tombstone blob.
///
/// Format: `[u16_le len][name bytes][u16_le len][name bytes]...`
/// Returns EIO on corrupt data.
fn parse_tombstone_blob(blob: &[u8]) -> io::Result<Vec<&[u8]>> {
    let mut entries = Vec::new();
    let mut pos = 0;

    while pos < blob.len() {
        if pos + 2 > blob.len() {
            return Err(platform::eio());
        }
        let len = u16::from_le_bytes([blob[pos], blob[pos + 1]]) as usize;
        pos += 2;
        if pos + len > blob.len() {
            return Err(platform::eio());
        }
        entries.push(&blob[pos..pos + len]);
        pos += len;
    }

    Ok(entries)
}

/// Read the tombstone xattr from a directory fd.
fn read_tombstone_xattr(fd: RawFd) -> io::Result<Option<Vec<u8>>> {
    // Build /proc/self/fd path once for all reads (Linux).
    #[cfg(target_os = "linux")]
    let path_cstr = {
        let path = format!("/proc/self/fd/{fd}");
        std::ffi::CString::new(path).map_err(|_| platform::eio())?
    };

    // Retry loop: the xattr may grow between sizing and reading (TOCTOU).
    // Bounded to 3 attempts to prevent infinite loops.
    for _ in 0..3 {
        // Get the size.
        #[cfg(target_os = "linux")]
        let size = unsafe {
            libc::getxattr(
                path_cstr.as_ptr(),
                TOMBSTONES_XATTR_KEY.as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };

        #[cfg(target_os = "macos")]
        let size = unsafe {
            libc::fgetxattr(
                fd,
                TOMBSTONES_XATTR_KEY.as_ptr(),
                std::ptr::null_mut(),
                0,
                0,
                0,
            )
        };

        if size < 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(0);
            #[cfg(target_os = "linux")]
            if errno == libc::ENODATA {
                return Ok(None);
            }
            #[cfg(target_os = "macos")]
            if errno == libc::ENOATTR {
                return Ok(None);
            }
            if errno == libc::EOPNOTSUPP {
                return Ok(None);
            }
            return Err(platform::linux_error(err));
        }

        let size = size as usize;
        if size == 0 {
            return Ok(None);
        }

        let mut buf = vec![0u8; size];

        #[cfg(target_os = "linux")]
        let ret = unsafe {
            libc::getxattr(
                path_cstr.as_ptr(),
                TOMBSTONES_XATTR_KEY.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                size,
            )
        };

        #[cfg(target_os = "macos")]
        let ret = unsafe {
            libc::fgetxattr(
                fd,
                TOMBSTONES_XATTR_KEY.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                size,
                0,
                0,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            // ERANGE means the xattr grew between sizing and reading.
            // Retry from the top.
            if err.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            return Err(platform::linux_error(err));
        }

        buf.truncate(ret as usize);
        return Ok(Some(buf));
    }

    // Exhausted retries — the xattr keeps changing.
    Err(platform::eio())
}

/// Write the tombstone xattr on a directory fd.
fn write_tombstone_xattr(fd: RawFd, blob: &[u8]) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/self/fd/{fd}");
        let path_cstr = std::ffi::CString::new(path).map_err(|_| platform::eio())?;
        let ret = unsafe {
            libc::setxattr(
                path_cstr.as_ptr(),
                TOMBSTONES_XATTR_KEY.as_ptr(),
                blob.as_ptr() as *const libc::c_void,
                blob.len(),
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
                TOMBSTONES_XATTR_KEY.as_ptr(),
                blob.as_ptr() as *const libc::c_void,
                blob.len(),
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

/// Remove the tombstone xattr from a directory fd.
fn remove_tombstone_xattr(fd: RawFd) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/self/fd/{fd}");
        let path_cstr = std::ffi::CString::new(path).map_err(|_| platform::eio())?;
        let ret = unsafe { libc::removexattr(path_cstr.as_ptr(), TOMBSTONES_XATTR_KEY.as_ptr()) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(0);
            if errno == libc::ENODATA {
                return Ok(());
            }
            return Err(platform::linux_error(err));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let ret = unsafe { libc::fremovexattr(fd, TOMBSTONES_XATTR_KEY.as_ptr(), 0) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error().unwrap_or(0);
            if errno == libc::ENOATTR {
                return Ok(());
            }
            return Err(platform::linux_error(err));
        }
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Remove the tombstone xattr from a directory fd if present, ignoring errors.
///
/// Used during rmdir cleanup to remove overflow whiteout metadata.
pub(crate) fn remove_tombstone_xattr_if_present(fd: RawFd) {
    let _ = remove_tombstone_xattr(fd);
}
