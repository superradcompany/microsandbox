//! Origin tracking for lower-layer hardlink unification.
//!
//! Each lower-layer object is assigned a stable `LowerOriginId` based on its
//! layer index and host inode number. Files with multiple hardlinks within the
//! same layer share the same origin ID, enabling the overlay to present them
//! as a single guest inode.
//!
//! ## Persistence
//!
//! During copy-up, the origin ID is written as the `user.containers.overlay_origin`
//! xattr (12 bytes: `[u32_le layer_idx][u64_le object_id]`). At mount time, BFS
//! hydration reads these xattrs to rebuild the `origin_index`.

use std::{ffi::CStr, io, os::fd::RawFd};

use crate::backends::shared::platform;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Size of the serialized origin xattr value.
const ORIGIN_XATTR_SIZE: usize = 12;

/// Xattr key for origin tracking.
pub(crate) const ORIGIN_XATTR_KEY: &CStr = c"user.containers.overlay_origin";

/// Xattr key for redirect paths on renamed directories.
pub(crate) const REDIRECT_XATTR_KEY: &CStr = c"user.containers.overlay_redirect";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Stable identity for a lower-layer object within its layer.
///
/// Assigned during lower-layer lookup. Hardlink aliases within the same layer
/// share the same origin ID (same host inode number → same object_id).
#[derive(Clone, Copy, Debug, PartialOrd, Ord, PartialEq, Eq, Hash)]
pub(crate) struct LowerOriginId {
    /// Which layer this origin belongs to.
    pub layer_idx: usize,

    /// Unique ID within the layer (typically the host inode number).
    pub object_id: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LowerOriginId {
    /// Create a new origin ID from a layer index and host inode number.
    pub fn new(layer_idx: usize, object_id: u64) -> Self {
        Self {
            layer_idx,
            object_id,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Serialize a `LowerOriginId` to a 12-byte binary representation.
///
/// Format: `[u32_le layer_idx][u64_le object_id]`
fn serialize_origin(origin: &LowerOriginId) -> [u8; ORIGIN_XATTR_SIZE] {
    debug_assert!(
        origin.layer_idx <= u32::MAX as usize,
        "layer_idx overflows u32"
    );
    let mut buf = [0u8; ORIGIN_XATTR_SIZE];
    buf[..4].copy_from_slice(&(origin.layer_idx as u32).to_le_bytes());
    buf[4..12].copy_from_slice(&origin.object_id.to_le_bytes());
    buf
}

/// Deserialize a `LowerOriginId` from a 12-byte binary representation.
fn deserialize_origin(bytes: &[u8]) -> Option<LowerOriginId> {
    if bytes.len() < ORIGIN_XATTR_SIZE {
        return None;
    }
    let layer_idx = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
    let object_id = u64::from_le_bytes([
        bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9], bytes[10], bytes[11],
    ]);
    Some(LowerOriginId::new(layer_idx, object_id))
}

/// Write the origin xattr on an upper-layer fd.
pub(crate) fn set_origin_xattr(fd: RawFd, origin: &LowerOriginId) -> io::Result<()> {
    let buf = serialize_origin(origin);

    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/self/fd/{fd}\0");
        let ret = unsafe {
            libc::setxattr(
                path.as_ptr() as *const libc::c_char,
                ORIGIN_XATTR_KEY.as_ptr(),
                buf.as_ptr() as *const libc::c_void,
                ORIGIN_XATTR_SIZE,
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
                ORIGIN_XATTR_KEY.as_ptr(),
                buf.as_ptr() as *const libc::c_void,
                ORIGIN_XATTR_SIZE,
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

/// Read the origin xattr from an fd.
pub(crate) fn get_origin_xattr(fd: RawFd) -> io::Result<Option<LowerOriginId>> {
    let mut buf = [0u8; ORIGIN_XATTR_SIZE];

    #[cfg(target_os = "linux")]
    let ret = {
        let path = format!("/proc/self/fd/{fd}\0");
        unsafe {
            libc::getxattr(
                path.as_ptr() as *const libc::c_char,
                ORIGIN_XATTR_KEY.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                ORIGIN_XATTR_SIZE,
            )
        }
    };

    #[cfg(target_os = "macos")]
    let ret = unsafe {
        libc::fgetxattr(
            fd,
            ORIGIN_XATTR_KEY.as_ptr(),
            buf.as_mut_ptr() as *mut libc::c_void,
            ORIGIN_XATTR_SIZE,
            0,
            0,
        )
    };

    if ret < 0 {
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

    Ok(deserialize_origin(&buf))
}

/// Serialize redirect path components to binary.
///
/// Format: `[u16_le count][u16_le len][bytes][u16_le len][bytes]...`
fn serialize_redirect(components: &[Vec<u8>]) -> Vec<u8> {
    debug_assert!(
        components.len() <= u16::MAX as usize,
        "too many redirect components"
    );
    let total_size = 2 + components.iter().map(|c| 2 + c.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(total_size);
    buf.extend_from_slice(&(components.len() as u16).to_le_bytes());
    for component in components {
        debug_assert!(
            component.len() <= u16::MAX as usize,
            "redirect component too long"
        );
        buf.extend_from_slice(&(component.len() as u16).to_le_bytes());
        buf.extend_from_slice(component);
    }
    buf
}

/// Deserialize redirect path components from binary.
fn deserialize_redirect(bytes: &[u8]) -> Option<Vec<Vec<u8>>> {
    if bytes.len() < 2 {
        return None;
    }
    let count = u16::from_le_bytes([bytes[0], bytes[1]]) as usize;
    let mut pos = 2;
    let mut components = Vec::with_capacity(count);

    for _ in 0..count {
        if pos + 2 > bytes.len() {
            return None;
        }
        let len = u16::from_le_bytes([bytes[pos], bytes[pos + 1]]) as usize;
        pos += 2;
        if pos + len > bytes.len() {
            return None;
        }
        components.push(bytes[pos..pos + len].to_vec());
        pos += len;
    }

    Some(components)
}

/// Write the redirect xattr on an upper directory fd.
pub(crate) fn set_redirect_xattr(fd: RawFd, components: &[Vec<u8>]) -> io::Result<()> {
    let buf = serialize_redirect(components);

    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/self/fd/{fd}\0");
        let ret = unsafe {
            libc::setxattr(
                path.as_ptr() as *const libc::c_char,
                REDIRECT_XATTR_KEY.as_ptr(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
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
                REDIRECT_XATTR_KEY.as_ptr(),
                buf.as_ptr() as *const libc::c_void,
                buf.len(),
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

/// Read the redirect xattr from an fd.
pub(crate) fn get_redirect_xattr(fd: RawFd) -> io::Result<Option<Vec<Vec<u8>>>> {
    // Build /proc/self/fd path once for all reads (Linux).
    #[cfg(target_os = "linux")]
    let path = format!("/proc/self/fd/{fd}\0");

    // Retry loop: the xattr may grow between sizing and reading (TOCTOU).
    // Bounded to 3 attempts to prevent infinite loops.
    for _ in 0..3 {
        // Get the size.
        #[cfg(target_os = "linux")]
        let size = unsafe {
            libc::getxattr(
                path.as_ptr() as *const libc::c_char,
                REDIRECT_XATTR_KEY.as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };

        #[cfg(target_os = "macos")]
        let size = unsafe {
            libc::fgetxattr(
                fd,
                REDIRECT_XATTR_KEY.as_ptr(),
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
                path.as_ptr() as *const libc::c_char,
                REDIRECT_XATTR_KEY.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                size,
            )
        };

        #[cfg(target_os = "macos")]
        let ret = unsafe {
            libc::fgetxattr(
                fd,
                REDIRECT_XATTR_KEY.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                size,
                0,
                0,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            // ERANGE means the xattr grew between sizing and reading — retry.
            if err.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            return Err(platform::linux_error(err));
        }

        buf.truncate(ret as usize);
        return Ok(deserialize_redirect(&buf));
    }

    // Exhausted retries — the xattr keeps changing.
    Err(platform::eio())
}
