//! Name validation for filesystem operations.
//!
//! Every operation that accepts a guest-provided directory entry name must
//! call [`validate_name`] to prevent path traversal attacks.

use std::ffi::CStr;
use std::io;

use super::platform;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate a directory entry name, blocking traversal attacks.
///
/// Rejects: empty names, `..`, and names containing `/`.
///
/// Backslash is intentionally allowed — it is a valid filename character on
/// Linux. The filesystem operates on raw bytes, not path-separator-aware
/// strings.
pub(crate) fn validate_name(name: &CStr) -> io::Result<()> {
    let bytes = name.to_bytes();

    if bytes.is_empty() {
        return Err(platform::einval());
    }
    if bytes == b".." {
        return Err(platform::eperm());
    }
    if bytes.contains(&b'/') {
        return Err(platform::eperm());
    }

    Ok(())
}

/// Validate a directory entry name for overlay operations.
///
/// Extends [`validate_name`] with overlay-specific rejection of whiteout/opaque
/// marker names (`.wh.*`), which are internal overlay artifacts that must not
/// be created or accessed directly by the guest.
pub(crate) fn validate_overlay_name(name: &CStr) -> io::Result<()> {
    validate_name(name)?;

    let bytes = name.to_bytes();
    if bytes.starts_with(b".wh.") {
        return Err(platform::einval());
    }

    Ok(())
}
