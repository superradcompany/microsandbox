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
/// Rejects: empty names, `..`, names containing `/` or `\`, and names
/// containing null bytes.
pub(crate) fn validate_name(name: &CStr) -> io::Result<()> {
    let bytes = name.to_bytes();

    if bytes.is_empty() {
        return Err(platform::einval());
    }
    if bytes == b".." {
        return Err(platform::eperm());
    }
    if bytes.contains(&b'/') || bytes.contains(&b'\\') {
        return Err(platform::eperm());
    }

    Ok(())
}
