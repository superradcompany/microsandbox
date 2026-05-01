//! Name validation for filesystem operations.
//!
//! Every operation that accepts a guest-provided directory entry name must
//! call [`validate_name`] to prevent path traversal attacks.

use std::{ffi::CStr, io};

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

/// Maximum allowed component length (NAME_MAX on Linux).
const NAME_MAX: usize = 255;

/// Validate a directory entry name for in-memory filesystem operations.
///
/// Extends [`validate_name`] with rejection of:
/// - `.` (would alias the directory itself)
/// - Names longer than `NAME_MAX` (255 bytes)
pub(crate) fn validate_memfs_name(name: &CStr) -> io::Result<()> {
    validate_name(name)?;

    let bytes = name.to_bytes();

    if bytes == b"." {
        return Err(platform::eperm());
    }
    if bytes.len() > NAME_MAX {
        return Err(platform::enametoolong());
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    fn cstr(s: &[u8]) -> CString {
        CString::new(s.to_vec()).unwrap()
    }

    #[test]
    fn validate_name_accepts_normal() {
        assert!(validate_name(&cstr(b"hello.txt")).is_ok());
        assert!(validate_name(&cstr(b".hidden")).is_ok());
        assert!(validate_name(&cstr(b".")).is_ok()); // validate_name allows "." (overlay rejects it)
    }

    #[test]
    fn validate_name_rejects_empty() {
        let name = c"";
        assert!(validate_name(name).is_err());
    }

    #[test]
    fn validate_name_rejects_dotdot() {
        assert!(validate_name(&cstr(b"..")).is_err());
    }

    #[test]
    fn validate_name_rejects_slash() {
        assert!(validate_name(&cstr(b"a/b")).is_err());
    }

    #[test]
    fn validate_name_allows_backslash() {
        assert!(validate_name(&cstr(b"a\\b")).is_ok());
    }
}
