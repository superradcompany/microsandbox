//! Name validation for filesystem operations.
//!
//! Every operation that accepts a guest-provided directory entry name must
//! call [`validate_name`] to prevent path traversal attacks.

use std::{ffi::CStr, io};

use super::platform;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Maximum allowed component length (NAME_MAX on Linux).
const NAME_MAX: usize = 255;

/// Maximum absolute path length (PATH_MAX on Linux).
const PATH_MAX: usize = 4096;

/// Maximum symlink target length accepted on the wire.
const MAX_SYMLINK_TARGET: usize = 4096;

/// Maximum extended-attribute value length accepted on the wire.
#[allow(dead_code)]
const MAX_XATTR_VALUE: usize = 64 * 1024;

/// The component checks shared by every name validator, on raw bytes.
///
/// Rejects: empty names, `..`, names containing `/` or NUL.
///
/// Backslash is intentionally allowed — it is a valid filename character on
/// Linux. The filesystem operates on raw bytes, not path-separator-aware
/// strings. `.` and length limits are layered on by the stricter validators.
fn validate_component_bytes(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Err(platform::einval());
    }
    if bytes.contains(&0) {
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

/// [`validate_component_bytes`] plus the two rules a real on-disk/in-memory
/// component must also satisfy: it may not be `.` (which would alias the
/// directory itself) and may not exceed `NAME_MAX` bytes.
fn validate_strict_component_bytes(bytes: &[u8]) -> io::Result<()> {
    validate_component_bytes(bytes)?;
    if bytes == b"." {
        return Err(platform::eperm());
    }
    if bytes.len() > NAME_MAX {
        return Err(platform::enametoolong());
    }
    Ok(())
}

/// Validate a directory entry name for lookup, blocking traversal attacks.
///
/// Rejects: empty names, `..`, names containing `/` or NUL, and names longer
/// than `NAME_MAX`. Allows `.` (aliases the directory itself).
pub(crate) fn validate_name(name: &CStr) -> io::Result<()> {
    validate_component_bytes(name.to_bytes())?;
    if name.to_bytes().len() > NAME_MAX {
        return Err(platform::enametoolong());
    }
    Ok(())
}

/// Validate a directory entry name for create/rename/unlink mutations.
///
/// Rejects: empty names, `.`, `..`, names containing `/` or NUL, and names
/// longer than `NAME_MAX`.
pub(crate) fn validate_create_name(name: &CStr) -> io::Result<()> {
    validate_strict_component_bytes(name.to_bytes())
}

/// Validate a symlink target before passing it to a provider.
///
/// Rejects NUL bytes, absolute targets, and `..` path components that could
/// confuse naive resolution if mishandled.
pub(crate) fn validate_symlink_target_bytes(bytes: &[u8]) -> io::Result<()> {
    if bytes.len() > MAX_SYMLINK_TARGET {
        return Err(platform::enametoolong());
    }
    if bytes.contains(&0) {
        return Err(platform::einval());
    }
    if !bytes.is_empty() && bytes[0] == b'/' {
        return Err(platform::eperm());
    }
    for component in bytes.split(|&b| b == b'/') {
        if component == b".." {
            return Err(platform::eperm());
        }
    }
    Ok(())
}

/// Validate a directory entry name returned by a provider's `readdir`.
///
/// Rejects empty names, `.`, `..`, names containing `/`, and names longer
/// than `NAME_MAX`. The scaffold synthesizes `.`/`..` itself.
pub(crate) fn validate_readdir_name(name: &[u8]) -> io::Result<()> {
    validate_strict_component_bytes(name)
}

/// Validate an extended-attribute name before passing it to a provider.
///
/// Rejects empty names, NUL bytes, `/`, and names longer than `NAME_MAX`.
pub(crate) fn validate_xattr_name_bytes(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() {
        return Err(platform::einval());
    }
    if bytes.contains(&0) {
        return Err(platform::einval());
    }
    if bytes.contains(&b'/') {
        return Err(platform::einval());
    }
    if bytes.len() > NAME_MAX {
        return Err(platform::enametoolong());
    }
    Ok(())
}

/// Validate a directory entry name for in-memory filesystem operations.
///
/// Same rules as [`validate_create_name`]: rejects `.`, `..`, `/`, NUL, empty
/// names, and names longer than `NAME_MAX`.
pub(crate) fn validate_memfs_name(name: &CStr) -> io::Result<()> {
    validate_strict_component_bytes(name.to_bytes())
}

/// Validate an absolute guest path on the virtual-filesystem RPC wire.
///
/// Rejects relative paths, NUL bytes, `.`/`..` components, empty components,
/// and paths or components that exceed Linux `PATH_MAX`/`NAME_MAX`.
pub(crate) fn validate_provider_path_bytes(bytes: &[u8]) -> io::Result<()> {
    if bytes.is_empty() || bytes[0] != b'/' {
        return Err(platform::einval());
    }
    if bytes.len() > PATH_MAX {
        return Err(platform::enametoolong());
    }
    if bytes.contains(&0) {
        return Err(platform::einval());
    }
    if bytes.len() == 1 {
        return Ok(());
    }
    for component in bytes[1..].split(|&b| b == b'/') {
        if component.is_empty() {
            return Err(platform::einval());
        }
        if component == b"." || component == b".." {
            return Err(platform::eperm());
        }
        validate_strict_component_bytes(component)?;
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
    }

    #[test]
    fn validate_name_accepts_dot() {
        assert!(validate_name(&cstr(b".")).is_ok());
    }

    #[test]
    fn validate_create_name_rejects_dot() {
        assert!(validate_create_name(&cstr(b".")).is_err());
    }

    #[test]
    fn validate_component_bytes_rejects_nul() {
        assert!(validate_readdir_name(b"a\0b").is_err());
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

    #[test]
    fn validate_readdir_name_rejects_dot_and_dotdot() {
        assert!(validate_readdir_name(b".").is_err());
        assert!(validate_readdir_name(b"..").is_err());
    }

    #[test]
    fn validate_readdir_name_rejects_slash_and_empty() {
        assert!(validate_readdir_name(b"").is_err());
        assert!(validate_readdir_name(b"a/b").is_err());
    }

    #[test]
    fn validate_provider_path_bytes_rejects_long_component() {
        let long = vec![b'a'; 256];
        let mut path = b"/".to_vec();
        path.extend_from_slice(&long);
        assert!(validate_provider_path_bytes(&path).is_err());
    }

    #[test]
    fn validate_provider_path_bytes_rejects_relative_and_nul() {
        assert!(validate_provider_path_bytes(b"relative").is_err());
        let mut with_nul = b"/a".to_vec();
        with_nul.push(0);
        assert!(validate_provider_path_bytes(&with_nul).is_err());
    }

    #[test]
    fn validate_provider_path_bytes_rejects_trailing_slash_and_empty_component() {
        assert!(validate_provider_path_bytes(b"/inbox/").is_err());
        assert!(validate_provider_path_bytes(b"/a//b").is_err());
    }

    #[test]
    fn validate_symlink_target_bytes_rejects_dotdot_and_nul() {
        assert!(validate_symlink_target_bytes(b"../etc").is_err());
        assert!(validate_symlink_target_bytes(b"ok/../x").is_err());
        let mut with_nul = b"target".to_vec();
        with_nul.push(0);
        assert!(validate_symlink_target_bytes(&with_nul).is_err());
        assert!(validate_symlink_target_bytes(b"../").is_err());
        assert!(validate_symlink_target_bytes(b"relative/target").is_ok());
    }

    #[test]
    fn validate_symlink_target_bytes_rejects_absolute() {
        assert!(validate_symlink_target_bytes(b"/etc/passwd").is_err());
    }

    #[test]
    fn validate_symlink_target_bytes_rejects_long_target() {
        assert!(validate_symlink_target_bytes(&vec![b'a'; MAX_SYMLINK_TARGET + 1]).is_err());
    }

    #[test]
    fn validate_xattr_name_bytes_rejects_empty_slash_and_nul() {
        assert!(validate_xattr_name_bytes(b"").is_err());
        assert!(validate_xattr_name_bytes(b"user.foo").is_ok());
        assert!(validate_xattr_name_bytes(b"user/foo").is_err());
        let mut with_nul = b"user".to_vec();
        with_nul.push(0);
        assert!(validate_xattr_name_bytes(&with_nul).is_err());
    }

    #[test]
    fn validate_xattr_name_bytes_rejects_long_name() {
        let long = vec![b'a'; 256];
        assert!(validate_xattr_name_bytes(&long).is_err());
    }
}
