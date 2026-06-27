//! Host path byte conversion helpers.

use std::ffi::{OsStr, OsString};
use std::io;
use std::path::Path;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return the stable byte representation used for image paths.
#[cfg(unix)]
pub(crate) fn os_str_bytes(value: &OsStr) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;

    value.as_bytes()
}

/// Return the stable byte representation used for image paths.
#[cfg(windows)]
pub(crate) fn os_str_bytes(value: &OsStr) -> &[u8] {
    value.as_encoded_bytes()
}

/// Return the stable byte representation used for an image path.
pub(crate) fn path_bytes(path: &Path) -> &[u8] {
    os_str_bytes(path.as_os_str())
}

/// Build an [`OsString`] from OCI/tar path bytes.
///
/// Unix paths can carry arbitrary non-NUL bytes. Windows host paths cannot, so
/// Windows admits only UTF-8 layer names rather than performing a lossy
/// conversion that could change path identity.
#[cfg(unix)]
pub(crate) fn os_string_from_bytes(bytes: &[u8]) -> io::Result<OsString> {
    use std::os::unix::ffi::OsStringExt;

    Ok(OsString::from_vec(bytes.to_vec()))
}

/// Build an [`OsString`] from OCI/tar path bytes.
#[cfg(windows)]
pub(crate) fn os_string_from_bytes(bytes: &[u8]) -> io::Result<OsString> {
    let value = std::str::from_utf8(bytes).map_err(|_| invalid_path_encoding(bytes))?;
    Ok(OsString::from(value))
}

/// Build an [`OsString`] from an owned OCI/tar path byte buffer.
pub(crate) fn os_string_from_vec(bytes: Vec<u8>) -> io::Result<OsString> {
    os_string_from_bytes(&bytes)
}

#[cfg(windows)]
fn invalid_path_encoding(bytes: &[u8]) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "image path is not valid UTF-8 on Windows: {:?}",
            String::from_utf8_lossy(bytes)
        ),
    )
}
