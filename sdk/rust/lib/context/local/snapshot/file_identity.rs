//! Physical identity of an open file, independent of mutable timestamps and link counts.

use std::fs::File;
use std::io;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) type Key = (u64, u64);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
pub(super) fn key(file: &File) -> io::Result<Key> {
    use std::os::unix::fs::MetadataExt;
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
pub(super) fn key(file: &File) -> io::Result<Key> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // The live File owns the handle; this API fills the complete fixed-size structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        u64::from(info.dwVolumeSerialNumber),
        u64::from(info.nFileIndexHigh) << 32 | u64::from(info.nFileIndexLow),
    ))
}

#[cfg(not(any(unix, windows)))]
pub(super) fn key(_file: &File) -> io::Result<Key> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "physical file identity is unavailable",
    ))
}
