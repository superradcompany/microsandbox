//! Windows startup-only transfer of sidecar locks into the runtime process.
//!
//! The launcher duplicates non-inheritable handles into this exact process before sending
//! their values over stdin. Never reopen the sidecar: that would break continuous ownership.

use std::collections::HashSet;
use std::fs::File;
use std::io::{self, Read};
use std::os::windows::io::FromRawHandle;

use windows_sys::Win32::Foundation::{GetHandleInformation, HANDLE, HANDLE_FLAG_INHERIT};
use windows_sys::Win32::Storage::FileSystem::{FILE_TYPE_DISK, GetFileType};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Bound the startup message independently of the number of guest disks.
pub const MAX_MESSAGE_BYTES: usize = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Adopt launcher-transferred locks before constructing any guest disk backend.
///
/// The returned files must remain alive until runtime teardown. This private bootstrap accepts
/// only handles already duplicated into the receiver by its trusted launcher, not host paths.
///
/// # Safety
///
/// Each valid handle in the message must have been transferred exclusively to this receiver.
/// Handle validation cannot establish ownership or detect another Rust owner of the same handle.
pub unsafe fn receive(reader: impl Read) -> io::Result<Vec<File>> {
    Ok(read_handles(reader)?
        .into_iter()
        .map(|handle| {
            // SAFETY: the caller guarantees exclusive ownership of the validated handles.
            unsafe { File::from_raw_handle(handle as _) }
        })
        .collect())
}

fn read_handles(reader: impl Read) -> io::Result<Vec<usize>> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_MESSAGE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(io::Error::other("disk lock handoff exceeds startup limit"));
    }
    let handles: Vec<usize> = serde_json::from_slice(&bytes)?;
    if handles.is_empty() {
        return Err(io::Error::other("disk lock handoff is empty"));
    }
    let mut seen = HashSet::new();
    // Validate the complete set before adopting anything, avoiding duplicate ownership of a
    // handle if a malformed message repeats it. Startup failure exits the process and closes
    // all transferred handles, including those not adopted here.
    for value in &handles {
        let handle = *value as HANDLE;
        let mut flags = 0;
        if *value == 0
            || !seen.insert(*value)
            || unsafe { GetHandleInformation(handle, &mut flags) } == 0
            || flags & HANDLE_FLAG_INHERIT != 0
            || unsafe { GetFileType(handle) } != FILE_TYPE_DISK
        {
            return Err(io::Error::other("invalid transferred disk lock handle"));
        }
    }
    Ok(handles)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::os::windows::io::AsRawHandle;

    use super::*;

    #[test]
    fn reject_missing_truncated_empty_invalid_and_oversized_handoff() {
        for bytes in [
            b"".as_slice(),
            b"[",
            b"[]",
            b"[0]",
            b"[18446744073709551615]",
        ] {
            assert!(read_handles(bytes).is_err());
        }
        assert!(read_handles(vec![b' '; MAX_MESSAGE_BYTES + 1].as_slice()).is_err());
    }

    #[test]
    fn reject_duplicate_without_adopting_borrowed_handle() {
        let file = File::open(std::env::current_exe().unwrap()).unwrap();
        let value = file.as_raw_handle() as usize;
        let bytes = serde_json::to_vec(&[value, value]).unwrap();
        assert!(read_handles(bytes.as_slice()).is_err());
        assert!(file.metadata().is_ok());
    }
}
