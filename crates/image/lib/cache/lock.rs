//! Cross-process file locking helpers.
//!
//! Used by the download and materialization pipelines to coordinate
//! concurrent access to shared cache artifacts.

use std::fs::{File, OpenOptions};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::io::RawFd;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::path::Path;

#[cfg(windows)]
use windows_sys::Win32::Foundation::HANDLE;
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{LOCKFILE_EXCLUSIVE_LOCK, LockFileEx, UnlockFileEx};
#[cfg(windows)]
use windows_sys::Win32::System::IO::OVERLAPPED;

use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open (or create) a zero-byte lock file for cross-process coordination.
pub(crate) fn open_lock_file(path: &Path) -> ImageResult<File> {
    OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .open(path)
        .map_err(|e| ImageError::Cache {
            path: path.to_path_buf(),
            source: e,
        })
}

/// Acquire an exclusive lock on an open cache lock file.
///
/// Safe to call from `tokio::task::spawn_blocking` — does not reference
/// any async runtime state.
pub(crate) fn lock_exclusive(file: &File) -> ImageResult<()> {
    lock_exclusive_by_file(file)
}

/// Release a cache file lock.
pub(crate) fn flock_unlock(file: &File) -> ImageResult<()> {
    unlock_file(file)
}

#[cfg(unix)]
pub(crate) fn flock_exclusive_by_fd(fd: RawFd) -> ImageResult<()> {
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
    if ret != 0 {
        return Err(ImageError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(unix)]
fn lock_exclusive_by_file(file: &File) -> ImageResult<()> {
    flock_exclusive_by_fd(file.as_raw_fd())
}

#[cfg(windows)]
fn lock_exclusive_by_file(file: &File) -> ImageResult<()> {
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        LockFileEx(
            file.as_raw_handle() as HANDLE,
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if ret == 0 {
        return Err(ImageError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(unix)]
fn unlock_file(file: &File) -> ImageResult<()> {
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if ret != 0 {
        return Err(ImageError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

#[cfg(windows)]
fn unlock_file(file: &File) -> ImageResult<()> {
    let mut overlapped: OVERLAPPED = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        UnlockFileEx(
            file.as_raw_handle() as HANDLE,
            0,
            u32::MAX,
            u32::MAX,
            &mut overlapped,
        )
    };
    if ret == 0 {
        return Err(ImageError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}
