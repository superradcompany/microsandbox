//! Cross-process file locking helpers.
//!
//! Used by the download and materialization pipelines to coordinate
//! concurrent access to shared cache artifacts via `flock()`.

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::io::RawFd;
use std::path::Path;

use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open (or create) a zero-byte lock file for `flock()` coordination.
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

/// Acquire an exclusive `flock()` by raw fd.
///
/// Safe to call from `tokio::task::spawn_blocking` — does not reference
/// any async runtime state.
pub(crate) fn flock_exclusive_by_fd(fd: RawFd) -> ImageResult<()> {
    let ret = unsafe { libc::flock(fd, libc::LOCK_EX) };
    if ret != 0 {
        return Err(ImageError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}

/// Release a `flock()`.
pub(crate) fn flock_unlock(file: &File) -> ImageResult<()> {
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if ret != 0 {
        return Err(ImageError::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}
