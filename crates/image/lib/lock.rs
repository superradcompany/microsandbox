//! Cross-process file locking utilities based on `flock(2)`.

use std::{
    fs::{File, OpenOptions},
    io,
    os::fd::AsRawFd,
    path::Path,
};

use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open or create a lock file.
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

/// Acquire an exclusive `flock()` on a blocking thread pool.
pub(crate) async fn flock_exclusive_async(file: File) -> ImageResult<File> {
    tokio::task::spawn_blocking(move || {
        flock_exclusive(&file)?;
        Ok::<_, ImageError>(file)
    })
    .await
    .map_err(|error| ImageError::Io(io::Error::other(format!("lock task failed: {error}"))))?
}

/// Release a `flock()`.
pub(crate) fn flock_unlock(file: &File) -> ImageResult<()> {
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    if ret != 0 {
        return Err(ImageError::Io(io::Error::last_os_error()));
    }
    Ok(())
}

/// Acquire an exclusive `flock()`.
fn flock_exclusive(file: &File) -> ImageResult<()> {
    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
    if ret != 0 {
        return Err(ImageError::Io(io::Error::last_os_error()));
    }
    Ok(())
}
