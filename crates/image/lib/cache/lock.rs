//! Cross-process file locking helpers.
//!
//! Used by the download and materialization pipelines to coordinate
//! concurrent access to shared cache artifacts.

use std::fs::File;
use std::path::Path;

use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open (or create) a zero-byte lock file for cross-process coordination.
pub(crate) fn open_lock_file(path: &Path) -> ImageResult<File> {
    microsandbox_utils::process_lock::open_lock_file(path).map_err(|e| ImageError::Cache {
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
    microsandbox_utils::process_lock::unlock(file).map_err(ImageError::Io)
}

#[cfg(unix)]
fn lock_exclusive_by_file(file: &File) -> ImageResult<()> {
    microsandbox_utils::process_lock::lock_exclusive(file).map_err(ImageError::Io)
}

#[cfg(windows)]
fn lock_exclusive_by_file(file: &File) -> ImageResult<()> {
    microsandbox_utils::process_lock::lock_exclusive(file).map_err(ImageError::Io)
}
