//! Retain source protection inside blocking workers, even if their async caller is cancelled.

use std::path::Path;

use microsandbox_image::snapshot::{DESCRIPTOR_FILENAME, migration::V066_DESCRIPTOR_FILENAME};
use microsandbox_image::storage_lease::StorageLease;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Namespace protection prevents publication while the descriptor pin excludes readers.
#[derive(Clone)]
pub(super) struct DeletionLease {
    _namespace: StorageLease,
    _descriptor: Option<StorageLease>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn reader(path: &Path) -> std::io::Result<StorageLease> {
    let descriptor = descriptor(path)?;
    StorageLease::descriptor(&descriptor, false)?
        .ok_or_else(|| std::io::Error::other("snapshot descriptor is busy"))
}

pub(super) async fn reader_async(path: std::path::PathBuf) -> std::io::Result<StorageLease> {
    tokio::task::spawn_blocking(move || reader(&path))
        .await
        .map_err(std::io::Error::other)?
}

pub(super) fn deletion(path: &Path) -> std::io::Result<Option<DeletionLease>> {
    let Some(namespace) = StorageLease::try_exclusive(path)? else {
        return Ok(None);
    };
    let descriptor = match descriptor(path) {
        Ok(descriptor) => {
            let Some(lease) = StorageLease::descriptor(&descriptor, true)? else {
                return Ok(None);
            };
            Some(lease)
        }
        Err(error)
            if matches!(
                error.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
            ) =>
        {
            None
        }
        Err(error) => return Err(error),
    };
    Ok(Some(DeletionLease {
        _namespace: namespace,
        _descriptor: descriptor,
    }))
}

fn descriptor(path: &Path) -> std::io::Result<std::path::PathBuf> {
    let canonical = path.join(DESCRIPTOR_FILENAME);
    match std::fs::symlink_metadata(&canonical) {
        Ok(_) => Ok(canonical),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let legacy = path.join(V066_DESCRIPTOR_FILENAME);
            std::fs::symlink_metadata(&legacy)?;
            Ok(legacy)
        }
        Err(error) => Err(error),
    }
}

pub(super) fn pin_source(path: &Path) -> std::io::Result<Option<StorageLease>> {
    for parent in path.ancestors() {
        if parent.join(DESCRIPTOR_FILENAME).is_file()
            || parent.join(V066_DESCRIPTOR_FILENAME).is_file()
        {
            let parent = parent.canonicalize()?;
            let lease = reader(&parent)?;
            if !parent.join(DESCRIPTOR_FILENAME).is_file()
                && !parent.join(V066_DESCRIPTOR_FILENAME).is_file()
            {
                return Err(std::io::Error::other(
                    "snapshot disappeared before source admission",
                ));
            }
            return Ok(Some(lease));
        }
    }
    // Capture/restore staging and raw independent source files have no installed descriptor.
    Ok(None)
}
