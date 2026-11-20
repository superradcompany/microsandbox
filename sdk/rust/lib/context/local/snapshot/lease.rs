//! Retain source protection inside blocking workers, even if their async caller is cancelled.

use std::path::{Path, PathBuf};

use microsandbox_image::snapshot::{DESCRIPTOR_FILENAME, migration::V066_DESCRIPTOR_FILENAME};
use microsandbox_image::storage_lease::StorageLease;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The namespace protects the entry; Unix also retains the descriptor pin through deletion.
#[derive(Clone)]
pub(super) struct DeletionLease {
    _namespace: StorageLease,
    _group: Option<GroupDeletionLease>,
    _writer: Option<super::writer::WriterLease>,
    #[cfg(unix)]
    _descriptor: Option<StorageLease>,
}

/// One exclusive group lifetime gate can be shared by all members in a rollback.
#[derive(Clone)]
pub(super) struct GroupDeletionLease {
    directory: PathBuf,
    _lease: StorageLease,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn reader(path: &Path) -> std::io::Result<StorageLease> {
    #[cfg(windows)]
    {
        // A handle anywhere inside a snapshot prevents Windows from moving its directory.
        // The stable sibling lock protects the entry without retaining a payload handle.
        match StorageLease::shared(path) {
            Ok(lease) => {
                let descriptor = descriptor(path)?;
                if !std::fs::symlink_metadata(descriptor)?.file_type().is_file() {
                    return Err(std::io::Error::other(
                        "snapshot descriptor is not a regular file",
                    ));
                }
                return Ok(lease);
            }
            // An explicitly opened external snapshot may have a read-only parent. Its
            // descriptor remains a sidecar-free reader pin; a Windows directory move
            // cannot succeed while that descriptor handle is open.
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied => {}
            Err(error) => return Err(error),
        }
    }
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
    // Enter before member pins, never while waiting on the group publication lock.
    let writer = if let Some(group) = super::group::group_path(path) {
        let Some(writer) = super::writer::WriterLease::try_acquire(&group)? else {
            return Ok(None);
        };
        Some(writer)
    } else {
        None
    };
    let group = if let Some(directory) = super::group::group_path(path) {
        let Some(lease) = group_deletion(&directory)? else {
            return Ok(None);
        };
        Some(lease)
    } else {
        None
    };
    deletion_inner(path, writer, group)
}

/// Journal recovery already owns the group lock and must not invert admission ordering.
/// It only tries member pins; a conflicting remover leaves the journal intact for retry.
pub(super) fn deletion_under_group_lock(
    path: &Path,
    group: &GroupDeletionLease,
) -> std::io::Result<Option<DeletionLease>> {
    if path.parent().map(Path::canonicalize).transpose()?.as_ref() != Some(&group.directory) {
        return Err(std::io::Error::other(
            "group deletion lease belongs to another history",
        ));
    }
    deletion_inner(path, None, Some(group.clone()))
}

pub(super) fn group_deletion(directory: &Path) -> std::io::Result<Option<GroupDeletionLease>> {
    let directory = directory.canonicalize()?;
    Ok(
        StorageLease::try_exclusive(&directory)?.map(|lease| GroupDeletionLease {
            directory,
            _lease: lease,
        }),
    )
}

fn deletion_inner(
    path: &Path,
    writer: Option<super::writer::WriterLease>,
    group: Option<GroupDeletionLease>,
) -> std::io::Result<Option<DeletionLease>> {
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
    #[cfg(windows)]
    {
        // Check descriptor-only readers, including read-only external snapshots, but
        // close our own handle before a rename. A reader admitted after this check still
        // makes the Windows move fail rather than letting it retire an active artifact.
        drop(descriptor);
        Ok(Some(DeletionLease {
            _namespace: namespace,
            _group: group,
            _writer: writer,
        }))
    }
    #[cfg(unix)]
    {
        Ok(Some(DeletionLease {
            _namespace: namespace,
            _group: group,
            _writer: writer,
            _descriptor: descriptor,
        }))
    }
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, windows))]
mod tests {
    use super::*;

    #[test]
    fn exclusive_lease_does_not_hold_a_handle_inside_the_snapshot() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("snapshot");
        std::fs::create_dir(&path).unwrap();
        std::fs::write(path.join(DESCRIPTOR_FILENAME), b"{}").unwrap();

        let reader = reader(&path).unwrap();
        assert!(deletion(&path).unwrap().is_none());
        drop(reader);

        let deletion = deletion(&path).unwrap().unwrap();
        // Windows rejects this rename if the admission check retained snapshot.json.
        let retired = root.path().join("retired");
        std::fs::rename(&path, &retired).unwrap();
        std::fs::remove_dir_all(retired).unwrap();
        drop(deletion);
    }
}
