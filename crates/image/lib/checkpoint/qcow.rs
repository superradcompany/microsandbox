//! Atomic creation of managed qcow2 continuation heads.

use std::path::{Path, PathBuf};

use imago::FormatCreateBuilder;
use imago::file::File as ImagoFile;
use imago::qcow2::Qcow2;

use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const QCOW_CLUSTER_SIZE: usize = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create and durably publish one empty qcow2 head over `backing`.
///
/// The header carries only the backing file name for ordinary tooling. Runtime attachment still
/// supplies the complete caller-resolved chain and refuses implicit path traversal.
pub async fn create_qcow2_overlay(
    destination: &Path,
    virtual_size: u64,
    backing: &Path,
    backing_format: &str,
) -> ImageResult<()> {
    if virtual_size == 0 || !virtual_size.is_multiple_of(512) {
        return Err(ImageError::ManifestParse(
            "qcow2 virtual size must be non-zero and sector aligned".into(),
        ));
    }
    let backing_name = backing
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .ok_or_else(|| ImageError::ManifestParse("qcow2 backing name is not portable".into()))?;
    if !matches!(backing_format, "raw" | "qcow2") {
        return Err(ImageError::ManifestParse(
            "qcow2 backing format must be raw or qcow2".into(),
        ));
    }
    if destination.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!(
                "qcow2 destination already exists: {}",
                destination.display()
            ),
        )
        .into());
    }

    let parent = destination.parent().ok_or_else(|| {
        ImageError::ManifestParse("qcow2 destination has no parent directory".into())
    })?;
    std::fs::create_dir_all(parent)?;
    let temporary = temporary_path(parent, destination);
    let std_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let storage = ImagoFile::try_from(std_file)?;
    let create = Qcow2::<ImagoFile>::create_builder(storage)
        .size(virtual_size)
        .cluster_size(QCOW_CLUSTER_SIZE)
        .backing(backing_name.to_string(), backing_format.to_string())
        .create()
        .await;
    if let Err(error) = create {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    // Windows requires write access for `FlushFileBuffers`, which backs `sync_all`. Reopen the
    // completed image read-write so the same durability fence works on every supported host.
    let sync_result = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&temporary)
        .and_then(|file| file.sync_all());
    if let Err(error) = sync_result {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    if let Err(error) = std::fs::rename(&temporary, destination) {
        let _ = std::fs::remove_file(&temporary);
        return Err(error.into());
    }
    sync_directory(parent)?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn temporary_path(parent: &Path, destination: &Path) -> PathBuf {
    let name = destination
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("overlay.qcow2");
    parent.join(format!(".{name}.{}.tmp", rand::random::<u64>()))
}

fn sync_directory(path: &Path) -> ImageResult<()> {
    #[cfg(unix)]
    std::fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::create_qcow2_overlay;

    use imago::file::File as ImagoFile;
    use imago::format::drivers::FormatDriverInstance;
    use imago::qcow2::Qcow2;
    use imago::{DenyImplicitOpenGate, FormatDriverBuilder};

    #[tokio::test]
    async fn creates_sparse_overlay_with_declared_virtual_size() {
        let dir = tempfile::tempdir().unwrap();
        let backing = dir.path().join("upper.ext4");
        let overlay = dir.path().join("upper-2.qcow2");
        std::fs::File::create(&backing)
            .unwrap()
            .set_len(16 * 1024 * 1024)
            .unwrap();

        create_qcow2_overlay(&overlay, 16 * 1024 * 1024, &backing, "raw")
            .await
            .unwrap();

        let storage = ImagoFile::try_from(std::fs::File::open(&overlay).unwrap()).unwrap();
        let image = Qcow2::<ImagoFile>::builder(storage)
            .backing(None)
            .data_file(None)
            .open(DenyImplicitOpenGate::default())
            .await
            .unwrap();
        assert_eq!(image.size(), 16 * 1024 * 1024);
        assert!(overlay.metadata().unwrap().len() < 1024 * 1024);
    }
}
