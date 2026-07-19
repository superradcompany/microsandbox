//! Private runtime disks cloned from immutable flat OCI rootfs artifacts.

use std::path::{Path, PathBuf};
use std::time::Instant;

use microsandbox_types::FlatClone;
use microsandbox_utils::copy::FastCopyStrategy;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const BYTES_PER_MIB: u64 = 1024 * 1024;

/// Canonical filename for a sandbox-owned flat rootfs disk.
pub(crate) const FLAT_ROOTFS_FILENAME: &str = "rootfs.raw";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Clone one immutable cached base into a private sparse disk and grow it offline.
pub(crate) async fn create_private_flat_rootfs(
    base: PathBuf,
    destination: PathBuf,
    target_mib: u32,
    clone: FlatClone,
) -> MicrosandboxResult<FlatClone> {
    let base_size = tokio::fs::metadata(&base)
        .await
        .map_err(|error| {
            MicrosandboxError::Custom(format!(
                "cannot read flat rootfs artifact at {}: {error}",
                base.display()
            ))
        })?
        .len();
    let target_bytes = u64::from(target_mib)
        .checked_mul(BYTES_PER_MIB)
        .ok_or_else(|| MicrosandboxError::InvalidConfig("flat root disk size overflows".into()))?;
    if target_bytes < base_size {
        let minimum_mib = base_size.div_ceil(BYTES_PER_MIB);
        return Err(MicrosandboxError::InvalidConfig(format!(
            "flat root disk must be at least {minimum_mib} MiB for this image (requested {target_mib} MiB)"
        )));
    }

    tokio::task::spawn_blocking(move || {
        create_private_flat_rootfs_sync(&base, &destination, target_bytes, clone)
    })
    .await
    .map_err(|error| {
        MicrosandboxError::Runtime(format!("flat rootfs clone task failed: {error}"))
    })?
}

/// Grow a stopped sandbox's private flat root disk to the requested capacity.
pub(crate) async fn grow_private_flat_rootfs(
    path: PathBuf,
    target_mib: u32,
) -> MicrosandboxResult<()> {
    let target_bytes = u64::from(target_mib) * BYTES_PER_MIB;
    let current_bytes = tokio::fs::metadata(&path)
        .await
        .map_err(|error| {
            MicrosandboxError::Custom(format!(
                "cannot grow flat rootfs at {}: {error}",
                path.display()
            ))
        })?
        .len();
    if current_bytes >= target_bytes {
        return Ok(());
    }

    tokio::task::spawn_blocking(move || microsandbox_image::ext4::grow_image(&path, target_bytes))
        .await
        .map_err(|error| {
            MicrosandboxError::Runtime(format!("flat rootfs grow task failed: {error}"))
        })?
        .map(|_| ())
        .map_err(|error| MicrosandboxError::Custom(format!("failed to grow flat rootfs: {error}")))
}

/// Publish the private clone only after copy, growth, and synchronization all succeed.
fn create_private_flat_rootfs_sync(
    base: &Path,
    destination: &Path,
    target_bytes: u64,
    clone: FlatClone,
) -> MicrosandboxResult<FlatClone> {
    let total_started_at = Instant::now();
    if destination.exists() {
        return Err(MicrosandboxError::Custom(format!(
            "flat rootfs already exists at {}",
            destination.display()
        )));
    }
    let temp = destination.with_extension("raw.part");
    if temp.exists() {
        std::fs::remove_file(&temp)?;
    }

    let result = (|| {
        let clone_started_at = Instant::now();
        let resolved_clone = match clone {
            FlatClone::Auto => {
                let (_, strategy) =
                    microsandbox_utils::copy::staged_fast_copy_with_strategy(base, &temp)?;
                match strategy {
                    FastCopyStrategy::Reflink => FlatClone::Reflink,
                    FastCopyStrategy::SparseCopy => FlatClone::Copy,
                }
            }
            FlatClone::Copy => {
                // The clone remains an unpublished `.part`. A grow synchronizes all copied data in
                // its first crash-ordering phase; without a grow, the final sync below does so.
                // Avoiding an intermediate sync preserves the same publication boundary while
                // coalescing the clone and resize writes into one storage flush.
                microsandbox_utils::copy::staged_sparse_copy(base, &temp)?;
                FlatClone::Copy
            }
            FlatClone::Reflink => {
                microsandbox_utils::copy::reflink(base, &temp).map_err(|error| {
                    MicrosandboxError::Custom(format!(
                        "flat rootfs requested clone=reflink, but the clone failed: {error}"
                    ))
                })?;
                FlatClone::Reflink
            }
        };
        let clone_us = clone_started_at.elapsed().as_micros();
        let base_apparent_bytes = std::fs::metadata(base)?.len();
        let grow_started_at = Instant::now();
        let grew = std::fs::metadata(&temp)?.len() < target_bytes;
        if grew {
            microsandbox_image::ext4::grow_image(&temp, target_bytes).map_err(|error| {
                MicrosandboxError::Custom(format!("failed to grow cloned flat rootfs: {error}"))
            })?;
        }
        let grow_us = grow_started_at.elapsed().as_micros();
        let sync_started_at = Instant::now();
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&temp)?
            .sync_all()?;
        let sync_us = sync_started_at.elapsed().as_micros();
        let publish_started_at = Instant::now();
        std::fs::rename(&temp, destination)?;
        let publish_us = publish_started_at.elapsed().as_micros();
        let allocated_bytes = tracing::enabled!(tracing::Level::DEBUG)
            .then(|| host_allocated_bytes(destination))
            .flatten();
        tracing::debug!(
            requested_clone = clone.as_str(),
            resolved_clone = resolved_clone.as_str(),
            base_apparent_bytes,
            target_bytes,
            allocated_bytes,
            grew,
            clone_us,
            grow_us,
            sync_us,
            publish_us,
            total_us = total_started_at.elapsed().as_micros(),
            "private flat rootfs provisioning attribution"
        );
        Ok(resolved_clone)
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

#[cfg(unix)]
fn host_allocated_bytes(path: &Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;

    std::fs::metadata(path)
        .ok()
        .map(|metadata| metadata.blocks().saturating_mul(512))
}

#[cfg(not(unix))]
fn host_allocated_bytes(_path: &Path) -> Option<u64> {
    // Keep Windows attribution honest until allocation size is exposed by a shared host helper.
    None
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom};

    use microsandbox_image::ext4::{Ext4RootfsOptions, materialize_ext4_rootfs};
    use microsandbox_image::tree::FileTree;

    use super::*;

    #[tokio::test]
    async fn clones_and_grows_a_materialized_rootfs() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.raw");
        let artifact =
            materialize_ext4_rootfs(&base, FileTree::new(), &Ext4RootfsOptions::default()).unwrap();
        let destination = dir.path().join(FLAT_ROOTFS_FILENAME);
        let target_mib = u32::try_from(artifact.virtual_size_bytes / BYTES_PER_MIB).unwrap() + 128;

        create_private_flat_rootfs(
            base.clone(),
            destination.clone(),
            target_mib,
            FlatClone::Copy,
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::metadata(destination).unwrap().len(),
            u64::from(target_mib) * BYTES_PER_MIB
        );
        assert_eq!(
            std::fs::metadata(base).unwrap().len(),
            artifact.virtual_size_bytes,
            "growing a private clone must not mutate the cached base"
        );
    }

    #[tokio::test]
    async fn clones_without_growing_before_publication() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.raw");
        let artifact =
            materialize_ext4_rootfs(&base, FileTree::new(), &Ext4RootfsOptions::default()).unwrap();
        let destination = dir.path().join(FLAT_ROOTFS_FILENAME);
        let target_mib = u32::try_from(artifact.virtual_size_bytes / BYTES_PER_MIB).unwrap();

        create_private_flat_rootfs(
            base.clone(),
            destination.clone(),
            target_mib,
            FlatClone::Copy,
        )
        .await
        .unwrap();

        assert_eq!(
            std::fs::metadata(&destination).unwrap().len(),
            artifact.virtual_size_bytes
        );
        let mut base_file = std::fs::File::open(base).unwrap();
        let mut destination_file = std::fs::File::open(&destination).unwrap();
        for offset in [0, 1024, artifact.virtual_size_bytes - 4096] {
            let mut expected = [0u8; 4096];
            let mut actual = [0u8; 4096];
            base_file.seek(SeekFrom::Start(offset)).unwrap();
            destination_file.seek(SeekFrom::Start(offset)).unwrap();
            base_file.read_exact(&mut expected).unwrap();
            destination_file.read_exact(&mut actual).unwrap();
            assert_eq!(actual, expected, "clone differed at byte offset {offset}");
        }
        assert!(!destination.with_extension("raw.part").exists());
    }

    #[tokio::test]
    async fn removes_unpublished_clone_when_growth_fails() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("invalid.raw");
        std::fs::write(&base, vec![0xAB; BYTES_PER_MIB as usize]).unwrap();
        let destination = dir.path().join(FLAT_ROOTFS_FILENAME);
        let temp = destination.with_extension("raw.part");

        let error = create_private_flat_rootfs(base, destination.clone(), 2, FlatClone::Copy)
            .await
            .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("failed to grow cloned flat rootfs")
        );
        assert!(!destination.exists());
        assert!(!temp.exists());
    }

    #[tokio::test]
    async fn rejects_a_target_smaller_than_the_cached_base() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.raw");
        materialize_ext4_rootfs(&base, FileTree::new(), &Ext4RootfsOptions::default()).unwrap();

        let error = create_private_flat_rootfs(
            base,
            dir.path().join(FLAT_ROOTFS_FILENAME),
            1,
            FlatClone::Copy,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("must be at least"));
    }
}
