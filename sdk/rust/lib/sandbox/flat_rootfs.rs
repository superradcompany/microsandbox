//! Private runtime disks cloned from immutable flat OCI rootfs artifacts.

use std::path::{Path, PathBuf};

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
) -> MicrosandboxResult<()> {
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
        create_private_flat_rootfs_sync(&base, &destination, target_bytes)
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
) -> MicrosandboxResult<()> {
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
        microsandbox_utils::copy::fast_copy(base, &temp)?;
        if std::fs::metadata(&temp)?.len() < target_bytes {
            microsandbox_image::ext4::grow_image(&temp, target_bytes).map_err(|error| {
                MicrosandboxError::Custom(format!("failed to grow cloned flat rootfs: {error}"))
            })?;
        }
        std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&temp)?
            .sync_all()?;
        std::fs::rename(&temp, destination)?;
        Ok(())
    })();

    if result.is_err() {
        let _ = std::fs::remove_file(&temp);
    }
    result
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
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

        create_private_flat_rootfs(base.clone(), destination.clone(), target_mib)
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
    async fn rejects_a_target_smaller_than_the_cached_base() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.raw");
        materialize_ext4_rootfs(&base, FileTree::new(), &Ext4RootfsOptions::default()).unwrap();

        let error = create_private_flat_rootfs(base, dir.path().join(FLAT_ROOTFS_FILENAME), 1)
            .await
            .unwrap_err();

        assert!(error.to_string().contains("must be at least"));
    }
}
