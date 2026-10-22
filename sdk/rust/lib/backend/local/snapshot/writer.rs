//! Stable admission for updated writers, outside a replaceable group directory.
//!
//! Older writers do not honor this gate and must be excluded operationally during
//! atomic imports. Exact readers retain descriptor pins; whole-group verification
//! uses a separate shared group lifetime lease honored by updated removers.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use microsandbox_image::storage_lease::StorageLease;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Retain admission in detached workers until publication and catalog work finish.
#[derive(Clone)]
pub(super) struct WriterLease {
    directory: PathBuf,
    _lease: StorageLease,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WriterLease {
    /// Poll a nonblocking lock so a cancelled waiter does not occupy a blocking worker.
    pub(super) async fn acquire(directory: &Path) -> io::Result<Self> {
        loop {
            if let Some(lease) = Self::try_acquire(directory)? {
                return Ok(lease);
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    /// Deletion uses nonblocking admission, preserving its existing busy behavior.
    pub(super) fn try_acquire(directory: &Path) -> io::Result<Option<Self>> {
        let directory = directory.canonicalize()?;
        Self::try_acquire_key(directory)
    }

    /// Creation reserves the stable writer key before the destination directory exists.
    /// The caller serializes name creation with the root creation lock.
    pub(super) fn try_reserve(directory: &Path) -> io::Result<Option<Self>> {
        Self::try_acquire_key(StorageLease::key(directory)?)
    }

    fn try_acquire_key(directory: PathBuf) -> io::Result<Option<Self>> {
        let parent = directory
            .parent()
            .ok_or_else(|| io::Error::other("group has no parent"))?;
        let name = directory
            .file_name()
            .ok_or_else(|| io::Error::other("group has no name"))?;
        // StorageLease hashes this name into the parent's .msb-leases directory.
        // Keep the key distinct from a lifetime lease on the group itself, and never
        // unlink its lock file when deleting or replacing the group.
        let mut key = std::ffi::OsString::from(".group-writer-");
        key.push(name);
        Ok(
            StorageLease::try_exclusive(&parent.join(key))?.map(|lease| Self {
                directory,
                _lease: lease,
            }),
        )
    }

    /// An admitted operation may call internal helpers without acquiring its lock twice.
    pub(super) fn validate(&self, directory: &Path) -> io::Result<()> {
        if directory.canonicalize()? != self.directory {
            return Err(io::Error::other(
                "writer admission belongs to another snapshot group",
            ));
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn admission_survives_replacement_and_is_scoped_to_one_group() {
        let root = tempfile::tempdir().unwrap();
        let group = root.path().join("group");
        let other = root.path().join("other");
        std::fs::create_dir(&group).unwrap();
        std::fs::create_dir(&other).unwrap();
        let owner = WriterLease::acquire(&group).await.unwrap();
        let worker = owner.clone();
        assert!(WriterLease::try_acquire(&group).unwrap().is_none());
        assert!(WriterLease::try_acquire(&other).unwrap().is_some());
        assert!(owner.validate(&other).is_err());
        std::fs::rename(&group, root.path().join("retired")).unwrap();
        std::fs::create_dir(&group).unwrap();
        assert!(WriterLease::try_acquire(&group).unwrap().is_none());
        drop(owner);
        assert!(WriterLease::try_acquire(&group).unwrap().is_none());
        drop(worker);
        tokio::time::timeout(Duration::from_secs(2), WriterLease::acquire(&group))
            .await
            .expect("last owner did not release admission")
            .unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn path_aliases_share_admission_and_cancelled_waiters_do_not_acquire() {
        let root = tempfile::tempdir().unwrap();
        let group = root.path().join("group");
        std::fs::create_dir(&group).unwrap();
        let alias = root.path().join("alias");
        std::os::unix::fs::symlink(&group, &alias).unwrap();
        let owner = WriterLease::acquire(&group).await.unwrap();
        assert!(WriterLease::try_acquire(&alias).unwrap().is_none());
        assert!(
            tokio::time::timeout(Duration::from_millis(30), WriterLease::acquire(&alias))
                .await
                .is_err()
        );
        drop(owner);
        tokio::time::timeout(Duration::from_secs(2), WriterLease::acquire(&alias))
            .await
            .expect("cancelled waiter retained admission")
            .unwrap();
    }
}
