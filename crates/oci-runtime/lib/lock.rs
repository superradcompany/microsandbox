//! Cross-process serialization of short OCI lifecycle operations.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::OpenOptionsExt;
use std::time::Duration;

use anyhow::Result;
use microsandbox_runtime::oci::OciStateStore;
use nix::fcntl::{Flock, FlockArg};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn acquire(store: &OciStateStore, id: &str) -> Result<Flock<File>> {
    let directory = store.container_dir(id)?;
    let locks = directory
        .parent()
        .expect("container has root")
        .join(".locks");
    std::fs::create_dir_all(&locks)?;
    // Keep lock inodes after delete, so waiters cannot lock a different inode.
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(locks.join(id))?;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        match Flock::lock(file, FlockArg::LockExclusiveNonblock) {
            Ok(lock) => return Ok(lock),
            Err((returned, nix::errno::Errno::EWOULDBLOCK))
                if tokio::time::Instant::now() < deadline =>
            {
                file = returned;
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            Err((_, error)) => return Err(error.into()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn serializes_same_id_but_not_different_containers() {
        let root = tempfile::tempdir().unwrap();
        let store = OciStateStore::new(root.path());
        let first = acquire(&store, "a").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(30), acquire(&store, "a"))
                .await
                .is_err()
        );
        let other = acquire(&store, "b").await.unwrap();
        drop(first);
        acquire(&store, "a").await.unwrap();
        drop(other);
    }
}
