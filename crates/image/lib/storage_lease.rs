//! Cooperative, process-held leases for installed storage entries.
//!
//! Locks name directory entries, not content digests: two installed copies have independent
//! lifetimes. The stable lock inode lives beside the entry, outside any removable payload.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox_utils::process_lock;
use sha2::{Digest, Sha256};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A shared reader/publisher lease or an exclusive deletion lease.
///
/// Clones retain the same OS lock until the last clone is dropped. Legacy processes which do
/// not participate in this protocol are not protected by it.
#[derive(Clone, Debug)]
pub struct StorageLease {
    _file: Arc<File>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl StorageLease {
    /// Pin an existing immutable descriptor without writing beside it. Its identity is
    /// checked after locking, so a waiter cannot accidentally admit a retired generation.
    pub fn descriptor(path: &Path, exclusive: bool) -> io::Result<Option<Self>> {
        let mut options = std::fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW);
        }
        let file = options.open(path)?;
        if !file.metadata()?.is_file() {
            return Err(io::Error::other(
                "snapshot descriptor is not a regular file",
            ));
        }
        if !process_lock::lock_descriptor(&file, exclusive, exclusive)? {
            return Ok(None);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            let admitted = file.metadata()?;
            let current = std::fs::symlink_metadata(path)?;
            if !current.file_type().is_file()
                || (admitted.dev(), admitted.ino()) != (current.dev(), current.ino())
            {
                return Err(io::Error::other("snapshot changed during admission"));
            }
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
            };
            fn identity(file: &File) -> io::Result<(u32, u32, u32)> {
                let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
                if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) }
                    == 0
                {
                    return Err(io::Error::last_os_error());
                }
                let info = unsafe { info.assume_init() };
                Ok((
                    info.dwVolumeSerialNumber,
                    info.nFileIndexHigh,
                    info.nFileIndexLow,
                ))
            }
            if !std::fs::symlink_metadata(path)?.file_type().is_file()
                || identity(&file)? != identity(&File::open(path)?)?
            {
                return Err(io::Error::other("snapshot changed during admission"));
            }
        }
        Ok(Some(Self {
            _file: Arc::new(file),
        }))
    }

    /// Canonical coordination key, without resolving the removable entry itself.
    pub fn key(path: &Path) -> io::Result<PathBuf> {
        let name = path
            .file_name()
            .ok_or_else(|| io::Error::other("storage entry has no filename"))?;
        let parent = path
            .parent()
            .ok_or_else(|| io::Error::other("storage entry has no parent"))?;
        Ok(parent.canonicalize()?.join(name))
    }

    /// Serialize a short publication critical section. Never upgrade a shared lease on
    /// the same key: publication gates and lifetime pins use distinct keys.
    pub fn exclusive(path: &Path) -> io::Result<Self> {
        let file = open(path)?;
        process_lock::lock_exclusive(&file)?;
        Ok(Self {
            _file: Arc::new(file),
        })
    }

    /// Protect an entry before reading it or publishing files and their catalog references.
    /// Call from blocking work; a deletion already in progress may briefly delay this call.
    pub fn shared(path: &Path) -> io::Result<Self> {
        let file = open(path)?;
        process_lock::lock_shared(&file)?;
        Ok(Self {
            _file: Arc::new(file),
        })
    }

    /// Acquire reader protection without blocking the async executor.
    pub async fn shared_async(path: PathBuf) -> io::Result<Self> {
        tokio::task::spawn_blocking(move || Self::shared(&path))
            .await
            .map_err(io::Error::other)?
    }

    /// Try to exclude readers and publishers. Deleters never wait for other entry leases,
    /// so taking multiple leases cannot deadlock with dependency discovery by readers.
    pub fn try_exclusive(path: &Path) -> io::Result<Option<Self>> {
        let file = open(path)?;
        Ok(process_lock::try_lock_exclusive(&file)?.then(|| Self {
            _file: Arc::new(file),
        }))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Compare the exact file identities of two regular entries without following entry symlinks.
/// Used by deletion recovery to distinguish the admitted file from a later replacement.
pub fn same_file(left: &Path, right: &Path) -> io::Result<bool> {
    for path in [left, right] {
        if !std::fs::symlink_metadata(path)?.file_type().is_file() {
            return Err(io::Error::other(
                "storage recovery entry is not a regular file",
            ));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let left = std::fs::metadata(left)?;
        let right = std::fs::metadata(right)?;
        Ok((left.dev(), left.ino()) == (right.dev(), right.ino()))
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        fn identity(path: &Path) -> io::Result<(u32, u32, u32)> {
            let file = File::open(path)?;
            let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
            // SAFETY: the file retains a live handle and the API initializes info on success.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
                return Err(io::Error::last_os_error());
            }
            let info = unsafe { info.assume_init() };
            Ok((
                info.dwVolumeSerialNumber,
                info.nFileIndexHigh,
                info.nFileIndexLow,
            ))
        }
        Ok(identity(left)? == identity(right)?)
    }
}

fn open(path: &Path) -> io::Result<File> {
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::other("storage entry has no filename"))?;
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("storage entry has no parent"))?;
    // Resolve aliases of the parent before choosing a lock. Never follow an entry symlink:
    // callers validate the payload only after acquiring protection for this exact name.
    let parent = parent.canonicalize()?;
    let directory = parent.join(".msb-leases");
    match std::fs::create_dir(&directory) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    if !std::fs::symlink_metadata(&directory)?.file_type().is_dir() {
        return Err(io::Error::other(
            "storage lease directory is not a real directory",
        ));
    }
    let key = format!(
        "{}.lock",
        hex::encode(Sha256::digest(name.as_encoded_bytes()))
    );
    let file = process_lock::open_lock_file(&directory.join(key))?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("storage lease is not a regular file"));
    }
    Ok(file)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_pins_allow_reads_and_exclude_retirement() {
        use std::time::{Duration, Instant};

        let directory = tempfile::tempdir().unwrap();
        let descriptor = directory.path().join("snapshot.json");
        std::fs::write(&descriptor, b"descriptor").unwrap();
        let reader = StorageLease::descriptor(&descriptor, false)
            .unwrap()
            .unwrap();
        let clone = reader.clone();
        assert_eq!(std::fs::read(&descriptor).unwrap(), b"descriptor");
        assert!(
            StorageLease::descriptor(&descriptor, true)
                .unwrap()
                .is_none()
        );
        drop(reader);
        assert!(
            StorageLease::descriptor(&descriptor, true)
                .unwrap()
                .is_none()
        );
        drop(clone);
        let deadline = Instant::now() + Duration::from_secs(2);
        let deletion = loop {
            if let Some(lease) = StorageLease::descriptor(&descriptor, true).unwrap() {
                break lease;
            }
            // Parallel tests may fork while this descriptor is live. The child retains
            // the flock briefly until exec closes its inherited descriptor.
            assert!(Instant::now() < deadline, "descriptor remained busy");
            std::thread::sleep(Duration::from_millis(1));
        };
        // Windows must reserve a marker beyond the JSON bytes, not a mandatory lock
        // over bytes that the deleting operation still needs to inspect.
        assert_eq!(std::fs::read(&descriptor).unwrap(), b"descriptor");
        drop(deletion);
    }

    #[test]
    fn readers_exclude_deletion_but_not_unrelated_entries() {
        let directory = tempfile::tempdir().unwrap();
        let a = directory.path().join("a");
        let b = directory.path().join("b");
        let reader = StorageLease::shared(&a).unwrap();
        let clone = reader.clone();
        assert!(StorageLease::try_exclusive(&a).unwrap().is_none());
        assert!(StorageLease::try_exclusive(&b).unwrap().is_some());
        drop(reader);
        assert!(StorageLease::try_exclusive(&a).unwrap().is_none());
        drop(clone);
        assert!(StorageLease::try_exclusive(&a).unwrap().is_some());
    }

    #[test]
    fn replacing_payload_does_not_replace_its_lock() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("snapshot");
        std::fs::create_dir(&path).unwrap();
        let lease = StorageLease::try_exclusive(&path).unwrap().unwrap();
        std::fs::remove_dir(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(StorageLease::try_exclusive(&path).unwrap().is_none());
        drop(lease);
        assert!(StorageLease::try_exclusive(&path).unwrap().is_some());
    }

    #[test]
    fn process_exit_releases_reader_lease() {
        use std::io::{BufRead, BufReader};
        use std::process::{Command, Stdio};
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("resource");
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "storage_lease::tests::child_reader",
                "--ignored",
                "--nocapture",
            ])
            .env("MSB_TEST_STORAGE_LEASE", &path)
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let output = child.stdout.take().unwrap();
        let (sender, receiver) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(output).lines() {
                if line.unwrap().contains("LEASE_READY") {
                    sender.send(()).unwrap();
                    break;
                }
            }
        });
        let ready = receiver.recv_timeout(std::time::Duration::from_secs(15));
        if ready.is_err() {
            let _ = child.kill();
        }
        ready.unwrap();
        assert!(StorageLease::try_exclusive(&path).unwrap().is_none());
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(StorageLease::try_exclusive(&path).unwrap().is_some());
    }

    #[test]
    #[ignore = "subprocess helper, exercised by process_exit_releases_reader_lease"]
    fn child_reader() {
        use std::io::Write;
        let path = PathBuf::from(std::env::var_os("MSB_TEST_STORAGE_LEASE").unwrap());
        let _lease = StorageLease::shared(&path).unwrap();
        println!("LEASE_READY");
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }
}
