//! In-process reuse of a verified immutable disk file, never a path-only verification cache.

use std::fs::{File, Metadata, OpenOptions};
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::SystemTime;

use super::sparse_file_integrity;
use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Admission still checks every layer; only this many file handles are kept for hash reuse.
const MAX_ADMITTED_DISK_FILES: usize = 32;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A bounded optimization cache, not a limit on the number of admitted disk layers.
#[derive(Clone, Debug, Default)]
pub(super) struct AdmittedDiskLayers {
    layers: Vec<AdmittedDiskLayer>,
}

/// A file handle keeps the admitted inode alive even if its original name is removed.
#[derive(Clone, Debug)]
struct AdmittedDiskLayer {
    file: Arc<File>,
    stamp: FileStamp,
    root: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FileStamp {
    identity: (u64, u64),
    length: u64,
    modified: SystemTime,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AdmittedDiskLayers {
    pub(super) fn admit(&mut self, path: &Path, expected: &str) -> ImageResult<()> {
        // Always verify, even when the resulting receipt will not fit in the cache. Retaining
        // the largest physical files usually keeps the expensive base disk rather than tiny
        // overlays; uncached layers simply take the caller's normal fresh-hash path.
        let layer = AdmittedDiskLayer::admit(path, expected)?;
        if self.layers.len() < MAX_ADMITTED_DISK_FILES {
            self.layers.push(layer);
        } else if let Some((index, smallest)) = self
            .layers
            .iter()
            .enumerate()
            .min_by_key(|(_, candidate)| candidate.stamp.length)
            && layer.stamp.length > smallest.stamp.length
        {
            self.layers[index] = layer;
        }
        Ok(())
    }

    pub(super) fn reuse_for(&self, path: &Path) -> ImageResult<Option<&str>> {
        if self.layers.is_empty() {
            return Ok(None);
        }
        // Open once per candidate, not once per admitted ancestor. The remaining checks are
        // bounded by the cache size, including detection of a changed retained inode.
        let candidate = FileStamp::read(&open_regular(path)?)?;
        for layer in &self.layers {
            if let Some(root) = layer.reuse_for(&candidate)? {
                return Ok(Some(root));
            }
        }
        Ok(None)
    }
}

impl AdmittedDiskLayer {
    fn admit(path: &Path, expected: &str) -> ImageResult<Self> {
        let file = open_regular(path)?;
        let stamp = FileStamp::read(&file)?;
        let integrity = sparse_file_integrity(path)?;
        if integrity.root != expected {
            return Err(ImageError::DigestMismatch {
                digest: path.display().to_string(),
                expected: expected.into(),
                actual: integrity.root,
            });
        }
        // Cooperative writers never mutate sealed files. Detect accidental replacement or a
        // concurrent writer before binding the computed root to this exact owned file.
        if FileStamp::read(&file)? != stamp || FileStamp::read(&open_regular(path)?)? != stamp {
            return Err(io::Error::other("disk layer changed during admission").into());
        }
        Ok(Self {
            file: Arc::new(file),
            stamp,
            root: expected.into(),
        })
    }

    fn reuse_for(&self, candidate: &FileStamp) -> ImageResult<Option<&str>> {
        // A copied or header-relocated layer needs a fresh identity, but an admitted sealed
        // inode changing is corruption. Never bless its replacement contents as a new root.
        if FileStamp::read(&self.file)? != self.stamp
            || (candidate.identity == self.stamp.identity && *candidate != self.stamp)
        {
            return Err(io::Error::other("admitted disk layer was modified").into());
        }
        if *candidate == self.stamp {
            Ok(Some(&self.root))
        } else {
            Ok(None)
        }
    }
}

impl FileStamp {
    fn read(file: &File) -> io::Result<Self> {
        let metadata = file.metadata()?;
        Ok(Self {
            identity: file_identity(file, &metadata)?,
            length: metadata.len(),
            modified: metadata.modified()?,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn open_regular(path: &Path) -> io::Result<File> {
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::other("disk layer is not a regular file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ};
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_DELETE);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("disk layer is not a regular file"));
    }
    Ok(file)
}

#[cfg(unix)]
fn file_identity(_file: &File, metadata: &Metadata) -> io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(windows)]
fn file_identity(file: &File, _metadata: &Metadata) -> io::Result<(u64, u64)> {
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
    };
    let mut info: BY_HANDLE_FILE_INFORMATION = unsafe { std::mem::zeroed() };
    // The live File owns this handle; the API fills the complete fixed-size output structure.
    if unsafe { GetFileInformationByHandle(file.as_raw_handle(), &mut info) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok((
        u64::from(info.dwVolumeSerialNumber),
        u64::from(info.nFileIndexHigh) << 32 | u64::from(info.nFileIndexLow),
    ))
}

#[cfg(not(any(unix, windows)))]
fn file_identity(_file: &File, _metadata: &Metadata) -> io::Result<(u64, u64)> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "disk file identity is unavailable",
    ))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admission_reuses_a_hardlink_but_not_a_copy_or_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let linked = dir.path().join("linked");
        let copied = dir.path().join("copied");
        std::fs::write(&source, b"sealed disk").unwrap();
        let root = sparse_file_integrity(&source).unwrap().root;
        let mut admitted = AdmittedDiskLayers::default();
        admitted.admit(&source, &root).unwrap();
        std::fs::hard_link(&source, &linked).unwrap();
        std::fs::copy(&source, &copied).unwrap();
        assert_eq!(admitted.reuse_for(&linked).unwrap(), Some(root.as_str()));
        assert_eq!(admitted.reuse_for(&copied).unwrap(), None);
        std::fs::remove_file(&source).unwrap();
        std::fs::write(&source, b"sealed disk").unwrap();
        assert_eq!(admitted.reuse_for(&source).unwrap(), None);
        assert_eq!(admitted.reuse_for(&linked).unwrap(), Some(root.as_str()));
    }

    #[test]
    fn admission_rejects_corruption() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        std::fs::write(&source, b"original").unwrap();
        let root = sparse_file_integrity(&source).unwrap().root;
        std::fs::write(&source, b"modified").unwrap();
        assert!(AdmittedDiskLayers::default().admit(&source, &root).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn detected_mutation_is_not_treated_as_an_unrelated_copy() {
        use std::fs::FileTimes;
        use std::time::Duration;

        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source");
        let copy = dir.path().join("copy");
        std::fs::write(&source, b"original").unwrap();
        std::fs::copy(&source, &copy).unwrap();
        let root = sparse_file_integrity(&source).unwrap().root;
        let mut admitted = AdmittedDiskLayers::default();
        admitted.admit(&source, &root).unwrap();
        std::fs::write(&source, b"modified").unwrap();
        let writer = OpenOptions::new().write(true).open(&source).unwrap();
        writer
            .set_times(
                FileTimes::new()
                    .set_modified(admitted.layers[0].stamp.modified + Duration::from_secs(1)),
            )
            .unwrap();
        assert!(admitted.reuse_for(&source).is_err());
        assert!(admitted.reuse_for(&copy).is_err());
    }

    #[test]
    fn receipt_cache_retains_largest_files_and_still_admits_uncached_layers() {
        let dir = tempfile::tempdir().unwrap();
        let mut admitted = AdmittedDiskLayers::default();
        let mut paths = Vec::new();
        for length in 1..=MAX_ADMITTED_DISK_FILES + 3 {
            let path = dir.path().join(format!("layer-{length}"));
            std::fs::write(&path, vec![0x55; length]).unwrap();
            let root = sparse_file_integrity(&path).unwrap().root;
            admitted.admit(&path, &root).unwrap();
            assert!(admitted.layers.len() <= MAX_ADMITTED_DISK_FILES);
            paths.push((path, root));
        }
        assert_eq!(admitted.layers.len(), MAX_ADMITTED_DISK_FILES);
        for (index, (path, root)) in paths.iter().enumerate() {
            let expected = (index >= 3).then_some(root.as_str());
            assert_eq!(admitted.reuse_for(path).unwrap(), expected);
        }

        // The smallest layer will not receive a retained receipt, but its bytes must still
        // pass full admission. A full cache is never permission to skip verification.
        let (smallest, root) = &paths[0];
        std::fs::write(smallest, b"X").unwrap();
        assert!(admitted.admit(smallest, root).is_err());
        assert_eq!(admitted.layers.len(), MAX_ADMITTED_DISK_FILES);
    }
}
