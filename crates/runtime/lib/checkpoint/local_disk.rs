//! Exact-file receipts for an owned local disk handoff, not portable snapshot admission.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::SystemTime;

use microsandbox_image::checkpoint::DiskGenerationManifest;
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const RECEIPTS_FILE: &str = "local-disk-admission.json";
const MAX_RECEIPT_BYTES: u64 = 1024 * 1024;
const MAX_RECEIPTS: usize = 32;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DiskReceipt {
    filename: PathBuf,
    root: Option<String>,
    stamp: FileStamp,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct FileStamp {
    identity: (u64, u64),
    length: u64,
    modified: SystemTime,
}

/// Retained handles prevent receipt identities being recycled while constructing the child.
pub(super) struct LocalDiskAdmissions {
    layers: Vec<(File, FileStamp, Option<String>)>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalDiskAdmissions {
    pub(super) fn publish(root: &Path, layers: &[(PathBuf, Option<String>)]) -> io::Result<()> {
        let mut receipts = layers
            .iter()
            .map(|(path, root)| {
                Ok(DiskReceipt {
                    filename: path
                        .file_name()
                        .ok_or_else(|| io::Error::other("invalid local disk path"))?
                        .into(),
                    root: root.clone(),
                    stamp: FileStamp::read(&open_regular(path)?)?,
                })
            })
            .collect::<io::Result<Vec<_>>>()?;
        // Bound retained handles without limiting chain depth. The journal hashes uncached
        // ancestors; keeping the largest physical files retains the expensive base first.
        receipts.sort_by_key(|receipt| std::cmp::Reverse(receipt.stamp.length));
        receipts.truncate(MAX_RECEIPTS);
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(root.join(RECEIPTS_FILE))?;
        serde_json::to_writer(&mut file, &receipts).map_err(io::Error::other)?;
        file.flush()
    }

    pub(super) fn open(root: &Path, disks: &[DiskGenerationManifest]) -> io::Result<Option<Self>> {
        let path = root.join(RECEIPTS_FILE);
        let file = match open_regular(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut bytes = Vec::new();
        file.take(MAX_RECEIPT_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_RECEIPT_BYTES {
            return Err(io::Error::other("local disk receipts exceed size bound"));
        }
        let receipts: Vec<DiskReceipt> =
            serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if receipts.len() > MAX_RECEIPTS {
            return Err(io::Error::other("local disk receipts exceed layer bound"));
        }
        let mut layers = Vec::with_capacity(receipts.len());
        for receipt in receipts {
            let mut components = receipt.filename.components();
            if !matches!(components.next(), Some(Component::Normal(_)))
                || components.next().is_some()
            {
                return Err(io::Error::other(
                    "local disk receipt filename is not confined",
                ));
            }
            let expected = disks.iter().flat_map(|disk| &disk.layers).find(|layer| {
                receipt.filename == Path::new(&format!("{}.{}", layer.layer_id, layer.format))
            });
            if expected.is_none_or(|layer| {
                layer.integrity_root != receipt.root || layer.file_size != receipt.stamp.length
            }) {
                return Err(io::Error::other(
                    "local disk receipt does not match captured disk",
                ));
            }
            let file = open_regular(&root.join("layers").join(&receipt.filename))?;
            if FileStamp::read(&file)? != receipt.stamp {
                return Err(io::Error::other("local disk changed after handoff"));
            }
            layers.push((file, receipt.stamp, receipt.root));
        }
        Ok(Some(Self { layers }))
    }

    pub(super) fn reuse_for(&self, path: &Path) -> Result<Option<String>, String> {
        let candidate = FileStamp::read(&open_regular(path).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        for (file, stamp, root) in &self.layers {
            if FileStamp::read(file).map_err(|e| e.to_string())? != *stamp {
                return Err("local disk changed during child construction".into());
            }
            if candidate.identity == stamp.identity {
                if candidate != *stamp {
                    return Err("local disk binding changed during child construction".into());
                }
                return Ok(root.clone());
            }
        }
        Ok(None)
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

/// Link an immutable file without allowing a conflicting existing alias to select other bytes.
pub(super) fn link_exact(source: &Path, target: &Path) -> io::Result<()> {
    let file = open_regular(source)?;
    let expected = FileStamp::read(&file)?;
    match std::fs::hard_link(source, target) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    if FileStamp::read(&open_regular(target)?)? != expected || FileStamp::read(&file)? != expected {
        return Err(io::Error::other(
            "local disk alias conflicts with captured file",
        ));
    }
    Ok(())
}

fn open_regular(path: &Path) -> io::Result<File> {
    if !std::fs::symlink_metadata(path)?.is_file() {
        return Err(io::Error::other("local disk member is not a regular file"));
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
        use windows_sys::Win32::Storage::FileSystem::{
            FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
        };
        // Rollover captures the quiesced head before replacing its still-open writable backend.
        // Pause ownership, then exact-file stamps, enforce immutability—not Windows sharing.
        options.share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE);
    }
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("local disk member is not regular"));
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
    // The live file owns this handle, and the API initializes its fixed-size output.
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
        "local disk identity unavailable",
    ))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_image::checkpoint::{DiskLayerRef, sparse_file_integrity};

    fn fixture(root: &Path, count: usize) -> DiskGenerationManifest {
        std::fs::create_dir_all(root.join("layers")).unwrap();
        let mut sources = Vec::new();
        let mut layers = Vec::new();
        for index in 0..count {
            let id = format!("layer_{index}");
            let path = root.join("layers").join(format!("{id}.raw"));
            std::fs::write(&path, vec![0x55; index + 1]).unwrap();
            let integrity = sparse_file_integrity(&path).unwrap().root;
            sources.push((path, Some(integrity.clone())));
            layers.push(DiskLayerRef {
                file_size: (index + 1) as u64,
                layer_id: id,
                format: "raw".into(),
                virtual_size: 4096,
                predecessor: None,
                integrity_root: Some(integrity),
            });
        }
        LocalDiskAdmissions::publish(root, &sources).unwrap();
        DiskGenerationManifest {
            schema: "microsandbox.disk-generation/1".into(),
            volume_id: "volume".into(),
            device_id: "vdb".into(),
            generation: 1,
            head: layers.last().unwrap().layer_id.clone(),
            layers,
            pause_generation: 1,
        }
    }

    #[test]
    fn local_receipt_reuses_exact_links_not_copies_and_survives_source_unlink() {
        let dir = tempfile::tempdir().unwrap();
        let disk = fixture(dir.path(), 1);
        let source = dir.path().join("layers/layer_0.raw");
        let linked = dir.path().join("owned.raw");
        let copied = dir.path().join("copied.raw");
        link_exact(&source, &linked).unwrap();
        link_exact(&source, &linked).unwrap();
        std::fs::copy(&source, &copied).unwrap();
        let admissions = LocalDiskAdmissions::open(dir.path(), std::slice::from_ref(&disk))
            .unwrap()
            .unwrap();
        assert_eq!(
            admissions.reuse_for(&linked).unwrap(),
            disk.layers[0].integrity_root.clone()
        );
        assert_eq!(admissions.reuse_for(&copied).unwrap(), None);
        assert!(link_exact(&copied, &linked).is_err());
        std::fs::remove_file(&source).unwrap();
        assert_eq!(
            admissions.reuse_for(&linked).unwrap(),
            disk.layers[0].integrity_root.clone()
        );
    }

    #[test]
    fn local_receipt_rejects_modified_or_replaced_members() {
        for replace in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let disk = fixture(dir.path(), 1);
            let source = dir.path().join("layers/layer_0.raw");
            // Retain the original inode to ensure replacement cannot recycle its identity.
            let _pin = File::open(&source).unwrap();
            if replace {
                std::fs::remove_file(&source).unwrap();
            }
            std::fs::write(&source, b"changed").unwrap();
            assert!(LocalDiskAdmissions::open(dir.path(), &[disk]).is_err());
        }
    }

    #[test]
    fn local_receipt_cache_is_optional_bounded_and_selects_larger_files() {
        let dir = tempfile::tempdir().unwrap();
        let disk = fixture(dir.path(), MAX_RECEIPTS + 1);
        let admissions = LocalDiskAdmissions::open(dir.path(), std::slice::from_ref(&disk))
            .unwrap()
            .unwrap();
        assert_eq!(admissions.layers.len(), MAX_RECEIPTS);
        assert!(
            admissions
                .reuse_for(&dir.path().join("layers/layer_0.raw"))
                .unwrap()
                .is_none()
        );
        assert!(
            admissions
                .reuse_for(&dir.path().join(format!("layers/layer_{MAX_RECEIPTS}.raw")))
                .unwrap()
                .is_some()
        );
        std::fs::remove_file(dir.path().join(RECEIPTS_FILE)).unwrap();
        assert!(
            LocalDiskAdmissions::open(dir.path(), &[disk])
                .unwrap()
                .is_none()
        );
    }
}
