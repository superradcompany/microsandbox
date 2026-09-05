//! Atomic creation of managed qcow2 continuation heads.

use std::io::{Read, Seek, SeekFrom, Write};
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

/// Build a replacement first cluster with a portable backing filename.
///
/// Only the name changes: callers must keep the same predecessor bytes and format. Applying the
/// prefix to a private copy before hashing preserves guest data and never mutates sealed sources.
pub fn relocated_qcow2_header(path: &Path, backing: &Path) -> std::io::Result<Vec<u8>> {
    let invalid = || {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid qcow2 backing header",
        )
    };
    let name = backing
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(invalid)?;
    if name.is_empty() || name.len() > 1023 || name.contains(['/', '\\', '\0']) {
        return Err(invalid());
    }
    let mut file = std::fs::File::open(path)?;
    let mut fixed = [0u8; 32];
    file.read_exact(&mut fixed)?;
    let version = u32::from_be_bytes(fixed[4..8].try_into().unwrap());
    let bits = u32::from_be_bytes(fixed[20..24].try_into().unwrap());
    if &fixed[..4] != b"QFI\xfb" || !matches!(version, 2 | 3) || !(9..=21).contains(&bits) {
        return Err(invalid());
    }
    let cluster_size = 1usize << bits;
    let offset = u64::from_be_bytes(fixed[8..16].try_into().unwrap());
    let old_len = u32::from_be_bytes(fixed[16..20].try_into().unwrap()) as u64;
    if old_len == 0
        || old_len > 1023
        || offset < 72
        || offset > cluster_size as u64
        || old_len > cluster_size as u64 - offset
        || name.len() as u64 > cluster_size as u64 - offset
    {
        return Err(invalid());
    }
    let mut header = vec![0u8; cluster_size];
    file.seek(SeekFrom::Start(0))?;
    file.read_exact(&mut header)?;
    let header_len = if version == 3 {
        u32::from_be_bytes(header[100..104].try_into().unwrap()) as usize
    } else {
        72
    };
    if header_len < if version == 3 { 104 } else { 72 } || header_len > offset as usize {
        return Err(invalid());
    }
    // Extensions precede the backing string. Refuse malformed overlap instead of overwriting
    // format metadata. The qcow2 first cluster is reserved for the header and this string.
    let mut cursor = header_len;
    loop {
        if cursor + 8 > offset as usize {
            return Err(invalid());
        }
        let kind = u32::from_be_bytes(header[cursor..cursor + 4].try_into().unwrap());
        let len = u32::from_be_bytes(header[cursor + 4..cursor + 8].try_into().unwrap()) as usize;
        cursor += 8;
        if kind == 0 {
            break;
        }
        cursor = cursor
            .checked_add(len)
            .and_then(|n| n.checked_add(7))
            .ok_or_else(invalid)?
            & !7;
    }
    let offset = offset as usize;
    header[offset..offset + old_len as usize].fill(0);
    header[offset..offset + name.len()].copy_from_slice(name.as_bytes());
    header[16..20].copy_from_slice(&(name.len() as u32).to_be_bytes());
    Ok(header)
}

/// Update the backing filename of an unpublished, exclusively owned qcow2 copy.
pub fn relocate_qcow2_backing(path: &Path, backing: &Path) -> std::io::Result<()> {
    let header = relocated_qcow2_header(path, backing)?;
    let mut file = std::fs::OpenOptions::new().write(true).open(path)?;
    file.write_all(&header)?;
    file.sync_all()
}

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
    use super::{create_qcow2_overlay, relocate_qcow2_backing, relocated_qcow2_header};

    use imago::file::File as ImagoFile;
    use imago::format::drivers::FormatDriverInstance;
    use imago::qcow2::Qcow2;
    use imago::{DenyImplicitOpenGate, FormatDriverBuilder};

    #[tokio::test]
    async fn relocation_preserves_source_and_non_header_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("source.qcow2");
        create_qcow2_overlay(
            &source,
            16 * 1024 * 1024,
            std::path::Path::new("old.raw"),
            "raw",
        )
        .await
        .unwrap();
        let original = std::fs::read(&source).unwrap();
        let copy = dir.path().join("copy.qcow2");
        std::fs::copy(&source, &copy).unwrap();
        let backing = std::path::Path::new("layer_00000000000000000000000000000001.raw");
        let prefix = relocated_qcow2_header(&source, backing).unwrap();
        relocate_qcow2_backing(&copy, backing).unwrap();
        let relocated = std::fs::read(&copy).unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), original);
        assert_eq!(&relocated[..prefix.len()], prefix);
        assert_eq!(&relocated[prefix.len()..], &original[prefix.len()..]);
        let storage = ImagoFile::try_from(std::fs::File::open(&copy).unwrap()).unwrap();
        let image = Qcow2::<ImagoFile>::builder(storage)
            .backing(None)
            .data_file(None)
            .open(DenyImplicitOpenGate::default())
            .await
            .unwrap();
        assert_eq!(
            image.implicit_backing_file().map(String::as_str),
            backing.to_str()
        );
        assert_eq!(image.size(), 16 * 1024 * 1024);
    }

    #[test]
    fn relocation_rejects_corrupt_or_overflowing_headers_without_writing() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("bad.qcow2");
        let mut bytes = vec![0u8; 512];
        bytes[..4].copy_from_slice(b"QFI\xfb");
        bytes[4..8].copy_from_slice(&3u32.to_be_bytes());
        bytes[8..16].copy_from_slice(&u64::MAX.to_be_bytes());
        bytes[16..20].copy_from_slice(&10u32.to_be_bytes());
        bytes[20..24].copy_from_slice(&9u32.to_be_bytes());
        std::fs::write(&path, &bytes).unwrap();
        assert!(relocate_qcow2_backing(&path, std::path::Path::new("base.raw")).is_err());
        assert_eq!(std::fs::read(path).unwrap(), bytes);
    }

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
