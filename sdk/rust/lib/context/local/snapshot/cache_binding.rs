//! Host-local OCI cache ownership for a snapshot copy.

use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const FILENAME: &str = "image-cache.json";
pub(crate) const INDEX_BINDING: &str = "oci-image-cache:v1";
const MAX_BYTES: u64 = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct CacheBinding {
    descriptor_digest: String,
    cache_dir: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn read(artifact: &Path, digest: &str) -> MicrosandboxResult<Option<PathBuf>> {
    let path = artifact.join(FILENAME);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = match options.open(&path) {
        Ok(file) if file.metadata()?.file_type().is_file() => file,
        Ok(_) => return Err(invalid_binding(&path)),
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid_binding(&path));
    }
    let binding: CacheBinding = serde_json::from_slice(&bytes)?;
    if binding.descriptor_digest != digest || !binding.cache_dir.is_absolute() {
        return Err(invalid_binding(&path));
    }
    Ok(Some(binding.cache_dir))
}

/// Write only inside publication-owned staging, before the directory becomes visible.
pub(super) fn write(artifact: &Path, digest: &str, cache_dir: &Path) -> MicrosandboxResult<()> {
    let path = artifact.join(FILENAME);
    if !cache_dir.is_absolute() {
        return Err(invalid_binding(&path));
    }
    if let Some(existing) = read(artifact, digest)? {
        return if existing == cache_dir {
            Ok(())
        } else {
            Err(invalid_binding(&path))
        };
    }
    let binding = CacheBinding {
        descriptor_digest: digest.to_owned(),
        cache_dir: cache_dir.to_path_buf(),
    };
    let bytes = serde_json::to_vec(&binding)?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err(invalid_binding(&path));
    }
    let mut file = std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(path)?;
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Record that this host verified a bundle for this exact snapshot descriptor.
pub(super) fn record_bundle(
    cache_dir: &Path,
    digest: &str,
    created: &mut Vec<PathBuf>,
) -> MicrosandboxResult<()> {
    let receipt = bundle_receipt(cache_dir, digest)?;
    let directory = receipt.parent().expect("receipt directory");
    std::fs::create_dir_all(directory)?;
    match std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(&receipt)
    {
        Ok(file) => {
            created.push(receipt.clone());
            file.sync_all()?;
        }
        Err(error) if error.kind() == ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error.into()),
    }
    #[cfg(unix)]
    {
        std::fs::File::open(directory)?.sync_all()?;
        std::fs::File::open(cache_dir)?.sync_all()?;
    }
    Ok(())
}

pub(super) fn has_bundle(cache_dir: &Path, digest: &str) -> MicrosandboxResult<bool> {
    let receipt = bundle_receipt(cache_dir, digest)?;
    match std::fs::symlink_metadata(receipt) {
        Ok(metadata) => Ok(metadata.file_type().is_file() && metadata.len() == 0),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn bundle_receipt(cache_dir: &Path, digest: &str) -> MicrosandboxResult<PathBuf> {
    let digest: microsandbox_image::Digest = digest.parse()?;
    Ok(cache_dir
        .join("snapshot-bundles")
        .join(digest.to_path_safe()))
}

fn invalid_binding(path: &Path) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(format!(
        "invalid local image cache binding: {}",
        path.display()
    ))
}
