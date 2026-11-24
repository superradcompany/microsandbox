//! Host-local OCI cache ownership for a snapshot copy.

use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::context::local::LocalContext;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const FILENAME: &str = "image-cache.json";
pub(crate) const INDEX_BINDING: &str = "oci-image-cache:v1";
const BINDINGS_DIR: &str = "snapshot-bindings";
const BUNDLES_DIR: &str = "snapshot-bundles";
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

pub(super) fn read_managed(
    local: &LocalContext,
    artifact: &Path,
    digest: &str,
) -> MicrosandboxResult<Option<PathBuf>> {
    let Some(cache_dir) = read(artifact, digest)? else {
        return Ok(None);
    };
    let managed = is_managed_snapshot_path(&local.snapshots_dir(), artifact);
    let resolved_cache = match local.resolve_image_cache_dir(Some(&cache_dir)) {
        Ok(resolved) => resolved,
        Err(_) if !managed => return Ok(None),
        Err(error) => return Err(error),
    };
    if !has_binding(&resolved_cache, digest)? {
        return if managed {
            Err(invalid_binding(&artifact.join(FILENAME)))
        } else {
            Ok(None)
        };
    }
    Ok(Some(resolved_cache))
}

/// Write only inside publication-owned staging, before the directory becomes visible.
pub(super) fn write(artifact: &Path, digest: &str, cache_dir: &Path) -> MicrosandboxResult<()> {
    let path = artifact.join(FILENAME);
    if !cache_dir.is_absolute() {
        return Err(invalid_binding(&path));
    }
    record_binding(cache_dir, digest)?;
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
    record_receipt(cache_dir, BUNDLES_DIR, digest, Some(created))
}

pub(super) fn has_bundle(cache_dir: &Path, digest: &str) -> MicrosandboxResult<bool> {
    has_receipt(cache_dir, BUNDLES_DIR, digest)
}

fn record_binding(cache_dir: &Path, digest: &str) -> MicrosandboxResult<()> {
    record_receipt(cache_dir, BINDINGS_DIR, digest, None)
}

fn has_binding(cache_dir: &Path, digest: &str) -> MicrosandboxResult<bool> {
    has_receipt(cache_dir, BINDINGS_DIR, digest)
}

fn record_receipt(
    cache_dir: &Path,
    subdir: &str,
    digest: &str,
    created: Option<&mut Vec<PathBuf>>,
) -> MicrosandboxResult<()> {
    let receipt = receipt_path(cache_dir, subdir, digest)?;
    let directory = receipt.parent().expect("receipt directory");
    std::fs::create_dir_all(directory)?;
    match std::fs::File::options()
        .write(true)
        .create_new(true)
        .open(&receipt)
    {
        Ok(file) => {
            if let Some(created) = created {
                created.push(receipt.clone());
            }
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

fn has_receipt(cache_dir: &Path, subdir: &str, digest: &str) -> MicrosandboxResult<bool> {
    let receipt = receipt_path(cache_dir, subdir, digest)?;
    match std::fs::symlink_metadata(receipt) {
        Ok(metadata) => Ok(metadata.file_type().is_file() && metadata.len() == 0),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn receipt_path(cache_dir: &Path, subdir: &str, digest: &str) -> MicrosandboxResult<PathBuf> {
    let digest: microsandbox_image::Digest = digest.parse()?;
    Ok(cache_dir.join(subdir).join(digest.to_path_safe()))
}

fn is_managed_snapshot_path(snapshots_dir: &Path, artifact: &Path) -> bool {
    let Ok(managed_root) = std::fs::canonicalize(snapshots_dir) else {
        return false;
    };
    let Ok(resolved_artifact) = std::fs::canonicalize(artifact) else {
        return false;
    };
    resolved_artifact != managed_root && resolved_artifact.starts_with(&managed_root)
}

fn invalid_binding(path: &Path) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(format!(
        "invalid local image cache binding: {}",
        path.display()
    ))
}
