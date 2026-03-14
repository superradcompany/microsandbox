//! Layer extraction pipeline.
//!
//! Two-pass async extraction using `async-compression` + `astral-tokio-tar`.
//! Handles stat virtualization via `user.containers.override_stat` xattr,
//! platform-aware symlinks, special file handling, and whiteout markers.

use std::{
    io::Read,
    path::{Component, Path, PathBuf},
};

use async_compression::tokio::bufread::{GzipDecoder, ZstdDecoder};
use tokio::io::{AsyncRead, BufReader};
use tokio_tar as tar;

use super::OVERRIDE_XATTR_KEY;
use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Binary format version for OverrideStat.
const OVERRIDE_STAT_VERSION: u8 = 1;

/// Maximum total extracted size (10 GiB).
const MAX_TOTAL_SIZE: u64 = 10 * 1024 * 1024 * 1024;

/// Maximum single file size (5 GiB).
const MAX_FILE_SIZE: u64 = 5 * 1024 * 1024 * 1024;

/// Maximum number of tar entries.
const MAX_ENTRY_COUNT: u64 = 1_000_000;

/// Maximum path depth.
const MAX_PATH_DEPTH: usize = 128;

/// File type bits (from libc).
const S_IFREG: u32 = libc::S_IFREG as u32;
const S_IFDIR: u32 = libc::S_IFDIR as u32;
const S_IFLNK: u32 = libc::S_IFLNK as u32;
const S_IFBLK: u32 = libc::S_IFBLK as u32;
const S_IFCHR: u32 = libc::S_IFCHR as u32;
const S_IFIFO: u32 = libc::S_IFIFO as u32;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Deferred hardlink to create in the second pass.
struct DeferredHardlink {
    path: PathBuf,
    target: PathBuf,
}

/// Compression format for a layer blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LayerCompression {
    Plain,
    Gzip,
    Zstd,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Extract a compressed layer tarball to a directory.
///
/// Two-pass extraction:
/// 1. Files, directories, symlinks, and special files (with xattr stat virtualization).
/// 2. Hard links (targets must exist from pass 1).
pub(crate) async fn extract_layer(
    tar_path: &Path,
    dest: &Path,
    parent_layers: &[PathBuf],
    media_type: Option<&str>,
) -> ImageResult<()> {
    use tar::Archive;

    let compression = detect_layer_compression(tar_path, media_type)?;

    let file = tokio::fs::File::open(tar_path)
        .await
        .map_err(|e| ImageError::Extraction {
            digest: tar_path.display().to_string(),
            message: format!("failed to open tarball: {e}"),
            source: Some(Box::new(e)),
        })?;
    let archive_reader: Box<dyn AsyncRead + Unpin + Send> = match compression {
        LayerCompression::Plain => Box::new(BufReader::new(file)),
        LayerCompression::Gzip => Box::new(BufReader::new(GzipDecoder::new(BufReader::new(file)))),
        LayerCompression::Zstd => Box::new(BufReader::new(ZstdDecoder::new(BufReader::new(file)))),
    };
    let mut archive = Archive::new(archive_reader);

    let mut deferred_hardlinks: Vec<DeferredHardlink> = Vec::new();
    let mut total_size: u64 = 0;
    let mut entry_count: u64 = 0;

    let mut entries = archive.entries().map_err(|e| ImageError::Extraction {
        digest: tar_path.display().to_string(),
        message: format!("failed to read tar entries: {e}"),
        source: Some(Box::new(e)),
    })?;

    use futures::StreamExt;

    // Pass 1: Regular files, directories, symlinks, special files.
    while let Some(entry_result) = entries.next().await {
        let mut entry = entry_result.map_err(|e| ImageError::Extraction {
            digest: tar_path.display().to_string(),
            message: format!("failed to read tar entry: {e}"),
            source: Some(Box::new(e)),
        })?;

        entry_count += 1;
        if entry_count > MAX_ENTRY_COUNT {
            return Err(ImageError::Extraction {
                digest: tar_path.display().to_string(),
                message: format!("exceeded max entry count ({MAX_ENTRY_COUNT})"),
                source: None,
            });
        }

        let header = entry.header().clone();
        let entry_path = entry
            .path()
            .map_err(|e| ImageError::Extraction {
                digest: tar_path.display().to_string(),
                message: format!("invalid entry path: {e}"),
                source: Some(Box::new(e)),
            })?
            .into_owned();

        // Validate path.
        let full_path = validate_entry_path(dest, &entry_path, tar_path)?;

        let uid = header.uid().unwrap_or(0) as u32;
        let gid = header.gid().unwrap_or(0) as u32;
        let tar_mode = header.mode().unwrap_or(0o644);
        let size = header.size().unwrap_or(0);

        let entry_type = header.entry_type();

        // Check for hardlink — defer to pass 2.
        if entry_type == tar::EntryType::Link {
            if let Ok(Some(link_target)) = entry.link_name() {
                let target_full = validate_entry_path(dest, &link_target, tar_path)?;
                deferred_hardlinks.push(DeferredHardlink {
                    path: full_path,
                    target: target_full,
                });
            }
            continue;
        }

        if entry_type == tar::EntryType::Directory {
            // Directory.
            if !full_path.exists() {
                std::fs::create_dir_all(&full_path).map_err(|e| extraction_err(tar_path, e))?;
            }
            // Set host permissions: u+rwx minimum.
            set_host_permissions(&full_path, 0o700)?;
            // Set stat xattr.
            let mode = S_IFDIR | (tar_mode & 0o7777);
            set_override_stat(&full_path, uid, gid, mode, 0)?;
        } else if entry_type == tar::EntryType::Symlink {
            let link_target = entry
                .link_name()
                .map_err(|e| extraction_err(tar_path, e))?
                .map(|p| p.into_owned())
                .unwrap_or_default();

            // Ensure parent directory exists.
            ensure_parent_dir(&full_path, dest, parent_layers)?;

            let mode = S_IFLNK | 0o777;

            if cfg!(target_os = "linux") {
                // Linux: store as regular file with content = target path.
                // (xattrs can't be set on symlinks on most Linux filesystems.)
                if let Some(parent) = full_path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| extraction_err(tar_path, e))?;
                }
                // Remove any existing entry (could be a directory from a lower layer).
                let _ = std::fs::remove_dir_all(&full_path);
                let _ = std::fs::remove_file(&full_path);
                std::fs::write(&full_path, link_target.as_os_str().as_encoded_bytes())
                    .map_err(|e| extraction_err(tar_path, e))?;
                set_host_permissions(&full_path, 0o600)?;
                set_override_stat(&full_path, uid, gid, mode, 0)?;
            } else {
                // macOS: real symlink with XATTR_NOFOLLOW.
                if let Some(parent) = full_path.parent() {
                    std::fs::create_dir_all(parent).map_err(|e| extraction_err(tar_path, e))?;
                }
                // Remove any existing file at the target.
                let _ = std::fs::remove_file(&full_path);
                std::os::unix::fs::symlink(&link_target, &full_path)
                    .map_err(|e| extraction_err(tar_path, e))?;
                set_override_stat_symlink(&full_path, uid, gid, mode, 0)?;
            }
        } else if entry_type == tar::EntryType::Regular || entry_type == tar::EntryType::Continuous
        {
            // Regular file.
            if size > MAX_FILE_SIZE {
                return Err(ImageError::Extraction {
                    digest: tar_path.display().to_string(),
                    message: format!("file too large: {} bytes (max {MAX_FILE_SIZE})", size),
                    source: None,
                });
            }
            total_size += size;
            if total_size > MAX_TOTAL_SIZE {
                return Err(ImageError::Extraction {
                    digest: tar_path.display().to_string(),
                    message: format!("total extraction size exceeded {MAX_TOTAL_SIZE} bytes"),
                    source: None,
                });
            }

            ensure_parent_dir(&full_path, dest, parent_layers)?;

            let mut file = tokio::fs::File::create(&full_path)
                .await
                .map_err(|e| extraction_err(tar_path, e))?;
            tokio::io::copy(&mut entry, &mut file)
                .await
                .map_err(|e| extraction_err(tar_path, e))?;
            drop(file);

            set_host_permissions(&full_path, 0o600)?;
            let mode = S_IFREG | (tar_mode & 0o7777);
            set_override_stat(&full_path, uid, gid, mode, 0)?;
        } else if entry_type == tar::EntryType::Block || entry_type == tar::EntryType::Char {
            // Block/char device: store as empty regular file with device info in xattr.
            ensure_parent_dir(&full_path, dest, parent_layers)?;
            std::fs::write(&full_path, b"").map_err(|e| extraction_err(tar_path, e))?;
            set_host_permissions(&full_path, 0o600)?;

            let major = header.device_major().unwrap_or(None).unwrap_or(0);
            let minor = header.device_minor().unwrap_or(None).unwrap_or(0);
            let rdev = makedev(major, minor);
            let type_bits = if entry_type == tar::EntryType::Block {
                S_IFBLK
            } else {
                S_IFCHR
            };
            let mode = type_bits | (tar_mode & 0o7777);
            set_override_stat(&full_path, uid, gid, mode, rdev)?;
        } else if entry_type == tar::EntryType::Fifo {
            // FIFO: store as empty regular file.
            ensure_parent_dir(&full_path, dest, parent_layers)?;
            std::fs::write(&full_path, b"").map_err(|e| extraction_err(tar_path, e))?;
            set_host_permissions(&full_path, 0o600)?;
            let mode = S_IFIFO | (tar_mode & 0o7777);
            set_override_stat(&full_path, uid, gid, mode, 0)?;
        }
        // Skip other types (GNUSparse, XHeader, etc.)
    }

    // Pass 2: Hard links.
    for hl in deferred_hardlinks {
        if !hl.target.exists() {
            tracing::warn!(
                target = %hl.target.display(),
                link = %hl.path.display(),
                "hardlink target not found, skipping"
            );
            continue;
        }
        ensure_parent_dir(&hl.path, dest, parent_layers)?;
        let _ = std::fs::remove_file(&hl.path);
        std::fs::hard_link(&hl.target, &hl.path).map_err(|e| ImageError::Extraction {
            digest: tar_path.display().to_string(),
            message: format!(
                "failed to create hardlink {} -> {}: {e}",
                hl.path.display(),
                hl.target.display()
            ),
            source: Some(Box::new(e)),
        })?;
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Validate a tar entry path to prevent path traversal.
fn validate_entry_path(dest: &Path, entry_path: &Path, tar_path: &Path) -> ImageResult<PathBuf> {
    // Reject absolute paths.
    if entry_path.is_absolute() {
        return Err(ImageError::Extraction {
            digest: tar_path.display().to_string(),
            message: format!("absolute path in tar entry: {}", entry_path.display()),
            source: None,
        });
    }

    // Reject .. components.
    let mut depth = 0usize;
    for component in entry_path.components() {
        match component {
            Component::ParentDir => {
                return Err(ImageError::Extraction {
                    digest: tar_path.display().to_string(),
                    message: format!("path traversal in tar entry: {}", entry_path.display()),
                    source: None,
                });
            }
            Component::Normal(_) => {
                depth += 1;
                if depth > MAX_PATH_DEPTH {
                    return Err(ImageError::Extraction {
                        digest: tar_path.display().to_string(),
                        message: format!(
                            "path too deep ({depth} components): {}",
                            entry_path.display()
                        ),
                        source: None,
                    });
                }
            }
            _ => {}
        }
    }

    let full_path = dest.join(entry_path);
    ensure_host_path_contained(dest, &full_path, tar_path)?;
    Ok(full_path)
}

/// Ensure parent directories exist, searching parent layers if needed.
fn ensure_parent_dir(path: &Path, dest: &Path, parent_layers: &[PathBuf]) -> ImageResult<()> {
    if let Some(parent) = path.parent() {
        if parent.exists() {
            return Ok(());
        }

        // Walk up to find the first missing ancestor.
        let mut missing = Vec::new();
        let mut current = parent.to_path_buf();
        while !current.exists() && current != *dest {
            missing.push(current.clone());
            if let Some(p) = current.parent() {
                current = p.to_path_buf();
            } else {
                break;
            }
        }

        // Create missing directories, copying xattrs from parent layers if found.
        for dir in missing.into_iter().rev() {
            std::fs::create_dir_all(&dir).map_err(|e| ImageError::Extraction {
                digest: String::new(),
                message: format!("failed to create dir {}: {e}", dir.display()),
                source: Some(Box::new(e)),
            })?;

            // Try to copy xattrs from a parent layer.
            if let Ok(rel) = dir.strip_prefix(dest) {
                for parent_dir in parent_layers.iter().rev() {
                    let parent_path = parent_dir.join(rel);
                    if parent_path.exists() {
                        // Copy the override stat xattr.
                        if let Ok(Some(data)) = xattr::get(&parent_path, OVERRIDE_XATTR_KEY) {
                            let _ = xattr::set(&dir, OVERRIDE_XATTR_KEY, &data);
                        }
                        break;
                    }
                }
            }

            set_host_permissions(&dir, 0o700)?;
        }
    }
    Ok(())
}

/// Set host file permissions (minimum readable/writable by owner).
fn set_host_permissions(path: &Path, mode: u32) -> ImageResult<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).map_err(|e| {
        ImageError::Extraction {
            digest: String::new(),
            message: format!("failed to set permissions on {}: {e}", path.display()),
            source: Some(Box::new(e)),
        }
    })
}

/// Serialize an `OverrideStat` into a 20-byte xattr value.
fn override_stat_bytes(uid: u32, gid: u32, mode: u32, rdev: u32) -> [u8; 20] {
    let mut buf = [0u8; 20];
    buf[0] = OVERRIDE_STAT_VERSION;
    // buf[1..4] is padding (already zeroed)
    buf[4..8].copy_from_slice(&uid.to_le_bytes());
    buf[8..12].copy_from_slice(&gid.to_le_bytes());
    buf[12..16].copy_from_slice(&mode.to_le_bytes());
    buf[16..20].copy_from_slice(&rdev.to_le_bytes());
    buf
}

/// Set the `user.containers.override_stat` xattr on a regular file or directory.
fn set_override_stat(path: &Path, uid: u32, gid: u32, mode: u32, rdev: u32) -> ImageResult<()> {
    let bytes = override_stat_bytes(uid, gid, mode, rdev);

    xattr::set(path, OVERRIDE_XATTR_KEY, &bytes).map_err(|e| ImageError::Extraction {
        digest: String::new(),
        message: format!("failed to set xattr on {}: {e}", path.display()),
        source: Some(Box::new(e)),
    })
}

/// Set the override stat xattr on a symlink (macOS only, uses XATTR_NOFOLLOW).
#[cfg(target_os = "macos")]
fn set_override_stat_symlink(
    path: &Path,
    uid: u32,
    gid: u32,
    mode: u32,
    rdev: u32,
) -> ImageResult<()> {
    let bytes = override_stat_bytes(uid, gid, mode, rdev);

    // Use lsetxattr on symlinks.
    use std::{ffi::CString, os::unix::ffi::OsStrExt};
    let c_path = CString::new(path.as_os_str().as_bytes()).map_err(|e| ImageError::Extraction {
        digest: String::new(),
        message: format!("invalid path for xattr: {e}"),
        source: None,
    })?;
    let c_name = CString::new(OVERRIDE_XATTR_KEY).unwrap();

    // macOS: setxattr with XATTR_NOFOLLOW option
    let ret = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            bytes.as_ptr() as *const libc::c_void,
            bytes.len(),
            0, // position
            libc::XATTR_NOFOLLOW,
        )
    };
    if ret != 0 {
        let e = std::io::Error::last_os_error();
        return Err(ImageError::Extraction {
            digest: String::new(),
            message: format!("failed to set xattr on symlink {}: {e}", path.display()),
            source: Some(Box::new(e)),
        });
    }
    Ok(())
}

#[cfg(not(target_os = "macos"))]
fn set_override_stat_symlink(
    _path: &Path,
    _uid: u32,
    _gid: u32,
    _mode: u32,
    _rdev: u32,
) -> ImageResult<()> {
    // On Linux, symlinks are stored as regular files with S_IFLNK in the xattr.
    // set_override_stat() is called on the regular file, not the symlink.
    Ok(())
}

/// Construct a device number from major and minor (glibc-compatible encoding).
fn makedev(major: u32, minor: u32) -> u32 {
    ((major & 0xFFF) << 8) | (minor & 0xFF) | ((minor & 0xFFFFF00) << 12)
}

fn extraction_err(
    tar_path: &Path,
    e: impl Into<Box<dyn std::error::Error + Send + Sync>>,
) -> ImageError {
    let source = e.into();
    ImageError::Extraction {
        digest: tar_path.display().to_string(),
        message: source.to_string(),
        source: Some(source),
    }
}

/// Ensure the deepest existing ancestor of `path` still resolves under `dest`.
fn ensure_host_path_contained(dest: &Path, path: &Path, tar_path: &Path) -> ImageResult<()> {
    let root = std::fs::canonicalize(dest).map_err(|e| ImageError::Extraction {
        digest: tar_path.display().to_string(),
        message: format!(
            "failed to canonicalize extraction root {}: {e}",
            dest.display()
        ),
        source: Some(Box::new(e)),
    })?;

    let mut ancestor = path;
    while !ancestor.exists() {
        ancestor = ancestor.parent().ok_or_else(|| ImageError::Extraction {
            digest: tar_path.display().to_string(),
            message: format!("invalid extraction path: {}", path.display()),
            source: None,
        })?;
    }

    let canonical_ancestor =
        std::fs::canonicalize(ancestor).map_err(|e| ImageError::Extraction {
            digest: tar_path.display().to_string(),
            message: format!("failed to canonicalize {}: {e}", ancestor.display()),
            source: Some(Box::new(e)),
        })?;

    if !canonical_ancestor.starts_with(&root) {
        return Err(ImageError::Extraction {
            digest: tar_path.display().to_string(),
            message: format!(
                "tar entry escapes extraction root via symlinked ancestor: {}",
                path.display()
            ),
            source: None,
        });
    }

    Ok(())
}

/// Detect the compression format for a layer blob.
fn detect_layer_compression(
    tar_path: &Path,
    media_type: Option<&str>,
) -> ImageResult<LayerCompression> {
    if let Some(media_type) = media_type {
        if media_type.contains("zstd") {
            return Ok(LayerCompression::Zstd);
        }
        if media_type.contains("gzip") {
            return Ok(LayerCompression::Gzip);
        }
        if media_type.contains(".tar") {
            return Ok(LayerCompression::Plain);
        }
    }

    let mut file = std::fs::File::open(tar_path).map_err(|e| ImageError::Extraction {
        digest: tar_path.display().to_string(),
        message: format!("failed to open tarball for compression detection: {e}"),
        source: Some(Box::new(e)),
    })?;
    let mut header = [0u8; 4];
    let read = file.read(&mut header).map_err(|e| ImageError::Extraction {
        digest: tar_path.display().to_string(),
        message: format!("failed to read tarball header: {e}"),
        source: Some(Box::new(e)),
    })?;

    if read >= 2 && header[..2] == [0x1F, 0x8B] {
        return Ok(LayerCompression::Gzip);
    }
    if read == 4 && header == [0x28, 0xB5, 0x2F, 0xFD] {
        return Ok(LayerCompression::Zstd);
    }

    Ok(LayerCompression::Plain)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;

    use tempfile::tempdir;

    use super::{LayerCompression, detect_layer_compression, validate_entry_path};

    #[test]
    fn test_detect_layer_compression_from_media_type() {
        assert_eq!(
            detect_layer_compression(
                Path::new("/nonexistent"),
                Some("application/vnd.oci.image.layer.v1.tar+gzip")
            )
            .unwrap(),
            LayerCompression::Gzip,
        );
        assert_eq!(
            detect_layer_compression(
                Path::new("/nonexistent"),
                Some("application/vnd.oci.image.layer.v1.tar+zstd")
            )
            .unwrap(),
            LayerCompression::Zstd,
        );
        assert_eq!(
            detect_layer_compression(
                Path::new("/nonexistent"),
                Some("application/vnd.oci.image.layer.v1.tar")
            )
            .unwrap(),
            LayerCompression::Plain,
        );
    }

    #[test]
    fn test_validate_entry_path_rejects_symlink_escape() {
        let temp = tempdir().unwrap();
        let root = temp.path().join("root");
        let outside = temp.path().join("outside");
        std::fs::create_dir(&root).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("escape")).unwrap();

        let err = validate_entry_path(&root, Path::new("escape/file.txt"), Path::new("layer.tar"))
            .unwrap_err();
        assert!(err.to_string().contains("escapes extraction root"));
    }
}
