//! Layer extraction pipeline.
//!
//! Two-pass async extraction using `async-compression` + `astral-tokio-tar`.
//! Handles stat virtualization via `user.containers.override_stat` xattr,
//! platform-aware symlinks, special file handling, and whiteout markers.

use std::{
    collections::BTreeSet,
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
#[cfg(target_os = "linux")]
const S_IFREG: u32 = libc::S_IFREG;
#[cfg(target_os = "macos")]
const S_IFREG: u32 = libc::S_IFREG as u32;
#[cfg(target_os = "linux")]
const S_IFDIR: u32 = libc::S_IFDIR;
#[cfg(target_os = "macos")]
const S_IFDIR: u32 = libc::S_IFDIR as u32;
#[cfg(target_os = "linux")]
const S_IFLNK: u32 = libc::S_IFLNK;
#[cfg(target_os = "macos")]
const S_IFLNK: u32 = libc::S_IFLNK as u32;
#[cfg(target_os = "linux")]
const S_IFBLK: u32 = libc::S_IFBLK;
#[cfg(target_os = "macos")]
const S_IFBLK: u32 = libc::S_IFBLK as u32;
#[cfg(target_os = "linux")]
const S_IFCHR: u32 = libc::S_IFCHR;
#[cfg(target_os = "macos")]
const S_IFCHR: u32 = libc::S_IFCHR as u32;
#[cfg(target_os = "linux")]
const S_IFIFO: u32 = libc::S_IFIFO;
#[cfg(target_os = "macos")]
const S_IFIFO: u32 = libc::S_IFIFO as u32;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result of layer extraction.
pub(crate) struct ExtractionResult {
    /// Relative paths of directories created implicitly (not from tar entries).
    ///
    /// These directories were created by `ensure_parent_dir` because a tar entry
    /// referenced a path whose parent didn't exist in this layer. Their xattrs
    /// have default values (uid=0, gid=0, mode=S_IFDIR|0o755) and may need
    /// correction from lower layers in a post-extraction fixup pass.
    pub implicit_dirs: Vec<PathBuf>,
}

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
    media_type: Option<&str>,
) -> ImageResult<ExtractionResult> {
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
    let mut implicit_dirs: BTreeSet<PathBuf> = BTreeSet::new();
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
            clear_implicit_entry(&full_path, dest, &mut implicit_dirs);
        } else if entry_type == tar::EntryType::Symlink {
            let link_target = entry
                .link_name()
                .map_err(|e| extraction_err(tar_path, e))?
                .map(|p| p.into_owned())
                .unwrap_or_default();

            // Ensure parent directory exists.
            ensure_parent_dir(&full_path, dest, &mut implicit_dirs)?;

            let mode = S_IFLNK | 0o777;

            if cfg!(target_os = "linux") {
                // Linux: store as regular file with content = target path.
                // (xattrs can't be set on symlinks on most Linux filesystems.)
                // Remove any existing entry (could be a directory from a lower layer).
                let _ = std::fs::remove_dir_all(&full_path);
                let _ = std::fs::remove_file(&full_path);
                std::fs::write(&full_path, link_target.as_os_str().as_encoded_bytes())
                    .map_err(|e| extraction_err(tar_path, e))?;
                set_host_permissions(&full_path, 0o600)?;
                set_override_stat(&full_path, uid, gid, mode, 0)?;
                clear_implicit_entry(&full_path, dest, &mut implicit_dirs);
            } else {
                // macOS: real symlink with XATTR_NOFOLLOW.
                // Remove any existing entry (could be a directory from a lower layer).
                let _ = std::fs::remove_dir_all(&full_path);
                let _ = std::fs::remove_file(&full_path);
                std::os::unix::fs::symlink(&link_target, &full_path)
                    .map_err(|e| extraction_err(tar_path, e))?;
                set_override_stat_symlink(&full_path, uid, gid, mode, 0)?;
                clear_implicit_entry(&full_path, dest, &mut implicit_dirs);
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

            ensure_parent_dir(&full_path, dest, &mut implicit_dirs)?;

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
            clear_implicit_entry(&full_path, dest, &mut implicit_dirs);
        } else if entry_type == tar::EntryType::Block || entry_type == tar::EntryType::Char {
            // Block/char device: store as empty regular file with device info in xattr.
            ensure_parent_dir(&full_path, dest, &mut implicit_dirs)?;
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
            clear_implicit_entry(&full_path, dest, &mut implicit_dirs);
        } else if entry_type == tar::EntryType::Fifo {
            // FIFO: store as empty regular file.
            ensure_parent_dir(&full_path, dest, &mut implicit_dirs)?;
            std::fs::write(&full_path, b"").map_err(|e| extraction_err(tar_path, e))?;
            set_host_permissions(&full_path, 0o600)?;
            let mode = S_IFIFO | (tar_mode & 0o7777);
            set_override_stat(&full_path, uid, gid, mode, 0)?;
            clear_implicit_entry(&full_path, dest, &mut implicit_dirs);
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
        ensure_parent_dir(&hl.path, dest, &mut implicit_dirs)?;
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
        clear_implicit_entry(&hl.path, dest, &mut implicit_dirs);
    }

    Ok(ExtractionResult {
        implicit_dirs: implicit_dirs.into_iter().collect(),
    })
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

/// Ensure parent directories exist, tracking implicitly-created ones for post-fixup.
///
/// Directories created here (not from tar entries) get a default xattr
/// (`uid=0, gid=0, mode=S_IFDIR|0o755`). Their relative paths are appended
/// to `implicit_dirs` so a post-extraction fixup pass can copy the correct
/// xattr from the lower layer that originally defined the directory.
fn ensure_parent_dir(
    path: &Path,
    dest: &Path,
    implicit_dirs: &mut BTreeSet<PathBuf>,
) -> ImageResult<()> {
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

        // Create missing directories with default xattrs (top-down after reverse).
        for dir in missing.into_iter().rev() {
            std::fs::create_dir(&dir).map_err(|e| ImageError::Extraction {
                digest: String::new(),
                message: format!("failed to create dir {}: {e}", dir.display()),
                source: Some(Box::new(e)),
            })?;

            set_host_permissions(&dir, 0o700)?;

            // Default xattr — may be corrected in the fixup pass.
            let mode = S_IFDIR | 0o755;
            set_override_stat(&dir, 0, 0, mode, 0)?;

            // Track for post-fixup.
            if let Ok(rel) = dir.strip_prefix(dest) {
                implicit_dirs.insert(rel.to_path_buf());
            }
        }
    }
    Ok(())
}

fn clear_implicit_entry(path: &Path, dest: &Path, implicit_dirs: &mut BTreeSet<PathBuf>) {
    if let Ok(rel) = path.strip_prefix(dest) {
        implicit_dirs.remove(rel);
    }
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

/// Fix xattrs on implicitly-created directories by copying from lower layers.
///
/// After parallel extraction, directories that were created by `ensure_parent_dir`
/// (not from tar entries) have default xattrs. This pass searches lower layers
/// bottom-to-top and copies the correct xattr from the first layer that defines
/// the directory.
///
/// This is typically a no-op — most OCI layers include explicit directory entries
/// for all paths they touch.
pub(crate) fn fixup_implicit_dirs(
    layer_dir: &Path,
    implicit_dirs: &[PathBuf],
    lower_layers: &[PathBuf],
) -> ImageResult<()> {
    for rel_dir in implicit_dirs {
        let target = layer_dir.join(rel_dir);
        if !target.exists() {
            continue;
        }

        // Search lower layers top-to-bottom (most recent first).
        for lower in lower_layers.iter().rev() {
            let source = lower.join(rel_dir);
            if source.exists() {
                if let Ok(Some(data)) = xattr::get(&source, OVERRIDE_XATTR_KEY)
                    && let Err(e) = xattr::set(&target, OVERRIDE_XATTR_KEY, &data)
                {
                    tracing::warn!(
                        target = %target.display(),
                        source = %source.display(),
                        error = %e,
                        "failed to copy override_stat xattr during fixup"
                    );
                }
                break;
            }
        }
    }
    Ok(())
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

    use super::{
        LayerCompression, OVERRIDE_XATTR_KEY, detect_layer_compression, extract_layer,
        validate_entry_path,
    };

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

    #[test]
    fn test_extract_layer_clears_explicit_dirs_from_fixup_set() {
        let temp = tempdir().unwrap();
        let tar_path = temp.path().join("layer.tar");
        let dest = temp.path().join("dest");
        std::fs::create_dir(&dest).unwrap();

        let tar_file = std::fs::File::create(&tar_path).unwrap();
        let mut builder = tar::Builder::new(tar_file);

        let file_contents = b"tool";
        let mut file_header = tar::Header::new_gnu();
        file_header.set_size(file_contents.len() as u64);
        file_header.set_mode(0o644);
        file_header.set_uid(0);
        file_header.set_gid(0);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, "usr/local/bin/tool", &file_contents[..])
            .unwrap();

        let mut dir_header = tar::Header::new_gnu();
        dir_header.set_entry_type(tar::EntryType::Directory);
        dir_header.set_size(0);
        dir_header.set_mode(0o700);
        dir_header.set_uid(42);
        dir_header.set_gid(7);
        dir_header.set_cksum();
        builder
            .append_data(&mut dir_header, "usr/local", std::io::empty())
            .unwrap();
        builder.finish().unwrap();

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let result = runtime
            .block_on(extract_layer(
                &tar_path,
                &dest,
                Some("application/vnd.oci.image.layer.v1.tar"),
            ))
            .unwrap();

        assert!(
            !result
                .implicit_dirs
                .contains(&Path::new("usr/local").to_path_buf())
        );
        assert!(
            result
                .implicit_dirs
                .contains(&Path::new("usr").to_path_buf())
        );
        assert!(
            result
                .implicit_dirs
                .contains(&Path::new("usr/local/bin").to_path_buf())
        );

        let xattr = xattr::get(dest.join("usr/local"), OVERRIDE_XATTR_KEY)
            .unwrap()
            .unwrap();
        assert_eq!(xattr.len(), 20);
        assert_eq!(u32::from_le_bytes(xattr[4..8].try_into().unwrap()), 42);
        assert_eq!(u32::from_le_bytes(xattr[8..12].try_into().unwrap()), 7);
        assert_eq!(
            u32::from_le_bytes(xattr[12..16].try_into().unwrap()) & 0o7777,
            0o700
        );
    }
}
