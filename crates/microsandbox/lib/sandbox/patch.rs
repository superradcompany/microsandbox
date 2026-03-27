//! Patch application logic for rootfs modification before VM start.

use std::path::{Path, PathBuf};

use tokio::fs;

use super::types::{Patch, RootfsSource};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Apply patches to the rootfs before VM start.
///
/// For OCI images, patches are written to the `rw/` upper layer so that the shared
/// extracted image layers remain untouched. For bind roots, patches are written
/// directly to the host directory.
pub(crate) async fn apply_patches(
    image: &RootfsSource,
    patches: &[Patch],
    sandbox_dir: &Path,
    resolved_layers: &[PathBuf],
) -> MicrosandboxResult<()> {
    if patches.is_empty() {
        return Ok(());
    }

    let (target_dir, lower_layers) = match image {
        RootfsSource::Oci(_) => {
            let rw_dir = sandbox_dir.join("rw");
            (rw_dir, resolved_layers)
        }
        RootfsSource::Bind(host_dir) => (host_dir.clone(), [].as_slice()),
        RootfsSource::DiskImage { .. } => {
            return Err(crate::MicrosandboxError::InvalidConfig(
                "patches are not compatible with disk image rootfs".into(),
            ));
        }
    };

    for patch in patches {
        apply_one(&target_dir, lower_layers, patch).await?;
    }

    Ok(())
}

/// Apply a single patch operation.
async fn apply_one(
    target_dir: &Path,
    lower_layers: &[PathBuf],
    patch: &Patch,
) -> MicrosandboxResult<()> {
    match patch {
        Patch::Text {
            path,
            content,
            mode,
            replace,
        } => {
            let dest = resolve_guest_path(target_dir, path)?;
            check_replace(&dest, lower_layers, path, *replace)?;
            ensure_parent(&dest).await?;
            fs::write(&dest, content.as_bytes()).await?;
            if let Some(mode) = mode {
                set_permissions(&dest, *mode).await?;
            }
        }
        Patch::File {
            path,
            content,
            mode,
            replace,
        } => {
            let dest = resolve_guest_path(target_dir, path)?;
            check_replace(&dest, lower_layers, path, *replace)?;
            ensure_parent(&dest).await?;
            fs::write(&dest, content).await?;
            if let Some(mode) = mode {
                set_permissions(&dest, *mode).await?;
            }
        }
        Patch::CopyFile {
            src,
            dst,
            mode,
            replace,
        } => {
            let dest = resolve_guest_path(target_dir, dst)?;
            check_replace(&dest, lower_layers, dst, *replace)?;
            ensure_parent(&dest).await?;
            fs::copy(src, &dest).await?;
            if let Some(mode) = mode {
                set_permissions(&dest, *mode).await?;
            }
        }
        Patch::CopyDir { src, dst, replace } => {
            let dest = resolve_guest_path(target_dir, dst)?;
            check_replace(&dest, lower_layers, dst, *replace)?;
            copy_dir_recursive(src, &dest).await?;
        }
        Patch::Symlink {
            target,
            link,
            replace,
        } => {
            let link_path = resolve_guest_path(target_dir, link)?;
            check_replace(&link_path, lower_layers, link, *replace)?;
            ensure_parent(&link_path).await?;
            // Remove existing if replace was allowed and something exists.
            if link_path.exists() {
                fs::remove_file(&link_path).await.ok();
            }
            #[cfg(unix)]
            tokio::fs::symlink(target, &link_path).await?;
        }
        Patch::Mkdir { path, mode } => {
            let dest = resolve_guest_path(target_dir, path)?;
            fs::create_dir_all(&dest).await?;
            if let Some(mode) = mode {
                set_permissions(&dest, *mode).await?;
            }
        }
        Patch::Remove { path } => {
            let dest = resolve_guest_path(target_dir, path)?;
            if dest.is_dir() {
                fs::remove_dir_all(&dest).await.ok();
            } else {
                fs::remove_file(&dest).await.ok();
            }
        }
        Patch::Append { path, content } => {
            let dest = resolve_guest_path(target_dir, path)?;
            // If the file doesn't exist in the target dir, try to copy up from lower layers.
            if !dest.exists()
                && let Some(source) = find_in_layers(lower_layers, path)
            {
                ensure_parent(&dest).await?;
                fs::copy(&source, &dest).await?;
            }
            if dest.exists() {
                use tokio::io::AsyncWriteExt;
                let mut file = fs::OpenOptions::new().append(true).open(&dest).await?;
                file.write_all(content.as_bytes()).await?;
            } else {
                return Err(crate::MicrosandboxError::PatchFailed(format!(
                    "cannot append to '{path}': file not found in rootfs"
                )));
            }
        }
    }

    Ok(())
}

/// Resolve a guest absolute path to a host path within the target directory.
fn resolve_guest_path(target_dir: &Path, guest_path: &str) -> MicrosandboxResult<PathBuf> {
    if !guest_path.starts_with('/') {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "patch path must be absolute: '{guest_path}'"
        )));
    }
    // Strip the leading `/` so joining works correctly.
    let relative = guest_path.strip_prefix('/').unwrap_or(guest_path);
    let resolved = target_dir.join(relative);

    // Prevent path traversal.
    if !resolved.starts_with(target_dir) {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "patch path escapes rootfs: '{guest_path}'"
        )));
    }

    Ok(resolved)
}

/// Check if a path already exists in the target dir or lower layers.
/// Returns an error if it exists and `replace` is false.
fn check_replace(
    dest: &Path,
    lower_layers: &[PathBuf],
    guest_path: &str,
    replace: bool,
) -> MicrosandboxResult<()> {
    if replace {
        return Ok(());
    }

    // Check the target directory (rw layer for OCI, host dir for bind).
    if dest.exists() {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "path already exists in rootfs: '{guest_path}' (set replace to allow)"
        )));
    }

    // Check lower layers (OCI image layers).
    if find_in_layers(lower_layers, guest_path).is_some() {
        return Err(crate::MicrosandboxError::PatchFailed(format!(
            "path exists in image layer: '{guest_path}' (set replace to allow)"
        )));
    }

    Ok(())
}

/// Search lower layers (bottom-to-top) for a guest path. Returns the first match.
fn find_in_layers(layers: &[PathBuf], guest_path: &str) -> Option<PathBuf> {
    let relative = guest_path.strip_prefix('/').unwrap_or(guest_path);
    // Search top-to-bottom (last layer = topmost).
    for layer in layers.iter().rev() {
        let candidate = layer.join(relative);
        if candidate.exists() {
            return Some(candidate);
        }
    }
    None
}

/// Ensure parent directories exist.
async fn ensure_parent(path: &Path) -> MicrosandboxResult<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).await?;
    }
    Ok(())
}

/// Set Unix file permissions.
#[cfg(unix)]
async fn set_permissions(path: &Path, mode: u32) -> MicrosandboxResult<()> {
    use std::os::unix::fs::PermissionsExt;
    let perms = std::fs::Permissions::from_mode(mode);
    fs::set_permissions(path, perms).await?;
    Ok(())
}

/// Recursively copy a directory.
async fn copy_dir_recursive(src: &Path, dst: &Path) -> MicrosandboxResult<()> {
    fs::create_dir_all(dst).await?;
    let mut entries = fs::read_dir(src).await?;
    while let Some(entry) = entries.next_entry().await? {
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        if entry.file_type().await?.is_dir() {
            Box::pin(copy_dir_recursive(&src_path, &dst_path)).await?;
        } else {
            fs::copy(&src_path, &dst_path).await?;
        }
    }
    Ok(())
}
