//! Sidecar index generation for extracted layers.
//!
//! Walks the extracted layer tree and generates a binary sidecar index
//! using [`IndexBuilder`](microsandbox_utils::index::IndexBuilder).

use std::path::Path;

use microsandbox_utils::index::IndexBuilder;

use super::{OVERRIDE_XATTR_KEY, S_IFLNK, S_IFMT};
use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Whiteout file prefix.
const WHITEOUT_PREFIX: &str = ".wh.";

/// Opaque whiteout marker.
const OPAQUE_WHITEOUT: &str = ".wh..wh..opq";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a binary sidecar index for an extracted layer directory.
///
/// The index is written to `index_path` and can be mmap'd by OverlayFs
/// for O(log n) lookups.
pub(crate) async fn build_sidecar_index(
    extracted_dir: &Path,
    index_path: &Path,
) -> ImageResult<()> {
    let extracted = extracted_dir.to_path_buf();
    let output = index_path.to_path_buf();

    // Run in a blocking thread since it does filesystem walking.
    tokio::task::spawn_blocking(move || build_index_sync(&extracted, &output))
        .await
        .map_err(|e| {
            ImageError::IndexBuild(
                extracted_dir.display().to_string(),
                std::io::Error::other(format!("task join error: {e}")),
            )
        })?
}

fn build_index_sync(extracted_dir: &Path, index_path: &Path) -> ImageResult<()> {
    let builder = IndexBuilder::new();

    // Walk the extracted tree.
    let builder = walk_dir(extracted_dir, extracted_dir, builder)?;

    let index_data = builder.build();
    std::fs::write(index_path, &index_data)
        .map_err(|e| ImageError::IndexBuild(extracted_dir.display().to_string(), e))?;

    Ok(())
}

fn walk_dir(root: &Path, dir: &Path, mut builder: IndexBuilder) -> ImageResult<IndexBuilder> {
    let rel_path = dir.strip_prefix(root).unwrap_or(Path::new(""));

    let rel_str = if rel_path == Path::new("") {
        "".to_string()
    } else {
        format!("{}", rel_path.display())
    };

    // Check if directory is opaque.
    let opaque = dir.join(OPAQUE_WHITEOUT).exists();
    if opaque {
        builder = builder.opaque_dir(&rel_str);
    } else {
        builder = builder.dir(&rel_str);
    }

    // Read directory entries.
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(dir = %dir.display(), error = %e, "failed to read dir for index");
            return Ok(builder);
        }
    };

    for entry_result in entries {
        let entry = match entry_result {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!(dir = %dir.display(), error = %e, "failed to read dir entry for index");
                continue;
            }
        };

        let name = entry.file_name();
        let name_str = name.to_string_lossy();

        // Skip .complete marker.
        if name_str == ".complete" {
            continue;
        }

        // Skip opaque whiteout marker (already handled as dir flag).
        if name_str == OPAQUE_WHITEOUT {
            continue;
        }

        let entry_path = entry.path();

        // Handle whiteout files.
        if let Some(target_name) = name_str.strip_prefix(WHITEOUT_PREFIX) {
            if !target_name.is_empty() {
                builder = builder.whiteout(&rel_str, target_name);
            }
            continue;
        }

        // Read metadata.
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(path = %entry_path.display(), error = %e, "failed to read metadata for index");
                continue;
            }
        };

        // Read override stat xattr for mode.
        let (_uid, _gid, mode) = read_override_stat(&entry_path);

        if metadata.is_dir() {
            // Register as subdirectory entry (permissions only, S_IFDIR added automatically).
            builder = builder.subdir(&rel_str, &name_str, mode & 0o7777);

            // Recurse into subdirectory.
            builder = walk_dir(root, &entry_path, builder)?;
        } else if (mode & S_IFMT) == S_IFLNK {
            // Symlink.
            builder = builder.symlink(&rel_str, &name_str);
        } else {
            // Regular file, device node, FIFO, etc. (permissions only, S_IFREG added automatically).
            builder = builder.file(&rel_str, &name_str, mode & 0o7777);
        }
    }

    Ok(builder)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Read the override stat xattr and return (uid, gid, mode).
/// Returns default values if xattr is missing or invalid.
fn read_override_stat(path: &Path) -> (u32, u32, u32) {
    let data = match xattr::get(path, OVERRIDE_XATTR_KEY) {
        Ok(Some(d)) if d.len() >= 20 => d,
        _ => return (0, 0, 0),
    };

    // Parse the 20-byte binary format.
    let uid = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    let gid = u32::from_le_bytes([data[8], data[9], data[10], data[11]]);
    let mode = u32::from_le_bytes([data[12], data[13], data[14], data[15]]);

    (uid, gid, mode)
}
