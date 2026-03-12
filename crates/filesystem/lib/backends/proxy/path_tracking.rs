//! Path tracking for inode-to-path and handle-to-path mappings.
//!
//! ProxyFs maintains best-effort path maps so hooks receive human-readable
//! paths instead of opaque inode numbers. Paths are relative to the mount
//! root with no leading `/`.

use std::ffi::CStr;

use super::ProxyFs;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Root inode number (FUSE convention).
const ROOT_INODE: u64 = 1;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a path for a child entry from its parent inode and name.
///
/// Returns a path relative to mount root (e.g. `"etc/passwd"`, `"config.toml"`).
/// Root-level entries are returned as just the name (no leading `/`).
pub(crate) fn build_path(fs: &ProxyFs, parent_inode: u64, name: &CStr) -> String {
    let name_str = name.to_string_lossy();
    let paths = fs.paths.read().unwrap();

    if parent_inode == ROOT_INODE {
        name_str.into_owned()
    } else if let Some(parent_path) = paths.get(&parent_inode) {
        if parent_path.is_empty() {
            name_str.into_owned()
        } else {
            format!("{}/{}", parent_path, name_str)
        }
    } else {
        // Parent path unknown — use inode number as fallback.
        format!("<{}>/{}", parent_inode, name_str)
    }
}

/// Update path tracking after a rename operation.
///
/// Updates the renamed inode's path and all descendant paths that share
/// the old prefix. This is O(n) where n is the number of tracked paths.
pub(crate) fn update_paths_after_rename(
    fs: &ProxyFs,
    old_parent: u64,
    old_name: &CStr,
    new_parent: u64,
    new_name: &CStr,
    renamed_inode: u64,
) {
    let old_path = build_path(fs, old_parent, old_name);
    let new_path = build_path(fs, new_parent, new_name);

    let mut paths = fs.paths.write().unwrap();

    // Update the renamed entry itself.
    paths.insert(renamed_inode, new_path.clone());

    // Update all descendant paths (prefix replacement).
    let old_prefix = format!("{}/", old_path);
    let new_prefix = format!("{}/", new_path);

    let updates: Vec<(u64, String)> = paths
        .iter()
        .filter(|(_, path)| path.starts_with(&old_prefix))
        .map(|(&ino, path)| {
            let suffix = &path[old_prefix.len()..];
            (ino, format!("{}{}", new_prefix, suffix))
        })
        .collect();

    for (ino, updated_path) in updates {
        paths.insert(ino, updated_path);
    }
}

/// Resolve the inode for a child within a parent directory.
///
/// Searches the path table for an inode whose path matches
/// `build_path(parent, name)`. Returns `None` if not found.
pub(crate) fn resolve_inode(fs: &ProxyFs, parent: u64, name: &CStr) -> Option<u64> {
    let expected_path = build_path(fs, parent, name);
    let paths = fs.paths.read().unwrap();
    paths
        .iter()
        .find(|(_, path)| **path == expected_path)
        .map(|(&ino, _)| ino)
}

/// Register a path for an inode in the paths table.
pub(crate) fn register_path(fs: &ProxyFs, inode: u64, path: String) {
    fs.paths.write().unwrap().insert(inode, path);
}

/// Copy an inode's path to the handle_paths table.
pub(crate) fn register_handle_path(fs: &ProxyFs, inode: u64, handle: u64) {
    let path = fs.paths.read().unwrap().get(&inode).cloned();
    if let Some(path) = path {
        fs.handle_paths.write().unwrap().insert(handle, path);
    }
}

/// Remove a handle from the handle_paths table.
pub(crate) fn remove_handle_path(fs: &ProxyFs, handle: u64) {
    fs.handle_paths.write().unwrap().remove(&handle);
}
