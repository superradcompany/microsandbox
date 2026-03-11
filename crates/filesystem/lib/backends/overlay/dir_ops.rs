//! Directory operations: opendir, readdir, readdirplus, releasedir.
//!
//! ## Merged Readdir
//!
//! The overlay readdir merges entries across all layers: upper first, then lowers
//! (top-down). Whiteout entries add to the "seen" set without being emitted.
//! Opaque directories stop lower scanning. The merged snapshot is built lazily
//! on the first readdir call per handle and is immutable for the handle's lifetime.
//!
//! ## Memory Strategy
//!
//! Same bounded-leak pattern as passthrough: names for `DirEntry<'static>` are
//! collected into a single contiguous buffer, leaked once per readdir call.

use std::collections::HashSet;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use super::OverlayFs;
use super::inode;
use super::layer;
use super::types::{DirHandle, DirSnapshot, MergedDirEntry, ROOT_INODE};
use crate::backends::shared::init_binary;
use crate::backends::shared::platform;
use crate::{Context, DirEntry, Entry, OpenOptions};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a directory and return a handle.
pub(crate) fn do_opendir(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    _flags: u32,
) -> io::Result<(Option<u64>, OpenOptions)> {
    // Verify node exists and is a directory.
    {
        let nodes = fs.nodes.read().unwrap();
        let node = nodes.get(&ino).ok_or_else(platform::enoent)?;
        if node.kind != libc::S_IFDIR as u32 && ino != ROOT_INODE {
            return Err(platform::enoent());
        }
    }

    let handle = fs.next_handle.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(DirHandle {
        inode: ino,
        snapshot: Mutex::new(None),
    });

    fs.dir_handles.write().unwrap().insert(handle, data);
    Ok((Some(handle), fs.cache_dir_options()))
}

/// Read directory entries from a merged snapshot.
pub(crate) fn do_readdir(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    handle: u64,
    _size: u32,
    offset: u64,
) -> io::Result<Vec<DirEntry<'static>>> {
    let handles = fs.dir_handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;

    // Build snapshot on first call.
    let mut snapshot_lock = data.snapshot.lock().unwrap();
    if snapshot_lock.is_none() {
        *snapshot_lock = Some(build_snapshot(fs, ino)?);
    }
    let snapshot = snapshot_lock.as_ref().unwrap();

    // Serve entries from offset.
    let start = if offset == 0 {
        0
    } else {
        // Find the first entry with offset > requested offset.
        snapshot
            .entries
            .iter()
            .position(|e| e.offset > offset)
            .unwrap_or(snapshot.entries.len())
    };

    if start >= snapshot.entries.len() {
        return Ok(Vec::new());
    }

    let slice = &snapshot.entries[start..];

    // Collect names into a contiguous buffer for bounded leak.
    let mut names_buf: Vec<u8> = Vec::new();
    let mut raw_entries: Vec<(u64, u64, u32, usize, usize)> = Vec::new();

    for entry in slice {
        let name_offset = names_buf.len();
        names_buf.extend_from_slice(&entry.name);
        raw_entries.push((
            0, // ino — not meaningful for overlay (guest sees synthetic inodes)
            entry.offset,
            entry.file_type,
            name_offset,
            entry.name.len(),
        ));
    }

    if raw_entries.is_empty() {
        return Ok(Vec::new());
    }

    // Leak one contiguous buffer (bounded: one per readdir call).
    let leaked: &'static [u8] = Box::leak(names_buf.into_boxed_slice());

    let entries = raw_entries
        .into_iter()
        .map(|(ino, off, typ, start, len)| DirEntry {
            ino,
            offset: off,
            type_: typ,
            name: &leaked[start..start + len],
        })
        .collect();

    Ok(entries)
}

/// Read directory entries with attributes (readdirplus).
pub(crate) fn do_readdirplus(
    fs: &OverlayFs,
    ctx: Context,
    ino: u64,
    handle: u64,
    size: u32,
    offset: u64,
) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
    let dir_entries = do_readdir(fs, ctx, ino, handle, size, offset)?;
    let mut result = Vec::with_capacity(dir_entries.len());

    for de in dir_entries {
        let name_bytes = de.name;
        // Skip . and ..
        if name_bytes == b"." || name_bytes == b".." {
            continue;
        }

        // For init.krun, return synthetic entry.
        if name_bytes == init_binary::INIT_FILENAME {
            let entry = init_binary::init_entry(fs.cfg.entry_timeout, fs.cfg.attr_timeout);
            result.push((de, entry));
            continue;
        }

        // Look up the entry to get full attributes.
        let name_cstr = match std::ffi::CString::new(name_bytes.to_vec()) {
            Ok(c) => c,
            Err(_) => continue,
        };
        match inode::do_lookup(fs, ino, &name_cstr) {
            Ok(entry) => {
                // Correct d_type from lookup's stat.
                let mut de = de;
                let file_type = entry.attr.st_mode as u32 & libc::S_IFMT as u32;
                de.type_ = mode_to_dtype(file_type);
                result.push((de, entry));
            }
            Err(_) => continue,
        }
    }

    Ok(result)
}

/// Release an open directory handle.
pub(crate) fn do_releasedir(
    fs: &OverlayFs,
    _ctx: Context,
    _ino: u64,
    _flags: u32,
    handle: u64,
) -> io::Result<()> {
    fs.dir_handles.write().unwrap().remove(&handle);
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Build a merged directory snapshot across all layers.
fn build_snapshot(fs: &OverlayFs, ino: u64) -> io::Result<DirSnapshot> {
    let node = {
        let nodes = fs.nodes.read().unwrap();
        nodes.get(&ino).cloned().ok_or_else(platform::enoent)?
    };

    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut entries: Vec<MergedDirEntry> = Vec::new();
    let mut is_opaque = node.opaque.load(Ordering::Relaxed);

    // Phase 1: Scan upper layer.
    let upper_dir_fd = get_dir_fd_for_scan(fs, &node);
    if let Some(upper_fd_node) = upper_dir_fd {
        let upper_fd = upper_fd_node.raw();
        let raw_entries = layer::read_dir_entries_raw(upper_fd)?;

        for (name, d_type) in raw_entries {
            if name.starts_with(b".wh.") {
                if name == b".wh..wh..opq" {
                    is_opaque = true;
                } else {
                    // Whiteout: mask the target name.
                    let masked = name[4..].to_vec();
                    seen.insert(masked);
                }
                continue;
            }

            seen.insert(name.clone());
            entries.push(MergedDirEntry {
                name,
                offset: 0, // Assigned below.
                file_type: d_type,
            });
        }

        // Read overflow tombstone names from upper directory.
        for name in super::whiteout::get_tombstoned_names(upper_fd)? {
            seen.insert(name);
        }
        // NodeFd drops here, closing the fd if owned.
    }

    // Phase 2: Scan lower layers (top-down), only if not opaque.
    if !is_opaque {
        for lower in fs.lowers.iter().rev() {
            let lower_parent_fd = get_lower_dir_fd(fs, lower, &node);
            let lower_fd = match lower_parent_fd {
                Some(fd) => fd,
                None => continue,
            };

            let raw_entries = layer::read_dir_entries_raw(lower_fd)?;

            // Read overflow tombstone names from this lower directory.
            for name in super::whiteout::get_tombstoned_names(lower_fd)? {
                seen.insert(name);
            }

            unsafe { libc::close(lower_fd) };

            let mut layer_opaque = false;
            for (name, d_type) in raw_entries {
                if name.starts_with(b".wh.") {
                    if name == b".wh..wh..opq" {
                        layer_opaque = true;
                    } else {
                        let masked = name[4..].to_vec();
                        seen.insert(masked);
                    }
                    continue;
                }

                if seen.contains(&name) {
                    continue;
                }

                seen.insert(name.clone());
                entries.push(MergedDirEntry {
                    name,
                    offset: 0,
                    file_type: d_type,
                });
            }

            if layer_opaque {
                break;
            }
        }
    }

    // Inject init.krun into root directory.
    if ino == ROOT_INODE {
        let init_name = init_binary::INIT_FILENAME.to_vec();
        if !seen.contains(&init_name) {
            entries.push(MergedDirEntry {
                name: init_name,
                offset: 0,
                file_type: libc::DT_REG as u32,
            });
        }
    }

    // Assign 1-based monotonic offsets.
    for (i, entry) in entries.iter_mut().enumerate() {
        entry.offset = (i + 1) as u64;
    }

    Ok(DirSnapshot { entries })
}

/// Check whether a merged directory has any guest-visible entries.
///
/// Same merge logic as `build_snapshot` but short-circuits on the first
/// visible entry. Returns `true` if empty, `false` if any entry is visible.
pub(crate) fn is_merged_dir_empty(fs: &OverlayFs, ino: u64) -> io::Result<bool> {
    let node = {
        let nodes = fs.nodes.read().unwrap();
        nodes.get(&ino).cloned().ok_or_else(platform::enoent)?
    };

    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut is_opaque = node.opaque.load(Ordering::Relaxed);

    // Phase 1: Scan upper layer.
    let upper_dir_fd = get_dir_fd_for_scan(fs, &node);
    if let Some(upper_fd_node) = upper_dir_fd {
        let upper_fd = upper_fd_node.raw();
        let raw_entries = layer::read_dir_entries_raw(upper_fd)?;

        // Read overflow tombstone names from upper directory.
        for name in super::whiteout::get_tombstoned_names(upper_fd)? {
            seen.insert(name);
        }
        // NodeFd drops here, closing the fd if owned.
        drop(upper_fd_node);

        for (name, _d_type) in raw_entries {
            if name.starts_with(b".wh.") {
                if name == b".wh..wh..opq" {
                    is_opaque = true;
                } else {
                    let masked = name[4..].to_vec();
                    seen.insert(masked);
                }
                continue;
            }
            // Found a visible upper entry — not empty.
            return Ok(false);
        }
    }

    // Phase 2: Scan lower layers (top-down), only if not opaque.
    if !is_opaque {
        for lower in fs.lowers.iter().rev() {
            let lower_fd = match get_lower_dir_fd(fs, lower, &node) {
                Some(fd) => fd,
                None => continue,
            };

            let raw_entries = layer::read_dir_entries_raw(lower_fd)?;

            // Read overflow tombstone names from this lower directory.
            for name in super::whiteout::get_tombstoned_names(lower_fd)? {
                seen.insert(name);
            }

            unsafe { libc::close(lower_fd) };

            let mut layer_opaque = false;
            for (name, _d_type) in raw_entries {
                if name.starts_with(b".wh.") {
                    if name == b".wh..wh..opq" {
                        layer_opaque = true;
                    } else {
                        let masked = name[4..].to_vec();
                        seen.insert(masked);
                    }
                    continue;
                }

                if seen.contains(&name) {
                    continue;
                }

                // Found a visible lower entry — not empty.
                return Ok(false);
            }

            if layer_opaque {
                break;
            }
        }
    }

    Ok(true)
}

/// Get the directory fd for scanning the upper layer of a node.
///
/// Returns an `inode::NodeFd` that is automatically closed on drop if owned.
fn get_dir_fd_for_scan(fs: &OverlayFs, node: &super::types::OverlayNode) -> Option<inode::NodeFd> {
    inode::get_upper_dir_fd(fs, node)
}

/// Get a directory fd for scanning a lower layer.
///
/// Uses the same path-resolution logic as lookup: handles Root, same-layer
/// Lower, cross-layer, Upper (copied-up), and redirected parents.
/// Returns an owned fd that the caller must close.
fn get_lower_dir_fd(
    fs: &OverlayFs,
    lower: &super::types::Layer,
    node: &super::types::OverlayNode,
) -> Option<i32> {
    let path_components = inode::get_parent_lower_path(fs, node);
    let node_fd = inode::open_lower_parent(lower, node, &path_components)?;
    // Caller expects an owned fd it will close — ensure we return one.
    if node_fd.is_owned() {
        Some(node_fd.into_raw())
    } else {
        // Borrowed fd (e.g. root) — dup it so caller can safely close.
        let fd = unsafe { libc::dup(node_fd.raw()) };
        if fd >= 0 { Some(fd) } else { None }
    }
}

/// Convert a file mode type to a directory entry type.
fn mode_to_dtype(mode_type: u32) -> u32 {
    match mode_type {
        m if m == libc::S_IFLNK as u32 => libc::DT_LNK as u32,
        m if m == libc::S_IFDIR as u32 => libc::DT_DIR as u32,
        m if m == libc::S_IFCHR as u32 => libc::DT_CHR as u32,
        m if m == libc::S_IFBLK as u32 => libc::DT_BLK as u32,
        m if m == libc::S_IFIFO as u32 => libc::DT_FIFO as u32,
        m if m == libc::S_IFSOCK as u32 => libc::DT_SOCK as u32,
        _ => libc::DT_REG as u32,
    }
}
