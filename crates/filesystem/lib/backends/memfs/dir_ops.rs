//! Directory operations: opendir, readdir, readdirplus, releasedir.
//!
//! Readdir builds a point-in-time snapshot on first call. The snapshot is
//! immutable for the handle's lifetime. Names use the bounded-leak technique
//! for `DirEntry<'static>` lifetime requirements.

use std::{
    io,
    sync::{Arc, Mutex, atomic::Ordering},
};

use super::{
    MemFs, inode,
    types::{DirHandle, DirSnapshot, InodeContent, MemDirEntry, ROOT_INODE},
};
use crate::{
    Context, DirEntry, Entry, OpenOptions,
    backends::shared::{init_binary, platform},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a directory and return a handle.
pub(crate) fn do_opendir(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    _flags: u32,
) -> io::Result<(Option<u64>, OpenOptions)> {
    let node = inode::get_node(fs, ino)?;

    if node.kind != platform::MODE_DIR {
        return Err(platform::enotdir());
    }

    let handle = fs.next_handle.fetch_add(1, Ordering::Relaxed);
    let dh = Arc::new(DirHandle {
        node: Arc::clone(&node),
        snapshot: Mutex::new(None),
    });

    fs.dir_handles.write().unwrap().insert(handle, dh);
    Ok((Some(handle), fs.cache_dir_options()))
}

/// Read directory entries from a snapshot.
pub(crate) fn do_readdir(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    handle: u64,
    _size: u32,
    offset: u64,
) -> io::Result<Vec<DirEntry<'static>>> {
    serve_snapshot_entries(fs, ino, handle, offset)
}

/// Read directory entries with attributes (readdirplus).
pub(crate) fn do_readdirplus(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    handle: u64,
    _size: u32,
    offset: u64,
) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
    let dir_entries = serve_snapshot_entries(fs, ino, handle, offset)?;
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
        let child_ino = de.ino;
        if let Ok(node) = inode::get_node(fs, child_ino) {
            inode::inc_lookup(&node);
            let entry = inode::build_entry(fs, &node);
            result.push((de, entry));
        }
    }

    Ok(result)
}

/// Release an open directory handle.
pub(crate) fn do_releasedir(
    fs: &MemFs,
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

/// Build or retrieve the snapshot and serve entries from the given offset.
fn serve_snapshot_entries(
    fs: &MemFs,
    ino: u64,
    handle: u64,
    offset: u64,
) -> io::Result<Vec<DirEntry<'static>>> {
    let handles = fs.dir_handles.read().unwrap();
    let dh = handles.get(&handle).ok_or_else(platform::ebadf)?;

    // Build snapshot on first call.
    let mut snapshot_lock = dh.snapshot.lock().unwrap();
    if snapshot_lock.is_none() {
        *snapshot_lock = Some(build_snapshot(fs, ino, &dh.node)?);
    }
    let snapshot = snapshot_lock.as_ref().unwrap();

    // Serve entries from offset.
    let start = if offset == 0 {
        0
    } else {
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
            entry.inode,
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

/// Build a point-in-time snapshot of a directory's entries.
fn build_snapshot(fs: &MemFs, ino: u64, node: &super::types::MemNode) -> io::Result<DirSnapshot> {
    let children = match &node.content {
        InodeContent::Directory { children, .. } => children.read().unwrap(),
        _ => return Err(platform::enotdir()),
    };

    let mut entries = Vec::with_capacity(children.len() + 3);

    // "." entry.
    entries.push(MemDirEntry {
        name: b".".to_vec(),
        inode: ino,
        offset: 0,
        file_type: platform::DIRENT_DIR,
    });

    // ".." entry.
    let parent_ino = match &node.content {
        InodeContent::Directory { parent, .. } => parent.load(Ordering::Relaxed),
        _ => ino,
    };
    entries.push(MemDirEntry {
        name: b"..".to_vec(),
        inode: parent_ino,
        offset: 0,
        file_type: platform::DIRENT_DIR,
    });

    // Inject init.krun for root directory.
    if ino == ROOT_INODE {
        entries.push(MemDirEntry {
            name: init_binary::INIT_FILENAME.to_vec(),
            inode: init_binary::INIT_INODE,
            offset: 0,
            file_type: platform::DIRENT_REG,
        });
    }

    // Child entries.
    for (name, &child_ino) in children.iter() {
        let child_type = {
            let nodes = fs.nodes.read().unwrap();
            match nodes.get(&child_ino) {
                Some(child) => inode::mode_to_dtype(child.kind),
                None => libc::DT_UNKNOWN.into(),
            }
        };

        entries.push(MemDirEntry {
            name: name.clone(),
            inode: child_ino,
            offset: 0,
            file_type: child_type,
        });
    }

    // Assign 1-based monotonic offsets.
    for (i, entry) in entries.iter_mut().enumerate() {
        entry.offset = (i + 1) as u64;
    }

    Ok(DirSnapshot { entries })
}
