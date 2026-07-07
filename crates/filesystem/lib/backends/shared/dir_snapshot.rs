//! Shared helpers for serving snapshot-backed directory entries.

use std::io;

use crate::DirEntry;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// View over a backend-owned directory snapshot entry.
pub(crate) trait SnapshotEntry {
    /// Guest-visible inode number.
    fn inode(&self) -> u64;

    /// Stable offset cookie.
    fn offset(&self) -> u64;

    /// Guest-visible directory entry type.
    fn file_type(&self) -> u32;

    /// Entry name bytes.
    fn name(&self) -> &[u8];
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Serve directory entries from a snapshot starting strictly after `offset`.
pub(crate) fn serve_snapshot_entries<T: SnapshotEntry>(
    entries: &[T],
    offset: u64,
) -> Vec<DirEntry<'static>> {
    let start = entries
        .iter()
        .position(|entry| entry.offset() > offset)
        .unwrap_or(entries.len());

    let slice = &entries[start..];
    if slice.is_empty() {
        return Vec::new();
    }

    let mut names_buf = Vec::new();
    let mut raw_entries = Vec::with_capacity(slice.len());

    for entry in slice {
        let name_offset = names_buf.len();
        names_buf.extend_from_slice(entry.name());
        raw_entries.push((
            entry.inode(),
            entry.offset(),
            entry.file_type(),
            name_offset,
            entry.name().len(),
        ));
    }

    let leaked: &'static [u8] = Box::leak(names_buf.into_boxed_slice());

    raw_entries
        .into_iter()
        .map(|(ino, off, typ, start, len)| DirEntry {
            ino,
            offset: off,
            type_: typ,
            name: &leaked[start..start + len],
        })
        .collect()
}

/// Stream directory entries from a snapshot starting strictly after `offset`.
pub(crate) fn serve_snapshot_entries_for_each<T, F>(
    entries: &[T],
    offset: u64,
    mut add_entry: F,
) -> io::Result<()>
where
    T: SnapshotEntry,
    F: for<'name> FnMut(DirEntry<'name>) -> io::Result<usize>,
{
    for entry in snapshot_entries_after(entries, offset) {
        let dir_entry = DirEntry {
            ino: entry.inode(),
            offset: entry.offset(),
            type_: entry.file_type(),
            name: entry.name(),
        };

        if add_entry(dir_entry)? == 0 {
            break;
        }
    }

    Ok(())
}

/// Return snapshot entries strictly after `offset`.
pub(crate) fn snapshot_entries_after<T: SnapshotEntry>(entries: &[T], offset: u64) -> &[T] {
    let start = entries
        .iter()
        .position(|entry| entry.offset() > offset)
        .unwrap_or(entries.len());

    &entries[start..]
}
