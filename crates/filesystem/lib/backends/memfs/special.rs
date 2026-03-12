//! Special operations: statfs, lseek, fallocate, fsync, fsyncdir.

use std::io;
use std::sync::atomic::Ordering;

use super::MemFs;
use super::inode;
use super::types::InodeContent;
use crate::backends::shared::init_binary;
use crate::backends::shared::platform;
use crate::{Context, statvfs64};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `SEEK_DATA` — seek to next data region.
const SEEK_DATA: u32 = 3;

/// `SEEK_HOLE` — seek to next hole region.
const SEEK_HOLE: u32 = 4;

/// `FALLOC_FL_PUNCH_HOLE` — punch a hole (zero-fill) in the file.
const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;

/// `FALLOC_FL_KEEP_SIZE` — don't change file size.
const FALLOC_FL_KEEP_SIZE: u32 = 0x01;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return filesystem statistics.
pub(crate) fn do_statfs(fs: &MemFs, _ctx: Context, _ino: u64) -> io::Result<statvfs64> {
    let bsize = 4096u64;

    let total_bytes = fs.cfg.capacity.unwrap_or(1u64 << 50); // 1 PiB
    let total_inodes = fs.cfg.max_inodes.unwrap_or(1u64 << 30); // ~1 billion

    let used = fs.used_bytes.load(Ordering::Relaxed);
    let used_ino = fs.inode_count.load(Ordering::Relaxed);

    let mut st: statvfs64 = unsafe { std::mem::zeroed() };

    #[cfg(target_os = "linux")]
    {
        st.f_bsize = bsize;
        st.f_frsize = bsize;
        st.f_blocks = total_bytes / bsize;
        st.f_bfree = total_bytes.saturating_sub(used) / bsize;
        st.f_bavail = total_bytes.saturating_sub(used) / bsize;
        st.f_files = total_inodes;
        st.f_ffree = total_inodes.saturating_sub(used_ino);
        st.f_favail = total_inodes.saturating_sub(used_ino);
        st.f_namemax = 255;
    }

    #[cfg(target_os = "macos")]
    {
        st.f_bsize = bsize;
        st.f_frsize = bsize;
        st.f_blocks = (total_bytes / bsize) as u32;
        st.f_bfree = (total_bytes.saturating_sub(used) / bsize) as u32;
        st.f_bavail = (total_bytes.saturating_sub(used) / bsize) as u32;
        st.f_files = total_inodes as u32;
        st.f_ffree = total_inodes.saturating_sub(used_ino) as u32;
        st.f_favail = total_inodes.saturating_sub(used_ino) as u32;
        st.f_namemax = 255;
    }

    Ok(st)
}

/// Seek to a position in a file.
pub(crate) fn do_lseek(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    handle: u64,
    offset: u64,
    whence: u32,
) -> io::Result<u64> {
    if ino == init_binary::INIT_INODE {
        return lseek_init(offset, whence);
    }

    let handles = fs.file_handles.read().unwrap();
    let fh = handles.get(&handle).ok_or_else(platform::ebadf)?;

    let data = match &fh.node.content {
        InodeContent::RegularFile { data } => data.read().unwrap(),
        _ => return Err(platform::einval()),
    };

    let file_size = data.len() as u64;

    match whence {
        w if w == libc::SEEK_SET as u32 => Ok(offset),
        w if w == libc::SEEK_END as u32 => {
            let signed_offset = offset as i64;
            let pos = (file_size as i64)
                .checked_add(signed_offset)
                .ok_or_else(platform::einval)?;
            if pos < 0 {
                return Err(platform::einval());
            }
            Ok(pos as u64)
        }
        SEEK_DATA => {
            // All data is non-sparse in memory.
            if offset >= file_size {
                Err(platform::enxio())
            } else {
                Ok(offset)
            }
        }
        SEEK_HOLE => {
            // Hole starts at EOF.
            if offset >= file_size {
                Err(platform::enxio())
            } else {
                Ok(file_size)
            }
        }
        _ => Err(platform::einval()),
    }
}

/// Allocate or punch a hole in a file.
pub(crate) fn do_fallocate(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    handle: u64,
    mode: u32,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    let handles = fs.file_handles.read().unwrap();
    let fh = handles.get(&handle).ok_or_else(platform::ebadf)?;

    if fh.node.kind != libc::S_IFREG as u32 {
        return Err(platform::enodev());
    }

    if mode == 0 {
        // Allocate space: extend file if needed.
        let new_end = offset
            .checked_add(length)
            .ok_or_else(platform::einval)?;
        if new_end > i64::MAX as u64 {
            return Err(platform::efbig());
        }
        let new_end_usize = usize::try_from(new_end).map_err(|_| platform::efbig())?;

        if let InodeContent::RegularFile { ref data } = fh.node.content {
            let mut d = data.write().unwrap();
            if new_end_usize > d.len() {
                let growth = new_end - d.len() as u64;
                inode::reserve_bytes(fs, growth)?;
                d.resize(new_end_usize, 0);
                fh.node.meta.write().unwrap().size = new_end;
            }
        }
        Ok(())
    } else if mode & FALLOC_FL_PUNCH_HOLE != 0 && mode & FALLOC_FL_KEEP_SIZE != 0 {
        // Punch hole: zero out range without changing file size.
        if let InodeContent::RegularFile { ref data } = fh.node.content {
            let mut d = data.write().unwrap();
            let start = std::cmp::min(offset as usize, d.len());
            let end_offset = offset.checked_add(length).unwrap_or(u64::MAX);
            let end = std::cmp::min(end_offset as usize, d.len());
            if start < end {
                d[start..end].fill(0);
            }
        }
        Ok(())
    } else {
        Err(platform::eopnotsupp())
    }
}

/// Sync a file to disk (no-op for MemFs).
pub(crate) fn do_fsync(
    _fs: &MemFs,
    _ctx: Context,
    _ino: u64,
    _datasync: bool,
    _handle: u64,
) -> io::Result<()> {
    Ok(())
}

/// Sync a directory to disk (no-op for MemFs).
pub(crate) fn do_fsyncdir(
    _fs: &MemFs,
    _ctx: Context,
    _ino: u64,
    _datasync: bool,
    _handle: u64,
) -> io::Result<()> {
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// lseek on the virtual init binary.
fn lseek_init(offset: u64, whence: u32) -> io::Result<u64> {
    use crate::agentd::AGENTD_BYTES;
    let file_size = AGENTD_BYTES.len() as u64;

    match whence {
        w if w == libc::SEEK_SET as u32 => Ok(offset),
        w if w == libc::SEEK_END as u32 => {
            let signed_offset = offset as i64;
            let pos = (file_size as i64)
                .checked_add(signed_offset)
                .ok_or_else(platform::einval)?;
            if pos < 0 {
                return Err(platform::einval());
            }
            Ok(pos as u64)
        }
        SEEK_DATA => {
            if offset >= file_size {
                Err(platform::enxio())
            } else {
                Ok(offset)
            }
        }
        SEEK_HOLE => {
            if offset >= file_size {
                Err(platform::enxio())
            } else {
                Ok(file_size)
            }
        }
        _ => Err(platform::einval()),
    }
}
