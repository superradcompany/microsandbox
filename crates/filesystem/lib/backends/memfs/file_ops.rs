//! File operations: open, read, write, readlink, flush, release.
//!
//! File data lives in `Vec<u8>` buffers in memory. Read and write use a
//! staging file (memfd/tmpfile) to bridge the ZeroCopy traits, which
//! operate on file descriptors rather than byte slices.

use std::{
    cmp, io,
    os::fd::AsRawFd,
    sync::{Arc, atomic::Ordering},
};

use super::{
    MemFs, inode,
    types::{FileHandle, InodeContent},
};
use crate::{
    Context, OpenOptions, ZeroCopyReader, ZeroCopyWriter,
    backends::shared::{init_binary, platform},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a file and return a handle.
pub(crate) fn do_open(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    kill_priv: bool,
    flags: u32,
) -> io::Result<(Option<u64>, OpenOptions)> {
    if ino == init_binary::INIT_INODE {
        return Ok((Some(init_binary::INIT_HANDLE), OpenOptions::KEEP_CACHE));
    }

    let node = inode::get_node(fs, ino)?;

    if node.kind == platform::MODE_DIR {
        return Err(platform::eisdir());
    }

    let open_flags = super::normalize_handle_flags(fs.writeback.load(Ordering::Relaxed), flags);

    // Handle O_TRUNC: truncate file data.
    if open_flags & super::GUEST_O_TRUNC != 0
        && let InodeContent::RegularFile { ref data } = node.content
    {
        let mut data = data.write().unwrap();
        let old_len = data.len() as u64;
        data.clear();
        if old_len > 0 {
            inode::release_bytes(fs, old_len);
        }
        let mut meta = node.meta.write().unwrap();
        meta.size = 0;
        let now = inode::current_time();
        meta.mtime = now;
        meta.ctime = now;
    }

    // Handle kill_priv: clear SUID/SGID on truncate.
    if kill_priv && (open_flags & super::GUEST_O_TRUNC != 0) {
        let mut meta = node.meta.write().unwrap();
        if meta.mode & (platform::MODE_SETUID | platform::MODE_SETGID) != 0 {
            meta.mode &= !(platform::MODE_SETUID | platform::MODE_SETGID);
            meta.ctime = inode::current_time();
        }
    }

    let handle = fs.next_handle.fetch_add(1, Ordering::Relaxed);
    let fh = Arc::new(FileHandle {
        node: Arc::clone(&node),
        flags: open_flags,
    });

    fs.file_handles.write().unwrap().insert(handle, fh);
    Ok((Some(handle), fs.cache_open_options()))
}

/// Read data from a file.
///
/// Uses the staging file to bridge in-memory data to the ZeroCopyWriter.
pub(crate) fn do_read(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    handle: u64,
    w: &mut dyn ZeroCopyWriter,
    size: u32,
    offset: u64,
) -> io::Result<usize> {
    if ino == init_binary::INIT_INODE {
        return init_binary::read_init(w, &fs.init_file, size, offset);
    }

    let handles = fs.file_handles.read().unwrap();
    let fh = handles.get(&handle).ok_or_else(platform::ebadf)?;

    let data = match &fh.node.content {
        InodeContent::RegularFile { data } => data.read().unwrap(),
        _ => return Err(platform::eisdir()),
    };

    if offset >= data.len() as u64 {
        return Ok(0);
    }

    let end = cmp::min(offset as usize + size as usize, data.len());
    let slice = &data[offset as usize..end];
    let count = slice.len();

    if count == 0 {
        return Ok(0);
    }

    // Write data to staging file, then use write_from for FUSE transfer.
    let staging = fs.staging_file.lock().unwrap();
    let written = unsafe {
        libc::pwrite(
            staging.as_raw_fd(),
            slice.as_ptr() as *const libc::c_void,
            count,
            0,
        )
    };
    if written < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    w.write_from(&staging, count, 0)
}

/// Write data to a file.
///
/// Uses the staging file to bridge ZeroCopyReader data to the in-memory buffer.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_write(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    handle: u64,
    r: &mut dyn ZeroCopyReader,
    size: u32,
    offset: u64,
    kill_priv: bool,
) -> io::Result<usize> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    let handles = fs.file_handles.read().unwrap();
    let fh = handles.get(&handle).ok_or_else(platform::ebadf)?;

    let data_lock = match &fh.node.content {
        InodeContent::RegularFile { data } => data,
        _ => return Err(platform::eisdir()),
    };
    let append_mode = fh.flags & super::GUEST_O_APPEND != 0;

    // Validate that the write won't exceed stat64 representable size.
    if !append_mode {
        let requested_end = offset
            .checked_add(size as u64)
            .ok_or_else(platform::einval)?;
        if requested_end > i64::MAX as u64 {
            return Err(platform::efbig());
        }
    }

    // Read from guest into staging file.
    let staging = fs.staging_file.lock().unwrap();
    let count = r.read_to(&staging, size as usize, 0)?;

    if count == 0 {
        return Ok(0);
    }

    // Read data back from staging file.
    let mut buf = vec![0u8; count];
    let read_back = unsafe {
        libc::pread(
            staging.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            count,
            0,
        )
    };
    if read_back < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    drop(staging);

    let count = read_back as usize;

    // Write to in-memory data. Append mode must observe the current EOF under
    // the write lock so concurrent appenders serialize correctly.
    {
        let mut data = data_lock.write().unwrap();
        let start = if append_mode {
            data.len()
        } else {
            usize::try_from(offset).map_err(|_| platform::efbig())?
        };
        let new_end = start.checked_add(count).ok_or_else(platform::efbig)?;

        if (new_end as u64) > i64::MAX as u64 {
            return Err(platform::efbig());
        }

        if new_end > data.len() {
            let delta = (new_end - data.len()) as u64;
            inode::reserve_bytes(fs, delta)?;
            data.resize(new_end, 0);
        }

        data[start..new_end].copy_from_slice(&buf[..count]);

        // Update metadata.
        let mut meta = fh.node.meta.write().unwrap();
        meta.size = data.len() as u64;
        let now = inode::current_time();
        meta.mtime = now;
        meta.ctime = now;

        // kill_priv: clear SUID/SGID on data write.
        if kill_priv {
            meta.mode &= !(platform::MODE_SETUID | platform::MODE_SETGID);
        }
    }

    Ok(count)
}

/// Read the target of a symbolic link.
pub(crate) fn do_readlink(fs: &MemFs, _ctx: Context, ino: u64) -> io::Result<Vec<u8>> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::einval());
    }

    let node = inode::get_node(fs, ino)?;
    match &node.content {
        InodeContent::Symlink { target } => Ok(target.clone()),
        _ => Err(platform::einval()),
    }
}

/// Flush pending data for a file handle.
pub(crate) fn do_flush(_fs: &MemFs, _ctx: Context, ino: u64, _handle: u64) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Ok(());
    }
    // No-op for MemFs — data is already in memory.
    Ok(())
}

/// Release an open file handle.
pub(crate) fn do_release(fs: &MemFs, _ctx: Context, ino: u64, handle: u64) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Ok(());
    }

    if let Some(fh) = fs.file_handles.write().unwrap().remove(&handle) {
        // If this was the last reference to a regular file already evicted
        // from the nodes table, release the capacity.
        if fh.node.kind == platform::MODE_REG
            && Arc::strong_count(&fh.node) == 1
            && let InodeContent::RegularFile { ref data } = fh.node.content
        {
            let size = data.read().unwrap().len() as u64;
            if size > 0 {
                inode::release_bytes(fs, size);
            }
        }
    }

    Ok(())
}
