//! File operations: open, read, write, readlink, flush, release.
//!
//! File data lives in `Vec<u8>` buffers in memory. Read and write use a
//! staging file (memfd/tmpfile) to bridge the ZeroCopy traits, which
//! operate on file descriptors rather than byte slices.

use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::{cmp, io};

use super::MemFs;
use super::inode;
use super::types::{FileHandle, InodeContent};
use crate::backends::shared::init_binary;
use crate::backends::shared::platform;
use crate::{Context, OpenOptions, ZeroCopyReader, ZeroCopyWriter};

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

    if node.kind == libc::S_IFDIR as u32 {
        return Err(platform::eisdir());
    }

    let mut open_flags = flags as i32;

    // Writeback cache adjustments.
    if fs.writeback.load(Ordering::Relaxed) {
        if open_flags & libc::O_WRONLY != 0 {
            open_flags = (open_flags & !libc::O_WRONLY) | libc::O_RDWR;
        }
        open_flags &= !libc::O_APPEND;
    }

    // Handle O_TRUNC: truncate file data.
    if open_flags & libc::O_TRUNC != 0 {
        if let InodeContent::RegularFile { ref data } = node.content {
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
    }

    // Handle kill_priv: clear SUID/SGID on truncate.
    if kill_priv && (open_flags & libc::O_TRUNC != 0) {
        let mut meta = node.meta.write().unwrap();
        if meta.mode & (libc::S_ISUID as u32 | libc::S_ISGID as u32) != 0 {
            meta.mode &= !(libc::S_ISUID as u32 | libc::S_ISGID as u32);
            meta.ctime = inode::current_time();
        }
    }

    let handle = fs.next_handle.fetch_add(1, Ordering::Relaxed);
    let fh = Arc::new(FileHandle {
        inode: ino,
        node: Arc::clone(&node),
        flags: open_flags as u32,
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

    w.write_from(&*staging, count, 0)
}

/// Write data to a file.
///
/// Uses the staging file to bridge ZeroCopyReader data to the in-memory buffer.
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

    // Validate that the write won't exceed stat64 representable size.
    let requested_end = (offset as u64)
        .checked_add(size as u64)
        .ok_or_else(platform::einval)?;
    if requested_end > i64::MAX as u64 {
        return Err(platform::efbig());
    }

    // Read from guest into staging file.
    let staging = fs.staging_file.lock().unwrap();
    let count = r.read_to(&*staging, size as usize, 0)?;

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
    let start = offset as usize;
    let new_end = start
        .checked_add(count)
        .ok_or_else(platform::efbig)?;

    // Reserve capacity for growth.
    {
        let current_len = data_lock.read().unwrap().len();
        if new_end > current_len {
            let delta = (new_end - current_len) as u64;
            inode::reserve_bytes(fs, delta)?;
        }
    }

    // Write to in-memory data.
    {
        let mut data = data_lock.write().unwrap();
        if new_end > data.len() {
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
            meta.mode &= !(libc::S_ISUID as u32 | libc::S_ISGID as u32);
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
pub(crate) fn do_flush(
    _fs: &MemFs,
    _ctx: Context,
    ino: u64,
    _handle: u64,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Ok(());
    }
    // No-op for MemFs — data is already in memory.
    Ok(())
}

/// Release an open file handle.
pub(crate) fn do_release(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    handle: u64,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Ok(());
    }

    if let Some(fh) = fs.file_handles.write().unwrap().remove(&handle) {
        // If this was the last reference to a regular file already evicted
        // from the nodes table, release the capacity.
        if fh.node.kind == libc::S_IFREG as u32 && Arc::strong_count(&fh.node) == 1 {
            if let InodeContent::RegularFile { ref data } = fh.node.content {
                let size = data.read().unwrap().len() as u64;
                if size > 0 {
                    inode::release_bytes(fs, size);
                }
            }
        }
    }

    Ok(())
}
