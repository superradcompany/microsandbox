//! File operations: open, read, write, flush, release.
//!
//! ## I/O Path
//!
//! Read and write use the `ZeroCopyWriter`/`ZeroCopyReader` traits from msb_krun, which
//! bridge FUSE transport buffers directly to file I/O via `preadv64`/`pwritev64`. These take
//! an explicit offset and do NOT modify the fd seek position, so `HandleData.file` only needs
//! a `RwLock` read lock for I/O — the write lock is reserved for `lseek`, `fsync`, `ftruncate`.
//!
//! ## Writeback Cache
//!
//! When writeback caching is negotiated, the kernel may read from write-only files for cache
//! coherency. `do_open` adjusts `O_WRONLY` → `O_RDWR` and strips `O_APPEND` (which races with
//! the kernel's cached view of the file).

use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};

use super::inode;
use super::PassthroughFs;
use crate::backends::shared::handle_table::HandleData;
use crate::backends::shared::init_binary;
use crate::backends::shared::platform;
use crate::backends::shared::stat_override;
use crate::{Context, OpenOptions, ZeroCopyReader, ZeroCopyWriter};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a file and return a handle.
///
/// When `kill_priv` is true and the open includes `O_TRUNC`, clears SUID/SGID
/// bits from the override xattr — truncating a setuid binary should remove setuid.
pub(crate) fn do_open(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    kill_priv: bool,
    flags: u32,
) -> io::Result<(Option<u64>, OpenOptions)> {
    if inode == init_binary::INIT_INODE {
        return Ok((Some(init_binary::INIT_HANDLE), OpenOptions::KEEP_CACHE));
    }

    let mut open_flags = inode::translate_open_flags(flags as i32);

    // Writeback cache: kernel may issue reads on O_WRONLY fds for cache coherency,
    // so widen to O_RDWR. Strip O_APPEND because it races with the kernel's cached
    // write position.
    if fs.writeback.load(Ordering::Relaxed) {
        if open_flags & libc::O_WRONLY != 0 {
            open_flags = (open_flags & !libc::O_WRONLY) | libc::O_RDWR;
        }
        open_flags &= !libc::O_APPEND;
    }

    // open_inode_fd adds O_NOFOLLOW and O_CLOEXEC itself for security
    // (prevents procfd magic-link following), so no need to set them here.
    let fd = inode::open_inode_fd(fs, inode, open_flags)?;

    // Clear SUID/SGID on open+truncate (HANDLE_KILLPRIV_V2).
    if kill_priv && (open_flags & libc::O_TRUNC != 0) {
        if let Ok(Some(ovr)) = stat_override::get_override(fd) {
            let new_mode = ovr.mode & !(libc::S_ISUID as u32 | libc::S_ISGID as u32);
            if new_mode != ovr.mode {
                let _ = stat_override::set_override(fd, ovr.uid, ovr.gid, new_mode, ovr.rdev);
            }
        }
    }

    let file = unsafe { std::fs::File::from_raw_fd(fd) };

    let handle = fs.next_handle.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(HandleData {
        file: RwLock::new(file),
    });

    fs.handles.write().unwrap().insert(handle, data);
    Ok((Some(handle), fs.cache_open_options()))
}

/// Read data from a file.
pub(crate) fn do_read(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    handle: u64,
    w: &mut dyn ZeroCopyWriter,
    size: u32,
    offset: u64,
) -> io::Result<usize> {
    // Virtual init.krun binary.
    if inode == init_binary::INIT_INODE {
        return init_binary::read_init(w, &fs.init_file, size, offset);
    }

    let handles = fs.handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;
    let f = data.file.read().unwrap();
    w.write_from(&f, size as usize, offset)
}

/// Write data to a file.
///
/// When `kill_priv` is true (HANDLE_KILLPRIV_V2 negotiated), clears SUID/SGID
/// bits from the override xattr after a successful write — the guest kernel
/// expects the filesystem to handle this.
pub(crate) fn do_write(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    handle: u64,
    r: &mut dyn ZeroCopyReader,
    size: u32,
    offset: u64,
    kill_priv: bool,
) -> io::Result<usize> {
    if inode == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    let handles = fs.handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;
    let f = data.file.read().unwrap();
    let written = r.read_to(&f, size as usize, offset)?;

    if kill_priv {
        let fd = f.as_raw_fd();
        if let Ok(Some(ovr)) = stat_override::get_override(fd) {
            let new_mode = ovr.mode & !(libc::S_ISUID as u32 | libc::S_ISGID as u32);
            if new_mode != ovr.mode {
                let _ = stat_override::set_override(fd, ovr.uid, ovr.gid, new_mode, ovr.rdev);
            }
        }
    }

    Ok(written)
}

/// Flush pending data for a file handle.
///
/// Emulates POSIX close semantics by duplicating and closing the fd.
/// Called on every guest `close()` (may fire multiple times if the fd was `dup`'d).
/// The dup+close flushes pending data and surfaces I/O errors without releasing the handle.
pub(crate) fn do_flush(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    handle: u64,
) -> io::Result<()> {
    if inode == init_binary::INIT_INODE {
        return Ok(());
    }

    let handles = fs.handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;
    let f = data.file.read().unwrap();

    let newfd = unsafe { libc::dup(f.as_raw_fd()) };
    if newfd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    let ret = unsafe { libc::close(newfd) };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(())
}

/// Release an open file handle.
pub(crate) fn do_release(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    handle: u64,
) -> io::Result<()> {
    if inode == init_binary::INIT_INODE {
        return Ok(());
    }

    fs.handles.write().unwrap().remove(&handle);
    Ok(())
}
