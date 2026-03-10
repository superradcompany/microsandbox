//! Special operations: fsync, fsyncdir, fallocate, lseek, statfs, copyfilerange.
//!
//! ## copyfilerange
//!
//! Implemented on Linux using `copy_file_range(2)`, which enables server-side file copies
//! that stay within the host kernel — avoiding the FUSE round-trip of read+write through
//! guest memory. Returns `ENOSYS` on macOS; the guest kernel falls back to read+write.
//!
//! ## fallocate
//!
//! On macOS, uses `fcntl(F_PREALLOCATE)` + `ftruncate` since `fallocate64` doesn't exist.
//! Tries contiguous allocation first, falls back to non-contiguous.

use std::io;
use std::os::fd::AsRawFd;

use super::PassthroughFs;
use crate::backends::shared::init_binary;
use crate::backends::shared::platform;
use crate::{Context, statvfs64};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Synchronize file contents.
pub(crate) fn do_fsync(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    datasync: bool,
    handle: u64,
) -> io::Result<()> {
    if inode == init_binary::INIT_INODE {
        return Ok(());
    }

    let handles = fs.handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;
    // Write lock: fsync/fdatasync modify fd state.
    #[allow(clippy::readonly_write_lock)]
    let f = data.file.write().unwrap();
    let fd = f.as_raw_fd();

    #[cfg(target_os = "linux")]
    let ret = if datasync {
        unsafe { libc::fdatasync(fd) }
    } else {
        unsafe { libc::fsync(fd) }
    };

    #[cfg(target_os = "macos")]
    let ret = {
        let _ = datasync;
        unsafe { libc::fsync(fd) }
    };

    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(())
}

/// Synchronize directory contents.
pub(crate) fn do_fsyncdir(
    fs: &PassthroughFs,
    ctx: Context,
    inode: u64,
    datasync: bool,
    handle: u64,
) -> io::Result<()> {
    do_fsync(fs, ctx, inode, datasync, handle)
}

/// Allocate space for a file.
pub(crate) fn do_fallocate(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    handle: u64,
    mode: u32,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    if inode == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    let handles = fs.handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;
    // Write lock: fallocate modifies file state.
    #[allow(clippy::readonly_write_lock)]
    let f = data.file.write().unwrap();
    let fd = f.as_raw_fd();

    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::fallocate64(fd, mode as i32, offset as i64, length as i64) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    #[cfg(target_os = "macos")]
    {
        // macOS only supports the default "allocate space" mode here.
        if mode != 0 {
            return Err(platform::linux_error(io::Error::from_raw_os_error(
                libc::EOPNOTSUPP,
            )));
        }

        let alloc_len = i64::try_from(length)
            .map_err(|_| platform::linux_error(io::Error::from_raw_os_error(libc::EOVERFLOW)))?;

        let mut store = libc::fstore_t {
            fst_flags: libc::F_ALLOCATECONTIG,
            fst_posmode: libc::F_PEOFPOSMODE,
            fst_offset: 0,
            fst_length: alloc_len,
            fst_bytesalloc: 0,
        };

        let ret = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut store) };
        if ret < 0 {
            // Try non-contiguous allocation.
            store.fst_flags = libc::F_ALLOCATEALL;
            let ret = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut store) };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
        }

        // Extend file size if needed.
        let new_size = offset
            .checked_add(length)
            .ok_or_else(|| platform::linux_error(io::Error::from_raw_os_error(libc::EOVERFLOW)))
            .and_then(|size| {
                i64::try_from(size).map_err(|_| {
                    platform::linux_error(io::Error::from_raw_os_error(libc::EOVERFLOW))
                })
            })?;
        let ret = unsafe { libc::ftruncate(fd, new_size) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Reposition read/write file offset (seek for sparse files).
pub(crate) fn do_lseek(
    fs: &PassthroughFs,
    _ctx: Context,
    inode: u64,
    handle: u64,
    offset: u64,
    whence: u32,
) -> io::Result<u64> {
    if inode == init_binary::INIT_INODE {
        return Err(platform::enosys());
    }

    let handles = fs.handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;
    // Write lock: lseek modifies fd seek position.
    #[allow(clippy::readonly_write_lock)]
    let f = data.file.write().unwrap();
    let fd = f.as_raw_fd();

    let ret = unsafe { libc::lseek(fd, offset as i64, whence as i32) };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    Ok(ret as u64)
}

/// Copy a range of data from one file to another using the kernel's
/// `copy_file_range(2)` syscall (Linux only).
///
/// On macOS, returns `ENOSYS` — the guest kernel will fall back to read+write.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_copyfilerange(
    fs: &PassthroughFs,
    _ctx: Context,
    inode_in: u64,
    handle_in: u64,
    offset_in: u64,
    inode_out: u64,
    handle_out: u64,
    offset_out: u64,
    len: u64,
    flags: u64,
) -> io::Result<usize> {
    if inode_in == init_binary::INIT_INODE || inode_out == init_binary::INIT_INODE {
        return Err(platform::enosys());
    }

    #[cfg(target_os = "linux")]
    {
        let handles = fs.handles.read().unwrap();
        let data_in = handles.get(&handle_in).ok_or_else(platform::ebadf)?;
        let data_out = handles.get(&handle_out).ok_or_else(platform::ebadf)?;
        let f_in = data_in.file.read().unwrap();
        let f_out = data_out.file.read().unwrap();

        let mut off_in = offset_in as i64;
        let mut off_out = offset_out as i64;

        let ret = unsafe {
            libc::copy_file_range(
                f_in.as_raw_fd(),
                &mut off_in,
                f_out.as_raw_fd(),
                &mut off_out,
                len as usize,
                flags as u32,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        Ok(ret as usize)
    }

    #[cfg(target_os = "macos")]
    {
        let _ = (
            fs, offset_in, inode_out, handle_in, handle_out, offset_out, len, flags,
        );
        Err(platform::enosys())
    }
}

/// Get filesystem statistics.
pub(crate) fn do_statfs(fs: &PassthroughFs, _ctx: Context, inode: u64) -> io::Result<statvfs64> {
    // Keep InodeFd guard alive so the fd isn't closed before fstatvfs uses it.
    let inode_fd;
    let fd = if inode == init_binary::INIT_INODE || inode == 1 {
        fs.root_fd.as_raw_fd()
    } else {
        inode_fd = super::inode::get_inode_fd(fs, inode)?;
        inode_fd.raw()
    };

    #[cfg(target_os = "linux")]
    {
        let mut st = unsafe { std::mem::zeroed::<statvfs64>() };
        let ret = unsafe { libc::fstatvfs64(fd, &mut st) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        Ok(st)
    }

    #[cfg(target_os = "macos")]
    {
        let mut st = unsafe { std::mem::zeroed::<statvfs64>() };
        let ret = unsafe { libc::fstatvfs(fd, &mut st) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        Ok(st)
    }
}
