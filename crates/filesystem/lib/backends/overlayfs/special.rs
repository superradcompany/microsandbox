//! Special operations: statfs, fsync, fsyncdir, lseek, fallocate, copyfilerange.

use std::{io, os::fd::AsRawFd};

use super::OverlayFs;
use crate::{
    Context,
    backends::shared::{init_binary, platform},
    statvfs64,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Get filesystem statistics from the upper layer.
pub(crate) fn do_statfs(fs: &OverlayFs, _ctx: Context, _ino: u64) -> io::Result<statvfs64> {
    let fd = match &fs.upper {
        Some(upper) => upper.root_fd.as_raw_fd(),
        None => fs.lowers.last().unwrap().root_fd.as_raw_fd(),
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

/// Synchronize file contents.
pub(crate) fn do_fsync(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    datasync: bool,
    handle: u64,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Ok(());
    }

    let handles = fs.file_handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;

    if fs.cfg.read_only {
        return Ok(());
    }
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
///
/// Syncs the directory handle fd if it has been opened for modification.
pub(crate) fn do_fsyncdir(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    datasync: bool,
    _handle: u64,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Ok(());
    }

    if fs.cfg.read_only {
        return Ok(());
    }

    // Open the directory for syncing.
    let fd = super::inode::open_node_fd(fs, ino, libc::O_RDONLY)?;
    let _close = scopeguard::guard(fd, |fd| unsafe {
        libc::close(fd);
    });

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

/// Reposition read/write file offset (seek for sparse files).
pub(crate) fn do_lseek(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    handle: u64,
    offset: u64,
    whence: u32,
) -> io::Result<u64> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::enosys());
    }

    let handles = fs.file_handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;
    #[allow(clippy::readonly_write_lock)]
    let f = data.file.write().unwrap();
    let fd = f.as_raw_fd();

    let ret = unsafe { libc::lseek(fd, offset as i64, whence as i32) };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    Ok(ret as u64)
}

/// Allocate space for a file.
///
/// The file must already be on the upper layer (do_open triggers copy-up).
pub(crate) fn do_fallocate(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    handle: u64,
    mode: u32,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    if fs.cfg.read_only {
        return Err(platform::erofs());
    }
    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    let handles = fs.file_handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;
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
            store.fst_flags = libc::F_ALLOCATEALL;
            let ret = unsafe { libc::fcntl(fd, libc::F_PREALLOCATE, &mut store) };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
        }

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

/// Copy a range of data from one file to another.
///
/// Linux: uses `copy_file_range(2)`. macOS: returns ENOSYS.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_copyfilerange(
    fs: &OverlayFs,
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
    if fs.cfg.read_only {
        return Err(platform::erofs());
    }
    if inode_in == init_binary::INIT_INODE || inode_out == init_binary::INIT_INODE {
        return Err(platform::enosys());
    }

    #[cfg(target_os = "linux")]
    {
        let handles = fs.file_handles.read().unwrap();
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
