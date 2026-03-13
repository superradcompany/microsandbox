//! File operations: open, read, write, readlink, flush, release.
//!
//! Write-mode opens trigger copy-up of lower-layer files to the upper layer.
//! Subsequent reads and writes operate on the upper copy.

use std::{
    io,
    os::fd::{AsRawFd, FromRawFd},
    sync::{Arc, RwLock, atomic::Ordering},
};

use super::{
    OverlayFs, copy_up, inode,
    types::{FileHandle, NodeState},
};
use crate::{
    Context, OpenOptions, ZeroCopyReader, ZeroCopyWriter,
    backends::shared::{init_binary, platform, stat_override},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a file and return a handle.
///
/// Write-mode opens trigger copy-up so the file is on the upper layer.
pub(crate) fn do_open(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    kill_priv: bool,
    flags: u32,
) -> io::Result<(Option<u64>, OpenOptions)> {
    if ino == init_binary::INIT_INODE {
        return Ok((Some(init_binary::INIT_HANDLE), OpenOptions::KEEP_CACHE));
    }

    let mut open_flags = inode::translate_open_flags(flags as i32);

    // Determine if this is a write open.
    let access_mode = open_flags & libc::O_ACCMODE;
    let is_write = access_mode == libc::O_WRONLY
        || access_mode == libc::O_RDWR
        || open_flags & libc::O_TRUNC != 0;

    // Copy-up before write opens.
    if is_write {
        copy_up::ensure_upper(fs, ino)?;
    }

    // Writeback cache adjustments (same as passthrough).
    if fs.writeback.load(Ordering::Relaxed) {
        if open_flags & libc::O_WRONLY != 0 {
            open_flags = (open_flags & !libc::O_WRONLY) | libc::O_RDWR;
        }
        open_flags &= !libc::O_APPEND;
    }

    let fd = inode::open_node_fd(fs, ino, open_flags)?;
    let fd_guard = scopeguard::guard(fd, |fd| unsafe {
        libc::close(fd);
    });

    // kill_priv: clear SUID/SGID on open+truncate.
    if kill_priv
        && (open_flags & libc::O_TRUNC != 0)
        && let Ok(Some(ovr)) = stat_override::get_override(*fd_guard)
    {
        let new_mode = ovr.mode & !(libc::S_ISUID as u32 | libc::S_ISGID as u32);
        if new_mode != ovr.mode {
            stat_override::set_override(*fd_guard, ovr.uid, ovr.gid, new_mode, ovr.rdev)?;
        }
    }

    let fd = scopeguard::ScopeGuard::into_inner(fd_guard);
    let file = unsafe { std::fs::File::from_raw_fd(fd) };

    let handle = fs.next_handle.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(FileHandle {
        file: RwLock::new(file),
    });

    fs.file_handles.write().unwrap().insert(handle, data);
    Ok((Some(handle), fs.cache_open_options()))
}

/// Read data from a file.
pub(crate) fn do_read(
    fs: &OverlayFs,
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
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;
    let f = data.file.read().unwrap();
    w.write_from(&f, size as usize, offset)
}

/// Write data to a file.
///
/// The file must already be on the upper layer (do_open triggers copy-up for
/// write opens). kill_priv clears SUID/SGID on first write.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_write(
    fs: &OverlayFs,
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
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;

    let f = data.file.read().unwrap();

    // kill_priv: clear SUID/SGID before first write.
    if kill_priv && let Ok(Some(ovr)) = stat_override::get_override(f.as_raw_fd()) {
        let new_mode = ovr.mode & !(libc::S_ISUID as u32 | libc::S_ISGID as u32);
        if new_mode != ovr.mode {
            stat_override::set_override(f.as_raw_fd(), ovr.uid, ovr.gid, new_mode, ovr.rdev)?;
        }
    }

    r.read_to(&f, size as usize, offset)
}

/// Read the target of a symbolic link.
pub(crate) fn do_readlink(fs: &OverlayFs, _ctx: Context, ino: u64) -> io::Result<Vec<u8>> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::einval());
    }

    let node = {
        let nodes = fs.nodes.read().unwrap();
        nodes.get(&ino).cloned().ok_or_else(platform::enoent)?
    };

    #[cfg(target_os = "linux")]
    {
        // Dup the O_PATH fd while the state lock is held to prevent a
        // concurrent copy-up from closing it underneath us. open_node_fd
        // reopens with O_NOFOLLOW which fails with ELOOP for real symlinks,
        // so we use the O_PATH fd directly.
        let (dup_fd, st) = {
            let state = node.state.read().unwrap();
            let fd = match &*state {
                NodeState::Lower { file, .. } | NodeState::Upper { file, .. } => file.as_raw_fd(),
                _ => return Err(platform::einval()),
            };
            let dup = unsafe { libc::fcntl(fd, libc::F_DUPFD_CLOEXEC, 0) };
            if dup < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            (dup, platform::fstat(fd)?)
        };
        let _close_dup = scopeguard::guard(dup_fd, |fd| unsafe {
            libc::close(fd);
        });

        if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
            // Real symlink — read target via /proc/self/fd/<dup'd O_PATH>.
            let proc_path = format!("/proc/self/fd/{}\0", dup_fd);
            let mut buf = vec![0u8; libc::PATH_MAX as usize];
            let len = unsafe {
                libc::readlinkat(
                    libc::AT_FDCWD,
                    proc_path.as_ptr() as *const libc::c_char,
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            };
            if len < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            buf.truncate(len as usize);
            return Ok(buf);
        }

        // File-backed symlink: reopen for reading (safe — it's a regular file).
        let fd = inode::open_node_fd(fs, ino, libc::O_RDONLY)?;
        let _close = scopeguard::guard(fd, |fd| unsafe { libc::close(fd) });

        // Verify xattr says S_IFLNK — missing or wrong type is an integrity error.
        if let Some(ovr) = stat_override::get_override(fd)? {
            if ovr.mode & libc::S_IFMT as u32 != libc::S_IFLNK as u32 {
                return Err(platform::eio());
            }
        } else {
            return Err(platform::eio());
        }

        // Fstat the reopened fd for authoritative size (O_PATH fstat may be
        // stale if copy-up raced between the dup and open_node_fd).
        let file_st = platform::fstat(fd)?;
        let size = file_st.st_size as usize;
        let mut buf = vec![0u8; size];
        let mut pos = 0;
        while pos < size {
            let n = unsafe {
                libc::pread(
                    fd,
                    buf[pos..].as_mut_ptr() as *mut libc::c_void,
                    size - pos,
                    pos as libc::off_t,
                )
            };
            if n < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            if n == 0 {
                break; // EOF
            }
            pos += n as usize;
        }
        buf.truncate(pos);
        Ok(buf)
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, symlinks are real. Use /.vol path.
        // Extract dev/ino from the already-validated state (guard was dropped above).
        let (node_dev, node_ino) = {
            let state = node.state.read().unwrap();
            match &*state {
                NodeState::Lower { ino, dev, .. } | NodeState::Upper { ino, dev, .. } => {
                    (*dev, *ino)
                }
                _ => return Err(platform::einval()),
            }
        };
        let path = inode::vol_path(node_dev, node_ino);
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let len = unsafe {
            libc::readlink(
                path.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if len < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        buf.truncate(len as usize);
        Ok(buf)
    }
}

/// Flush pending data for a file handle.
pub(crate) fn do_flush(fs: &OverlayFs, _ctx: Context, ino: u64, handle: u64) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Ok(());
    }

    let handles = fs.file_handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;
    let f = data.file.read().unwrap();

    let newfd = unsafe { libc::fcntl(f.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
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
pub(crate) fn do_release(fs: &OverlayFs, _ctx: Context, ino: u64, handle: u64) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Ok(());
    }
    fs.file_handles.write().unwrap().remove(&handle);
    Ok(())
}
