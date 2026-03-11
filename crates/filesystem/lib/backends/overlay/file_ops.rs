//! File operations: open, read, write, readlink, flush, release.
//!
//! Write-mode opens trigger copy-up of lower-layer files to the upper layer.
//! Subsequent reads and writes operate on the upper copy.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};

use super::OverlayFs;
use super::copy_up;
use super::inode;
use super::types::{FileHandle, NodeState};
use crate::backends::shared::init_binary;
use crate::backends::shared::platform;
use crate::backends::shared::stat_override;
use crate::{Context, OpenOptions, ZeroCopyReader, ZeroCopyWriter};

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

    // kill_priv: clear SUID/SGID on open+truncate.
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
    let data = Arc::new(FileHandle {
        inode: ino,
        file: RwLock::new(file),
        writable: is_write,
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

    // kill_priv: clear SUID/SGID before first write.
    if kill_priv {
        let f = data.file.read().unwrap();
        if let Ok(Some(ovr)) = stat_override::get_override(f.as_raw_fd()) {
            let new_mode = ovr.mode & !(libc::S_ISUID as u32 | libc::S_ISGID as u32);
            if new_mode != ovr.mode {
                let _ =
                    stat_override::set_override(f.as_raw_fd(), ovr.uid, ovr.gid, new_mode, ovr.rdev);
            }
        }
    }

    let f = data.file.read().unwrap();
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

    let state = node.state.read().unwrap();

    #[cfg(target_os = "linux")]
    {
        // Get fd for the symlink.
        let fd = match &*state {
            NodeState::Lower { file, .. } | NodeState::Upper { file, .. } => {
                inode::open_node_fd(fs, ino, libc::O_RDONLY)?
            }
            NodeState::Root { .. } => return Err(platform::einval()),
            NodeState::Init => return Err(platform::einval()),
        };
        let _close = scopeguard::guard(fd, |fd| unsafe { libc::close(fd) });

        // Check if it's a real symlink or file-backed.
        let st = platform::fstat(fd)?;
        if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
            // Real symlink — readlinkat.
            let mut buf = vec![0u8; libc::PATH_MAX as usize];
            let len = unsafe { libc::readlinkat(fd, c"".as_ptr(), buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
            if len < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            buf.truncate(len as usize);
            return Ok(buf);
        }

        // File-backed symlink: verify xattr says S_IFLNK, then read content.
        if let Some(ovr) = stat_override::get_override(fd)? {
            if ovr.mode & libc::S_IFMT as u32 != libc::S_IFLNK as u32 {
                return Err(platform::einval());
            }
        } else {
            return Err(platform::einval());
        }

        // Read file content as link target.
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        buf.truncate(n as usize);
        Ok(buf)
    }

    #[cfg(target_os = "macos")]
    {
        // On macOS, symlinks are real. Use /.vol path.
        match &*state {
            NodeState::Lower { ino: node_ino, dev, .. } | NodeState::Upper { ino: node_ino, dev, .. } => {
                let path = inode::vol_path(*dev, *node_ino);
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
            _ => Err(platform::einval()),
        }
    }
}

/// Flush pending data for a file handle.
pub(crate) fn do_flush(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    handle: u64,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Ok(());
    }

    let handles = fs.file_handles.read().unwrap();
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
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    handle: u64,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Ok(());
    }
    fs.file_handles.write().unwrap().remove(&handle);
    Ok(())
}
