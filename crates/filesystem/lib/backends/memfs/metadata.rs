//! Attribute operations: getattr, setattr, access.
//!
//! All stat results are built directly from in-memory metadata.
//! No xattr-based stat virtualization is needed — MemFs owns all metadata.

use std::io;
use std::time::Duration;

use super::MemFs;
use super::inode;
use super::types::InodeContent;
use crate::backends::shared::init_binary;
use crate::backends::shared::platform;
use crate::{Context, SetattrValid, stat64};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Get attributes for an inode.
pub(crate) fn do_getattr(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    _handle: Option<u64>,
) -> io::Result<(stat64, Duration)> {
    if ino == init_binary::INIT_INODE {
        return Ok((init_binary::init_stat(), fs.cfg.attr_timeout));
    }

    let node = inode::get_node(fs, ino)?;
    let st = inode::build_stat(&node);
    Ok((st, fs.cfg.attr_timeout))
}

/// Set attributes on an inode.
pub(crate) fn do_setattr(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    attr: stat64,
    _handle: Option<u64>,
    valid: SetattrValid,
) -> io::Result<(stat64, Duration)> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    let node = inode::get_node(fs, ino)?;
    let mut meta = node.meta.write().unwrap();

    // Handle size changes (truncate/extend).
    if valid.contains(SetattrValid::SIZE) {
        if let InodeContent::RegularFile { ref data } = node.content {
            let old_len = {
                let d = data.read().unwrap();
                d.len() as u64
            };
            if attr.st_size < 0 {
                return Err(platform::einval());
            }
            let new_len = attr.st_size as u64;
            if new_len > i64::MAX as u64 {
                return Err(platform::efbig());
            }
            let new_len_usize = usize::try_from(new_len).map_err(|_| platform::efbig())?;

            if new_len < old_len {
                let mut d = data.write().unwrap();
                d.truncate(new_len_usize);
                inode::release_bytes(fs, old_len - new_len);
            } else if new_len > old_len {
                let growth = new_len - old_len;
                inode::reserve_bytes(fs, growth)?;
                let mut d = data.write().unwrap();
                d.resize(new_len_usize, 0);
            }
            meta.size = new_len;
        } else {
            return Err(platform::einval());
        }
    }

    // Handle mode changes (preserve file type bits).
    if valid.contains(SetattrValid::MODE) {
        #[cfg(target_os = "linux")]
        let attr_mode = attr.st_mode;
        #[cfg(target_os = "macos")]
        let attr_mode = attr.st_mode as u32;
        meta.mode = (meta.mode & libc::S_IFMT as u32) | (attr_mode & !libc::S_IFMT as u32);
    }

    if valid.contains(SetattrValid::UID) {
        meta.uid = attr.st_uid;
    }

    if valid.contains(SetattrValid::GID) {
        meta.gid = attr.st_gid;
    }

    // Handle timestamp changes.
    if valid.contains(SetattrValid::ATIME) {
        if valid.contains(SetattrValid::ATIME_NOW) {
            meta.atime = inode::current_time();
        } else {
            meta.atime = super::types::Timespec {
                sec: attr.st_atime,
                nsec: attr.st_atime_nsec,
            };
        }
    }

    if valid.contains(SetattrValid::MTIME) {
        if valid.contains(SetattrValid::MTIME_NOW) {
            meta.mtime = inode::current_time();
        } else {
            meta.mtime = super::types::Timespec {
                sec: attr.st_mtime,
                nsec: attr.st_mtime_nsec,
            };
        }
    }

    // Handle kill SUID/SGID.
    if valid.contains(SetattrValid::KILL_SUIDGID) {
        meta.mode &= !(libc::S_ISUID as u32 | libc::S_ISGID as u32);
    }

    meta.ctime = inode::current_time();

    let st = inode::build_stat_from_meta(ino, &meta);
    Ok((st, fs.cfg.attr_timeout))
}

/// Check file access permissions using in-memory metadata.
pub(crate) fn do_access(fs: &MemFs, ctx: Context, ino: u64, mask: u32) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        if mask & libc::W_OK as u32 != 0 {
            return Err(platform::eacces());
        }
        return Ok(());
    }

    let node = inode::get_node(fs, ino)?;
    let meta = node.meta.read().unwrap();

    // F_OK: just check existence.
    if mask == libc::F_OK as u32 {
        return Ok(());
    }

    let st_mode = meta.mode;

    // Root bypasses read/write checks.
    if ctx.uid == 0 {
        if mask & libc::X_OK as u32 != 0 && st_mode & 0o111 == 0 {
            return Err(platform::eacces());
        }
        return Ok(());
    }

    let bits = if meta.uid == ctx.uid {
        (st_mode >> 6) & 0o7
    } else if meta.gid == ctx.gid {
        (st_mode >> 3) & 0o7
    } else {
        st_mode & 0o7
    };

    if mask & libc::R_OK as u32 != 0 && bits & 0o4 == 0 {
        return Err(platform::eacces());
    }
    if mask & libc::W_OK as u32 != 0 && bits & 0o2 == 0 {
        return Err(platform::eacces());
    }
    if mask & libc::X_OK as u32 != 0 && bits & 0o1 == 0 {
        return Err(platform::eacces());
    }

    Ok(())
}
