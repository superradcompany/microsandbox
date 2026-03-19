//! Attribute operations: getattr, setattr, access.
//!
//! All stat results pass through `patched_stat` which applies the override xattr.
//! The guest sees virtualized uid/gid/mode/rdev, while size/timestamps come from
//! the real host file.
//!
//! setattr triggers copy-up, then applies changes: UID/GID/mode via xattr,
//! size via ftruncate, timestamps via futimens.

use std::{io, time::Duration};

use super::{OverlayFs, copy_up, inode};
use crate::{
    Context, SetattrValid,
    backends::shared::{init_binary, platform, stat_override},
    stat64,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Get attributes for an inode.
pub(crate) fn do_getattr(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    _handle: Option<u64>,
) -> io::Result<(stat64, Duration)> {
    if ino == init_binary::INIT_INODE {
        return Ok((init_binary::init_stat(), fs.cfg.attr_timeout));
    }

    let st = inode::stat_node(fs, ino)?;
    Ok((st, fs.cfg.attr_timeout))
}

/// Set attributes on an inode.
///
/// Triggers copy-up for lower-layer files, then applies attribute changes
/// matching the passthrough setattr pattern.
pub(crate) fn do_setattr(
    fs: &OverlayFs,
    _ctx: Context,
    ino: u64,
    attr: stat64,
    _handle: Option<u64>,
    valid: SetattrValid,
) -> io::Result<(stat64, Duration)> {
    if fs.cfg.read_only {
        return Err(platform::erofs());
    }
    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    // Copy-up before mutation.
    copy_up::ensure_upper(fs, ino)?;

    // Open with O_RDWR when truncation is needed, O_RDONLY otherwise.
    let open_flags = if valid.contains(SetattrValid::SIZE) {
        libc::O_RDWR
    } else {
        libc::O_RDONLY
    };
    let fd = inode::open_node_fd(fs, ino, open_flags)?;
    let close_fd = scopeguard::guard(fd, |fd| unsafe {
        libc::close(fd);
    });

    let kill_priv = valid.intersects(SetattrValid::UID | SetattrValid::GID)
        || (valid.contains(SetattrValid::SIZE) && valid.contains(SetattrValid::KILL_SUIDGID));

    // Handle uid/gid/mode changes via xattr.
    if valid.intersects(SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE) || kill_priv {
        let current = stat_override::get_override(*close_fd)?;
        let (cur_uid, cur_gid, cur_mode, cur_rdev) = match current {
            Some(ovr) => (ovr.uid, ovr.gid, ovr.mode, ovr.rdev),
            None => {
                let st = platform::fstat(*close_fd)?;
                let mode = platform::mode_u32(st.st_mode);
                (st.st_uid, st.st_gid, mode, 0)
            }
        };

        let new_uid = if valid.contains(SetattrValid::UID) {
            attr.st_uid
        } else {
            cur_uid
        };
        let new_gid = if valid.contains(SetattrValid::GID) {
            attr.st_gid
        } else {
            cur_gid
        };
        let new_mode = if valid.contains(SetattrValid::MODE) {
            let attr_mode = platform::mode_u32(attr.st_mode);
            (cur_mode & platform::MODE_TYPE_MASK) | (attr_mode & !platform::MODE_TYPE_MASK)
        } else {
            cur_mode
        };
        let new_mode = if kill_priv {
            new_mode & !(platform::MODE_SETUID | platform::MODE_SETGID)
        } else {
            new_mode
        };

        stat_override::set_override(*close_fd, new_uid, new_gid, new_mode, cur_rdev)?;
    }

    // Handle size changes via ftruncate.
    if valid.contains(SetattrValid::SIZE) {
        let ret = unsafe { libc::ftruncate(*close_fd, attr.st_size) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    // Handle timestamp changes.
    if valid.intersects(SetattrValid::ATIME | SetattrValid::MTIME) {
        let mut times = [libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        }; 2];

        if valid.contains(SetattrValid::ATIME) {
            if valid.contains(SetattrValid::ATIME_NOW) {
                times[0].tv_nsec = libc::UTIME_NOW;
            } else {
                times[0].tv_sec = attr.st_atime;
                times[0].tv_nsec = attr.st_atime_nsec;
            }
        }

        if valid.contains(SetattrValid::MTIME) {
            if valid.contains(SetattrValid::MTIME_NOW) {
                times[1].tv_nsec = libc::UTIME_NOW;
            } else {
                times[1].tv_sec = attr.st_mtime;
                times[1].tv_nsec = attr.st_mtime_nsec;
            }
        }

        let ret = unsafe { libc::futimens(*close_fd, times.as_ptr()) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    drop(close_fd);

    // Return updated attributes.
    let st = inode::stat_node(fs, ino)?;
    Ok((st, fs.cfg.attr_timeout))
}

/// Check file access permissions using virtualized uid/gid/mode.
pub(crate) fn do_access(fs: &OverlayFs, ctx: Context, ino: u64, mask: u32) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Ok(());
    }

    let st = inode::stat_node(fs, ino)?;

    // F_OK: just check existence.
    if mask == platform::ACCESS_F_OK {
        return Ok(());
    }

    if fs.cfg.read_only && mask & platform::ACCESS_W_OK != 0 {
        return Err(platform::erofs());
    }

    let st_mode = platform::mode_u32(st.st_mode);

    // Root bypasses read/write checks.
    if ctx.uid == 0 {
        if mask & platform::ACCESS_X_OK != 0 && st_mode & 0o111 == 0 {
            return Err(platform::eacces());
        }
        return Ok(());
    }

    let bits = if st.st_uid == ctx.uid {
        (st_mode >> 6) & 0o7
    } else if st.st_gid == ctx.gid {
        (st_mode >> 3) & 0o7
    } else {
        st_mode & 0o7
    };

    if mask & platform::ACCESS_R_OK != 0 && bits & 0o4 == 0 {
        return Err(platform::eacces());
    }
    if mask & platform::ACCESS_W_OK != 0 && bits & 0o2 == 0 {
        return Err(platform::eacces());
    }
    if mask & platform::ACCESS_X_OK != 0 && bits & 0o1 == 0 {
        return Err(platform::eacces());
    }

    Ok(())
}
