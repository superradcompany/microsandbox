//! Attribute operations: getattr, setattr, access.
//!
//! ## Stat Virtualization
//!
//! All stat results pass through `patched_stat` which applies the override xattr. The guest
//! sees virtualized uid/gid/mode/rdev, while size/timestamps/blocks come from the real host file.
//!
//! ## setattr
//!
//! UID/GID/mode changes are stored in the override xattr — never via real `fchown`/`fchmod`
//! (the host process lacks `CAP_CHOWN`). Size changes use real `ftruncate`, and timestamp
//! changes use real `futimens`.

use std::io;
use std::time::Duration;

use super::PassthroughFs;
use super::inode;
use crate::backends::shared::init_binary;
use crate::backends::shared::platform;
use crate::backends::shared::stat_override;
use crate::{Context, SetattrValid, stat64};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Get attributes for an inode.
pub(crate) fn do_getattr(
    fs: &PassthroughFs,
    _ctx: Context,
    ino: u64,
    _handle: Option<u64>,
) -> io::Result<(stat64, Duration)> {
    if ino == init_binary::INIT_INODE {
        return Ok((init_binary::init_stat(), fs.cfg.attr_timeout));
    }

    let st = inode::stat_inode(fs, ino)?;
    Ok((st, fs.cfg.attr_timeout))
}

/// Set attributes on an inode.
pub(crate) fn do_setattr(
    fs: &PassthroughFs,
    _ctx: Context,
    ino: u64,
    attr: stat64,
    _handle: Option<u64>,
    valid: SetattrValid,
) -> io::Result<(stat64, Duration)> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    // Open with O_RDWR when truncation is needed, O_RDONLY otherwise.
    // ftruncate(2) requires write permission on the fd; opening O_RDONLY
    // would cause EINVAL on Linux when SIZE is in the valid mask.
    let open_flags = if valid.contains(SetattrValid::SIZE) {
        libc::O_RDWR
    } else {
        libc::O_RDONLY
    };
    let fd = inode::open_inode_fd(fs, ino, open_flags)?;
    let close_fd = scopeguard::guard(fd, |fd| unsafe {
        libc::close(fd);
    });

    // FUSE expects setattr-triggered truncate/chown to clear suid/sgid when
    // requested. UID/GID changes always clear them; SIZE changes only do so
    // when the kernel sets KILL_SUIDGID.
    let kill_priv = valid.intersects(SetattrValid::UID | SetattrValid::GID)
        || (valid.contains(SetattrValid::SIZE) && valid.contains(SetattrValid::KILL_SUIDGID));

    // Handle uid/gid/mode changes via xattr (not real chown/chmod).
    if valid.intersects(SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE) || kill_priv {
        let current = stat_override::get_override(*close_fd)?;
        let (cur_uid, cur_gid, cur_mode, cur_rdev) = match current {
            Some(ovr) => (ovr.uid, ovr.gid, ovr.mode, ovr.rdev),
            None => {
                let st = platform::fstat(*close_fd)?;
                #[cfg(target_os = "linux")]
                let mode = st.st_mode;
                #[cfg(target_os = "macos")]
                let mode = st.st_mode as u32;
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
            #[cfg(target_os = "linux")]
            let attr_mode = attr.st_mode;
            #[cfg(target_os = "macos")]
            let attr_mode = attr.st_mode as u32;
            (cur_mode & libc::S_IFMT as u32) | (attr_mode & !libc::S_IFMT as u32)
        } else {
            cur_mode
        };
        let new_mode = if kill_priv {
            new_mode & !(libc::S_ISUID as u32 | libc::S_ISGID as u32)
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
    let st = inode::stat_inode(fs, ino)?;
    Ok((st, fs.cfg.attr_timeout))
}

/// Check file access permissions using virtualized uid/gid/mode.
///
/// Uses `stat_inode` (which applies the override xattr) so permission checks honor
/// the guest-visible ownership and mode bits, not the real host file permissions.
/// Root (uid 0) bypasses read/write checks but still needs at least one execute bit.
pub(crate) fn do_access(fs: &PassthroughFs, ctx: Context, ino: u64, mask: u32) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        // init.krun is always readable and executable.
        return Ok(());
    }

    let st = inode::stat_inode(fs, ino)?;

    // F_OK: just check existence.
    if mask == libc::F_OK as u32 {
        return Ok(());
    }

    // Get mode as u32 for uniform handling.
    #[cfg(target_os = "linux")]
    let st_mode = st.st_mode;
    #[cfg(target_os = "macos")]
    let st_mode = st.st_mode as u32;

    // Root (uid 0) bypasses read/write checks.
    if ctx.uid == 0 {
        if mask & libc::X_OK as u32 != 0 && st_mode & 0o111 == 0 {
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
