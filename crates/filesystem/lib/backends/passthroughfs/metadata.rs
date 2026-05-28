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

use std::{io, os::fd::AsRawFd, time::Duration};

use super::host_mode::{fchmod_mirror, fchmod_raw, host_strip_priv_bits, mirror_eligible_type};
use super::{PassthroughFs, inode};
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
    fs: &PassthroughFs,
    _ctx: Context,
    ino: u64,
    handle: Option<u64>,
) -> io::Result<(stat64, Duration)> {
    if fs.is_virtual_init_inode(ino) {
        return Ok((init_binary::init_stat(), fs.cfg.attr_timeout));
    }

    let st = match handle {
        Some(handle) => stat_handle(fs, handle)?,
        None => inode::stat_inode(fs, ino)?,
    };
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
    if fs.is_virtual_init_inode(ino) {
        return Err(platform::eacces());
    }
    if fs.cfg.readonly() && setattr_mutates(valid) {
        return Err(platform::erofs());
    }

    // With xattr-overlay disabled, the only honest answer to a uid/gid change
    // is to reject it — the host process cannot chown(2) without CAP_CHOWN.
    if !fs.cfg.xattr_enabled() && valid.intersects(SetattrValid::UID | SetattrValid::GID) {
        return Err(platform::eperm());
    }

    #[cfg(target_os = "macos")]
    let guest_file_type = platform::mode_file_type(inode::stat_inode(fs, ino)?.st_mode);

    #[cfg(target_os = "macos")]
    if guest_file_type == platform::MODE_LNK && valid.contains(SetattrValid::SIZE) {
        return Err(platform::einval());
    }

    // Open with O_RDWR when truncation is needed, O_RDONLY otherwise.
    // ftruncate(2) requires write permission on the fd; opening O_RDONLY
    // would cause EINVAL on Linux when SIZE is in the valid mask.
    let open_flags = if valid.contains(SetattrValid::SIZE) {
        libc::O_RDWR
    } else {
        libc::O_RDONLY
    };

    #[cfg(target_os = "linux")]
    let fd = inode::open_inode_fd(fs, ino, open_flags)?;

    #[cfg(target_os = "macos")]
    let fd = if guest_file_type == platform::MODE_LNK {
        open_symlink_inode_fd_macos(fs, ino)?
    } else {
        inode::open_inode_fd(fs, ino, open_flags)?
    };
    let close_fd = scopeguard::guard(fd, |fd| unsafe {
        libc::close(fd);
    });

    // FUSE expects setattr-triggered truncate/chown to clear suid/sgid when
    // requested. UID/GID changes always clear them; SIZE changes only do so
    // when the kernel sets KILL_SUIDGID.
    let kill_priv = valid.intersects(SetattrValid::UID | SetattrValid::GID)
        || (valid.contains(SetattrValid::SIZE) && valid.contains(SetattrValid::KILL_SUIDGID));

    // Mode-change handling depends on three orthogonal flags:
    //   - xattr_enabled        : whether the override overlay is in use
    //   - mirror_host_perms    : whether guest chmod mutates the host inode
    //   - kill_priv            : kernel asked us to clear setuid/setgid
    if valid.intersects(SetattrValid::UID | SetattrValid::GID | SetattrValid::MODE) || kill_priv {
        if fs.cfg.xattr_enabled() {
            let current = stat_override::get_override(
                *close_fd,
                fs.cfg.xattr_enabled(),
                fs.cfg.strict_enabled(),
            )?;
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

            // Mirror perm bits to the host inode *first* — if fchmod fails we
            // must not advance the overlay past a state the host cannot back.
            if fs.cfg.mirror_host_permissions()
                && valid.contains(SetattrValid::MODE)
                && mirror_eligible_type(new_mode & platform::MODE_TYPE_MASK)
            {
                fchmod_mirror(*close_fd, new_mode, new_mode & platform::MODE_TYPE_MASK)?;
            }

            stat_override::set_override(*close_fd, new_uid, new_gid, new_mode, cur_rdev)?;
        } else if valid.contains(SetattrValid::MODE) {
            // xattr off: guest sees real host stat. Apply chmod directly.
            // For REG/DIR we keep the owner-access floor so the host process
            // doesn't lock itself out; for other types (notably macOS
            // symlinks) we pass the raw perms because clamping symlink mode
            // bits would silently corrupt link state.
            let attr_mode = platform::mode_u32(attr.st_mode);
            let host_st = platform::fstat(*close_fd)?;
            let file_type = platform::mode_u32(host_st.st_mode) & platform::MODE_TYPE_MASK;
            let mut perms = attr_mode & 0o7777;
            if kill_priv {
                perms &= !(platform::MODE_SETUID | platform::MODE_SETGID);
            }
            if mirror_eligible_type(file_type) {
                fchmod_mirror(*close_fd, perms, file_type)?;
            } else {
                fchmod_raw(*close_fd, perms)?;
            }
        } else if kill_priv {
            // xattr off + kill_priv with no MODE bit (typical: SIZE truncate
            // of a setuid binary). Strip setuid/setgid on the host inode so
            // we honor HANDLE_KILLPRIV_V2 semantics for `Off` mounts too.
            host_strip_priv_bits(*close_fd)?;
        }
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
        let times = platform::build_timespecs(attr, valid);

        #[cfg(target_os = "macos")]
        if guest_file_type == platform::MODE_LNK {
            set_symlink_times_macos(fs, ino, &times)?;
        } else {
            let ret = unsafe { libc::futimens(*close_fd, times.as_ptr()) };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
        }

        #[cfg(target_os = "linux")]
        {
            let ret = unsafe { libc::futimens(*close_fd, times.as_ptr()) };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
        }
    }

    drop(close_fd);

    // Return updated attributes.
    let st = inode::stat_inode(fs, ino)?;
    Ok((st, fs.cfg.attr_timeout))
}

fn setattr_mutates(valid: SetattrValid) -> bool {
    valid.intersects(
        SetattrValid::MODE
            | SetattrValid::UID
            | SetattrValid::GID
            | SetattrValid::SIZE
            | SetattrValid::ATIME
            | SetattrValid::MTIME
            | SetattrValid::ATIME_NOW
            | SetattrValid::MTIME_NOW
            | SetattrValid::CTIME,
    )
}

/// Check file access permissions using virtualized uid/gid/mode.
///
/// Uses `stat_inode` (which applies the override xattr) so permission checks honor
/// the guest-visible ownership and mode bits, not the real host file permissions.
/// Root (uid 0) bypasses read/write checks but still needs at least one execute bit.
pub(crate) fn do_access(fs: &PassthroughFs, ctx: Context, ino: u64, mask: u32) -> io::Result<()> {
    if fs.is_virtual_init_inode(ino) {
        // init.krun is always readable and executable.
        return Ok(());
    }

    let st = inode::stat_inode(fs, ino)?;

    // F_OK: just check existence.
    if mask == platform::ACCESS_F_OK {
        return Ok(());
    }

    let st_mode = platform::mode_u32(st.st_mode);

    // Root (uid 0) bypasses read/write checks.
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

fn stat_handle(fs: &PassthroughFs, handle: u64) -> io::Result<stat64> {
    let handles = fs.handles.read().unwrap();
    let data = handles.get(&handle).ok_or_else(platform::ebadf)?;
    let file = data.file.read().unwrap();
    let fd = file.as_raw_fd();
    let st = platform::fstat(fd)?;

    stat_override::patched_stat(fd, st, fs.cfg.xattr_enabled(), fs.cfg.strict_enabled())
}

#[cfg(target_os = "macos")]
pub(crate) fn open_symlink_inode_fd_macos(fs: &PassthroughFs, ino: u64) -> io::Result<i32> {
    let inodes = fs.inodes.read().unwrap();
    let data = inodes.get(&ino).ok_or_else(platform::ebadf)?;
    let path = inode::vol_path(data.dev, data.ino);
    let fd = unsafe {
        libc::open(
            path.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_SYMLINK,
        )
    };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    Ok(fd)
}

#[cfg(target_os = "macos")]
fn set_symlink_times_macos(
    fs: &PassthroughFs,
    ino: u64,
    times: &[libc::timespec; 2],
) -> io::Result<()> {
    let inodes = fs.inodes.read().unwrap();
    let data = inodes.get(&ino).ok_or_else(platform::ebadf)?;
    let path = inode::vol_path(data.dev, data.ino);
    let ret = unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            path.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    Ok(())
}
