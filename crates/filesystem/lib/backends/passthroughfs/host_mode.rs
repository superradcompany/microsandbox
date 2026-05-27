//! Shared host-mode helpers for the policy-driven create/setattr paths.
//!
//! These helpers implement the two policy contracts that need to touch the
//! real host inode:
//!
//! - **`HostPermissions::Mirror`** (`Strict`/`Relaxed`): mirror only the
//!   ordinary `0o777` perm bits to the host inode, with an owner-access floor
//!   so the host process keeps access to its own files. Setuid, setgid, and
//!   file-type bits are stripped — only regular files and directories are
//!   eligible.
//!
//! - **`StatVirtualization::Off` `HANDLE_KILLPRIV_V2`**: the overlay is absent
//!   so setuid/setgid clearing on truncate/write must hit the host inode
//!   directly. Otherwise a guest could write to a setuid host binary without
//!   ever clearing the privilege bits.

use std::{ffi::CStr, io, os::fd::RawFd};

use super::platform;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Owner-access floor for regular files: at least owner read/write.
pub(super) const OWNER_FLOOR_FILE: u32 = 0o600;

/// Owner-access floor for directories: at least owner read/write/execute.
pub(super) const OWNER_FLOOR_DIR: u32 = 0o700;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// True for file types whose permission bits should be mirrored to the host.
///
/// Regular files and directories only. Symlinks, FIFOs, sockets, and device
/// nodes are excluded: special types live entirely in the overlay (they are
/// virtualized regular files on the host), and symlink mode bits are not
/// portably meaningful.
pub(super) fn mirror_eligible_type(file_type: u32) -> bool {
    file_type == platform::MODE_REG || file_type == platform::MODE_DIR
}

/// Apply the `Mirror` policy to `fd`: `fchmod` to the guest's perm bits
/// merged with the owner-access floor for the given file type.
///
/// Strips file-type, setuid, and setgid bits — only ordinary rwx survives.
pub(super) fn fchmod_mirror(fd: RawFd, perms: u32, file_type: u32) -> io::Result<()> {
    let floor = if file_type == platform::MODE_DIR {
        OWNER_FLOOR_DIR
    } else {
        OWNER_FLOOR_FILE
    };
    let mode = (perms & 0o777) | floor;
    let ret = unsafe { libc::fchmod(fd, mode as libc::mode_t) };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(())
}

/// `fchmod_mirror` for a path: open through `dirfd`, `fchmod`, then close.
pub(super) fn fchmod_at_mirror(
    dirfd: RawFd,
    name: &CStr,
    perms: u32,
    file_type: u32,
) -> io::Result<()> {
    let open_flags = if file_type == platform::MODE_DIR {
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW
    } else {
        libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW
    };
    let fd = unsafe { libc::openat(dirfd, name.as_ptr(), open_flags) };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    let result = fchmod_mirror(fd, perms, file_type);
    unsafe { libc::close(fd) };
    result
}

/// Under `Off`, strip setuid/setgid bits from the host inode in place.
///
/// Called from `HANDLE_KILLPRIV_V2` paths (`open(O_TRUNC)`, `write`,
/// `setattr(SIZE | KILL_SUIDGID)`) when there is no overlay to update. A
/// no-op when neither bit is set, so the common case is just one extra
/// `fstat`.
pub(super) fn host_strip_priv_bits(fd: RawFd) -> io::Result<()> {
    let st = platform::fstat(fd)?;
    let mode = platform::mode_u32(st.st_mode);
    let stripped = mode & !(platform::MODE_SETUID | platform::MODE_SETGID);
    if stripped == mode {
        return Ok(());
    }
    let ret = unsafe { libc::fchmod(fd, (stripped & 0o7777) as libc::mode_t) };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(())
}

/// Raw `fchmod` for the `Off` chmod path on non-eligible types (e.g. macOS
/// symlinks). No owner floor is applied because symlink modes have no
/// reliable host meaning and clamping them would silently corrupt link state.
pub(super) fn fchmod_raw(fd: RawFd, perms: u32) -> io::Result<()> {
    let ret = unsafe { libc::fchmod(fd, (perms & 0o7777) as libc::mode_t) };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(())
}
