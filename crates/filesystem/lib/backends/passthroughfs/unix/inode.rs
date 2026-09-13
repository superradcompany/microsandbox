//! Inode management: lookup, forget, and reference counting.
//!
//! ## Lookup Strategy
//!
//! Linux lookup uses a "collapse" optimization: open → statx(AT_EMPTY_PATH) → getxattr,
//! yielding 3 syscalls instead of the naive 4 (fstatat + statx + open + getxattr). The stat
//! is taken on the *opened* fd, eliminating TOCTOU between stat and open.
//!
//! macOS lookup uses fstatat → inode table check → register, and reopens tracked
//! inodes in one of two modes, chosen once per share by the volfs probe:
//!
//! - Volfs mode, used when the share root's filesystem answers `/.vol/<dev>/<ino>`
//!   lookups: an inode is reopened by its identity path, which stays valid across
//!   host-side renames.
//! - Anchor mode, used when it does not (FSKit-backed volumes such as exFAT on
//!   macOS 15 reject every volfs lookup): an inode is reopened by an
//!   `openat(O_NOFOLLOW)` walk from the retained root fd along a recorded
//!   (parent inode, name) alias, followed by an `(st_dev, st_ino)` check on the
//!   opened fd.
//!
//! Residual guarantees in anchor mode: identity is always verified after the open,
//! so a host-side replacement of an anchored name is refused rather than served;
//! and path-based resolution can still go stale while the walk runs if the host
//! renames an intermediate directory — that one exposure is shared with the
//! Linux backend.
//!
//! The hard link source is name-bound in anchor mode, which is a macOS-only
//! exposure: Linux links through `/proc/self/fd/N`, which is bound to the
//! inode, while macOS has no fd-relative `linkat`. The source name is
//! therefore resolved twice — once by the anchor verification, once by the
//! syscall — and the created entry's identity is checked afterwards, reporting
//! `ENOENT` when it does not hold the tracked inode.
//!
//! A source swapped before the `linkat` is detected even if the host puts the
//! original name back afterwards: the created entry pins whichever inode the
//! syscall captured, so the check still sees the replacement. That entry is
//! left in place — it is the outcome an unchecked `linkat` would have had, and
//! removing it by name would be a second name-based race — so the guest is
//! refused while the host keeps the link.
//!
//! The check assumes `newname` still names the entry `linkat` created. A host
//! that replaces the destination name before the `fstatat`, or between it and
//! the `do_lookup` that follows, is a retained destination-name race: the
//! source swap-and-restore alone is detected, this is not.
//!
//!
//! ## Procfd Reopen
//!
//! `open_inode_fd` reopens tracked inodes for I/O via `/proc/self/fd/N`.
//! Procfd entries are themselves symlinks on Linux, so reopening them must not
//! add `O_NOFOLLOW` or the kernel will fail with `ELOOP`. Instead, the pinned
//! inode is `fstat`'d first and real host symlinks are rejected before reopen.

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::FromRawFd;
use std::{
    collections::HashSet,
    ffi::CStr,
    io,
    os::fd::{AsRawFd, RawFd},
    sync::{Arc, atomic::Ordering},
};

use super::PassthroughFs;
use crate::backends::shared::inode_table::NamespaceAlias;
use crate::{
    Entry,
    backends::shared::{
        inode_table::{InodeAltKey, InodeData, MultikeyBTreeMap},
        platform,
    },
    stat64,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Owned-or-borrowed fd for inode operations.
///
/// On Linux, linked inodes reopen from a trusted namespace anchor and detached
/// inodes dup a retained fd.
/// On macOS, may own a temporary fd opened via `/.vol/`.
pub(crate) struct InodeFd {
    fd: i32,
    owned: bool,
}

impl InodeFd {
    pub(crate) fn raw(&self) -> i32 {
        self.fd
    }
}

impl Drop for InodeFd {
    fn drop(&mut self) {
        if self.owned && self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}

/// Linux guest open flag constants.
///
/// The guest kernel sends Linux flag values over virtio-fs. On Linux hosts these
/// match `libc` constants, but on macOS the numeric values differ (e.g. Linux
/// `O_TRUNC` 0x200 = macOS `O_CREAT` 0x200). This module defines the Linux
/// values so we can translate them to host values on macOS.
#[cfg(all(target_os = "macos", target_arch = "x86_64"))]
mod linux_flags {
    pub const O_APPEND: i32 = 0x400;
    pub const O_CREAT: i32 = 0x40;
    pub const O_TRUNC: i32 = 0x200;
    pub const O_EXCL: i32 = 0x80;
    pub const O_NOFOLLOW: i32 = 0x20000;
    pub const O_NONBLOCK: i32 = 0x800;
    pub const O_CLOEXEC: i32 = 0x80000;
    pub const O_DIRECTORY: i32 = 0x10000;
}

#[cfg(all(target_os = "macos", target_arch = "aarch64"))]
mod linux_flags {
    pub const O_APPEND: i32 = 0x400;
    pub const O_CREAT: i32 = 0x40;
    pub const O_TRUNC: i32 = 0x200;
    pub const O_EXCL: i32 = 0x80;
    pub const O_NOFOLLOW: i32 = 0x8000;
    pub const O_NONBLOCK: i32 = 0x800;
    pub const O_CLOEXEC: i32 = 0x80000;
    pub const O_DIRECTORY: i32 = 0x4000;
}

#[cfg(all(
    target_os = "macos",
    not(any(target_arch = "x86_64", target_arch = "aarch64"))
))]
compile_error!("unsupported macOS architecture for Linux open-flag translation");

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Translate Linux guest open flags to host open flags.
///
/// On Linux this is a no-op (flags match). On macOS, maps Linux numeric values
/// to the corresponding macOS `libc` constants. Without this translation,
/// Linux `O_TRUNC` (0x200) becomes macOS `O_CREAT` (0x200), and Linux
/// `O_APPEND` (0x400) becomes macOS `O_TRUNC` (0x400).
#[cfg(target_os = "linux")]
pub(crate) fn translate_open_flags(flags: i32) -> i32 {
    platform::sanitize_linux_open_flags(flags)
}

#[cfg(target_os = "macos")]
pub(crate) fn translate_open_flags(linux_flags_val: i32) -> i32 {
    // Access mode (O_RDONLY=0, O_WRONLY=1, O_RDWR=2) — same on both platforms.
    let mut flags = linux_flags_val & 0b11;
    if linux_flags_val & linux_flags::O_APPEND != 0 {
        flags |= libc::O_APPEND;
    }
    if linux_flags_val & linux_flags::O_CREAT != 0 {
        flags |= libc::O_CREAT;
    }
    if linux_flags_val & linux_flags::O_TRUNC != 0 {
        flags |= libc::O_TRUNC;
    }
    if linux_flags_val & linux_flags::O_EXCL != 0 {
        flags |= libc::O_EXCL;
    }
    if linux_flags_val & linux_flags::O_NOFOLLOW != 0 {
        flags |= libc::O_NOFOLLOW;
    }
    if linux_flags_val & linux_flags::O_NONBLOCK != 0 {
        flags |= libc::O_NONBLOCK;
    }
    if linux_flags_val & linux_flags::O_CLOEXEC != 0 {
        flags |= libc::O_CLOEXEC;
    }
    if linux_flags_val & linux_flags::O_DIRECTORY != 0 {
        flags |= libc::O_DIRECTORY;
    }
    flags
}

#[cfg(target_os = "linux")]
pub(crate) fn store_unlinked_fd(data: &InodeData, fd: i32) {
    let mut retained = data.retained_fd.lock().unwrap();
    let new_file = unsafe { File::from_raw_fd(fd) };
    let _ = retained.replace(new_file);
}

#[cfg(target_os = "macos")]
pub(crate) fn store_unlinked_fd(data: &InodeData, fd: i32) {
    let previous = data.unlinked_fd.swap(fd as i64, Ordering::AcqRel);
    if previous >= 0 {
        unsafe { libc::close(previous as i32) };
    }
}

/// Whether a walk failure means "this alias no longer names the inode".
///
/// A final component that is missing, or an intermediate component that is no
/// longer a directory, is the stale-alias signal: the caller tries the next
/// alias. Every other error is a host-side condition and must be preserved.
#[cfg(target_os = "macos")]
fn is_stale_walk_error(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(code)
            if Some(code) == platform::enoent().raw_os_error()
                || Some(code) == platform::enotdir().raw_os_error()
    )
}

#[cfg(target_os = "macos")]
fn is_unsupported_macos_reopen_flag(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::EINVAL | libc::ENOTSUP | libc::EOPNOTSUPP)
    )
}

/// Reopen a trusted `/.vol/<dev>/<ino>` identity path on macOS.
///
/// These paths are derived from already-admitted inode identity, not from
/// guest-provided path bytes, so `O_NOFOLLOW_ANY` is the relevant safety
/// boundary here. `O_RESOLVE_BENEATH` is intentionally omitted because it
/// applies to fd-relative containment, not absolute `/.vol/` identity paths.
#[cfg(target_os = "macos")]
fn open_macos_inode_reopen(path: *const libc::c_char, flags: i32) -> io::Result<i32> {
    let attempts = [
        (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW_ANY) & !libc::O_EXLOCK,
        (flags | libc::O_CLOEXEC | libc::O_NOFOLLOW) & !libc::O_EXLOCK,
    ];

    let mut last_err: Option<io::Error> = None;
    for attempt in attempts {
        let fd = unsafe { libc::open(path, attempt) };
        if fd >= 0 {
            return Ok(fd);
        }

        let err = io::Error::last_os_error();
        if !is_unsupported_macos_reopen_flag(&err) {
            return Err(platform::linux_error(err));
        }
        last_err = Some(err);
    }

    Err(platform::linux_error(
        last_err.unwrap_or_else(io::Error::last_os_error),
    ))
}

/// Walk `components` from the share root with `openat(O_NOFOLLOW)` per step.
///
/// Intermediate components open with `O_DIRECTORY`; the last component opens
/// with `flags`. A symlink swapped in for an intermediate directory fails
/// closed as `ENOTDIR` — the same "stale alias" signal as a renamed-away
/// directory. A symlink at the final component fails as `ELOOP`, unless
/// `final_symlink` is set, in which case the link itself is opened via
/// `O_SYMLINK` so its own identity and metadata can still be read. `..`,
/// empty, or slash-bearing components are refused before any syscall. The
/// caller owns the returned fd.
#[cfg(target_os = "macos")]
pub(crate) fn secure_open_path_macos(
    fs: &PassthroughFs,
    components: &[Vec<u8>],
    flags: i32,
    final_symlink: bool,
) -> io::Result<RawFd> {
    let root_fd = unsafe { libc::fcntl(fs.root_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if root_fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    if components.is_empty() {
        return Ok(root_fd);
    }

    let mut current_fd = root_fd;
    for (index, component) in components.iter().enumerate() {
        if let Err(err) = validate_component(component) {
            unsafe { libc::close(current_fd) };
            return Err(err);
        }
        let name = match std::ffi::CString::new(component.as_slice()) {
            Ok(name) => name,
            Err(_) => {
                unsafe { libc::close(current_fd) };
                return Err(platform::einval());
            }
        };
        let is_last = index + 1 == components.len();
        let open_flags = if is_last {
            flags | libc::O_NOFOLLOW | libc::O_CLOEXEC
        } else {
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC
        };
        let next_fd = unsafe { libc::openat(current_fd, name.as_ptr(), open_flags) };
        if next_fd >= 0 {
            unsafe { libc::close(current_fd) };
            current_fd = next_fd;
            continue;
        }

        // Capture errno immediately: any intervening syscall (including the
        // close below) can clobber it before we get to inspect it.
        let open_err = io::Error::last_os_error();

        if is_last && final_symlink && open_err.raw_os_error() == Some(libc::ELOOP) {
            let symlink_flags = (flags & !libc::O_NOFOLLOW) | libc::O_SYMLINK | libc::O_CLOEXEC;
            let symlink_fd = unsafe { libc::openat(current_fd, name.as_ptr(), symlink_flags) };
            if symlink_fd >= 0 {
                unsafe { libc::close(current_fd) };
                return Ok(symlink_fd);
            }
            let symlink_err = io::Error::last_os_error();
            unsafe { libc::close(current_fd) };
            return Err(platform::linux_error(symlink_err));
        }

        unsafe { libc::close(current_fd) };
        if !is_last && open_err.raw_os_error() == Some(libc::ELOOP) {
            return Err(platform::enotdir());
        }
        return Err(platform::linux_error(open_err));
    }

    Ok(current_fd)
}

/// Confirm an anchor-walked fd is the inode we admitted at lookup time.
#[cfg(target_os = "macos")]
fn validate_identity_macos(fd: RawFd, data: &InodeData) -> io::Result<()> {
    let st = platform::fstat(fd)?;
    if platform::stat_ino(&st) != data.ino || platform::stat_dev(&st) != data.dev {
        return Err(platform::enoent());
    }
    Ok(())
}

/// Reopen a tracked inode by anchor walk with `flags` on the final component.
///
/// The root inode has no alias and resolves by opening `"."` relative to
/// `root_fd`. That is a fresh file description, not a dup: a dup would share
/// `root_fd`'s seek offset, so two concurrent root directory handles would
/// corrupt each other's `readdir`, and a write-intent reopen of the root would
/// hand back a readable fd instead of failing `EISDIR`.
/// For every other inode, tries the current anchor first, then every other
/// known alias. A stale alias — the final component failing `ENOENT` or
/// `ENOTDIR`, or an identity mismatch on open — means "try the next alias";
/// any other error (fd exhaustion, permissions, I/O, or `ELOOP` when
/// `final_symlink` is false and the target really is a symlink) is a
/// host-side problem and is preserved so it is not misreported as a missing
/// file. When a non-current alias succeeds the anchor is repaired to it.
#[cfg(target_os = "macos")]
pub(crate) fn open_anchor_fd_macos(
    fs: &PassthroughFs,
    inode: u64,
    flags: i32,
    final_symlink: bool,
) -> io::Result<RawFd> {
    if inode == 1 {
        // `.` is never a symlink, so dropping O_NOFOLLOW here is safe.
        let open_flags = (flags & !libc::O_NOFOLLOW) | libc::O_DIRECTORY | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(fs.root_fd.as_raw_fd(), c".".as_ptr(), open_flags) };
        if fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        return Ok(fd);
    }

    let inodes = fs.inodes.read().unwrap();
    let data = inodes.get(&inode).cloned().ok_or_else(platform::ebadf)?;

    let current_anchor = current_anchor_alias(&data);
    let candidates = candidate_aliases(&data, current_anchor.clone());
    let mut host_err: Option<io::Error> = None;
    for alias in candidates {
        let mut seen = HashSet::new();
        let components = match build_alias_components_locked(&inodes, &alias, &mut seen) {
            Ok(components) => components,
            Err(_) => continue,
        };
        let fd = match secure_open_path_macos(fs, &components, flags, final_symlink) {
            Ok(fd) => fd,
            Err(err) => {
                if !is_stale_walk_error(&err) {
                    host_err = Some(err);
                }
                continue;
            }
        };
        match validate_identity_macos(fd, &data) {
            Ok(()) => {
                drop(inodes);
                if current_anchor.as_ref() != Some(&alias) {
                    repair_anchor(fs, inode, &alias);
                }
                return Ok(fd);
            }
            Err(err) => {
                unsafe { libc::close(fd) };
                if err.raw_os_error() != platform::enoent().raw_os_error() {
                    host_err = Some(err);
                }
            }
        }
    }

    Err(host_err.unwrap_or_else(platform::enoent))
}

/// Clear `O_NONBLOCK` on a descriptor that was opened non-blocking only so the
/// open itself could not park the caller.
#[cfg(target_os = "macos")]
pub(crate) fn clear_nonblock_macos(fd: RawFd) -> io::Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFL, flags & !libc::O_NONBLOCK) } < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(())
}

/// Open the final component of an I/O reopen, counting FIFO endpoint opens.
///
/// Every endpoint open this path makes goes through here, so a test can see
/// exactly how many times the reopen touched a FIFO — an endpoint that is
/// opened and thrown away is otherwise invisible from outside the process.
/// The count is taken before the syscall: the attempt is what completes a
/// rendezvous, whether or not it succeeds.
#[cfg(target_os = "macos")]
fn open_endpoint_macos(
    fs: &PassthroughFs,
    parent_fd: RawFd,
    name: &CStr,
    flags: i32,
    is_fifo: bool,
) -> RawFd {
    #[cfg(test)]
    if is_fifo {
        fs.fifo_endpoint_opens.fetch_add(1, Ordering::AcqRel);
    }
    #[cfg(not(test))]
    let _ = is_fifo;
    let _ = fs;
    unsafe { libc::openat(parent_fd, name.as_ptr(), flags) }
}

/// Reopen a tracked inode for guest I/O.
///
/// No file is ever opened here "just to look at it". A non-blocking read-open
/// of a FIFO completes the rendezvous with a waiting writer, so a probe fd
/// that is opened, inspected and thrown away can take a writer's bytes with
/// it. The entry is therefore identified by `fstatat` on the verified parent,
/// and exactly one open follows:
///
/// - A FIFO is opened blocking, the way the guest asked. The inode-table guard
///   is already released by then, so only this worker waits, never the table.
/// - Everything else is opened non-blocking and has the flag cleared once its
///   identity is confirmed. The entry is not a FIFO, so the flag changes
///   nothing except that a FIFO swapped in under the name between the
///   `fstatat` and the open cannot park this worker; such a replacement is
///   refused by the identity check that follows.
///
/// A guest that asked for `O_NONBLOCK` gets a single non-blocking open with no
/// parent stat at all: nothing here waits, and a peerless write-open answers
/// `ENXIO`, as POSIX says it should. The root inode takes the same path — it
/// has no parent entry to stat, and a directory can never be a FIFO.
#[cfg(target_os = "macos")]
fn open_anchor_io_fd_macos(fs: &PassthroughFs, inode: u64, flags: i32) -> io::Result<RawFd> {
    if flags & libc::O_NONBLOCK != 0 || inode == 1 {
        return open_anchor_fd_macos(fs, inode, flags, false);
    }

    let data = {
        let inodes = fs.inodes.read().unwrap();
        inodes.get(&inode).cloned().ok_or_else(platform::ebadf)?
    };
    let (dir, name, st) = anchor_parent_name_stat_macos(fs, inode)?;
    let is_fifo = st.st_mode & libc::S_IFMT == libc::S_IFIFO;
    let open_flags = if is_fifo {
        flags | libc::O_NOFOLLOW | libc::O_CLOEXEC
    } else {
        flags | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC
    };

    // The blocking open is the only place an anchor reopen waits on another
    // process, so tests take their timing from here instead of guessing.
    #[cfg(test)]
    if is_fifo {
        let hook = fs.before_blocking_fifo_open.read().unwrap().clone();
        if let Some(hook) = hook {
            hook();
        }
    }

    let fd = open_endpoint_macos(fs, dir.raw(), &name, open_flags, is_fifo);
    if fd < 0 {
        // Capture errno before `dir` drops: its Drop closes the fd, and
        // close(2) can clobber errno.
        let err = io::Error::last_os_error();
        return Err(platform::linux_error(err));
    }
    // The name was verified before the open, so a mismatch here means the
    // entry was replaced in between: refuse it rather than serve it.
    if let Err(err) = validate_identity_macos(fd, &data) {
        unsafe { libc::close(fd) };
        return Err(err);
    }
    if !is_fifo && let Err(err) = clear_nonblock_macos(fd) {
        unsafe { libc::close(fd) };
        return Err(err);
    }
    Ok(fd)
}

/// Reopen a tracked inode for `*at()`/getattr use via a single anchor walk.
///
/// `O_RDONLY` opens cleanly for both files and directories on macOS, so one
/// walk covers both cases (no need for a directory-first, file-second retry
/// pair). `final_symlink` is set so a symlink target can still be opened —
/// via `O_SYMLINK` — and stat'ed instead of failing `ELOOP`.
///
/// `O_NONBLOCK` keeps a tracked FIFO from parking the FUSE worker until a
/// writer appears; the fd is used only for `fstat` and `fgetxattr`, never
/// handed to the guest, so the flag cannot leak into a guest handle. It also
/// carries into the `O_SYMLINK` retry inside the walk.
#[cfg(target_os = "macos")]
fn open_anchor_reopen_macos(fs: &PassthroughFs, inode: u64) -> io::Result<RawFd> {
    open_anchor_fd_macos(fs, inode, libc::O_RDONLY | libc::O_NONBLOCK, true)
}

/// Open the anchor's parent directory and return it with the entry name.
///
/// Used by operations that need a `(dirfd, name)` pair on macOS instead of an
/// fd on the inode itself: readlink, symlink times, symlink-fd opens, and hard
/// link sources. The name is verified to still refer to the tracked identity.
///
/// The root inode is refused: it is inode 1 by FUSE convention and has no
/// parent entry inside the share, so there is no `(dirfd, name)` pair for it.
#[cfg(target_os = "macos")]
pub(crate) fn anchor_parent_and_name_macos(
    fs: &PassthroughFs,
    inode: u64,
) -> io::Result<(InodeFd, std::ffi::CString)> {
    anchor_parent_name_stat_macos(fs, inode).map(|(dir, name, _)| (dir, name))
}

/// `anchor_parent_and_name_macos` plus the `fstatat` the verification used.
///
/// The entry's type decides how the caller may open it, and that answer has to
/// come from the stat that verified the identity — not from opening the entry
/// to find out, which for a FIFO would already be a rendezvous.
#[cfg(target_os = "macos")]
fn anchor_parent_name_stat_macos(
    fs: &PassthroughFs,
    inode: u64,
) -> io::Result<(InodeFd, std::ffi::CString, stat64)> {
    if inode == 1 {
        return Err(platform::einval());
    }

    let inodes = fs.inodes.read().unwrap();
    let data = inodes.get(&inode).cloned().ok_or_else(platform::ebadf)?;
    let current_anchor = current_anchor_alias(&data);
    let candidates = candidate_aliases(&data, current_anchor.clone());
    let mut host_err: Option<io::Error> = None;
    for alias in candidates {
        let mut seen = HashSet::new();
        let components = match build_alias_components_locked(&inodes, &alias, &mut seen) {
            Ok(components) => components,
            Err(_) => continue,
        };
        let Some((name, parents)) = components.split_last() else {
            continue;
        };
        let parent_fd =
            match secure_open_path_macos(fs, parents, libc::O_RDONLY | libc::O_DIRECTORY, false) {
                Ok(fd) => fd,
                Err(err) => {
                    if !is_stale_walk_error(&err) {
                        host_err = Some(err);
                    }
                    continue;
                }
            };
        let name = match std::ffi::CString::new(name.as_slice()) {
            Ok(name) => name,
            Err(_) => {
                unsafe { libc::close(parent_fd) };
                continue;
            }
        };
        match platform::fstatat_nofollow(parent_fd, &name) {
            Ok(st)
                if platform::stat_ino(&st) == data.ino && platform::stat_dev(&st) == data.dev =>
            {
                drop(inodes);
                if current_anchor.as_ref() != Some(&alias) {
                    repair_anchor(fs, inode, &alias);
                }
                return Ok((
                    InodeFd {
                        fd: parent_fd,
                        owned: true,
                    },
                    name,
                    st,
                ));
            }
            Ok(_) => {
                // Name resolves, but to a different identity: stale alias.
                unsafe { libc::close(parent_fd) };
            }
            Err(err) => {
                unsafe { libc::close(parent_fd) };
                if !is_stale_walk_error(&err) {
                    host_err = Some(err);
                }
            }
        }
    }
    Err(host_err.unwrap_or_else(platform::enoent))
}

/// Open a just-stat'ed child of `parent_fd` for stat patching in anchor mode.
///
/// Mirrors `open_macos_path_for_stat`, but relative to the parent directory
/// instead of a volfs identity path.
///
/// `O_NONBLOCK` keeps a FIFO child from parking the FUSE worker until a writer
/// appears. The fd never reaches the guest: the caller uses it for `fstat` and
/// `fgetxattr` and then closes it.
#[cfg(target_os = "macos")]
pub(crate) fn open_child_for_stat_macos(parent_fd: i32, name: &CStr) -> io::Result<i32> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
        )
    };
    if fd >= 0 {
        return Ok(fd);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::ELOOP) {
        let fd = unsafe {
            libc::openat(
                parent_fd,
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_SYMLINK | libc::O_NONBLOCK,
            )
        };
        if fd >= 0 {
            return Ok(fd);
        }
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
        )
    };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(fd)
}

#[cfg(target_os = "macos")]
pub(crate) fn vol_path(dev: u64, ino: u64) -> std::ffi::CString {
    use std::ffi::CString;

    CString::new(format!("/.vol/{dev}/{ino}"))
        .expect("formatted /.vol path never contains interior nul")
}

/// Look up a child name in a parent directory and return an [`Entry`].
///
/// If the inode is already in the table (matched by host identity), its
/// refcount is incremented and the existing inode number is returned.
/// Otherwise a new inode is allocated.
pub(crate) fn do_lookup(fs: &PassthroughFs, parent: u64, name: &CStr) -> io::Result<Entry> {
    crate::backends::shared::name_validation::validate_name(name)?;

    let parent_fd = get_inode_fd(fs, parent)?;

    #[cfg(target_os = "linux")]
    return do_lookup_linux(fs, parent, parent_fd.raw(), name);

    #[cfg(target_os = "macos")]
    return do_lookup_macos(fs, parent, parent_fd.raw(), name);
}

/// Linux lookup: open → statx(AT_EMPTY_PATH) → patched_stat (3 syscalls).
///
/// This is more efficient than the fstatat + statx + open path (4 syscalls),
/// and also more correct: the stat is on the *opened* fd, eliminating TOCTOU
/// between stat and open.
///
/// The open uses `RESOLVE_BENEATH` (Linux 5.6+) for kernel-enforced containment,
/// which atomically blocks `..` traversal, absolute symlinks, and handles concurrent
/// rename races. Falls back to `openat(O_NOFOLLOW)` on older kernels.
#[cfg(target_os = "linux")]
fn do_lookup_linux(
    fs: &PassthroughFs,
    parent: u64,
    parent_fd: i32,
    name: &CStr,
) -> io::Result<Entry> {
    // Syscall 1: Open with RESOLVE_BENEATH containment.
    let fd = platform::open_beneath(
        parent_fd,
        name.as_ptr(),
        libc::O_PATH | libc::O_NOFOLLOW,
        fs.has_openat2.load(Ordering::Relaxed),
    );
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    // Syscall 2: statx with AT_EMPTY_PATH on the opened fd.
    // Gets stat data + mnt_id in one call.
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_SYNC_AS_STAT,
            libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
            &mut stx,
        )
    };
    if ret < 0 {
        let err = platform::linux_error(io::Error::last_os_error());
        unsafe { libc::close(fd) };
        return Err(err);
    }

    let st = platform::statx_to_stat64(&stx);
    let mnt_id = stx.stx_mnt_id;
    let alt_key = InodeAltKey::new(st.st_ino, st.st_dev, mnt_id);
    let alias = NamespaceAlias::new(parent, name.to_bytes());
    let patched = crate::backends::shared::stat_override::patched_stat(
        fd,
        st,
        fs.cfg.xattr_enabled(),
        fs.cfg.strict_enabled(),
        fs.cfg.bind_identity_map.as_ref(),
    )?;

    let mut inodes = fs.inodes.write().unwrap();
    if let Some(data) = inodes.get_alt(&alt_key).cloned() {
        data.refcount.fetch_add(1, Ordering::Acquire);
        register_alias_locked(&mut inodes, &data, alias);
        unsafe { libc::close(fd) };
        return Ok(Entry {
            inode: data.inode,
            generation: 0,
            attr: patched,
            attr_flags: 0,
            attr_timeout: fs.cfg.attr_timeout,
            entry_timeout: fs.cfg.entry_timeout,
        });
    }

    let inode_num = fs.next_inode.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(InodeData {
        inode: inode_num,
        ino: st.st_ino,
        dev: st.st_dev,
        refcount: std::sync::atomic::AtomicU64::new(1),
        mnt_id,
        anchor_parent: std::sync::atomic::AtomicU64::new(0),
        anchor_name: std::sync::RwLock::new(Vec::new()),
        aliases: std::sync::RwLock::new(std::collections::BTreeSet::new()),
        anchor_children: std::sync::atomic::AtomicU64::new(0),
        retained_fd: std::sync::Mutex::new(None),
    });
    inodes.insert(inode_num, alt_key, data.clone());
    register_alias_locked(&mut inodes, &data, alias);
    unsafe { libc::close(fd) };

    Ok(Entry {
        inode: inode_num,
        generation: 0,
        attr: patched,
        attr_flags: 0,
        attr_timeout: fs.cfg.attr_timeout,
        entry_timeout: fs.cfg.entry_timeout,
    })
}

/// macOS lookup: fstatat → check table → register.
///
/// Opens a real fd via `/.vol/dev/ino` for xattr access since macOS
/// doesn't store per-inode fds (inode_raw_fd returns -1). The `/.vol/`
/// path scheme references files by device+inode identity, making it
/// stable across renames — similar to Linux's `/proc/self/fd/N`.
#[cfg(target_os = "macos")]
fn do_lookup_macos(
    fs: &PassthroughFs,
    parent: u64,
    parent_fd: i32,
    name: &CStr,
) -> io::Result<Entry> {
    let anchor_mode = fs.anchor_mode();

    // In anchor mode, open first and take both identity and metadata from
    // that one fd, so a host-side replacement between the stat and the open
    // cannot patch one inode's attributes with another inode's xattr data.
    // Falls back to fstatat + unpatched stat whenever the entry cannot be
    // opened at all — a denied permission, a socket, a device node the host
    // refuses to open — because volfs mode reports those entries too. Only an
    // fstatat failure fails the lookup.
    let (st, patched) = if anchor_mode {
        match open_child_for_stat_macos(parent_fd, name) {
            Ok(fd) => {
                let st = match platform::fstat(fd) {
                    Ok(st) => st,
                    Err(err) => {
                        unsafe { libc::close(fd) };
                        return Err(err);
                    }
                };
                let patched = patch_stat_with_open_macos(
                    Ok(fd),
                    st,
                    fs.cfg.xattr_enabled(),
                    fs.cfg.strict_enabled(),
                    fs.cfg.bind_identity_map.as_ref(),
                )?;
                (st, patched)
            }
            Err(err) => {
                let st = platform::fstatat_nofollow(parent_fd, name)?;
                let patched = patch_stat_with_open_macos(
                    Err(err),
                    st,
                    fs.cfg.xattr_enabled(),
                    fs.cfg.strict_enabled(),
                    fs.cfg.bind_identity_map.as_ref(),
                )?;
                (st, patched)
            }
        }
    } else {
        let st = platform::fstatat_nofollow(parent_fd, name)?;
        let patched = open_and_patch_stat_macos(
            platform::stat_dev(&st),
            platform::stat_ino(&st),
            st,
            fs.cfg.xattr_enabled(),
            fs.cfg.strict_enabled(),
            fs.cfg.bind_identity_map.as_ref(),
        )?;
        (st, patched)
    };

    let alt_key = InodeAltKey::new(platform::stat_ino(&st), platform::stat_dev(&st));
    let alias = anchor_mode.then(|| NamespaceAlias::new(parent, name.to_bytes()));

    // Fast path (volfs mode only): most lookups hit an already-tracked inode
    // and only need a refcount bump. Anchor mode always takes the write lock
    // because it must record the alias.
    if !anchor_mode {
        let inodes = fs.inodes.read().unwrap();
        if let Some(data) = inodes.get_alt(&alt_key) {
            data.refcount.fetch_add(1, Ordering::Acquire);
            return Ok(Entry {
                inode: data.inode,
                generation: 0,
                attr: patched,
                attr_flags: 0,
                attr_timeout: fs.cfg.attr_timeout,
                entry_timeout: fs.cfg.entry_timeout,
            });
        }
    }

    // Recheck under the write lock so concurrent lookups cannot register two
    // synthetic inode numbers for the same host identity.
    let mut inodes = fs.inodes.write().unwrap();
    if let Some(data) = inodes.get_alt(&alt_key).cloned() {
        data.refcount.fetch_add(1, Ordering::Acquire);
        if let Some(alias) = alias {
            register_alias_locked(&mut inodes, &data, alias);
        }
        return Ok(Entry {
            inode: data.inode,
            generation: 0,
            attr: patched,
            attr_flags: 0,
            attr_timeout: fs.cfg.attr_timeout,
            entry_timeout: fs.cfg.entry_timeout,
        });
    }

    let inode_num = fs.next_inode.fetch_add(1, Ordering::Relaxed);
    let data = Arc::new(InodeData {
        inode: inode_num,
        ino: platform::stat_ino(&st),
        dev: platform::stat_dev(&st),
        refcount: std::sync::atomic::AtomicU64::new(1),
        anchor_parent: std::sync::atomic::AtomicU64::new(0),
        anchor_name: std::sync::RwLock::new(Vec::new()),
        aliases: std::sync::RwLock::new(std::collections::BTreeSet::new()),
        anchor_children: std::sync::atomic::AtomicU64::new(0),
        unlinked_fd: std::sync::atomic::AtomicI64::new(-1),
    });
    inodes.insert(inode_num, alt_key, data.clone());
    if let Some(alias) = alias {
        register_alias_locked(&mut inodes, &data, alias);
    }

    Ok(Entry {
        inode: inode_num,
        generation: 0,
        attr: patched,
        attr_flags: 0,
        attr_timeout: fs.cfg.attr_timeout,
        entry_timeout: fs.cfg.entry_timeout,
    })
}

/// Apply stat patching using an already-attempted fd open.
///
/// Falls back to the unpatched (identity-mapped) stat when the open failed,
/// which keeps lookups working on hosts where neither volfs nor a relative
/// reopen is possible for this entry.
#[cfg(target_os = "macos")]
fn patch_stat_with_open_macos(
    opened: io::Result<i32>,
    st: stat64,
    xattr_enabled: bool,
    strict: bool,
    bind_identity_map: Option<&crate::backends::shared::stat_override::BindIdentityMapHandle>,
) -> io::Result<stat64> {
    if let Ok(fd) = opened {
        let result = crate::backends::shared::stat_override::patched_stat(
            fd,
            st,
            xattr_enabled,
            strict,
            bind_identity_map,
        );
        unsafe { libc::close(fd) };
        return result;
    }

    let mut st = st;
    if xattr_enabled {
        crate::backends::shared::stat_override::apply_bind_identity_map(&mut st, bind_identity_map);
    }
    Ok(st)
}

/// Open a real fd via `/.vol/dev/ino` for xattr access and apply stat patching.
///
/// Tries O_RDONLY first, then O_RDONLY|O_DIRECTORY (for directories that reject
/// plain O_RDONLY), falls back to unpatched stat if neither succeeds. This is
/// necessary because macOS doesn't store per-inode fds, so we must open a
/// temporary fd solely for `fgetxattr` to read the override stat.
#[cfg(target_os = "macos")]
fn open_and_patch_stat_macos(
    dev: u64,
    ino: u64,
    st: stat64,
    xattr_enabled: bool,
    strict: bool,
    bind_identity_map: Option<&crate::backends::shared::stat_override::BindIdentityMapHandle>,
) -> io::Result<stat64> {
    let path = vol_path(dev, ino);
    patch_stat_with_open_macos(
        open_macos_path_for_stat(path.as_ptr()),
        st,
        xattr_enabled,
        strict,
        bind_identity_map,
    )
}

#[cfg(target_os = "macos")]
fn open_macos_path_for_stat(path: *const libc::c_char) -> io::Result<i32> {
    match open_macos_inode_reopen(path, libc::O_RDONLY) {
        Ok(fd) => return Ok(fd),
        Err(err) if err.raw_os_error() == platform::eloop().raw_os_error() => {
            let fd =
                unsafe { libc::open(path, libc::O_RDONLY | libc::O_CLOEXEC | libc::O_SYMLINK) };
            if fd < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            return Ok(fd);
        }
        Err(_) => {}
    }

    open_macos_inode_reopen(path, libc::O_RDONLY | libc::O_DIRECTORY)
}

/// Decrement the reference count for an inode. Remove it from the table
/// when the count reaches zero.
pub(crate) fn forget_one(fs: &PassthroughFs, inode: u64, count: u64) {
    let mut inodes = fs.inodes.write().unwrap();
    forget_one_locked(&mut inodes, inode, count);
}

/// Decrement the reference count under an already-held write lock.
///
/// Used by [`super::PassthroughFs::batch_forget`] to process all entries
/// under a single lock acquisition (O(1) lock ops vs O(n) for per-entry locking).
///
/// Uses a CAS loop to handle the race where a concurrent `lookup` may increment
/// the refcount between our load and compare_exchange. `saturating_sub` prevents
/// underflow if the kernel sends a forget count larger than the current refcount.
pub(crate) fn forget_one_locked(
    inodes: &mut MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    inode: u64,
    count: u64,
) {
    if let Some(data) = inodes.get(&inode).cloned() {
        loop {
            let old = data.refcount.load(Ordering::Relaxed);
            let new = old.saturating_sub(count);
            if data
                .refcount
                .compare_exchange(old, new, Ordering::Release, Ordering::Relaxed)
                .is_ok()
            {
                if new == 0 {
                    maybe_remove_inode_locked(inodes, inode);
                }
                break;
            }
        }
    }
}

/// Get an fd for an inode suitable for `*at()` syscalls.
///
/// On Linux, linked inodes reopen from the export root using the current
/// trusted anchor, while detached inodes use the retained fd.
/// On macOS, opens a temporary fd via `/.vol/<dev>/<ino>`.
/// Root inode (1) always borrows the stored root fd.
pub(crate) fn get_inode_fd(fs: &PassthroughFs, inode: u64) -> io::Result<InodeFd> {
    // Root inode uses the stored root fd.
    if inode == 1 {
        let inodes = fs.inodes.read().unwrap();
        if inodes.get(&inode).is_none() {
            return Err(platform::ebadf());
        }
        drop(inodes);

        return Ok(InodeFd {
            fd: fs.root_fd.as_raw_fd(),
            owned: false,
        });
    }

    #[cfg(target_os = "linux")]
    {
        get_inode_fd_linux(fs, inode)
    }

    #[cfg(target_os = "macos")]
    {
        let inodes = fs.inodes.read().unwrap();
        let data = inodes.get(&inode).cloned().ok_or_else(platform::ebadf)?;

        // Try unlinked_fd first — /.vol/ path is invalid after unlink.
        let ufd = data.unlinked_fd.load(Ordering::Acquire);
        if ufd >= 0 {
            let fd = unsafe { libc::fcntl(ufd as i32, libc::F_DUPFD_CLOEXEC, 0) };
            if fd >= 0 {
                return Ok(InodeFd { fd, owned: true });
            }
        }

        if fs.anchor_mode() {
            drop(inodes);
            let fd = open_anchor_reopen_macos(fs, inode)?;
            return Ok(InodeFd { fd, owned: true });
        }
        let fd = open_vol_fd(data.dev, data.ino)?;
        Ok(InodeFd { fd, owned: true })
    }
}

#[cfg(target_os = "linux")]
fn get_inode_fd_linux(fs: &PassthroughFs, inode: u64) -> io::Result<InodeFd> {
    let inodes = fs.inodes.read().unwrap();
    let data = inodes.get(&inode).cloned().ok_or_else(platform::ebadf)?;
    let expected = inode_alt_key(&data);

    if let Some(fd) = dup_retained_fd_linux(&data)? {
        return Ok(InodeFd { fd, owned: true });
    }

    let current_anchor = current_anchor_alias(&data);
    let candidates = candidate_aliases(&data, current_anchor.clone());
    // Stale-alias failures (ENOENT/ENOTDIR — the path was renamed or removed) mean "try the next alias" and fall through to ENOENT. Any other reopen failure (EMFILE,
    // EACCES, EIO) is a host-side problem, not a missing file: preserve it so fd exhaustion does not masquerade as phantom "No such file or directory" in the guest.
    let mut host_err: Option<io::Error> = None;
    for alias in candidates {
        let mut seen = HashSet::new();
        let components = match build_alias_components_locked(&inodes, &alias, &mut seen) {
            Ok(components) => components,
            Err(_) => continue,
        };
        let fd = match secure_open_path_linux(fs, &components, libc::O_PATH | libc::O_NOFOLLOW) {
            Ok(fd) => fd,
            Err(err) => {
                if !matches!(err.raw_os_error(), Some(libc::ENOENT) | Some(libc::ENOTDIR)) {
                    host_err = Some(err);
                }
                continue;
            }
        };
        if validate_identity_linux(fd, expected).is_ok() {
            drop(inodes);
            if current_anchor.as_ref() != Some(&alias) {
                repair_anchor(fs, inode, &alias);
            }
            return Ok(InodeFd { fd, owned: true });
        }
        unsafe { libc::close(fd) };
    }

    Err(host_err.unwrap_or_else(platform::enoent))
}

#[cfg(target_os = "linux")]
fn inode_alt_key(data: &InodeData) -> InodeAltKey {
    InodeAltKey::new(data.ino, data.dev, data.mnt_id)
}

fn current_anchor_alias(data: &InodeData) -> Option<NamespaceAlias> {
    let parent = data.anchor_parent.load(Ordering::Acquire);
    if parent == 0 {
        return None;
    }

    Some(NamespaceAlias {
        parent,
        name: data.anchor_name.read().unwrap().clone(),
    })
}

fn candidate_aliases(
    data: &InodeData,
    current_anchor: Option<NamespaceAlias>,
) -> Vec<NamespaceAlias> {
    let aliases = data.aliases.read().unwrap();
    let mut result = Vec::with_capacity(aliases.len());
    if let Some(anchor) = current_anchor.as_ref()
        && aliases.contains(anchor)
    {
        result.push(anchor.clone());
    }
    for alias in aliases.iter() {
        if current_anchor.as_ref() == Some(alias) {
            continue;
        }
        result.push(alias.clone());
    }
    result
}

fn build_alias_components_locked(
    inodes: &MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    alias: &NamespaceAlias,
    seen: &mut HashSet<u64>,
) -> io::Result<Vec<Vec<u8>>> {
    validate_component(&alias.name)?;
    let mut components = if alias.parent == 1 {
        Vec::new()
    } else {
        build_anchor_components_locked(inodes, alias.parent, seen)?
    };
    components.push(alias.name.clone());
    Ok(components)
}

fn build_anchor_components_locked(
    inodes: &MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    inode: u64,
    seen: &mut HashSet<u64>,
) -> io::Result<Vec<Vec<u8>>> {
    if inode == 1 {
        return Ok(Vec::new());
    }
    if !seen.insert(inode) {
        return Err(platform::eio());
    }

    let data = inodes.get(&inode).ok_or_else(platform::ebadf)?;
    let alias = current_anchor_alias(data).ok_or_else(platform::enoent)?;
    build_alias_components_locked(inodes, &alias, seen)
}

fn validate_component(component: &[u8]) -> io::Result<()> {
    if component.is_empty() || component == b"." {
        return Err(platform::einval());
    }
    if component == b".." || component.contains(&b'/') {
        return Err(platform::eperm());
    }
    if component.contains(&0) {
        return Err(platform::einval());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn secure_open_path_linux(
    fs: &PassthroughFs,
    components: &[Vec<u8>],
    flags: i32,
) -> io::Result<RawFd> {
    let root_fd = unsafe { libc::fcntl(fs.root_fd.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if root_fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    if components.is_empty() {
        return Ok(root_fd);
    }

    let mut current_fd = root_fd;
    for (index, component) in components.iter().enumerate() {
        if let Err(err) = validate_component(component) {
            unsafe { libc::close(current_fd) };
            return Err(err);
        }
        let name = match std::ffi::CString::new(component.as_slice()) {
            Ok(name) => name,
            Err(_) => {
                unsafe { libc::close(current_fd) };
                return Err(platform::einval());
            }
        };
        let is_last = index + 1 == components.len();
        let open_flags = if is_last {
            flags
        } else {
            libc::O_PATH | libc::O_NOFOLLOW | libc::O_DIRECTORY
        };
        let next_fd = platform::open_beneath(
            current_fd,
            name.as_ptr(),
            open_flags,
            fs.has_openat2.load(Ordering::Relaxed),
        );
        let current_close = current_fd;
        unsafe { libc::close(current_close) };
        if next_fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        current_fd = next_fd;
    }

    Ok(current_fd)
}

#[cfg(target_os = "linux")]
fn validate_identity_linux(fd: RawFd, expected: InodeAltKey) -> io::Result<()> {
    let actual = linux_alt_key_from_fd(fd)?;
    if actual != expected {
        return Err(platform::enoent());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
pub(crate) fn linux_alt_key_from_fd(fd: RawFd) -> io::Result<InodeAltKey> {
    let mut stx: libc::statx = unsafe { std::mem::zeroed() };
    let ret = unsafe {
        libc::statx(
            fd,
            c"".as_ptr(),
            libc::AT_EMPTY_PATH | libc::AT_SYMLINK_NOFOLLOW | libc::AT_STATX_SYNC_AS_STAT,
            libc::STATX_BASIC_STATS | libc::STATX_MNT_ID,
            &mut stx,
        )
    };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    Ok(InodeAltKey::new(
        stx.stx_ino,
        platform::statx_to_stat64(&stx).st_dev,
        stx.stx_mnt_id,
    ))
}

#[cfg(target_os = "linux")]
fn dup_retained_fd_linux(data: &InodeData) -> io::Result<Option<RawFd>> {
    let retained = data.retained_fd.lock().unwrap();
    let Some(file) = retained.as_ref() else {
        return Ok(None);
    };
    let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(Some(fd))
}

fn repair_anchor(fs: &PassthroughFs, inode: u64, alias: &NamespaceAlias) {
    let mut inodes = fs.inodes.write().unwrap();
    let Some(data) = inodes.get(&inode).cloned() else {
        return;
    };
    if !data.aliases.read().unwrap().contains(alias) {
        return;
    }
    set_anchor_locked(&mut inodes, &data, Some(alias));
}

pub(crate) fn register_alias_locked(
    inodes: &mut MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    data: &Arc<InodeData>,
    alias: NamespaceAlias,
) {
    let inserted = data.aliases.write().unwrap().insert(alias.clone());
    if inserted && data.anchor_parent.load(Ordering::Acquire) == 0 {
        set_anchor_locked(inodes, data, Some(&alias));
    }
}

pub(crate) fn remove_alias_locked(
    inodes: &mut MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    data: &Arc<InodeData>,
    alias: &NamespaceAlias,
) -> bool {
    let removed = data.aliases.write().unwrap().remove(alias);
    if !removed {
        return false;
    }

    if current_anchor_alias(data).as_ref() == Some(alias) {
        let replacement = data.aliases.read().unwrap().iter().next().cloned();
        set_anchor_locked(inodes, data, replacement.as_ref());
    }

    data.aliases.read().unwrap().is_empty()
}

/// Hold a parent inode in the table while a caller reshuffles anchors.
///
/// A forgotten directory survives only through the children anchored to it,
/// so it is collected as soon as its last anchored child moves away. An
/// exchange across directories moves two children one after the other, and
/// the parent the second move is about to re-anchor to can disappear in
/// between — leaving the second child pointing at a parent that is no longer
/// in the table, and so unresolvable. Pinning both parents for the length of
/// the exchange closes that window. Returns whether a pin was taken.
#[cfg(target_os = "macos")]
pub(crate) fn pin_anchor_parent_locked(
    inodes: &MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    inode: u64,
) -> bool {
    let Some(data) = inodes.get(&inode) else {
        return false;
    };
    data.anchor_children.fetch_add(1, Ordering::AcqRel);
    true
}

/// Release a pin taken by `pin_anchor_parent_locked`, collecting the inode if
/// nothing else holds it any more.
#[cfg(target_os = "macos")]
pub(crate) fn unpin_anchor_parent_locked(
    inodes: &mut MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    inode: u64,
) {
    decrement_anchor_children_locked(inodes, inode);
}

fn set_anchor_locked(
    inodes: &mut MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    data: &Arc<InodeData>,
    alias: Option<&NamespaceAlias>,
) {
    let old_parent = data.anchor_parent.load(Ordering::Acquire);
    let new_parent = alias.map(|alias| alias.parent).unwrap_or(0);
    if let Some(alias) = alias {
        *data.anchor_name.write().unwrap() = alias.name.clone();
    } else {
        data.anchor_name.write().unwrap().clear();
    }
    data.anchor_parent.store(new_parent, Ordering::Release);

    if old_parent != new_parent {
        if new_parent != 0
            && let Some(parent) = inodes.get(&new_parent)
        {
            parent.anchor_children.fetch_add(1, Ordering::AcqRel);
        }
        if old_parent != 0 {
            decrement_anchor_children_locked(inodes, old_parent);
        }
    }
}

fn decrement_anchor_children_locked(
    inodes: &mut MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    inode: u64,
) {
    let Some(data) = inodes.get(&inode).cloned() else {
        return;
    };

    loop {
        let old = data.anchor_children.load(Ordering::Acquire);
        if old == 0 {
            break;
        }
        if data
            .anchor_children
            .compare_exchange(old, old - 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            break;
        }
    }

    maybe_remove_inode_locked(inodes, inode);
}

fn maybe_remove_inode_locked(
    inodes: &mut MultikeyBTreeMap<u64, InodeAltKey, Arc<InodeData>>,
    inode: u64,
) {
    if inode == 1 {
        return;
    }

    let Some(data) = inodes.get(&inode).cloned() else {
        return;
    };
    if data.refcount.load(Ordering::Acquire) != 0 {
        return;
    }
    if data.anchor_children.load(Ordering::Acquire) != 0 {
        return;
    }

    let anchor_parent = data.anchor_parent.load(Ordering::Acquire);
    if let Some(_removed) = inodes.remove(&inode) {
        // On macOS the retained fd is closed by `Drop for InodeData` when the
        // last `Arc` goes away, so removal must not close it here as well.
        #[cfg(target_os = "linux")]
        {
            let _ = _removed.retained_fd.lock().unwrap().take();
        }
    }

    if anchor_parent != 0 {
        decrement_anchor_children_locked(inodes, anchor_parent);
    }
}

/// Open a temporary fd via `/.vol/<dev>/<ino>` on macOS.
///
/// Tries `O_RDONLY | O_DIRECTORY` first (most callers need a parent directory fd),
/// then falls back to plain `O_RDONLY` for non-directory inodes.
#[cfg(target_os = "macos")]
fn open_vol_fd(dev: u64, ino: u64) -> io::Result<i32> {
    let path = vol_path(dev, ino);

    // Try directory open first (most callers want a parent fd).
    if let Ok(fd) = open_macos_inode_reopen(path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) {
        return Ok(fd);
    }

    // Fall back to regular open.
    if let Ok(fd) = open_macos_inode_reopen(path.as_ptr(), libc::O_RDONLY) {
        return Ok(fd);
    }

    Err(platform::linux_error(io::Error::last_os_error()))
}

/// Open a file for I/O by inode. Returns a real file descriptor (not O_PATH).
///
/// On Linux, uses `openat(proc_self_fd, "N", flags)` to reopen the tracked
/// procfd entry. Adding `O_NOFOLLOW` here would make every procfd reopen fail
/// with `ELOOP`, because `/proc/self/fd/N` is itself a symlink. Real host
/// symlinks are rejected before reopen so we never follow them through procfd.
pub(crate) fn open_inode_fd(fs: &PassthroughFs, inode: u64, flags: i32) -> io::Result<i32> {
    #[cfg(target_os = "linux")]
    {
        let inode_fd = get_inode_fd(fs, inode)?;
        let st = platform::fstat(inode_fd.raw())?;
        if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
            return Err(platform::eloop());
        }
        let mut buf = [0u8; 20];
        let fd_str = format_fd_cstr(inode_fd.raw(), &mut buf);
        let reopen_flags = (flags & !libc::O_NOFOLLOW) | libc::O_CLOEXEC;
        let fd = unsafe { libc::openat(fs.proc_self_fd.as_raw_fd(), fd_str, reopen_flags) };
        if fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        Ok(fd)
    }

    #[cfg(target_os = "macos")]
    {
        let inodes = fs.inodes.read().unwrap();
        let data = inodes.get(&inode).cloned().ok_or_else(platform::ebadf)?;

        // If the file was unlinked, dup the preserved fd instead of using /.vol/ path.
        let ufd = data.unlinked_fd.load(Ordering::Acquire);
        if ufd >= 0 {
            let fd = unsafe { libc::fcntl(ufd as i32, libc::F_DUPFD_CLOEXEC, 0) };
            if fd >= 0 {
                return Ok(fd);
            }
            // Fall through to /.vol/ path if dup fails.
        }

        if fs.anchor_mode() {
            drop(inodes);
            // A reopen targets an already-admitted inode by identity, not a
            // fresh path lookup: O_CREAT makes no sense here (do_create
            // already created the file before this reopen runs), and
            // O_TRUNC must not reach the walk's final openat, or a
            // host-side replacement at the anchored name would be
            // truncated before validate_identity_macos gets a chance to
            // reject it. Truncate only after the identity check passes.
            // O_EXCL is meaningless without O_CREAT (nothing left to
            // exclude against) and must NOT be rejected here: do_create's
            // reopen of a just-created file
            // (open_inode_fd(fs, entry.inode, open_flags & !O_CREAT)) keeps
            // O_EXCL set, so rejecting it would break every guest
            // O_CREAT|O_EXCL create in anchor mode.
            if flags & libc::O_CREAT != 0 {
                return Err(platform::einval());
            }
            let walk_flags = flags & !(libc::O_NOFOLLOW | libc::O_TRUNC | libc::O_EXCL);
            let fd = open_anchor_io_fd_macos(fs, inode, walk_flags)?;
            if flags & libc::O_TRUNC != 0 && unsafe { libc::ftruncate(fd, 0) } < 0 {
                let err = io::Error::last_os_error();
                unsafe { libc::close(fd) };
                return Err(platform::linux_error(err));
            }
            return Ok(fd);
        }
        let path = vol_path(data.dev, data.ino);
        open_macos_inode_reopen(path.as_ptr(), flags)
    }
}

/// Format a file descriptor number as a null-terminated C string into a stack buffer.
///
/// Avoids the heap allocation of `format!("/proc/self/fd/{fd}")` on the hot
/// reopen path. A 20-byte stack buffer is sufficient for any i32 fd number
/// plus null terminator.
#[cfg(target_os = "linux")]
fn format_fd_cstr(fd: i32, buf: &mut [u8; 20]) -> *const libc::c_char {
    use std::io::Write;
    let mut cursor = std::io::Cursor::new(&mut buf[..]);
    write!(cursor, "{}\0", fd).unwrap();
    buf.as_ptr() as *const libc::c_char
}

/// Stat an inode (with override xattr applied).
pub(crate) fn stat_inode(fs: &PassthroughFs, inode: u64) -> io::Result<stat64> {
    #[cfg(target_os = "linux")]
    {
        let fd = get_inode_fd(fs, inode)?;
        let st = platform::fstat(fd.raw())?;
        crate::backends::shared::stat_override::patched_stat(
            fd.raw(),
            st,
            fs.cfg.xattr_enabled(),
            fs.cfg.strict_enabled(),
            fs.cfg.bind_identity_map.as_ref(),
        )
    }

    #[cfg(target_os = "macos")]
    {
        let inodes = fs.inodes.read().unwrap();
        let data = inodes.get(&inode).cloned().ok_or_else(platform::ebadf)?;

        // Try unlinked_fd first — /.vol/ path is invalid after unlink.
        let ufd = data.unlinked_fd.load(Ordering::Acquire);
        if ufd >= 0 {
            let st = platform::fstat(ufd as i32)?;
            return crate::backends::shared::stat_override::patched_stat(
                ufd as i32,
                st,
                fs.cfg.xattr_enabled(),
                fs.cfg.strict_enabled(),
                fs.cfg.bind_identity_map.as_ref(),
            );
        }

        if fs.anchor_mode() {
            drop(inodes);
            let fd = open_anchor_reopen_macos(fs, inode)?;
            let result = platform::fstat(fd).and_then(|st| {
                crate::backends::shared::stat_override::patched_stat(
                    fd,
                    st,
                    fs.cfg.xattr_enabled(),
                    fs.cfg.strict_enabled(),
                    fs.cfg.bind_identity_map.as_ref(),
                )
            });
            unsafe { libc::close(fd) };
            return result;
        }

        if let Ok(fd) = open_vol_fd(data.dev, data.ino) {
            let result = platform::fstat(fd).and_then(|st| {
                crate::backends::shared::stat_override::patched_stat(
                    fd,
                    st,
                    fs.cfg.xattr_enabled(),
                    fs.cfg.strict_enabled(),
                    fs.cfg.bind_identity_map.as_ref(),
                )
            });
            unsafe { libc::close(fd) };
            return result;
        }

        let path = vol_path(data.dev, data.ino);
        let mut st = unsafe { std::mem::zeroed::<stat64>() };
        let ret = unsafe { libc::lstat(path.as_ptr(), &mut st) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        open_and_patch_stat_macos(
            data.dev,
            data.ino,
            st,
            fs.cfg.xattr_enabled(),
            fs.cfg.strict_enabled(),
            fs.cfg.bind_identity_map.as_ref(),
        )
    }
}
