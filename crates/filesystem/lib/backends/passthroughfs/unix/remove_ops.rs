//! Removal operations: unlink, rmdir, rename.
//!
//! All operations validate names and protect `init.krun` from deletion/renaming.
//! On Linux, `renameat2` is used for flag support (RENAME_NOREPLACE, RENAME_EXCHANGE).
//! On macOS, `renameatx_np` is used with translated flag values.

use std::{ffi::CStr, io};

use super::{PassthroughFs, inode};
#[cfg(target_os = "linux")]
use crate::backends::shared::inode_table::NamespaceAlias;
use crate::{
    Context,
    backends::shared::{name_validation, platform},
    stat64,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `RENAME_EXCHANGE` flag: atomically swap source and destination.
///
/// This is the Linux value; the macOS branch maps it to `RENAME_SWAP` before
/// calling `renameatx_np`, but the hide-path checks below reason about the flag in
/// this shared numbering.
const RENAME_EXCHANGE: u32 = 2;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Platform-agnostic outcome of the hide_path decision for a rename.
pub(super) enum RenameDecision {
    /// No hide-path rule matched and the checked identities are fresh: perform the move.
    Proceed,
    /// A hide-path rule matched: the caller returns `EACCES`.
    Deny,
    /// A checked identity went stale: the caller retries from the top.
    Retry,
}

/// One side of a rename: the pinned parent handle, its inode, and the entry name.
#[derive(Clone, Copy)]
pub(super) struct RenameEndpoint<'a> {
    /// Open handle to the parent directory.
    pub(super) fd: &'a inode::InodeFd,
    /// Parent inode number, used to reconstruct the mount-relative path.
    pub(super) dir: u64,
    /// Entry name within the parent.
    pub(super) name: &'a CStr,
}

/// Expected state of an atomic exchange (`RENAME_EXCHANGE`/`RENAME_SWAP`)
/// destination, captured when its type drives a directory-only hide_path decision.
///
/// The destination is re-read immediately before the move and the whole
/// check-and-move is retried when it no longer matches. A destination that was
/// absent must still be absent: a directory appearing in that window would
/// otherwise be swapped onto a dir-only-denied source name, and a non-exchange
/// rename never needs this because it always replaces the destination with the
/// source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ExchangeDest {
    /// The destination did not resolve when its type was assessed.
    Absent,
    /// The destination resolved with this host `(ino, dev)` identity.
    Present { ino: u64, dev: u64 },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExchangeDest {
    /// Capture the expectation from the destination's pre-move identity, if it
    /// was present.
    pub(super) fn capture(identity: Option<(u64, u64)>) -> Self {
        match identity {
            Some((ino, dev)) => Self::Present { ino, dev },
            None => Self::Absent,
        }
    }

    /// Whether a freshly read destination identity (absent when `None`) still
    /// satisfies this expectation.
    pub(super) fn still_matches(self, current: Option<(u64, u64)>) -> bool {
        match self {
            Self::Absent => current.is_none(),
            Self::Present { ino, dev } => current == Some((ino, dev)),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Apply the hide-path rules for a rename, shared by the Linux and macOS branches.
///
/// `source_st` is the source's freshly captured `fstat`, whose type and identity
/// the decision is pinned to. Returns [`RenameDecision::Deny`] when a pattern
/// matches, [`RenameDecision::Retry`] when the source or an exchange destination
/// changed under us, and [`RenameDecision::Proceed`] when the move may run. The
/// platform-specific syscall and any post-rename inode bookkeeping stay in the
/// caller.
pub(super) fn decide_rename_hide_path(
    fs: &PassthroughFs,
    old: RenameEndpoint<'_>,
    new: RenameEndpoint<'_>,
    flags: u32,
    source_st: &stat64,
) -> io::Result<RenameDecision> {
    // A rename replaces the destination with the source's type (and, for an
    // exchange, moves the destination onto the source name), so the source's
    // type drives every dir-only decision in both directions.
    let source_is_dir = fs.hide_path.has_dir_only_patterns()
        && platform::mode_file_type(source_st.st_mode) == platform::MODE_DIR;

    // Resolve each parent's mount-relative path once per attempt and reuse it
    // across the hide-path checks below: path patterns need it for every match, and
    // one resolution dominates the cost of a hide-path check. Component-only patterns
    // skip resolution entirely (basename fast path). An unresolvable parent fails
    // closed, mirroring `hide_path_matches_name`.
    let (old_comps, new_comps) = if fs.hide_path.needs_path_reconstruction() {
        let old_comps = inode::parent_path_components(&fs.inodes, old.dir, fs.hide_path_root())
            .ok_or_else(platform::eacces)?;
        // Same-directory renames are the dominant case; resolve once.
        let new_comps = if new.dir == old.dir {
            old_comps.clone()
        } else {
            inode::parent_path_components(&fs.inodes, new.dir, fs.hide_path_root())
                .ok_or_else(platform::eacces)?
        };
        (Some(old_comps), Some(new_comps))
    } else {
        (None, None)
    };

    // Case behavior is per directory (Linux ext4/btrfs casefold), so resolve
    // each parent's once and reuse it for every check below.
    let old_case = fs.hide_path_case_insensitive(old.dir);
    let new_case = fs.hide_path_case_insensitive(new.dir);

    // Authoritative hide_path decision against the pinned source type.
    if fs.hide_path_matches_name_in_dir(
        old_comps.as_deref(),
        old.name.to_bytes(),
        source_is_dir,
        old_case,
    ) || fs.hide_path_matches_name_in_dir(
        new_comps.as_deref(),
        new.name.to_bytes(),
        source_is_dir,
        new_case,
    ) {
        return Ok(RenameDecision::Deny);
    }

    let mut exchange_dest = None;
    if fs.hide_path.has_dir_only_patterns() {
        let dest_st = platform::fstatat_nofollow(new.fd.raw(), new.name).ok();
        let dest_is_dir = dest_st
            .as_ref()
            .map(|st| platform::mode_file_type(st.st_mode) == platform::MODE_DIR)
            .unwrap_or(false);
        if dest_is_dir
            && fs.hide_path_matches_name_in_dir(
                new_comps.as_deref(),
                new.name.to_bytes(),
                true,
                new_case,
            )
        {
            return Ok(RenameDecision::Deny);
        }
        // RENAME_EXCHANGE also moves the destination onto the *source* name, so
        // the reverse direction needs the destination's type: exchanging a file
        // at a dir-only-denied name with a directory at an allowed name would
        // otherwise land the directory at the denied name.
        if flags & RENAME_EXCHANGE != 0 {
            if dest_is_dir
                && fs.hide_path_matches_name_in_dir(
                    old_comps.as_deref(),
                    old.name.to_bytes(),
                    true,
                    old_case,
                )
            {
                return Ok(RenameDecision::Deny);
            }
            // Pin the destination as well, so an external writer swapping in a
            // directory (or creating one at an absent name) is caught by the
            // re-check below rather than landing at the denied source name.
            exchange_dest = Some(ExchangeDest::capture(
                dest_st
                    .as_ref()
                    .map(|st| (platform::stat_ino(st), platform::stat_dev(st))),
            ));
        }
    }

    // The source path must still refer to the pinned inode; otherwise the type
    // we checked is stale, so retry the whole check+move.
    match platform::fstatat_nofollow(old.fd.raw(), old.name) {
        Ok(st)
            if platform::stat_ino(&st) == platform::stat_ino(source_st)
                && platform::stat_dev(&st) == platform::stat_dev(source_st) => {}
        _ => return Ok(RenameDecision::Retry),
    }

    // An exchange destination must still match what we checked: a non-exchange
    // rename replaces the destination with the source, so only the source
    // identity matters there, but an exchange moves the destination onto the
    // source name and must not let a directory appear at (or replace) a
    // dir-only-denied destination.
    if let Some(expected) = exchange_dest {
        let current = platform::fstatat_nofollow(new.fd.raw(), new.name)
            .ok()
            .map(|st| (platform::stat_ino(&st), platform::stat_dev(&st)));
        if !expected.still_matches(current) {
            return Ok(RenameDecision::Retry);
        }
    }

    Ok(RenameDecision::Proceed)
}

/// Remove a file.
///
/// On macOS, opens an fd to the file before unlinking so that open handles
/// can still access the data after the last directory entry is removed (the
/// `/.vol/<dev>/<ino>` path becomes invalid after the final unlink).
pub(crate) fn do_unlink(
    fs: &PassthroughFs,
    _ctx: Context,
    parent: u64,
    name: &CStr,
) -> io::Result<()> {
    name_validation::validate_name(name)?;
    if fs.cfg.readonly() {
        return Err(platform::erofs());
    }

    // Protect init.krun from deletion.
    if fs.is_reserved_init_name(parent, name.to_bytes()) {
        return Err(platform::eacces());
    }

    let parent_fd = inode::get_inode_fd(fs, parent)?;

    // A dir-only pattern (`node_modules/`) must hide the directory from unlink
    // too: otherwise the raw unlink returns EISDIR and reveals that a hidden
    // name exists and is a directory. Only dir-only patterns depend on the
    // entry's type, so stat only when one is present; an unresolved type fails
    // closed by matching as a directory.
    let is_dir = if fs.hide_path.has_dir_only_patterns() {
        platform::fstatat_nofollow(parent_fd.raw(), name)
            .map(|st| platform::mode_file_type(st.st_mode) == platform::MODE_DIR)
            .unwrap_or(true)
    } else {
        false
    };
    if fs.hide_path_matches_name(parent, name.to_bytes(), is_dir) {
        return Err(platform::eacces());
    }

    #[cfg(target_os = "linux")]
    let pre_unlink_fd = {
        let fd = unsafe {
            libc::openat(
                parent_fd.raw(),
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd >= 0 { Some(fd) } else { None }
    };

    #[cfg(target_os = "linux")]
    let pre_unlink_key = match pre_unlink_fd {
        Some(fd) => match inode::linux_alt_key_from_fd(fd) {
            Ok(key) => Some(key),
            Err(err) => {
                unsafe { libc::close(fd) };
                return Err(err);
            }
        },
        None => None,
    };

    // Preserve writable access when the host allows it. A read-only fallback
    // still keeps readable files alive without requiring write permission to unlink.
    #[cfg(target_os = "macos")]
    let pre_unlink_fd = {
        let mut fd = unsafe {
            libc::openat(
                parent_fd.raw(),
                name.as_ptr(),
                libc::O_RDWR | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if fd < 0 {
            fd = unsafe {
                libc::openat(
                    parent_fd.raw(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
        }
        if fd >= 0 { Some(fd) } else { None }
    };

    let ret = unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), 0) };
    if ret < 0 {
        #[cfg(target_os = "linux")]
        if let Some(fd) = pre_unlink_fd {
            unsafe { libc::close(fd) };
        }
        #[cfg(target_os = "macos")]
        if let Some(fd) = pre_unlink_fd {
            unsafe { libc::close(fd) };
        }
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    #[cfg(target_os = "linux")]
    if let Some(fd) = pre_unlink_fd {
        let alias = NamespaceAlias::new(parent, name.to_bytes());
        if let Some(alt_key) = pre_unlink_key {
            let mut inodes = fs.inodes.write().unwrap();
            if let Some(data) = inodes.get_alt(&alt_key).cloned() {
                let detached = inode::remove_alias_locked(&mut inodes, &data, &alias);
                if detached {
                    inode::store_unlinked_fd(&data, fd);
                } else {
                    unsafe { libc::close(fd) };
                }
            } else {
                unsafe { libc::close(fd) };
            }
        } else {
            unsafe { libc::close(fd) };
        }
    }

    // Keep a fallback even if a hard link remains: the host can remove that
    // name without another FUSE unlink. open_inode_fd still reopens linked
    // inodes through /.vol/ with the requested access flags.
    #[cfg(target_os = "macos")]
    if let Some(fd) = pre_unlink_fd {
        // Look up the inode by stat identity from the pre-unlink fd.
        let st = platform::fstat(fd);
        if let Ok(st) = st {
            let alt_key = crate::backends::shared::inode_table::InodeAltKey::new(
                st.st_ino,
                platform::stat_dev(&st),
            );
            let inodes = fs.inodes.read().unwrap();
            if let Some(data) = inodes.get_alt(&alt_key) {
                inode::store_unlinked_fd(data, fd);
            } else {
                // No tracked inode — close the fd.
                unsafe { libc::close(fd) };
            }
        } else {
            unsafe { libc::close(fd) };
        }
    }

    Ok(())
}

/// Remove a directory.
pub(crate) fn do_rmdir(
    fs: &PassthroughFs,
    _ctx: Context,
    parent: u64,
    name: &CStr,
) -> io::Result<()> {
    name_validation::validate_name(name)?;
    if fs.cfg.readonly() {
        return Err(platform::erofs());
    }

    if fs.is_reserved_init_name(parent, name.to_bytes()) {
        return Err(platform::eacces());
    }

    if fs.hide_path_matches_name(parent, name.to_bytes(), true) {
        return Err(platform::eacces());
    }

    let parent_fd = inode::get_inode_fd(fs, parent)?;

    #[cfg(target_os = "linux")]
    let pre_rmdir_fd = {
        let fd = unsafe {
            libc::openat(
                parent_fd.raw(),
                name.as_ptr(),
                libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY,
            )
        };
        if fd >= 0 { Some(fd) } else { None }
    };

    #[cfg(target_os = "linux")]
    let pre_rmdir_key = match pre_rmdir_fd {
        Some(fd) => match inode::linux_alt_key_from_fd(fd) {
            Ok(key) => Some(key),
            Err(err) => {
                unsafe { libc::close(fd) };
                return Err(err);
            }
        },
        None => None,
    };

    let ret = unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), libc::AT_REMOVEDIR) };
    if ret < 0 {
        #[cfg(target_os = "linux")]
        if let Some(fd) = pre_rmdir_fd {
            unsafe { libc::close(fd) };
        }
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    #[cfg(target_os = "linux")]
    if let Some(fd) = pre_rmdir_fd {
        let alias = NamespaceAlias::new(parent, name.to_bytes());
        if let Some(alt_key) = pre_rmdir_key {
            let mut inodes = fs.inodes.write().unwrap();
            if let Some(data) = inodes.get_alt(&alt_key).cloned() {
                let detached = inode::remove_alias_locked(&mut inodes, &data, &alias);
                if detached {
                    inode::store_unlinked_fd(&data, fd);
                } else {
                    unsafe { libc::close(fd) };
                }
            } else {
                unsafe { libc::close(fd) };
            }
        } else {
            unsafe { libc::close(fd) };
        }
    }
    Ok(())
}

/// Rename a file or directory.
pub(crate) fn do_rename(
    fs: &PassthroughFs,
    _ctx: Context,
    olddir: u64,
    oldname: &CStr,
    newdir: u64,
    newname: &CStr,
    flags: u32,
) -> io::Result<()> {
    name_validation::validate_name(oldname)?;
    name_validation::validate_name(newname)?;
    if fs.cfg.readonly() {
        return Err(platform::erofs());
    }

    // Protect init.krun from being renamed or overwritten.
    if fs.is_reserved_init_name(olddir, oldname.to_bytes())
        || fs.is_reserved_init_name(newdir, newname.to_bytes())
    {
        return Err(platform::eacces());
    }

    let old_fd = inode::get_inode_fd(fs, olddir)?;
    let new_fd = inode::get_inode_fd(fs, newdir)?;

    #[cfg(target_os = "linux")]
    {
        // The source type can change between the hide-path checks and the move,
        // because external writers (host processes, or a second mount on the
        // same host directory) bypass the single-threaded virtio-fs worker that
        // serializes guest requests. A directory swapped in for a file would
        // otherwise land at a dir-only-denied destination. Narrow this by
        // capturing the source inode's identity, re-verifying the source path
        // still refers to it immediately before the move, and retrying the whole
        // check+move on a mismatch (mirrors virtiofsd's
        // verify-identity-and-retry pattern). The `O_PATH` probe fd is opened
        // for the post-rename alias key (`linux_alt_key_from_fd`), not to pin the
        // inode; it is closed before the move.
        const MAX_RETRIES: u32 = 3;
        let mut attempts = 0u32;

        let (source_key, target_probe) = loop {
            attempts += 1;
            if attempts > MAX_RETRIES {
                return Err(platform::ebusy());
            }

            let source_probe_fd = unsafe {
                libc::openat(
                    old_fd.raw(),
                    oldname.as_ptr(),
                    libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if source_probe_fd < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            let source_st = match platform::fstat(source_probe_fd) {
                Ok(st) => st,
                Err(err) => {
                    unsafe { libc::close(source_probe_fd) };
                    return Err(err);
                }
            };
            let source_key = match inode::linux_alt_key_from_fd(source_probe_fd) {
                Ok(key) => key,
                Err(err) => {
                    unsafe { libc::close(source_probe_fd) };
                    return Err(err);
                }
            };
            unsafe { libc::close(source_probe_fd) };

            match decide_rename_hide_path(
                fs,
                RenameEndpoint {
                    fd: &old_fd,
                    dir: olddir,
                    name: oldname,
                },
                RenameEndpoint {
                    fd: &new_fd,
                    dir: newdir,
                    name: newname,
                },
                flags,
                &source_st,
            )? {
                RenameDecision::Deny => return Err(platform::eacces()),
                RenameDecision::Retry => continue,
                RenameDecision::Proceed => {}
            }

            let target_probe_fd = unsafe {
                libc::openat(
                    new_fd.raw(),
                    newname.as_ptr(),
                    libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            let target_probe = if target_probe_fd >= 0 {
                let target_key = match inode::linux_alt_key_from_fd(target_probe_fd) {
                    Ok(key) => key,
                    Err(err) => {
                        unsafe { libc::close(target_probe_fd) };
                        return Err(err);
                    }
                };
                Some((target_probe_fd, target_key))
            } else if io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT) {
                None
            } else {
                return Err(platform::linux_error(io::Error::last_os_error()));
            };

            let ret = unsafe {
                libc::syscall(
                    libc::SYS_renameat2,
                    old_fd.raw(),
                    oldname.as_ptr(),
                    new_fd.raw(),
                    newname.as_ptr(),
                    flags,
                )
            };
            if ret < 0 {
                if let Some((fd, _)) = target_probe {
                    unsafe { libc::close(fd) };
                }
                return Err(platform::linux_error(io::Error::last_os_error()));
            }

            break (source_key, target_probe);
        };

        let old_alias = NamespaceAlias::new(olddir, oldname.to_bytes());
        let new_alias = NamespaceAlias::new(newdir, newname.to_bytes());
        let mut inodes = fs.inodes.write().unwrap();
        let source_data = inodes.get_alt(&source_key).cloned();

        if flags & RENAME_EXCHANGE != 0 {
            if let Some((fd, target_key)) = target_probe.as_ref()
                && *target_key == source_key
            {
                unsafe { libc::close(*fd) };
                return Ok(());
            }

            if let Some(source) = source_data.as_ref() {
                let _ = inode::remove_alias_locked(&mut inodes, source, &old_alias);
                inode::register_alias_locked(&mut inodes, source, new_alias.clone());
            }

            if let Some((fd, target_key)) = target_probe {
                if let Some(target) = inodes.get_alt(&target_key).cloned() {
                    let _ = inode::remove_alias_locked(&mut inodes, &target, &new_alias);
                    inode::register_alias_locked(&mut inodes, &target, old_alias);
                }
                unsafe { libc::close(fd) };
            }
        } else {
            if let Some(source) = source_data.as_ref() {
                let _ = inode::remove_alias_locked(&mut inodes, source, &old_alias);
                inode::register_alias_locked(&mut inodes, source, new_alias.clone());
            }

            if let Some((fd, target_key)) = target_probe {
                let source_inode = source_data.as_ref().map(|data| data.inode);
                if let Some(target) = inodes.get_alt(&target_key).cloned() {
                    if Some(target.inode) != source_inode {
                        let detached = inode::remove_alias_locked(&mut inodes, &target, &new_alias);
                        if detached {
                            inode::store_unlinked_fd(&target, fd);
                        } else {
                            unsafe { libc::close(fd) };
                        }
                    } else {
                        unsafe { libc::close(fd) };
                    }
                } else {
                    unsafe { libc::close(fd) };
                }
            }
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Same verify-identity-and-retry narrowing as the Linux branch: an
        // external writer can swap the source inode between the hide-path checks
        // and the move, letting a directory land at a dir-only-denied
        // destination. Capture the source identity, re-verify the source path
        // still refers to it immediately before the move, and retry on a
        // mismatch. Unlike the Linux branch there is no post-rename inode
        // bookkeeping to feed, so a plain `fstatat` is sufficient — no fd is
        // opened (an `O_RDONLY` open would block on FIFOs and has no value
        // here, since the fd would be closed before the gap anyway).
        const MAX_RETRIES: u32 = 3;
        let mut attempts = 0u32;

        loop {
            attempts += 1;
            if attempts > MAX_RETRIES {
                return Err(platform::ebusy());
            }

            let source_st = platform::fstatat_nofollow(old_fd.raw(), oldname)?;

            match decide_rename_hide_path(
                fs,
                RenameEndpoint {
                    fd: &old_fd,
                    dir: olddir,
                    name: oldname,
                },
                RenameEndpoint {
                    fd: &new_fd,
                    dir: newdir,
                    name: newname,
                },
                flags,
                &source_st,
            )? {
                RenameDecision::Deny => return Err(platform::eacces()),
                RenameDecision::Retry => continue,
                RenameDecision::Proceed => {}
            }

            let ret = if flags == 0 {
                unsafe {
                    libc::renameat(
                        old_fd.raw(),
                        oldname.as_ptr(),
                        new_fd.raw(),
                        newname.as_ptr(),
                    )
                }
            } else {
                // macOS uses renamex_np for RENAME_SWAP and RENAME_EXCL.
                // Map Linux flags to macOS equivalents.
                let mut macos_flags: libc::c_uint = 0;

                // Linux RENAME_NOREPLACE = 1, macOS RENAME_EXCL = 0x00000004
                if flags & 1 != 0 {
                    macos_flags |= 0x00000004; // RENAME_EXCL
                }
                // Linux RENAME_EXCHANGE = 2, macOS RENAME_SWAP = 0x00000002
                if flags & 2 != 0 {
                    macos_flags |= 0x00000002; // RENAME_SWAP
                }

                unsafe {
                    libc::renameatx_np(
                        old_fd.raw(),
                        oldname.as_ptr(),
                        new_fd.raw(),
                        newname.as_ptr(),
                        macos_flags,
                    )
                }
            };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }

            break;
        }
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::ExchangeDest;

    /// An initially-absent exchange destination must be treated as stale once
    /// anything appears at the name: the move could otherwise land a directory
    /// at a dir-only-denied source name.
    #[test]
    fn exchange_dest_absent_is_stale_when_destination_appears() {
        assert!(ExchangeDest::Absent.still_matches(None));
        assert!(!ExchangeDest::Absent.still_matches(Some((1, 2))));
    }

    /// A present exchange destination must match by identity, and any removal or
    /// replacement is stale.
    #[test]
    fn exchange_dest_present_is_stale_on_identity_change_or_removal() {
        let expected = ExchangeDest::capture(Some((5, 7)));
        assert!(expected.still_matches(Some((5, 7))));
        assert!(!expected.still_matches(Some((5, 8))));
        assert!(!expected.still_matches(Some((6, 7))));
        assert!(!expected.still_matches(None));
    }
}
