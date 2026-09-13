//! Removal operations: unlink, rmdir, rename.
//!
//! All operations validate names and protect `init.krun` from deletion/renaming.
//! On Linux, `renameat2` is used for flag support (RENAME_NOREPLACE, RENAME_EXCHANGE).
//! On macOS, `renameatx_np` is used with translated flag values.

use std::{ffi::CStr, io};

use super::{PassthroughFs, inode};
use crate::{
    Context,
    backends::shared::{inode_table::NamespaceAlias, name_validation, platform},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Linux `RENAME_EXCHANGE` flag: atomically swap source and destination.
const RENAME_EXCHANGE: u32 = 2;

/// Remove a file.
///
/// On macOS, opens an fd to the file before unlinking so that open handles
/// can still access the data after the directory entry is removed (the
/// `/.vol/<dev>/<ino>` path becomes invalid after unlink).
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

    // In anchor mode the alias must be dropped even for entries that cannot be
    // opened at all (a symlink fails ELOOP, a socket ENXIO), so take the
    // identity from the directory entry itself before the unlink, exactly as
    // `do_rmdir` does.
    #[cfg(target_os = "macos")]
    let pre_unlink_stat = if fs.anchor_mode() {
        platform::fstatat_nofollow(parent_fd.raw(), name).ok()
    } else {
        None
    };

    #[cfg(target_os = "macos")]
    let pre_unlink_key = pre_unlink_stat.as_ref().map(|st| {
        crate::backends::shared::inode_table::InodeAltKey::new(
            platform::stat_ino(st),
            platform::stat_dev(st),
        )
    });

    // Opening a FIFO endpoint is never harmless: a read-open completes the
    // rendezvous with a waiting writer, so this open could take bytes meant
    // for the guest and then drop them when the descriptor is released.
    // Removing a name needs no endpoint — there is no file content to keep
    // reachable behind a FIFO — so the entry is simply not opened. The
    // trade-off is that an unlinked FIFO keeps no descriptor, so once its
    // last name is gone an operation that has only the inode to work from
    // returns ENOENT where a regular file would still be served; retaining a
    // reader instead would hold the FIFO open behind the guest's back and
    // suppress its broken-pipe semantics. Handles keep their own descriptors
    // and are unaffected.
    #[cfg(target_os = "macos")]
    let entry_is_fifo = pre_unlink_stat
        .as_ref()
        .is_some_and(|st| st.st_mode & libc::S_IFMT == libc::S_IFIFO);

    // On macOS, grab an fd before unlink to keep the file data alive. A FIFO
    // is skipped outright, as explained above. `O_NONBLOCK` still guards the
    // remaining cases, where the entry's type is not known in advance (volfs
    // mode takes no pre-unlink stat) and a blocking open would park the FUSE
    // worker. The flag is cleared again once the fd is verified, so a retained
    // descriptor keeps the blocking semantics the guest expects.
    #[cfg(target_os = "macos")]
    let pre_unlink_fd = if entry_is_fifo {
        None
    } else {
        let fd = unsafe {
            libc::openat(
                parent_fd.raw(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK,
            )
        };
        if fd >= 0 { Some(fd) } else { None }
    };

    let ret = unsafe { libc::unlinkat(parent_fd.raw(), name.as_ptr(), 0) };
    if ret < 0 {
        // Capture errno before the close: close(2) can overwrite it.
        let err = io::Error::last_os_error();
        if let Some(fd) = pre_unlink_fd {
            unsafe { libc::close(fd) };
        }
        return Err(platform::linux_error(err));
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

    // Store the fd in InodeData so open_inode_fd can use it. In anchor mode
    // also drop the alias so no reopen tries the removed name — that part runs
    // off the pre-unlink directory-entry identity, so it works for entries the
    // pre-unlink open could not obtain an fd for.
    #[cfg(target_os = "macos")]
    if fs.anchor_mode() {
        // The key and the fd come from two syscalls, so the host can replace
        // the name between them. A replacement's fd must never be retained as
        // this inode's data: every later retained-fd read dups or stats it
        // before any anchor verification runs. Keep it only when it is the
        // same file the key names; the alias still goes away either way.
        let verified_fd = match pre_unlink_fd {
            Some(fd) => match (pre_unlink_key, platform::fstat(fd)) {
                (Some(key), Ok(st))
                    if platform::stat_ino(&st) == key.ino && platform::stat_dev(&st) == key.dev =>
                {
                    // The unlink itself already succeeded, so a failure to
                    // restore the blocking flag cannot be reported to the
                    // guest as a failed unlink. Keep the descriptor — dropping
                    // it would cost the guest access to the data behind its
                    // open handles — and say so in the log, because the
                    // retained fd then reads non-blocking.
                    if let Err(err) = inode::clear_nonblock_macos(fd) {
                        tracing::warn!(
                            ?err,
                            "macos passthrough kept an unlinked descriptor with O_NONBLOCK set"
                        );
                    }
                    Some(fd)
                }
                _ => {
                    unsafe { libc::close(fd) };
                    None
                }
            },
            None => None,
        };

        let mut kept_fd = false;
        if let Some(alt_key) = pre_unlink_key {
            let alias = NamespaceAlias::new(parent, name.to_bytes());
            let mut inodes = fs.inodes.write().unwrap();
            if let Some(data) = inodes.get_alt(&alt_key).cloned() {
                let detached = inode::remove_alias_locked(&mut inodes, &data, &alias);
                if detached && let Some(fd) = verified_fd {
                    inode::store_unlinked_fd(&data, fd);
                    kept_fd = true;
                }
            }
        }
        if !kept_fd && let Some(fd) = verified_fd {
            unsafe { libc::close(fd) };
        }
    } else if let Some(fd) = pre_unlink_fd {
        match platform::fstat(fd) {
            Ok(st) => {
                let alt_key = crate::backends::shared::inode_table::InodeAltKey::new(
                    st.st_ino,
                    platform::stat_dev(&st),
                );
                // Volfs mode only reads the table here, exactly as it did
                // before anchor mode existed.
                let inodes = fs.inodes.read().unwrap();
                match inodes.get_alt(&alt_key).cloned() {
                    Some(data) => {
                        // As above: the unlink has happened, so the descriptor
                        // is kept and the flag failure is reported in the log
                        // instead of being turned into a guest-visible error.
                        if let Err(err) = inode::clear_nonblock_macos(fd) {
                            tracing::warn!(
                                ?err,
                                "macos passthrough kept an unlinked descriptor with O_NONBLOCK set"
                            );
                        }
                        inode::store_unlinked_fd(&data, fd)
                    }
                    None => unsafe {
                        libc::close(fd);
                    },
                }
            }
            Err(_) => unsafe {
                libc::close(fd);
            },
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

    let parent_fd = inode::get_inode_fd(fs, parent)?;

    #[cfg(target_os = "macos")]
    let pre_rmdir_key = if fs.anchor_mode() {
        platform::fstatat_nofollow(parent_fd.raw(), name)
            .ok()
            .map(|st| {
                crate::backends::shared::inode_table::InodeAltKey::new(
                    platform::stat_ino(&st),
                    platform::stat_dev(&st),
                )
            })
    } else {
        None
    };

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

    #[cfg(target_os = "macos")]
    if let Some(alt_key) = pre_rmdir_key {
        let alias = NamespaceAlias::new(parent, name.to_bytes());
        let mut inodes = fs.inodes.write().unwrap();
        if let Some(data) = inodes.get_alt(&alt_key).cloned() {
            let _ = inode::remove_alias_locked(&mut inodes, &data, &alias);
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
        let source_key = match inode::linux_alt_key_from_fd(source_probe_fd) {
            Ok(key) => key,
            Err(err) => {
                unsafe { libc::close(source_probe_fd) };
                return Err(err);
            }
        };
        unsafe { libc::close(source_probe_fd) };

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
        let anchor_mode = fs.anchor_mode();
        let source_key = if anchor_mode {
            let st = platform::fstatat_nofollow(old_fd.raw(), oldname)?;
            Some(crate::backends::shared::inode_table::InodeAltKey::new(
                platform::stat_ino(&st),
                platform::stat_dev(&st),
            ))
        } else {
            None
        };
        // Keep the replaced target readable through open handles, as unlink does.
        // A FIFO target is never opened: a read-open would complete the
        // rendezvous with a waiting writer and then discard its bytes, and a
        // FIFO has no content to keep reachable anyway. For every other type
        // `O_NONBLOCK` guards against a FIFO swapped in under the name between
        // the stat and the open.
        let target_probe = if anchor_mode {
            match platform::fstatat_nofollow(new_fd.raw(), newname) {
                Ok(st) => {
                    let key = crate::backends::shared::inode_table::InodeAltKey::new(
                        platform::stat_ino(&st),
                        platform::stat_dev(&st),
                    );
                    let fd = if st.st_mode & libc::S_IFMT == libc::S_IFIFO {
                        -1
                    } else {
                        unsafe {
                            libc::openat(
                                new_fd.raw(),
                                newname.as_ptr(),
                                libc::O_RDONLY
                                    | libc::O_CLOEXEC
                                    | libc::O_NOFOLLOW
                                    | libc::O_NONBLOCK,
                            )
                        }
                    };
                    // The stat and the open are two steps, so the name can be
                    // replaced between them. Without this check the fd of the
                    // replacement would be retained under the original
                    // target's identity, and every later retained-fd access
                    // would skip the anchor identity check.
                    let fd = if fd >= 0 {
                        match platform::fstat(fd) {
                            Ok(opened)
                                if platform::stat_ino(&opened) == key.ino
                                    && platform::stat_dev(&opened) == key.dev =>
                            {
                                // Nothing has been mutated yet, so a failure
                                // to restore the blocking flag aborts the
                                // rename instead of handing the guest a
                                // descriptor with flags it never asked for.
                                if let Err(err) = inode::clear_nonblock_macos(fd) {
                                    unsafe { libc::close(fd) };
                                    return Err(err);
                                }
                                Some(fd)
                            }
                            _ => {
                                unsafe { libc::close(fd) };
                                None
                            }
                        }
                    } else {
                        None
                    };
                    Some((fd, key))
                }
                Err(err) if err.raw_os_error() == Some(libc::ENOENT) => None,
                Err(err) => return Err(err),
            }
        } else {
            None
        };

        if flags == 0 {
            let ret = unsafe {
                libc::renameat(
                    old_fd.raw(),
                    oldname.as_ptr(),
                    new_fd.raw(),
                    newname.as_ptr(),
                )
            };
            if ret < 0 {
                // Capture errno before the close: close(2) can overwrite it.
                let err = io::Error::last_os_error();
                if let Some((Some(fd), _)) = target_probe.as_ref() {
                    unsafe { libc::close(*fd) };
                }
                return Err(platform::linux_error(err));
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

            let ret = unsafe {
                libc::renameatx_np(
                    old_fd.raw(),
                    oldname.as_ptr(),
                    new_fd.raw(),
                    newname.as_ptr(),
                    macos_flags,
                )
            };
            if ret < 0 {
                // Capture errno before the close: close(2) can overwrite it.
                let err = io::Error::last_os_error();
                if let Some((Some(fd), _)) = target_probe.as_ref() {
                    unsafe { libc::close(*fd) };
                }
                return Err(platform::linux_error(err));
            }
        }

        if let Some(source_key) = source_key {
            let old_alias = NamespaceAlias::new(olddir, oldname.to_bytes());
            let new_alias = NamespaceAlias::new(newdir, newname.to_bytes());
            let mut inodes = fs.inodes.write().unwrap();
            let source_data = inodes.get_alt(&source_key).cloned();

            // Each move registers the new alias before removing the old one.
            // The reverse order can collect the new parent: if the guest has
            // already forgotten it and the removed alias was its last
            // dependent, the parent record disappears before the child is
            // attached to it, and the child becomes unresolvable. Registering
            // first raises the new parent's dependent count before the old
            // parent's count drops, and a same-parent rename nets to zero.
            if flags & RENAME_EXCHANGE != 0 {
                if let Some((fd, target_key)) = target_probe.as_ref()
                    && *target_key == source_key
                {
                    if let Some(fd) = fd {
                        unsafe { libc::close(*fd) };
                    }
                    return Ok(());
                }

                // An exchange moves two entries, and each move can drop the
                // last anchored child of a directory the guest has already
                // forgotten. Collecting that directory between the two moves
                // would strand the second entry on a parent that is no longer
                // in the table. Pinning both directories defers any such
                // collection until both anchors are installed. Registering the
                // new alias first is not enough on its own: an inode that
                // already has an anchor keeps its dependency counts unchanged
                // until the old alias goes away.
                let pinned_olddir = inode::pin_anchor_parent_locked(&inodes, olddir);
                let pinned_newdir = inode::pin_anchor_parent_locked(&inodes, newdir);

                if let Some(source) = source_data.as_ref() {
                    inode::register_alias_locked(&mut inodes, source, new_alias.clone());
                    let _ = inode::remove_alias_locked(&mut inodes, source, &old_alias);
                }
                if let Some((fd, target_key)) = target_probe {
                    if target_key != source_key
                        && let Some(target) = inodes.get_alt(&target_key).cloned()
                    {
                        inode::register_alias_locked(&mut inodes, &target, old_alias);
                        let _ = inode::remove_alias_locked(&mut inodes, &target, &new_alias);
                    }
                    if let Some(fd) = fd {
                        unsafe { libc::close(fd) };
                    }
                }

                if pinned_olddir {
                    inode::unpin_anchor_parent_locked(&mut inodes, olddir);
                }
                if pinned_newdir {
                    inode::unpin_anchor_parent_locked(&mut inodes, newdir);
                }
            } else {
                // POSIX: renaming one link of an inode onto another link of the
                // same inode does nothing at all — both names survive — so the
                // alias set must stay as it was.
                if let Some((fd, target_key)) = target_probe.as_ref()
                    && *target_key == source_key
                {
                    if let Some(fd) = fd {
                        unsafe { libc::close(*fd) };
                    }
                    return Ok(());
                }

                if let Some(source) = source_data.as_ref() {
                    inode::register_alias_locked(&mut inodes, source, new_alias.clone());
                    let _ = inode::remove_alias_locked(&mut inodes, source, &old_alias);
                }
                if let Some((fd, target_key)) = target_probe {
                    let source_inode = source_data.as_ref().map(|data| data.inode);
                    let mut keep_fd = false;
                    if let Some(target) = inodes.get_alt(&target_key).cloned()
                        && Some(target.inode) != source_inode
                    {
                        let detached = inode::remove_alias_locked(&mut inodes, &target, &new_alias);
                        if detached && let Some(fd) = fd {
                            inode::store_unlinked_fd(&target, fd);
                            keep_fd = true;
                        }
                    }
                    if !keep_fd && let Some(fd) = fd {
                        unsafe { libc::close(fd) };
                    }
                }
            }
        }
    }

    Ok(())
}
