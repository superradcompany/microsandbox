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
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Linux `RENAME_EXCHANGE` flag: atomically swap source and destination.
#[cfg(target_os = "linux")]
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

    if fs.deny_matches_name(parent, name.to_bytes(), false) {
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

    // On macOS, grab an fd before unlink to keep the file data alive.
    #[cfg(target_os = "macos")]
    let pre_unlink_fd = {
        let fd = unsafe {
            libc::openat(
                parent_fd.raw(),
                name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
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

    // Store the fd in InodeData so open_inode_fd can use it.
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

    if fs.deny_matches_name(parent, name.to_bytes(), true) {
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
        // The source type can change between the deny checks and the move,
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
            let source_is_dir = fs.deny.has_dir_only_patterns()
                && platform::mode_file_type(source_st.st_mode) == platform::MODE_DIR;
            let source_key = match inode::linux_alt_key_from_fd(source_probe_fd) {
                Ok(key) => key,
                Err(err) => {
                    unsafe { libc::close(source_probe_fd) };
                    return Err(err);
                }
            };
            unsafe { libc::close(source_probe_fd) };

            // Resolve each parent's mount-relative path once per attempt and
            // reuse it across the deny checks below: path patterns need it for
            // every match, and one resolution walks the inode anchor chain,
            // which dominates the cost of a deny check. Component-only patterns
            // skip resolution entirely (basename fast path). An unresolvable
            // parent fails closed, mirroring `deny_matches_name`.
            let (old_comps, new_comps) = if fs.deny.needs_path_reconstruction() {
                let old_comps = inode::parent_path_components(&fs.inodes, olddir, fs.deny_root())
                    .ok_or_else(platform::eacces)?;
                // Same-directory renames are the dominant case; resolve once.
                let new_comps = if newdir == olddir {
                    old_comps.clone()
                } else {
                    inode::parent_path_components(&fs.inodes, newdir, fs.deny_root())
                        .ok_or_else(platform::eacces)?
                };
                (Some(old_comps), Some(new_comps))
            } else {
                (None, None)
            };

            // Authoritative deny decision against the pinned source type.
            if fs.deny_matches_name_in_dir(old_comps.as_deref(), oldname.to_bytes(), source_is_dir)
                || fs.deny_matches_name_in_dir(
                    new_comps.as_deref(),
                    newname.to_bytes(),
                    source_is_dir,
                )
            {
                return Err(platform::eacces());
            }
            if fs.deny.has_dir_only_patterns() {
                let dest_is_dir = platform::fstatat_nofollow(new_fd.raw(), newname)
                    .map(|st| platform::mode_file_type(st.st_mode) == platform::MODE_DIR)
                    .unwrap_or(false);
                if dest_is_dir
                    && fs.deny_matches_name_in_dir(new_comps.as_deref(), newname.to_bytes(), true)
                {
                    return Err(platform::eacces());
                }
                // RENAME_EXCHANGE also moves the destination onto the *source*
                // name, so the reverse direction needs the destination's type:
                // exchanging a file at a dir-only-denied name with a directory at
                // an allowed name would otherwise land the directory at the
                // denied name.
                if flags & RENAME_EXCHANGE != 0
                    && dest_is_dir
                    && fs.deny_matches_name_in_dir(old_comps.as_deref(), oldname.to_bytes(), true)
                {
                    return Err(platform::eacces());
                }
            }

            // The source path must still refer to the pinned inode; otherwise the
            // type we checked is stale, so retry the whole check+move.
            match platform::fstatat_nofollow(old_fd.raw(), oldname) {
                Ok(st)
                    if platform::stat_ino(&st) == platform::stat_ino(&source_st)
                        && platform::stat_dev(&st) == platform::stat_dev(&source_st) => {}
                _ => continue,
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
        // external writer can swap the source inode between the deny checks
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
            let source_is_dir = fs.deny.has_dir_only_patterns()
                && platform::mode_file_type(source_st.st_mode) == platform::MODE_DIR;

            // Resolve each parent's mount-relative path once per attempt and
            // reuse it across the deny checks below: path patterns need it for
            // every match, and one resolution runs F_GETPATH through the
            // `/.vol/<dev>/<ino>` path, which dominates the cost of a deny
            // check. Component-only patterns skip resolution entirely (basename
            // fast path). An unresolvable parent fails closed, mirroring
            // `deny_matches_name`.
            let (old_comps, new_comps) = if fs.deny.needs_path_reconstruction() {
                let old_comps = inode::parent_path_components(&fs.inodes, olddir, fs.deny_root())
                    .ok_or_else(platform::eacces)?;
                // Same-directory renames are the dominant case; resolve once.
                let new_comps = if newdir == olddir {
                    old_comps.clone()
                } else {
                    inode::parent_path_components(&fs.inodes, newdir, fs.deny_root())
                        .ok_or_else(platform::eacces)?
                };
                (Some(old_comps), Some(new_comps))
            } else {
                (None, None)
            };

            // Authoritative deny decision against the freshly-captured source type.
            if fs.deny_matches_name_in_dir(old_comps.as_deref(), oldname.to_bytes(), source_is_dir)
                || fs.deny_matches_name_in_dir(
                    new_comps.as_deref(),
                    newname.to_bytes(),
                    source_is_dir,
                )
            {
                return Err(platform::eacces());
            }
            if fs.deny.has_dir_only_patterns() {
                let dest_is_dir = platform::fstatat_nofollow(new_fd.raw(), newname)
                    .map(|st| platform::mode_file_type(st.st_mode) == platform::MODE_DIR)
                    .unwrap_or(false);
                if dest_is_dir
                    && fs.deny_matches_name_in_dir(new_comps.as_deref(), newname.to_bytes(), true)
                {
                    return Err(platform::eacces());
                }
                // RENAME_EXCHANGE also moves the destination onto the *source*
                // name, so the reverse direction needs the destination's type:
                // exchanging a file at a dir-only-denied name with a directory at
                // an allowed name would otherwise land the directory at the
                // denied name. Linux RENAME_EXCHANGE = 2; `flags` is translated
                // to macOS renameatx_np flags below.
                if flags & 2 != 0
                    && dest_is_dir
                    && fs.deny_matches_name_in_dir(old_comps.as_deref(), oldname.to_bytes(), true)
                {
                    return Err(platform::eacces());
                }
            }

            // The source path must still refer to the captured inode.
            match platform::fstatat_nofollow(old_fd.raw(), oldname) {
                Ok(st)
                    if platform::stat_ino(&st) == platform::stat_ino(&source_st)
                        && platform::stat_dev(&st) == platform::stat_dev(&source_st) => {}
                _ => continue,
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
