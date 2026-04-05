//! Copy-up engine: promotes lower-layer entries to the upper layer before mutation.
//!
//! All mutation operations (write, setattr, setxattr, unlink, rmdir, rename)
//! must call [`ensure_upper`] on the target inode before modifying it.
//! Copy-up is atomic: data is staged in the staging directory and moved to the
//! upper layer with `renameat`.
//!
//! ## Ancestor copy-up
//!
//! When copying up a deeply nested file, all ancestor directories must be
//! copied up first (root-to-leaf). The ancestor chain is built via
//! `primary_parent`/`primary_name`, and each ancestor is ensured upper
//! before proceeding to the next.

use std::{
    ffi::CStr,
    io,
    os::fd::{AsRawFd, RawFd},
    sync::atomic::Ordering,
};

use super::{
    OverlayFs, inode, origin,
    types::{NodeState, OverlayNode, ROOT_INODE},
};
#[cfg(target_os = "macos")]
use crate::backends::shared::inode_table::InodeAltKey;
use crate::backends::shared::platform;
#[cfg(target_os = "linux")]
use crate::backends::shared::stat_override;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Size of the buffered copy buffer for file data.
const COPY_BUF_SIZE: usize = 128 * 1024;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Ensure an inode is on the upper layer, copying it up from lower if needed.
///
/// No-op if already Upper or Root. Thread-safe: uses `copy_up_lock` to prevent
/// concurrent copy-ups of the same inode.
pub(crate) fn ensure_upper(fs: &OverlayFs, ino: u64) -> io::Result<()> {
    // Fast path: check without locking.
    let node = {
        let nodes = fs.nodes.read().unwrap();
        nodes.get(&ino).cloned().ok_or_else(platform::enoent)?
    };

    {
        let state = node.state.read().unwrap();
        match &*state {
            NodeState::Upper { .. } | NodeState::Root { .. } => return Ok(()),
            NodeState::Lower { .. } => {}
        }
    }

    // Acquire copy-up lock.
    let _lock = node.copy_up_lock.lock().unwrap();

    // Double-check under lock.
    {
        let state = node.state.read().unwrap();
        match &*state {
            NodeState::Upper { .. } | NodeState::Root { .. } => return Ok(()),
            NodeState::Lower { .. } => {}
        }
    }

    // Build ancestor chain and ensure all ancestors are upper.
    let ancestors = build_ancestor_chain(fs, &node)?;
    for &(ancestor_ino, _) in &ancestors {
        if ancestor_ino == ino {
            continue; // Skip self.
        }
        ensure_upper(fs, ancestor_ino)?;
    }

    // Get the parent's upper directory fd.
    let parent_ino = node.primary_parent.load(Ordering::Acquire);
    let upper_parent_fd = open_upper_parent_fd(fs, parent_ino)?;
    let _close_parent = scopeguard::guard(upper_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Get the name for this entry.
    let name_bytes = {
        let name_id = node.primary_name.read().unwrap();
        fs.names.resolve(*name_id)
    };
    let name_cstr = std::ffi::CString::new(name_bytes).map_err(|_| platform::einval())?;

    // Dispatch by file type.
    let kind = node.kind;
    if kind == platform::MODE_DIR {
        copy_up_directory(fs, &node, upper_parent_fd, &name_cstr)?;
    } else if kind == platform::MODE_LNK {
        copy_up_symlink(fs, &node, upper_parent_fd, &name_cstr)?;
    } else if kind == platform::MODE_REG {
        copy_up_regular(fs, &node, upper_parent_fd, &name_cstr)?;
    } else {
        // Special file (device, fifo, socket).
        copy_up_special(fs, &node, upper_parent_fd, &name_cstr)?;
    }

    Ok(())
}

/// Open the upper-layer parent directory fd for an inode that is already Upper/Root.
///
/// Returns an owned fd (caller must close).
pub(crate) fn open_upper_parent_fd(fs: &OverlayFs, parent_ino: u64) -> io::Result<RawFd> {
    let parent_node = {
        let nodes = fs.nodes.read().unwrap();
        nodes
            .get(&parent_ino)
            .cloned()
            .ok_or_else(platform::enoent)?
    };

    let fd = inode::get_upper_dir_fd(fs, &parent_node).ok_or_else(platform::einval)?;
    if fd.is_owned() {
        Ok(fd.into_raw())
    } else {
        inode::dup_fd_raw(fd.raw())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Copy-up by type
//--------------------------------------------------------------------------------------------------

/// Copy up a regular file: stage in staging_dir, copy data + xattrs, atomic rename.
///
/// If another hardlink alias of this lower inode was already copied up, creates
/// an upper hardlink instead of copying data again.
fn copy_up_regular(
    fs: &OverlayFs,
    node: &OverlayNode,
    upper_parent_fd: RawFd,
    name: &CStr,
) -> io::Result<()> {
    // Check if another hardlink to this lower inode has already been copied up.
    if let Some(ref origin_id) = node.origin {
        let existing_upper_ino = {
            let idx = fs.origin_index.read().unwrap();
            idx.get(origin_id).copied()
        };

        if let Some(existing_ino) = existing_upper_ino
            && existing_ino != node.inode
        {
            // Another alias was already copied up — create hardlink.
            if try_link_to_existing(fs, existing_ino, upper_parent_fd, name)? {
                transition_to_upper(fs, node, upper_parent_fd, name)?;
                return Ok(());
            }
        }
    }

    // Open lower fd for reading.
    let lower_fd = inode::open_node_fd(fs, node.inode, libc::O_RDONLY)?;
    let _close_lower = scopeguard::guard(lower_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Create temp file in staging_dir.
    let (temp_fd, temp_name) = create_temp_file(fs)?;
    let _close_temp = scopeguard::guard(temp_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Scopeguard to unlink temp file on error. Defused after successful renameat.
    let staging_fd = fs.staging_fd.as_ref().unwrap().as_raw_fd();
    let mut unlink_guard = scopeguard::guard(Some(temp_name.clone()), |name| {
        if let Some(name) = name {
            unsafe { libc::unlinkat(staging_fd, name.as_ptr(), 0) };
        }
    });

    // Copy file data.
    let st = platform::fstat(lower_fd)?;
    let file_size = st.st_size as u64;
    copy_file_data(lower_fd, temp_fd, file_size)?;

    // Copy xattrs from lower to temp (non-internal only).
    copy_xattrs(lower_fd, temp_fd)?;

    // Preserve source timestamps on the temp file before install.
    apply_timestamps(temp_fd, &st)?;

    // fsync the temp file for crash safety.
    fsync_fd(temp_fd)?;

    // Atomic rename from staging_dir to upper parent.
    let ret = unsafe {
        libc::renameat(
            staging_fd,
            temp_name.as_ptr(),
            upper_parent_fd,
            name.as_ptr(),
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        return Err(platform::linux_error(err));
    }

    // Defuse the unlink guard — renameat succeeded.
    *unlink_guard = None;

    // fsync the destination parent for durability.
    fsync_fd(upper_parent_fd)?;

    // Update node state to Upper.
    transition_to_upper(fs, node, upper_parent_fd, name)?;

    Ok(())
}

/// Copy up a directory: mkdirat on upper, copy xattrs. Does NOT copy children.
fn copy_up_directory(
    fs: &OverlayFs,
    node: &OverlayNode,
    upper_parent_fd: RawFd,
    name: &CStr,
) -> io::Result<()> {
    // Create directory on upper with full permissions (real perms in xattr).
    let ret = unsafe {
        libc::mkdirat(
            upper_parent_fd,
            name.as_ptr(),
            libc::S_IRWXU as libc::mode_t,
        )
    };
    if ret < 0 {
        let err = io::Error::last_os_error();
        // EEXIST is OK — directory may already exist on upper.
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(platform::linux_error(err));
        }
    }

    // Copy xattrs from lower to upper dir.
    let lower_fd = inode::open_node_fd(fs, node.inode, libc::O_RDONLY)?;
    let _close_lower = scopeguard::guard(lower_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Open the newly created upper dir for xattr.
    let upper_dir_fd = unsafe {
        libc::openat(
            upper_parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if upper_dir_fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    let _close_upper_dir = scopeguard::guard(upper_dir_fd, |fd| unsafe {
        libc::close(fd);
    });

    copy_xattrs(lower_fd, upper_dir_fd)?;

    // Preserve lower directory timestamps.
    let lower_st = platform::fstat(lower_fd)?;
    apply_timestamps(upper_dir_fd, &lower_st)?;

    // fsync the destination parent for durability.
    fsync_fd(upper_parent_fd)?;

    // Update node state to Upper.
    transition_to_upper(fs, node, upper_parent_fd, name)?;

    Ok(())
}

/// Copy up a symlink.
///
/// On Linux, creates a file-backed symlink (regular file with target as content,
/// S_IFLNK in xattr).
/// On macOS, creates a real symlink.
fn copy_up_symlink(
    fs: &OverlayFs,
    node: &OverlayNode,
    upper_parent_fd: RawFd,
    name: &CStr,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let o_path_fd = inode::open_node_fd(fs, node.inode, libc::O_PATH | libc::O_NOFOLLOW)?;
        let _close = scopeguard::guard(o_path_fd, |fd| unsafe {
            libc::close(fd);
        });

        let st = platform::fstat(o_path_fd)?;

        if st.st_mode & libc::S_IFMT == libc::S_IFLNK {
            // Real symlink on lower: read target via readlinkat on the O_PATH fd.
            let mut buf = vec![0u8; libc::PATH_MAX as usize];
            let path = format!("/proc/self/fd/{o_path_fd}\0");
            let len = unsafe {
                libc::readlinkat(
                    libc::AT_FDCWD,
                    path.as_ptr() as *const libc::c_char,
                    buf.as_mut_ptr() as *mut libc::c_char,
                    buf.len(),
                )
            };
            if len < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            buf.truncate(len as usize);

            // Create file-backed symlink on upper: write target as content + set override.
            let (temp_fd, temp_name) = create_temp_file(fs)?;
            let _close_temp = scopeguard::guard(temp_fd, |fd| unsafe {
                libc::close(fd);
            });
            let staging_fd_raw = fs.staging_fd.as_ref().unwrap().as_raw_fd();
            let mut unlink_guard = scopeguard::guard(Some(temp_name.clone()), |name| {
                if let Some(name) = name {
                    unsafe { libc::unlinkat(staging_fd_raw, name.as_ptr(), 0) };
                }
            });

            let written =
                unsafe { libc::write(temp_fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
            if written < 0 || (written as usize) != buf.len() {
                return Err(platform::eio());
            }

            // Create stat override (real symlinks don't have overlay xattrs).
            let mode = platform::MODE_LNK | (platform::mode_u32(st.st_mode) & 0o7777);
            stat_override::set_override(temp_fd, st.st_uid, st.st_gid, mode, 0)?;

            stage_and_install(fs, temp_fd, &temp_name, &st, upper_parent_fd, name)?;
            *unlink_guard = None;
        } else {
            // File-backed symlink on lower: reopen for data copy.
            let lower_fd = inode::open_node_fd(fs, node.inode, libc::O_RDONLY)?;
            let _close_lower = scopeguard::guard(lower_fd, |fd| unsafe {
                libc::close(fd);
            });

            let (temp_fd, temp_name) = create_temp_file(fs)?;
            let _close_temp = scopeguard::guard(temp_fd, |fd| unsafe {
                libc::close(fd);
            });
            let staging_fd_raw = fs.staging_fd.as_ref().unwrap().as_raw_fd();
            let mut unlink_guard = scopeguard::guard(Some(temp_name.clone()), |name| {
                if let Some(name) = name {
                    unsafe { libc::unlinkat(staging_fd_raw, name.as_ptr(), 0) };
                }
            });

            copy_file_data(lower_fd, temp_fd, st.st_size as u64)?;
            copy_xattrs(lower_fd, temp_fd)?;

            stage_and_install(fs, temp_fd, &temp_name, &st, upper_parent_fd, name)?;
            *unlink_guard = None;
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Read link target on macOS using /.vol path.
        // Cannot use open_node_fd(O_RDONLY) because O_NOFOLLOW on a symlink returns ELOOP on macOS.
        let state = node.state.read().unwrap();
        let (node_dev, node_ino) = match &*state {
            NodeState::Lower { dev, ino, .. } | NodeState::Upper { dev, ino, .. } => (*dev, *ino),
            _ => return Err(platform::einval()),
        };
        drop(state);

        let vol = inode::vol_path(node_dev, node_ino);

        // Open the lower symlink with O_SYMLINK for xattr copy and fstat.
        let lower_fd = unsafe {
            libc::open(
                vol.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_SYMLINK,
            )
        };
        if lower_fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        let _close_lower = scopeguard::guard(lower_fd, |fd| unsafe {
            libc::close(fd);
        });
        let mut buf = vec![0u8; libc::PATH_MAX as usize];
        let len = unsafe {
            libc::readlink(
                vol.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };
        if len < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        buf.truncate(len as usize);
        buf.push(0); // NUL-terminate
        let target = unsafe { CStr::from_bytes_with_nul_unchecked(&buf) };

        // Stage: create symlink in staging_dir, not directly in upper.
        let staging_fd_raw = fs.staging_fd.as_ref().unwrap().as_raw_fd();
        let temp_name = create_temp_symlink_name(fs);
        let ret = unsafe { libc::symlinkat(target.as_ptr(), staging_fd_raw, temp_name.as_ptr()) };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }

        // Scopeguard to unlink staged symlink on error. Defused after renameat.
        let mut unlink_guard = scopeguard::guard(Some(temp_name.clone()), |name| {
            if let Some(name) = name {
                unsafe { libc::unlinkat(staging_fd_raw, name.as_ptr(), 0) };
            }
        });

        let lower_st = platform::fstat(lower_fd)?;

        // Copy xattrs via O_SYMLINK fd on the staged symlink.
        let sym_fd = unsafe {
            libc::openat(
                staging_fd_raw,
                temp_name.as_ptr(),
                libc::O_RDONLY | libc::O_CLOEXEC | libc::O_SYMLINK,
            )
        };
        if sym_fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        let _close_sym = scopeguard::guard(sym_fd, |fd| unsafe {
            libc::close(fd);
        });

        copy_xattrs(lower_fd, sym_fd)?;
        apply_timestamps(sym_fd, &lower_st)?;

        // Atomically install into upper.
        let ret = unsafe {
            libc::renameat(
                staging_fd_raw,
                temp_name.as_ptr(),
                upper_parent_fd,
                name.as_ptr(),
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }

        // Defuse — renameat succeeded.
        *unlink_guard = None;
    }

    // fsync the destination parent for durability.
    fsync_fd(upper_parent_fd)?;

    // Update node state to Upper.
    transition_to_upper(fs, node, upper_parent_fd, name)?;

    Ok(())
}

/// Copy up a special file (device, fifo, socket).
///
/// Creates a regular file in staging_dir, copies override xattr (which holds the
/// real type/rdev), then atomically renames into the upper layer.
fn copy_up_special(
    fs: &OverlayFs,
    node: &OverlayNode,
    upper_parent_fd: RawFd,
    name: &CStr,
) -> io::Result<()> {
    // Open lower fd for reading xattrs.
    let lower_fd = inode::open_node_fd(fs, node.inode, libc::O_RDONLY)?;
    let _close_lower = scopeguard::guard(lower_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Stage in staging_dir.
    let (temp_fd, temp_name) = create_temp_file(fs)?;
    let _close_temp = scopeguard::guard(temp_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Scopeguard to unlink temp file on error. Defused after renameat succeeds.
    let staging_fd_raw = fs.staging_fd.as_ref().unwrap().as_raw_fd();
    let mut unlink_guard = scopeguard::guard(Some(temp_name.clone()), |name| {
        if let Some(name) = name {
            unsafe { libc::unlinkat(staging_fd_raw, name.as_ptr(), 0) };
        }
    });

    // Fstat lower before creating temp file so failure doesn't leak it.
    let st = platform::fstat(lower_fd)?;

    // Copy xattrs from lower (which includes override with type/rdev info).
    copy_xattrs(lower_fd, temp_fd)?;

    // Preserve source timestamps.
    apply_timestamps(temp_fd, &st)?;

    // fsync temp file.
    fsync_fd(temp_fd)?;

    // Atomic rename from staging_dir to upper parent.
    let ret = unsafe {
        libc::renameat(
            staging_fd_raw,
            temp_name.as_ptr(),
            upper_parent_fd,
            name.as_ptr(),
        )
    };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    // Defuse — renameat succeeded.
    *unlink_guard = None;

    // fsync the destination parent for durability.
    fsync_fd(upper_parent_fd)?;

    // Update node state to Upper.
    transition_to_upper(fs, node, upper_parent_fd, name)?;

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Apply timestamps, fsync, and atomically install a staged temp file into the upper layer.
///
/// Callers must provide a scopeguard for temp file cleanup on error.
#[cfg(target_os = "linux")]
fn stage_and_install(
    fs: &OverlayFs,
    temp_fd: RawFd,
    temp_name: &CStr,
    st: &libc::stat64,
    upper_parent_fd: RawFd,
    name: &CStr,
) -> io::Result<()> {
    apply_timestamps(temp_fd, st)?;
    fsync_fd(temp_fd)?;

    let ret = unsafe {
        libc::renameat(
            fs.staging_fd.as_ref().unwrap().as_raw_fd(),
            temp_name.as_ptr(),
            upper_parent_fd,
            name.as_ptr(),
        )
    };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    Ok(())
}

/// Build the ancestor chain from an inode to root, returned in root-to-leaf order.
///
/// Each element is (ancestor_inode, name_bytes). The chain excludes the root itself.
fn build_ancestor_chain(fs: &OverlayFs, node: &OverlayNode) -> io::Result<Vec<(u64, Vec<u8>)>> {
    let mut chain = Vec::new();
    let mut current_ino = node.primary_parent.load(Ordering::Acquire);

    // Walk up to root.
    while current_ino != ROOT_INODE && current_ino != 0 {
        let cur_node = {
            let nodes = fs.nodes.read().unwrap();
            nodes
                .get(&current_ino)
                .cloned()
                .ok_or_else(platform::enoent)?
        };

        let name_bytes = {
            let name_id = cur_node.primary_name.read().unwrap();
            fs.names.resolve(*name_id)
        };

        chain.push((current_ino, name_bytes));
        current_ino = cur_node.primary_parent.load(Ordering::Acquire);
    }

    // Reverse to get root-to-leaf order.
    chain.reverse();
    Ok(chain)
}

/// Try to create a hardlink from an existing upper inode to a new location.
///
/// Used for hardlink-aware copy-up dedup: if another alias of the same lower
/// inode was already copied up, we link to it instead of copying data.
/// Returns true if the link was created, false if the existing inode was
/// not found or linking failed.
fn try_link_to_existing(
    fs: &OverlayFs,
    existing_ino: u64,
    upper_parent_fd: RawFd,
    name: &CStr,
) -> io::Result<bool> {
    let existing_node = {
        let nodes = fs.nodes.read().unwrap();
        match nodes.get(&existing_ino) {
            Some(node) => node.clone(),
            None => return Ok(false),
        }
    };

    let state = existing_node.state.read().unwrap();

    #[cfg(target_os = "linux")]
    {
        if matches!(&*state, NodeState::Upper { .. }) {
            let fd = inode::open_node_fd(fs, existing_node.inode, libc::O_PATH | libc::O_NOFOLLOW)?;
            let _close = scopeguard::guard(fd, |fd| unsafe {
                libc::close(fd);
            });
            // linkat via /proc/self/fd/<fd> with AT_EMPTY_PATH.
            let ret = unsafe {
                libc::linkat(
                    fd,
                    c"".as_ptr(),
                    upper_parent_fd,
                    name.as_ptr(),
                    libc::AT_EMPTY_PATH,
                )
            };
            if ret == 0 {
                return Ok(true);
            }
            let err = io::Error::last_os_error();
            // EEXIST means another thread raced — fall through to normal copy.
            if err.raw_os_error() == Some(libc::EEXIST) {
                return Ok(false);
            }
            // EPERM: AT_EMPTY_PATH requires CAP_DAC_READ_SEARCH. Try /proc path.
            if err.raw_os_error() == Some(libc::EPERM) {
                let proc_path = format!("/proc/self/fd/{fd}\0");
                let ret = unsafe {
                    libc::linkat(
                        libc::AT_FDCWD,
                        proc_path.as_ptr() as *const libc::c_char,
                        upper_parent_fd,
                        name.as_ptr(),
                        libc::AT_SYMLINK_FOLLOW,
                    )
                };
                if ret == 0 {
                    return Ok(true);
                }
                let err2 = io::Error::last_os_error();
                if err2.raw_os_error() == Some(libc::EEXIST) {
                    return Ok(false);
                }
            }
            return Ok(false);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let NodeState::Upper { ino, dev, .. } = &*state {
            let source_path = inode::vol_path(*dev, *ino);
            let ret = unsafe {
                libc::linkat(
                    libc::AT_FDCWD,
                    source_path.as_ptr(),
                    upper_parent_fd,
                    name.as_ptr(),
                    0,
                )
            };
            if ret == 0 {
                return Ok(true);
            }
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EEXIST) {
                return Ok(false);
            }
            return Ok(false);
        }
    }

    Ok(false)
}

/// Transition an inode's state from Lower to Upper after copy-up.
///
/// Opens the newly created upper entry and updates the node state, alt keys, etc.
pub(crate) fn transition_to_upper(
    fs: &OverlayFs,
    node: &OverlayNode,
    upper_parent_fd: RawFd,
    name: &CStr,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let fd = unsafe {
            libc::openat(
                upper_parent_fd,
                name.as_ptr(),
                libc::O_PATH | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        let _close_fd = scopeguard::guard(fd, |fd| unsafe {
            libc::close(fd);
        });

        // Write origin xattr if this was a lower-layer node.
        if let Some(ref origin_id) = node.origin {
            origin::set_origin_xattr(fd, origin_id)?;
        }

        let alt_key = inode::linux_identity_from_fd(fd)?;

        // Update node state.
        {
            let mut state = node.state.write().unwrap();
            *state = NodeState::Upper {};
        }
        *node.identity.write().unwrap() = Some(alt_key);

        // Register alt key.
        {
            let mut upper_alt = fs.upper_alt_keys.write().unwrap();
            upper_alt.insert(alt_key, node.inode);
        }
    }

    #[cfg(target_os = "macos")]
    {
        // Get stat of the new upper entry.
        let st = platform::fstatat_nofollow(upper_parent_fd, name)?;
        let alt_key = InodeAltKey::new(platform::stat_ino(&st), platform::stat_dev(&st));

        // Write origin xattr if this was a lower-layer node.
        if let Some(ref origin_id) = node.origin {
            // On macOS, open a writable fd to set xattr.
            let upper_path = inode::vol_path(platform::stat_dev(&st), platform::stat_ino(&st));
            let xattr_fd = unsafe {
                libc::open(
                    upper_path.as_ptr(),
                    libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if xattr_fd < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            let result = origin::set_origin_xattr(xattr_fd, origin_id);
            unsafe { libc::close(xattr_fd) };
            result?;
        }

        // Update node state.
        {
            let mut state = node.state.write().unwrap();
            *state = NodeState::Upper {
                ino: platform::stat_ino(&st),
                dev: platform::stat_dev(&st),
                unlinked_fd: std::sync::atomic::AtomicI64::new(-1),
            };
        }

        // Register alt key.
        {
            let mut upper_alt = fs.upper_alt_keys.write().unwrap();
            upper_alt.insert(alt_key, node.inode);
        }
    }

    // Populate origin_index.
    if let Some(ref origin_id) = node.origin {
        let mut idx = fs.origin_index.write().unwrap();
        idx.insert(*origin_id, node.inode);
    }

    Ok(())
}

/// Copy file data from src_fd to dst_fd.
///
/// Attempts in order: FICLONE (Linux) → copy_file_range (Linux) → buffered.
fn copy_file_data(src_fd: RawFd, dst_fd: RawFd, size: u64) -> io::Result<()> {
    if size == 0 {
        return Ok(());
    }

    // Try FICLONE for instant CoW clone (btrfs, xfs with reflink, bcachefs).
    if try_clone_file(src_fd, dst_fd) {
        return Ok(());
    }

    // Try copy_file_range on Linux.
    #[cfg(target_os = "linux")]
    {
        let mut off_in: i64 = 0;
        let mut off_out: i64 = 0;
        let mut remaining = size;

        while remaining > 0 {
            let to_copy = std::cmp::min(remaining, COPY_BUF_SIZE as u64) as usize;
            let ret = unsafe {
                libc::copy_file_range(src_fd, &mut off_in, dst_fd, &mut off_out, to_copy, 0)
            };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() == Some(libc::EXDEV)
                    || err.raw_os_error() == Some(libc::ENOSYS)
                {
                    // Fall back to buffered copy. This should only happen on the
                    // first call (before any data is copied). If partial progress
                    // was made, we cannot safely resume with a buffered fallback
                    // because the dst already has partial data.
                    if remaining != size {
                        return Err(platform::linux_error(err));
                    }
                    return copy_file_data_buffered(src_fd, dst_fd);
                }
                return Err(platform::linux_error(err));
            }
            if ret == 0 {
                break; // EOF
            }
            remaining -= ret as u64;
        }
        if remaining > 0 {
            return Err(platform::eio());
        }
        Ok(())
    }

    // macOS: buffered copy.
    #[cfg(target_os = "macos")]
    {
        copy_file_data_buffered(src_fd, dst_fd)
    }
}

/// Buffered read/write copy fallback.
fn copy_file_data_buffered(src_fd: RawFd, dst_fd: RawFd) -> io::Result<()> {
    // Seek both fds to the beginning.
    if unsafe { libc::lseek(src_fd, 0, libc::SEEK_SET) } < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    if unsafe { libc::lseek(dst_fd, 0, libc::SEEK_SET) } < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    let mut buf = vec![0u8; COPY_BUF_SIZE];
    loop {
        let n = unsafe { libc::read(src_fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
        if n == 0 {
            break;
        }
        let mut written = 0;
        while written < n as usize {
            let w = unsafe {
                libc::write(
                    dst_fd,
                    buf[written..].as_ptr() as *const libc::c_void,
                    n as usize - written,
                )
            };
            if w < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
            written += w as usize;
        }
    }
    Ok(())
}

/// Attempt to clone file data via CoW reflink.
///
/// On Linux, uses the FICLONE ioctl for instant block-level clone on
/// btrfs/xfs/bcachefs. Returns true if the clone succeeded.
fn try_clone_file(src_fd: RawFd, dst_fd: RawFd) -> bool {
    #[cfg(target_os = "linux")]
    {
        // FICLONE = _IOW(0x94, 9, int) = 0x40049409
        const FICLONE: libc::c_ulong = 0x40049409;
        let ret = unsafe { libc::ioctl(dst_fd, FICLONE, src_fd) };
        ret == 0
    }

    #[cfg(target_os = "macos")]
    {
        // APFS clonefile requires paths, not fd-to-fd. Skip for now.
        let _ = (src_fd, dst_fd);
        false
    }
}

/// Apply source timestamps (atime/mtime) to a destination file descriptor.
///
/// Preserves the original file's timestamps during copy-up so the guest sees
/// consistent metadata after promotion to upper.
fn apply_timestamps(dst_fd: RawFd, src_stat: &crate::stat64) -> io::Result<()> {
    let times = [
        libc::timespec {
            tv_sec: src_stat.st_atime,
            tv_nsec: src_stat.st_atime_nsec,
        },
        libc::timespec {
            tv_sec: src_stat.st_mtime,
            tv_nsec: src_stat.st_mtime_nsec,
        },
    ];
    let ret = unsafe { libc::futimens(dst_fd, times.as_ptr()) };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(())
}

/// Checked fsync — propagates errors instead of ignoring them.
pub(crate) fn fsync_fd(fd: RawFd) -> io::Result<()> {
    let ret = unsafe { libc::fsync(fd) };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(())
}

/// Copy non-internal extended attributes from src_fd to dst_fd.
pub(crate) fn copy_xattrs(src_fd: RawFd, dst_fd: RawFd) -> io::Result<()> {
    // List xattrs on source (with ERANGE retry for TOCTOU).
    let raw_list = list_xattrs(src_fd)?;
    let raw_list = match raw_list {
        Some(list) => list,
        None => return Ok(()),
    };

    // Iterate NUL-separated names and copy each non-internal one.
    for entry in raw_list.split(|&b| b == 0) {
        if entry.is_empty() {
            continue;
        }

        // Build CStr with NUL.
        let mut with_nul = entry.to_vec();
        with_nul.push(0);
        let key = unsafe { CStr::from_bytes_with_nul_unchecked(&with_nul) };

        // Skip internal overlay xattrs (but keep override_stat — it's needed).
        if is_internal_overlay_xattr(key) {
            continue;
        }

        // Read value from source.
        let value = read_xattr_value(src_fd, key)?;
        if let Some(val) = value {
            set_xattr_value(dst_fd, key, &val)?;
        }
    }

    Ok(())
}

/// Check if an xattr key is an internal overlay key (excluding override_stat).
///
/// We DO copy override_stat because it contains the virtualized permissions.
/// We skip origin, redirect, and tombstones.
fn is_internal_overlay_xattr(name: &CStr) -> bool {
    name == c"user.containers.overlay_origin"
        || name == c"user.containers.overlay_redirect"
        || name == c"user.containers.overlay_tombstones"
}

/// List xattr names on a file descriptor with ERANGE retry.
///
/// Returns `None` if xattrs are not supported or the list is empty.
fn list_xattrs(fd: RawFd) -> io::Result<Option<Vec<u8>>> {
    #[cfg(target_os = "linux")]
    let path = format!("/proc/self/fd/{fd}\0");

    for _ in 0..3 {
        #[cfg(target_os = "linux")]
        let size = unsafe {
            libc::listxattr(
                path.as_ptr() as *const libc::c_char,
                std::ptr::null_mut(),
                0,
            )
        };

        #[cfg(target_os = "macos")]
        let size = unsafe { libc::flistxattr(fd, std::ptr::null_mut(), 0, 0) };

        if size < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::EOPNOTSUPP) {
                return Ok(None);
            }
            return Err(platform::linux_error(err));
        }
        if size == 0 {
            return Ok(None);
        }

        let mut buf = vec![0u8; size as usize];

        #[cfg(target_os = "linux")]
        let ret = unsafe {
            libc::listxattr(
                path.as_ptr() as *const libc::c_char,
                buf.as_mut_ptr() as *mut libc::c_char,
                buf.len(),
            )
        };

        #[cfg(target_os = "macos")]
        let ret =
            unsafe { libc::flistxattr(fd, buf.as_mut_ptr() as *mut libc::c_char, buf.len(), 0) };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            return Err(platform::linux_error(err));
        }

        buf.truncate(ret as usize);
        return Ok(Some(buf));
    }

    // Exhausted retries.
    Err(platform::eio())
}

/// Read an xattr value from a file descriptor.
///
/// Uses a bounded ERANGE retry loop (3 attempts) to handle the TOCTOU race
/// where the xattr value grows between the size query and the data read.
fn read_xattr_value(fd: RawFd, name: &CStr) -> io::Result<Option<Vec<u8>>> {
    #[cfg(target_os = "linux")]
    let path = format!("/proc/self/fd/{fd}\0");

    for _ in 0..3 {
        // Size query.
        #[cfg(target_os = "linux")]
        let ret = unsafe {
            libc::getxattr(
                path.as_ptr() as *const libc::c_char,
                name.as_ptr(),
                std::ptr::null_mut(),
                0,
            )
        };

        #[cfg(target_os = "macos")]
        let ret = unsafe { libc::fgetxattr(fd, name.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };

        if ret < 0 {
            let err = io::Error::last_os_error();
            #[cfg(target_os = "linux")]
            if err.raw_os_error() == Some(libc::ENODATA) {
                return Ok(None);
            }
            #[cfg(target_os = "macos")]
            if err.raw_os_error() == Some(libc::ENOATTR) {
                return Ok(None);
            }
            return Err(platform::linux_error(err));
        }

        let size = ret as usize;
        let mut buf = vec![0u8; size];

        // Data read.
        #[cfg(target_os = "linux")]
        let ret = unsafe {
            libc::getxattr(
                path.as_ptr() as *const libc::c_char,
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
            )
        };

        #[cfg(target_os = "macos")]
        let ret = unsafe {
            libc::fgetxattr(
                fd,
                name.as_ptr(),
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len(),
                0,
                0,
            )
        };

        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(libc::ERANGE) {
                continue;
            }
            return Err(platform::linux_error(err));
        }
        buf.truncate(ret as usize);
        return Ok(Some(buf));
    }

    // Exhausted retries.
    Err(platform::eio())
}

/// Set an xattr value on a file descriptor.
fn set_xattr_value(fd: RawFd, name: &CStr, value: &[u8]) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/self/fd/{fd}\0");
        let ret = unsafe {
            libc::setxattr(
                path.as_ptr() as *const libc::c_char,
                name.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    #[cfg(target_os = "macos")]
    {
        let ret = unsafe {
            libc::fsetxattr(
                fd,
                name.as_ptr(),
                value.as_ptr() as *const libc::c_void,
                value.len(),
                0,
                0,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    Ok(())
}

/// Create a temporary file in the staging directory.
///
/// Returns (fd, name_cstring). The name is relative to `staging_fd`.
fn create_temp_file(fs: &OverlayFs) -> io::Result<(RawFd, std::ffi::CString)> {
    // Generate a unique name.
    let id = fs
        .next_handle
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!(".tmp.copyup.{id}");
    let name_cstr = std::ffi::CString::new(name).map_err(|_| platform::einval())?;

    let fd = unsafe {
        libc::openat(
            fs.staging_fd.as_ref().unwrap().as_raw_fd(),
            name_cstr.as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_RDWR | libc::O_CLOEXEC,
            (libc::S_IRUSR | libc::S_IWUSR) as libc::c_uint,
        )
    };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    Ok((fd, name_cstr))
}

/// Generate a unique temporary name for staging a symlink in the staging directory.
///
/// Returns a CString suitable for use with `symlinkat`/`renameat` relative to `staging_fd`.
#[cfg(target_os = "macos")]
fn create_temp_symlink_name(fs: &OverlayFs) -> std::ffi::CString {
    let id = fs
        .next_handle
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let name = format!(".tmp.symlink.{id}");
    // SAFETY: the generated name contains no NUL bytes.
    std::ffi::CString::new(name).unwrap()
}
