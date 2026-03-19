//! Removal operations: unlink, rmdir, rename, rename-exchange.
//!
//! All operations validate names, ensure parents are on the upper layer, and
//! create whiteouts when the deleted name exists on lower layers.
//!
//! Directory rename supports three cases: pure-upper directories use simple
//! renameat, lower-only directories create an upper directory with a redirect
//! xattr, and merged directories move the upper fragment and attach a redirect.
//!
//! RENAME_EXCHANGE atomically swaps two entries. For directories with lower-
//! layer presence, redirect xattrs are written before the swap to preserve
//! lower-child visibility at the new positions.

use std::{ffi::CStr, io, sync::atomic::Ordering};

use super::{
    OverlayFs, copy_up, dir_ops, inode, layer, origin,
    types::{NodeState, ROOT_INODE, RedirectState},
    whiteout,
};
use crate::{
    Context,
    backends::shared::{init_binary, name_validation, platform},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Linux `RENAME_NOREPLACE` flag: fail if destination exists.
const RENAME_NOREPLACE: u32 = 1;

/// Linux `RENAME_EXCHANGE` flag: atomically swap source and destination.
const RENAME_EXCHANGE: u32 = 2;

/// Mask of all supported rename flags.
const KNOWN_RENAME_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Remove a file.
///
/// Resolves the target using overlay-visible semantics to verify it exists
/// and is not a directory. Ensures the parent is on upper, unlinks the upper
/// entry if present, and creates a whiteout if the name exists on lower layers.
pub(crate) fn do_unlink(fs: &OverlayFs, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
    if fs.cfg.read_only {
        return Err(platform::erofs());
    }
    name_validation::validate_overlay_name(name)?;

    if init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    // Resolve the target entry to check type before acting.
    let target = inode::do_lookup(fs, parent, name)?;
    // Balance the internal lookup refcount — the FUSE kernel doesn't know about it.
    inode::forget_one(fs, target.inode, 1);
    let target_type = platform::mode_file_type(target.attr.st_mode);
    if target_type == platform::MODE_DIR {
        return Err(platform::eisdir());
    }

    copy_up::ensure_upper(fs, parent)?;

    let upper_parent_fd = copy_up::open_upper_parent_fd(fs, parent)?;
    let _close_parent = scopeguard::guard(upper_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Check if name exists on lower layers (before unlinking upper).
    let needs_whiteout = whiteout::has_lower_entry(fs, parent, name.to_bytes())?;

    // Try to unlink from upper.
    let ret = unsafe { libc::unlinkat(upper_parent_fd, name.as_ptr(), 0) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        // If the entry doesn't exist on upper but does on lower,
        // we still need to create a whiteout.
        if err.raw_os_error() != Some(libc::ENOENT) || !needs_whiteout {
            return Err(platform::linux_error(err));
        }
    }

    // Create whiteout if needed.
    if needs_whiteout {
        whiteout::create_whiteout(upper_parent_fd, name.to_bytes())?;
    }

    // Remove dentry from cache.
    let name_id = fs.names.intern(name.to_bytes());
    fs.dentries.write().unwrap().remove(&(parent, name_id));

    Ok(())
}

/// Remove a directory.
///
/// Resolves the target using overlay-visible semantics to verify it exists,
/// is a directory, and is empty across all layers. Ensures the parent is on
/// upper, removes the upper entry and creates a whiteout if needed.
pub(crate) fn do_rmdir(fs: &OverlayFs, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
    if fs.cfg.read_only {
        return Err(platform::erofs());
    }
    name_validation::validate_overlay_name(name)?;

    if init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eacces());
    }

    // Resolve the target entry to check type and emptiness.
    let target = inode::do_lookup(fs, parent, name)?;
    // Balance the internal lookup refcount — the FUSE kernel doesn't know about it.
    inode::forget_one(fs, target.inode, 1);
    let target_type = platform::mode_file_type(target.attr.st_mode);
    if target_type != platform::MODE_DIR {
        return Err(platform::enotdir());
    }

    // Check merged emptiness across all layers.
    if !dir_ops::is_merged_dir_empty(fs, target.inode)? {
        return Err(platform::enotempty());
    }

    copy_up::ensure_upper(fs, parent)?;

    let upper_parent_fd = copy_up::open_upper_parent_fd(fs, parent)?;
    let _close_parent = scopeguard::guard(upper_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    let needs_whiteout = whiteout::has_lower_entry(fs, parent, name.to_bytes())?;

    // Try to remove directory from upper (may contain whiteouts/opaque markers).
    // Remove internal overlay artifacts first so the host rmdir succeeds.
    remove_upper_dir_artifacts(upper_parent_fd, name)?;

    let ret = unsafe { libc::unlinkat(upper_parent_fd, name.as_ptr(), libc::AT_REMOVEDIR) };
    if ret < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::ENOENT) || !needs_whiteout {
            return Err(platform::linux_error(err));
        }
    }

    if needs_whiteout {
        whiteout::create_whiteout(upper_parent_fd, name.to_bytes())?;
    }

    let name_id = fs.names.intern(name.to_bytes());
    fs.dentries.write().unwrap().remove(&(parent, name_id));

    Ok(())
}

/// Rename a file or directory.
///
/// For files: copy-up source if lower, ensure both parents upper, renameat on
/// upper, create whiteout at old location if lower exists.
///
/// For directories: pure-upper uses simple renameat; lower-only or merged
/// directories use redirect-based rename to avoid recursively copying the
/// lower subtree.
pub(crate) fn do_rename(
    fs: &OverlayFs,
    _ctx: Context,
    olddir: u64,
    oldname: &CStr,
    newdir: u64,
    newname: &CStr,
    flags: u32,
) -> io::Result<()> {
    if fs.cfg.read_only {
        return Err(platform::erofs());
    }
    name_validation::validate_overlay_name(oldname)?;
    name_validation::validate_overlay_name(newname)?;

    // Reject any rename involving init.krun before dispatching into
    // exchange or regular paths.
    if init_binary::is_init_name(oldname.to_bytes())
        || init_binary::is_init_name(newname.to_bytes())
    {
        return Err(platform::eacces());
    }

    // Validate flags: only RENAME_NOREPLACE and RENAME_EXCHANGE are
    // supported, and they are mutually exclusive per Linux semantics.
    if flags & !KNOWN_RENAME_FLAGS != 0 {
        return Err(platform::einval());
    }
    if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
        return Err(platform::einval());
    }

    // RENAME_EXCHANGE: atomic swap of two entries.
    if flags & RENAME_EXCHANGE != 0 {
        return do_rename_exchange(fs, olddir, oldname, newdir, newname);
    }

    // Look up the source entry to determine its type and state.
    let source_entry = inode::do_lookup(fs, olddir, oldname)?;
    // Balance internal lookup refcount.
    inode::forget_one(fs, source_entry.inode, 1);
    let source_type = platform::mode_file_type(source_entry.attr.st_mode);
    let source_is_dir = source_type == platform::MODE_DIR;
    let oldname_id = fs.names.intern(oldname.to_bytes());
    let source_node = {
        let nodes = fs.nodes.read().unwrap();
        nodes.get(&source_entry.inode).cloned()
    };

    // Resolve destination to enforce type/emptiness constraints.
    let dest_entry = inode::do_lookup(fs, newdir, newname);
    // Balance internal lookup refcount for destination (if it exists).
    if let Ok(ref de) = dest_entry {
        inode::forget_one(fs, de.inode, 1);
    }

    // RENAME_NOREPLACE: fail if the destination already exists in the
    // merged overlay view. The host renameat2 only sees the upper layer,
    // so a lower-visible destination would be silently overwritten.
    if flags & RENAME_NOREPLACE != 0 && dest_entry.is_ok() {
        return Err(platform::eexist());
    }

    if let Ok(ref de) = dest_entry {
        let dest_type = platform::mode_file_type(de.attr.st_mode);
        let dest_is_dir = dest_type == platform::MODE_DIR;

        if !source_is_dir && dest_is_dir {
            return Err(platform::eisdir());
        }
        if source_is_dir && !dest_is_dir {
            return Err(platform::enotdir());
        }
        if source_is_dir && dest_is_dir && !dir_ops::is_merged_dir_empty(fs, de.inode)? {
            return Err(platform::enotempty());
        }
    }

    // Guard: reject rename-into-own-subtree for directories.
    // The host renameat catches this for pure-upper dirs, but redirect-based
    // renames (lower/merged) never ask the host to move the subtree, so the
    // cycle would go undetected.
    if source_is_dir && is_ancestor(fs, source_entry.inode, newdir) {
        return Err(platform::einval());
    }

    // Handle directory rename with redirect support.
    if let Some(ref node) = source_node
        && source_is_dir
    {
        let is_lower = {
            let state = node.state.read().unwrap();
            matches!(&*state, NodeState::Lower { .. })
        };

        if is_lower {
            return rename_lower_directory(
                fs,
                node,
                olddir,
                oldname,
                oldname_id,
                newdir,
                newname,
                &dest_entry,
            );
        }

        // Check if this is a merged directory (has lower presence or redirect).
        // An opaque pure-upper dir is masking someone else's lower subtree,
        // not merged with it — it must stay on the pure-upper rename path.
        let has_redirect = node.redirect.read().unwrap().is_some();
        let is_opaque = node.opaque.load(Ordering::Acquire);
        let has_lower = !is_opaque && whiteout::has_lower_entry(fs, olddir, oldname.to_bytes())?;
        if has_redirect || has_lower {
            return rename_merged_directory(
                fs,
                node,
                olddir,
                oldname,
                oldname_id,
                newdir,
                newname,
                flags,
                &dest_entry,
            );
        }

        // Pure-upper directory: fall through to simple renameat below.
    }

    // Copy-up source if needed (files and pure-upper dirs).
    if let Some(ref node) = source_node {
        copy_up::ensure_upper(fs, node.inode)?;
    }

    // Ensure both parents are on upper.
    copy_up::ensure_upper(fs, olddir)?;
    copy_up::ensure_upper(fs, newdir)?;

    let old_parent_fd = copy_up::open_upper_parent_fd(fs, olddir)?;
    let _close_old = scopeguard::guard(old_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    let new_parent_fd = copy_up::open_upper_parent_fd(fs, newdir)?;
    let _close_new = scopeguard::guard(new_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Remove whiteout at destination.
    whiteout::remove_whiteout(new_parent_fd, newname.to_bytes())?;

    // If destination is a guest-empty directory, remove its upper artifacts
    // so the host renameat can replace it.
    clear_dest_dir_if_needed(new_parent_fd, newname, &dest_entry)?;

    // Check if source exists on lower (need whiteout at old location).
    let needs_whiteout = whiteout::has_lower_entry(fs, olddir, oldname.to_bytes())?;

    // Perform the rename on upper.
    do_renameat(old_parent_fd, oldname, new_parent_fd, newname, flags)?;

    // Create whiteout at old location if needed.
    if needs_whiteout {
        whiteout::create_whiteout(old_parent_fd, oldname.to_bytes())?;
    }

    // For pure-upper directory rename: if destination had lower presence,
    // mark the directory opaque to suppress those lower entries.
    if let Some(ref node) = source_node
        && source_is_dir
    {
        let dest_has_lower = whiteout::has_lower_entry(fs, newdir, newname.to_bytes())?;
        if dest_has_lower {
            let dir_fd = open_dir_by_name(new_parent_fd, newname)?;
            let _close = scopeguard::guard(dir_fd, |fd| unsafe {
                libc::close(fd);
            });
            create_opaque_marker(dir_fd)?;
            node.opaque.store(true, Ordering::Release);
        }
    }

    // Update dentry cache.
    update_dentry_cache(
        fs,
        olddir,
        oldname_id,
        newdir,
        newname,
        source_node.as_deref(),
    );

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: RENAME_EXCHANGE
//--------------------------------------------------------------------------------------------------

/// Atomic swap of two directory entries (RENAME_EXCHANGE).
///
/// Both source and destination must exist in the overlay. Both entries (and
/// their parents) are copied up, then the host `renameat2(RENAME_EXCHANGE)`
/// performs the atomic swap on the upper layer.
///
/// For directories with lower-layer presence (lower-only, merged, or
/// redirected), redirect xattrs are written before the exchange so that each
/// directory retains access to its lower children at the new position. Pure-
/// upper directories that move to a position with lower-layer entries are
/// marked opaque to suppress those entries.
fn do_rename_exchange(
    fs: &OverlayFs,
    olddir: u64,
    oldname: &CStr,
    newdir: u64,
    newname: &CStr,
) -> io::Result<()> {
    // Both entries must exist.
    let source_entry = inode::do_lookup(fs, olddir, oldname)?;
    let dest_entry = inode::do_lookup(fs, newdir, newname)?;
    // Balance internal lookup refcounts.
    inode::forget_one(fs, source_entry.inode, 1);
    inode::forget_one(fs, dest_entry.inode, 1);

    let src_is_dir = platform::mode_file_type(source_entry.attr.st_mode) == platform::MODE_DIR;
    let dst_is_dir = platform::mode_file_type(dest_entry.attr.st_mode) == platform::MODE_DIR;

    // For directory entries, determine if they need redirect metadata after
    // exchange. A directory needs a redirect if it has any lower-layer presence
    // so that its lower children remain accessible after the position change.
    // Compute BEFORE copy-up while the directories are still at their original
    // positions.
    let src_redirect = if src_is_dir {
        compute_exchange_redirect(fs, source_entry.inode, olddir, oldname.to_bytes())?
    } else {
        None
    };
    let dst_redirect = if dst_is_dir {
        compute_exchange_redirect(fs, dest_entry.inode, newdir, newname.to_bytes())?
    } else {
        None
    };

    // Check lower presence at each position for opaque decisions.
    // If a pure-upper directory (no redirect) moves to a position with lower
    // entries, it needs opaque marking to suppress those entries.
    let old_has_lower = whiteout::has_lower_entry(fs, olddir, oldname.to_bytes())?;
    let new_has_lower = whiteout::has_lower_entry(fs, newdir, newname.to_bytes())?;

    // Copy up both entries and parents.
    copy_up::ensure_upper(fs, source_entry.inode)?;
    copy_up::ensure_upper(fs, dest_entry.inode)?;
    copy_up::ensure_upper(fs, olddir)?;
    copy_up::ensure_upper(fs, newdir)?;

    let old_parent_fd = copy_up::open_upper_parent_fd(fs, olddir)?;
    let _close_old = scopeguard::guard(old_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    let new_parent_fd = copy_up::open_upper_parent_fd(fs, newdir)?;
    let _close_new = scopeguard::guard(new_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Write redirect xattrs BEFORE the exchange so the metadata is in place
    // when the directories land at their new positions.
    if let Some(ref redirect_path) = src_redirect {
        let dir_fd = open_dir_by_name(old_parent_fd, oldname)?;
        let _close = scopeguard::guard(dir_fd, |fd| unsafe {
            libc::close(fd);
        });
        origin::set_redirect_xattr(dir_fd, redirect_path)?;
    }
    if let Some(ref redirect_path) = dst_redirect {
        let dir_fd = open_dir_by_name(new_parent_fd, newname)?;
        let _close = scopeguard::guard(dir_fd, |fd| unsafe {
            libc::close(fd);
        });
        origin::set_redirect_xattr(dir_fd, redirect_path)?;
    }

    // Perform the atomic exchange on upper.
    do_renameat(
        old_parent_fd,
        oldname,
        new_parent_fd,
        newname,
        RENAME_EXCHANGE,
    )?;

    // Post-exchange opaque marking:
    // Source (now at newname): if the destination position had lower entries
    // and source has no redirect, mark opaque to suppress those entries.
    if src_is_dir && new_has_lower && src_redirect.is_none() {
        let dir_fd = open_dir_by_name(new_parent_fd, newname)?;
        let _close = scopeguard::guard(dir_fd, |fd| unsafe {
            libc::close(fd);
        });
        create_opaque_marker(dir_fd)?;
    }
    // Dest (now at oldname): same logic in reverse.
    if dst_is_dir && old_has_lower && dst_redirect.is_none() {
        let dir_fd = open_dir_by_name(old_parent_fd, oldname)?;
        let _close = scopeguard::guard(dir_fd, |fd| unsafe {
            libc::close(fd);
        });
        create_opaque_marker(dir_fd)?;
    }

    // Intern names before taking locks.
    let oldname_id = fs.names.intern(oldname.to_bytes());
    let newname_id = fs.names.intern(newname.to_bytes());

    // Update in-memory state: opaque flags, redirects, primary_parent/name (single lock).
    {
        let nodes = fs.nodes.read().unwrap();
        if let Some(src_node) = nodes.get(&source_entry.inode) {
            if src_is_dir && new_has_lower && src_redirect.is_none() {
                src_node.opaque.store(true, Ordering::Release);
            }
            if let Some(redirect_path) = src_redirect {
                *src_node.redirect.write().unwrap() = Some(RedirectState {
                    lower_path: redirect_path,
                });
            }
            src_node.primary_parent.store(newdir, Ordering::Release);
            *src_node.primary_name.write().unwrap() = newname_id;
        }
        if let Some(dst_node) = nodes.get(&dest_entry.inode) {
            if dst_is_dir && old_has_lower && dst_redirect.is_none() {
                dst_node.opaque.store(true, Ordering::Release);
            }
            if let Some(redirect_path) = dst_redirect {
                *dst_node.redirect.write().unwrap() = Some(RedirectState {
                    lower_path: redirect_path,
                });
            }
            dst_node.primary_parent.store(olddir, Ordering::Release);
            *dst_node.primary_name.write().unwrap() = oldname_id;
        }
    }

    // Swap dentry cache entries.
    {
        let mut dentries = fs.dentries.write().unwrap();
        let old_key = (olddir, oldname_id);
        let new_key = (newdir, newname_id);
        let old_val = dentries.remove(&old_key);
        let new_val = dentries.remove(&new_key);
        if let Some(v) = old_val {
            dentries.insert(new_key, v);
        }
        if let Some(v) = new_val {
            dentries.insert(old_key, v);
        }
    }

    Ok(())
}

/// Compute the redirect path needed for a directory being exchanged.
///
/// Returns `Some(path)` if the directory has lower-layer presence and needs
/// a redirect to maintain access to its lower children after the exchange.
/// Returns `None` for pure-upper directories with no lower presence.
fn compute_exchange_redirect(
    fs: &OverlayFs,
    ino: u64,
    parent_ino: u64,
    name: &[u8],
) -> io::Result<Option<Vec<Vec<u8>>>> {
    let node = {
        let nodes = fs.nodes.read().unwrap();
        nodes.get(&ino).cloned().ok_or_else(platform::enoent)?
    };

    // Already has a redirect — preserve it.
    let redirect = node.redirect.read().unwrap();
    if let Some(ref redir) = *redirect {
        return Ok(Some(redir.lower_path.clone()));
    }
    drop(redirect);

    // Lower-only directory — compute redirect from current position.
    let is_lower = {
        let state = node.state.read().unwrap();
        matches!(&*state, NodeState::Lower { .. })
    };

    if is_lower {
        return Ok(Some(compute_redirect_path(fs, &node, parent_ino, name)?));
    }

    // Upper directory — check if it has lower presence (merged).
    // An opaque pure-upper dir is masking someone else's lower subtree at this
    // position, not merged with it. It should not get a redirect.
    if !node.opaque.load(Ordering::Acquire) && whiteout::has_lower_entry(fs, parent_ino, name)? {
        return Ok(Some(compute_redirect_path(fs, &node, parent_ino, name)?));
    }

    Ok(None)
}

//--------------------------------------------------------------------------------------------------
// Functions: Directory Rename
//--------------------------------------------------------------------------------------------------

/// Rename a lower-only directory using redirect.
///
/// Creates a new directory on the upper layer at the destination, attaches a
/// redirect xattr pointing to the source's lower path, and creates a whiteout
/// at the old location.
#[allow(clippy::too_many_arguments)]
fn rename_lower_directory(
    fs: &OverlayFs,
    node: &std::sync::Arc<super::types::OverlayNode>,
    olddir: u64,
    oldname: &CStr,
    oldname_id: super::types::NameId,
    newdir: u64,
    newname: &CStr,
    dest_entry: &Result<crate::Entry, io::Error>,
) -> io::Result<()> {
    // Compute the redirect path: source's current lower path.
    let redirect_path = compute_redirect_path(fs, node, olddir, oldname.to_bytes())?;

    // Ensure new parent is on upper.
    copy_up::ensure_upper(fs, olddir)?;
    copy_up::ensure_upper(fs, newdir)?;

    let old_parent_fd = copy_up::open_upper_parent_fd(fs, olddir)?;
    let _close_old = scopeguard::guard(old_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    let new_parent_fd = copy_up::open_upper_parent_fd(fs, newdir)?;
    let _close_new = scopeguard::guard(new_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Remove whiteout at destination.
    whiteout::remove_whiteout(new_parent_fd, newname.to_bytes())?;

    // If destination is a guest-empty directory, remove its upper artifacts.
    clear_dest_dir_if_needed(new_parent_fd, newname, dest_entry)?;

    // Create directory on upper at the new location.
    let ret = unsafe {
        libc::mkdirat(
            new_parent_fd,
            newname.as_ptr(),
            libc::S_IRWXU as libc::mode_t,
        )
    };
    if ret < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }

    // Copy all xattrs from lower source to the new upper directory
    // (same contract as copy_up_directory: stat override + user xattrs).
    let lower_fd = inode::open_node_fd(fs, node.inode, libc::O_RDONLY)?;
    let _close_lower = scopeguard::guard(lower_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Open the newly created upper directory to write xattrs and redirect.
    let dir_fd = open_dir_by_name(new_parent_fd, newname)?;
    let _close_dir = scopeguard::guard(dir_fd, |fd| unsafe {
        libc::close(fd);
    });

    copy_up::copy_xattrs(lower_fd, dir_fd)?;

    // Write redirect xattr.
    origin::set_redirect_xattr(dir_fd, &redirect_path)?;

    // Attach redirect state to the node.
    *node.redirect.write().unwrap() = Some(RedirectState {
        lower_path: redirect_path,
    });

    // Transition node state to Upper.
    copy_up::transition_to_upper(fs, node, new_parent_fd, newname)?;

    // Create whiteout at old location.
    whiteout::create_whiteout(old_parent_fd, oldname.to_bytes())?;

    // Update dentry cache.
    update_dentry_cache(fs, olddir, oldname_id, newdir, newname, Some(&**node));

    Ok(())
}

/// Rename a merged directory (upper fragment + lower children, or redirected).
///
/// Moves the upper fragment via renameat and updates the redirect xattr to
/// point to the original lower path.
#[allow(clippy::too_many_arguments)]
fn rename_merged_directory(
    fs: &OverlayFs,
    node: &std::sync::Arc<super::types::OverlayNode>,
    olddir: u64,
    oldname: &CStr,
    oldname_id: super::types::NameId,
    newdir: u64,
    newname: &CStr,
    flags: u32,
    dest_entry: &Result<crate::Entry, io::Error>,
) -> io::Result<()> {
    // Compute redirect path (preserve existing redirect, or build from lower path).
    let redirect_path = compute_redirect_path(fs, node, olddir, oldname.to_bytes())?;

    // Ensure both parents are on upper.
    copy_up::ensure_upper(fs, olddir)?;
    copy_up::ensure_upper(fs, newdir)?;

    let old_parent_fd = copy_up::open_upper_parent_fd(fs, olddir)?;
    let _close_old = scopeguard::guard(old_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    let new_parent_fd = copy_up::open_upper_parent_fd(fs, newdir)?;
    let _close_new = scopeguard::guard(new_parent_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Remove whiteout at destination.
    whiteout::remove_whiteout(new_parent_fd, newname.to_bytes())?;

    // If destination is a guest-empty directory, remove its upper artifacts.
    clear_dest_dir_if_needed(new_parent_fd, newname, dest_entry)?;

    // Check if source exists on lower (need whiteout at old location).
    let needs_whiteout = whiteout::has_lower_entry(fs, olddir, oldname.to_bytes())?;

    // Move the upper fragment.
    do_renameat(old_parent_fd, oldname, new_parent_fd, newname, flags)?;

    // Open the renamed directory to update redirect xattr.
    let dir_fd = open_dir_by_name(new_parent_fd, newname)?;
    let _close_dir = scopeguard::guard(dir_fd, |fd| unsafe {
        libc::close(fd);
    });

    // Write/update redirect xattr.
    origin::set_redirect_xattr(dir_fd, &redirect_path)?;

    // Attach redirect state to the node.
    *node.redirect.write().unwrap() = Some(RedirectState {
        lower_path: redirect_path,
    });

    // Create whiteout at old location if needed.
    if needs_whiteout {
        whiteout::create_whiteout(old_parent_fd, oldname.to_bytes())?;
    }

    // Update dentry cache.
    update_dentry_cache(fs, olddir, oldname_id, newdir, newname, Some(&**node));

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Compute the redirect lower path for a directory being renamed.
///
/// If the node already has a redirect, preserves it (no chaining).
/// Otherwise, builds the path from the parent's lower path + the entry name.
fn compute_redirect_path(
    fs: &OverlayFs,
    node: &super::types::OverlayNode,
    parent_ino: u64,
    name: &[u8],
) -> io::Result<Vec<Vec<u8>>> {
    // If node already has a redirect, preserve it (normalize — no chaining).
    let existing = node.redirect.read().unwrap();
    if let Some(ref redir) = *existing {
        return Ok(redir.lower_path.clone());
    }
    drop(existing);

    // Build path from parent's lower path + this name.
    let parent_node = {
        let nodes = fs.nodes.read().unwrap();
        nodes.get(&parent_ino).cloned()
    };

    let mut path = if let Some(ref pn) = parent_node {
        inode::get_parent_lower_path(fs, pn)?
    } else {
        Vec::new()
    };

    path.push(name.to_vec());
    Ok(path)
}

/// Check if `ancestor_ino` is an ancestor of `descendant_ino`.
///
/// Walks the parent chain from `descendant_ino` up to root. Returns `true`
/// if `ancestor_ino` appears on the path. Used to reject rename-into-own-subtree.
fn is_ancestor(fs: &OverlayFs, ancestor_ino: u64, descendant_ino: u64) -> bool {
    let mut current = descendant_ino;
    // Walk up to root with a depth cap to prevent infinite loops.
    for _ in 0..4096 {
        if current == ancestor_ino {
            return true;
        }
        if current == ROOT_INODE {
            return false;
        }
        let parent = {
            let nodes = fs.nodes.read().unwrap();
            match nodes.get(&current) {
                Some(node) => node.primary_parent.load(Ordering::Acquire),
                None => return false,
            }
        };
        if parent == 0 || parent == current {
            return false;
        }
        current = parent;
    }
    false
}

/// Perform a rename operation on the upper layer.
fn do_renameat(
    old_parent_fd: i32,
    oldname: &CStr,
    new_parent_fd: i32,
    newname: &CStr,
    flags: u32,
) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe {
            libc::syscall(
                libc::SYS_renameat2,
                old_parent_fd,
                oldname.as_ptr(),
                new_parent_fd,
                newname.as_ptr(),
                flags,
            )
        };
        if ret < 0 {
            return Err(platform::linux_error(io::Error::last_os_error()));
        }
    }

    #[cfg(target_os = "macos")]
    {
        if flags == 0 {
            let ret = unsafe {
                libc::renameat(
                    old_parent_fd,
                    oldname.as_ptr(),
                    new_parent_fd,
                    newname.as_ptr(),
                )
            };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
        } else {
            let mut macos_flags: libc::c_uint = 0;
            if flags & RENAME_NOREPLACE != 0 {
                macos_flags |= 0x00000004; // RENAME_EXCL
            }
            if flags & RENAME_EXCHANGE != 0 {
                macos_flags |= 0x00000002; // RENAME_SWAP
            }

            let ret = unsafe {
                libc::renameatx_np(
                    old_parent_fd,
                    oldname.as_ptr(),
                    new_parent_fd,
                    newname.as_ptr(),
                    macos_flags,
                )
            };
            if ret < 0 {
                return Err(platform::linux_error(io::Error::last_os_error()));
            }
        }
    }

    Ok(())
}

/// Update the dentry cache after a rename operation.
fn update_dentry_cache(
    fs: &OverlayFs,
    olddir: u64,
    oldname_id: super::types::NameId,
    newdir: u64,
    newname: &CStr,
    source_node: Option<&super::types::OverlayNode>,
) {
    let newname_id = fs.names.intern(newname.to_bytes());
    let mut dentries = fs.dentries.write().unwrap();

    // Remove old dentry.
    if let Some(dentry) = dentries.remove(&(olddir, oldname_id)) {
        // Update primary parent/name on the node.
        if let Some(node) = source_node {
            node.primary_parent.store(newdir, Ordering::Release);
            *node.primary_name.write().unwrap() = newname_id;
        }

        // Insert new dentry.
        dentries.insert(
            (newdir, newname_id),
            super::types::Dentry { node: dentry.node },
        );
    }
}

/// Remove destination directory artifacts if the destination is a directory.
///
/// Checks whether `dest_entry` is a directory; if so, removes upper-layer
/// whiteouts/opaque markers, then removes the empty directory itself.
/// ENOENT on the rmdir is tolerated (the dir may be lower-only).
fn clear_dest_dir_if_needed(
    parent_fd: i32,
    name: &CStr,
    dest_entry: &Result<crate::Entry, io::Error>,
) -> io::Result<()> {
    if let Ok(de) = dest_entry {
        let dest_type = platform::mode_file_type(de.attr.st_mode);
        if dest_type == platform::MODE_DIR {
            remove_upper_dir_artifacts(parent_fd, name)?;
            let ret = unsafe { libc::unlinkat(parent_fd, name.as_ptr(), libc::AT_REMOVEDIR) };
            if ret < 0 {
                let err = io::Error::last_os_error();
                if err.raw_os_error() != Some(libc::ENOENT) {
                    return Err(platform::linux_error(err));
                }
            }
        }
    }
    Ok(())
}

/// Open a directory by name relative to a parent fd.
fn open_dir_by_name(parent_fd: i32, name: &CStr) -> io::Result<i32> {
    let fd = unsafe {
        libc::openat(
            parent_fd,
            name.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW,
        )
    };
    if fd < 0 {
        return Err(platform::linux_error(io::Error::last_os_error()));
    }
    Ok(fd)
}

/// Remove internal overlay artifacts (whiteouts, opaque markers) from an
/// upper directory so that the host `rmdir` can succeed.
///
/// Called before rmdir on a merged-empty directory whose upper fragment may
/// contain `.wh.*` files or `.wh..wh..opq`. Returns `ENOTEMPTY` if any
/// non-whiteout entries are found, preventing partial cleanup that would
/// change guest-visible state without completing the operation.
fn remove_upper_dir_artifacts(parent_fd: i32, name: &CStr) -> io::Result<()> {
    let dir_fd = match open_dir_by_name(parent_fd, name) {
        Ok(fd) => fd,
        Err(e) if platform::is_enoent(&e) => return Ok(()),
        Err(e) => return Err(e),
    };
    let _close = scopeguard::guard(dir_fd, |fd| unsafe {
        libc::close(fd);
    });

    let entries = layer::read_dir_entries_raw(dir_fd)?;

    // Safety check: reject if any non-whiteout entries exist on upper.
    for (entry_name, _) in &entries {
        if !entry_name.starts_with(b".wh.") {
            return Err(platform::enotempty());
        }
    }

    for (entry_name, _) in entries {
        let mut buf = entry_name;
        buf.push(0);
        let cname = unsafe { CStr::from_bytes_with_nul_unchecked(&buf) };
        let ret = unsafe { libc::unlinkat(dir_fd, cname.as_ptr(), 0) };
        if ret < 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() != Some(libc::ENOENT) {
                return Err(platform::linux_error(err));
            }
        }
    }

    // Also remove the tombstone xattr if present.
    whiteout::remove_tombstone_xattr_if_present(dir_fd);

    Ok(())
}

/// Create an opaque marker (`.wh..wh..opq`) inside a directory.
///
/// Marks the directory as opaque so lower-layer entries are suppressed.
fn create_opaque_marker(dir_fd: i32) -> io::Result<()> {
    let fd = unsafe {
        libc::openat(
            dir_fd,
            c".wh..wh..opq".as_ptr(),
            libc::O_CREAT | libc::O_EXCL | libc::O_WRONLY | libc::O_CLOEXEC,
            0o000 as libc::c_uint,
        )
    };
    if fd < 0 {
        let err = io::Error::last_os_error();
        if err.raw_os_error() != Some(libc::EEXIST) {
            return Err(platform::linux_error(err));
        }
        // Marker already exists — still fsync below for durability in case a
        // prior crash happened between creation and fsync.
    } else {
        unsafe { libc::close(fd) };
    }

    // fsync the parent directory so the marker is durable before runtime
    // state treats this directory as opaque.
    copy_up::fsync_fd(dir_fd)?;

    Ok(())
}
