//! Unlink, rmdir, rename, and whiteout management.

use std::ffi::CStr;
use std::io;
use std::sync::atomic::Ordering;

use super::hooks::{CommitEvent, DentryChange, notify_observers};
use super::lookup::{
    backend, ensure_alias_linked, ensure_backend_presence, get_node, mark_metadata_authority,
    resolve_backend_inode,
};
use super::policy::{DualNamespaceView, HintBag, OpKind, RequestCtx};
use super::types::{BackendId, FileKind, GuestNode, ROOT_INODE};
use super::DualFs;
use crate::backends::shared::{init_binary, name_validation, platform};
use crate::Context;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Handle unlink.
pub(crate) fn do_unlink(fs: &DualFs, ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
    let name_bytes = name.to_bytes();
    name_validation::validate_name(name)?;

    // Protect init.krun.
    if parent == ROOT_INODE && init_binary::is_init_name(name_bytes) {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }

    let parent_node = get_node(&fs.state, parent)?;
    let view = DualNamespaceView { state: &fs.state };
    let req = RequestCtx {
        op: OpKind::Unlink,
        guest_inode: parent,
        node_state: parent_node.state.read().unwrap().clone(),
        file_kind: parent_node.kind,
        flags: 0,
        name: name_bytes.to_vec(),
        parent_inode: parent,
    };
    let plan = fs.policy.plan(&req, &view, &HintBag::new())?;
    let target = plan.target_backend().unwrap_or(BackendId::BackendA);

    ensure_backend_presence(fs, ctx, parent, target)?;

    // Resolve the child.
    let child_ino = fs
        .state
        .dentries
        .read()
        .unwrap()
        .get(&(parent, name_bytes.to_vec()))
        .copied()
        .ok_or_else(platform::enoent)?;

    let child_node = get_node(&fs.state, child_ino)?;

    // Ensure deferred alias linkage before target-side mutation.
    ensure_alias_linked(&fs.state, child_ino, parent, name_bytes)?;

    // If child has presence on target, unlink it there.
    if let Some(_target_child_inode) = child_node.state.read().unwrap().backend_inode(target) {
        if let Some(parent_target_inode) = resolve_backend_inode(&fs.state, parent, target) {
            backend(fs, target).unlink(ctx, parent_target_inode, name)?;
        }
    }

    // If child still has visible presence on the other backend, create whiteout.
    let other = target.other();
    if child_node.state.read().unwrap().backend_inode(other).is_some()
        && !super::lookup::is_opaque_against(&fs.state, parent, other)
    {
        fs.state
            .whiteouts
            .write()
            .unwrap()
            .insert((parent, name_bytes.to_vec(), other));
    }

    mark_metadata_authority(&fs.state, parent, target);

    // Remove dentry.
    fs.state
        .dentries
        .write()
        .unwrap()
        .remove(&(parent, name_bytes.to_vec()));
    fs.state
        .alias_index
        .write()
        .unwrap()
        .entry(child_ino)
        .and_modify(|s| {
            s.remove(&(parent, name_bytes.to_vec()));
        });

    // Anchor repair.
    let anchor_parent = child_node.anchor_parent.load(Ordering::Relaxed);
    let anchor_name = child_node.anchor_name.read().unwrap().clone();
    if anchor_parent == parent && anchor_name == name_bytes {
        if let Some(aliases) = fs.state.alias_index.read().unwrap().get(&child_ino) {
            if let Some((new_p, new_n)) = aliases.iter().next() {
                child_node.anchor_parent.store(*new_p, Ordering::Relaxed);
                *child_node.anchor_name.write().unwrap() = new_n.clone();
            }
        }
    }

    // hooks.after_commit
    notify_observers(&fs.hooks, |h| {
        h.after_commit(&CommitEvent {
            op: OpKind::Unlink,
            guest_inode: child_ino,
            transition: None,
            dentry_changes: vec![DentryChange::Removed {
                parent,
                name: name_bytes.to_vec(),
                child: child_ino,
            }],
        });
    });

    Ok(())
}

/// Handle rmdir.
pub(crate) fn do_rmdir(fs: &DualFs, ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
    let name_bytes = name.to_bytes();
    name_validation::validate_name(name)?;

    if parent == ROOT_INODE && init_binary::is_init_name(name_bytes) {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }

    let parent_node = get_node(&fs.state, parent)?;
    let view = DualNamespaceView { state: &fs.state };
    let req = RequestCtx {
        op: OpKind::Rmdir,
        guest_inode: parent,
        node_state: parent_node.state.read().unwrap().clone(),
        file_kind: parent_node.kind,
        flags: 0,
        name: name_bytes.to_vec(),
        parent_inode: parent,
    };
    let plan = fs.policy.plan(&req, &view, &HintBag::new())?;
    let target = plan.target_backend().unwrap_or(BackendId::BackendA);

    ensure_backend_presence(fs, ctx, parent, target)?;

    let child_ino = fs
        .state
        .dentries
        .read()
        .unwrap()
        .get(&(parent, name_bytes.to_vec()))
        .copied()
        .ok_or_else(platform::enoent)?;

    let child_node = get_node(&fs.state, child_ino)?;
    if child_node.kind != FileKind::Directory {
        return Err(platform::enotdir());
    }

    // Check merged emptiness: target-side children (from dentries) +
    // non-target-side children (minus whiteouts) must all be empty.
    check_merged_dir_empty(fs, ctx, child_ino, &child_node, target)?;

    // If child has target presence, rmdir it there.
    if child_node.state.read().unwrap().backend_inode(target).is_some() {
        if let Some(parent_target_inode) = resolve_backend_inode(&fs.state, parent, target) {
            backend(fs, target).rmdir(ctx, parent_target_inode, name)?;
        }
    }

    // Whiteout if other side still has the dir.
    let other = target.other();
    if child_node.state.read().unwrap().backend_inode(other).is_some()
        && !super::lookup::is_opaque_against(&fs.state, parent, other)
    {
        fs.state
            .whiteouts
            .write()
            .unwrap()
            .insert((parent, name_bytes.to_vec(), other));
    }

    mark_metadata_authority(&fs.state, parent, target);

    // Remove dentry.
    fs.state
        .dentries
        .write()
        .unwrap()
        .remove(&(parent, name_bytes.to_vec()));
    fs.state
        .alias_index
        .write()
        .unwrap()
        .entry(child_ino)
        .and_modify(|s| {
            s.remove(&(parent, name_bytes.to_vec()));
        });

    Ok(())
}

/// Known rename flags.
const RENAME_NOREPLACE: u32 = 1;
const RENAME_EXCHANGE: u32 = 2;
const KNOWN_RENAME_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;

/// Handle rename.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_rename(
    fs: &DualFs,
    ctx: Context,
    olddir: u64,
    oldname: &CStr,
    newdir: u64,
    newname: &CStr,
    flags: u32,
) -> io::Result<()> {
    let oldname_bytes = oldname.to_bytes();
    let newname_bytes = newname.to_bytes();
    name_validation::validate_name(oldname)?;
    name_validation::validate_name(newname)?;

    // Reject unknown flags.
    if flags & !KNOWN_RENAME_FLAGS != 0 {
        return Err(platform::einval());
    }
    // NOREPLACE and EXCHANGE are mutually exclusive.
    if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
        return Err(platform::einval());
    }

    // Protect init.krun.
    if (olddir == ROOT_INODE && init_binary::is_init_name(oldname_bytes))
        || (newdir == ROOT_INODE && init_binary::is_init_name(newname_bytes))
    {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }

    // Resolve source.
    let source_ino = fs
        .state
        .dentries
        .read()
        .unwrap()
        .get(&(olddir, oldname_bytes.to_vec()))
        .copied()
        .ok_or_else(platform::enoent)?;

    let source_node = get_node(&fs.state, source_ino)?;

    let _parent_node = get_node(&fs.state, olddir)?;
    let view = DualNamespaceView { state: &fs.state };
    let req = RequestCtx {
        op: OpKind::Rename,
        guest_inode: source_ino,
        node_state: source_node.state.read().unwrap().clone(),
        file_kind: source_node.kind,
        flags,
        name: oldname_bytes.to_vec(),
        parent_inode: olddir,
    };
    let plan = fs.policy.plan(&req, &view, &HintBag::new())?;
    let target = plan.target_backend().unwrap_or(BackendId::BackendA);

    // Directory rename: check if cross-layer EXDEV.
    if source_node.kind == FileKind::Directory {
        let state = source_node.state.read().unwrap();
        if !state.is_pure_on(target) {
            return Err(io::Error::from_raw_os_error(libc::EXDEV));
        }
    }

    // Materialize source if needed.
    let current_backend = source_node.state.read().unwrap().current_backend();
    if let Some(current) = current_backend {
        if current != target {
            super::materialize::do_materialize(fs, ctx, source_ino, current, target)?;
        }
    }

    ensure_backend_presence(fs, ctx, olddir, target)?;
    ensure_backend_presence(fs, ctx, newdir, target)?;

    // Ensure deferred alias linkage on source before target-side mutation.
    ensure_alias_linked(&fs.state, source_ino, olddir, oldname_bytes)?;

    // Check destination.
    let dest_ino = fs
        .state
        .dentries
        .read()
        .unwrap()
        .get(&(newdir, newname_bytes.to_vec()))
        .copied();

    // RENAME_NOREPLACE: fail if destination exists.
    if flags & RENAME_NOREPLACE != 0 && dest_ino.is_some() {
        return Err(platform::eexist());
    }

    // RENAME_EXCHANGE: atomically swap source and destination.
    if flags & RENAME_EXCHANGE != 0 {
        let dest_guest_ino = dest_ino.ok_or_else(platform::enoent)?;
        let dest_node = get_node(&fs.state, dest_guest_ino)?;

        // Materialize destination if needed.
        let dest_current = dest_node.state.read().unwrap().current_backend();
        if let Some(current) = dest_current {
            if current != target {
                super::materialize::do_materialize(
                    fs,
                    ctx,
                    dest_guest_ino,
                    current,
                    target,
                )?;
            }
        }
        ensure_alias_linked(&fs.state, dest_guest_ino, newdir, newname_bytes)?;

        // Delegate exchange to target backend.
        let olddir_target = resolve_backend_inode(&fs.state, olddir, target)
            .ok_or_else(platform::enoent)?;
        let newdir_target = resolve_backend_inode(&fs.state, newdir, target)
            .ok_or_else(platform::enoent)?;
        backend(fs, target).rename(
            ctx,
            olddir_target,
            oldname,
            newdir_target,
            newname,
            flags,
        )?;

        // Swap dentries.
        {
            let mut dentries = fs.state.dentries.write().unwrap();
            dentries.insert((olddir, oldname_bytes.to_vec()), dest_guest_ino);
            dentries.insert((newdir, newname_bytes.to_vec()), source_ino);
        }

        // Swap alias_index entries.
        {
            let mut alias = fs.state.alias_index.write().unwrap();
            alias.entry(source_ino).and_modify(|s| {
                s.remove(&(olddir, oldname_bytes.to_vec()));
                s.insert((newdir, newname_bytes.to_vec()));
            });
            alias.entry(dest_guest_ino).and_modify(|s| {
                s.remove(&(newdir, newname_bytes.to_vec()));
                s.insert((olddir, oldname_bytes.to_vec()));
            });
        }

        // Update anchors.
        source_node
            .anchor_parent
            .store(newdir, Ordering::Relaxed);
        *source_node.anchor_name.write().unwrap() = newname_bytes.to_vec();
        dest_node
            .anchor_parent
            .store(olddir, Ordering::Relaxed);
        *dest_node.anchor_name.write().unwrap() = oldname_bytes.to_vec();

        return Ok(());
    }

    // Handle existing destination: remove it first.
    if let Some(dest_ino) = dest_ino {
        let dest_node = get_node(&fs.state, dest_ino)?;

        // If dest has target presence, unlink/rmdir it there.
        if dest_node.state.read().unwrap().backend_inode(target).is_some() {
            if let Some(newdir_target) = resolve_backend_inode(&fs.state, newdir, target) {
                if dest_node.kind == FileKind::Directory {
                    backend(fs, target).rmdir(ctx, newdir_target, newname)?;
                } else {
                    backend(fs, target).unlink(ctx, newdir_target, newname)?;
                }
            }
        }

        // Whiteout if dest still has other-backend presence.
        let other = target.other();
        if dest_node.state.read().unwrap().backend_inode(other).is_some()
            && !super::lookup::is_opaque_against(&fs.state, newdir, other)
        {
            fs.state
                .whiteouts
                .write()
                .unwrap()
                .insert((newdir, newname_bytes.to_vec(), other));
        }

        // Remove dest dentry.
        fs.state
            .dentries
            .write()
            .unwrap()
            .remove(&(newdir, newname_bytes.to_vec()));
        fs.state
            .alias_index
            .write()
            .unwrap()
            .entry(dest_ino)
            .and_modify(|s| {
                s.remove(&(newdir, newname_bytes.to_vec()));
            });
    }

    // Delegate rename in target backend.
    let olddir_target = resolve_backend_inode(&fs.state, olddir, target)
        .ok_or_else(platform::enoent)?;
    let newdir_target = resolve_backend_inode(&fs.state, newdir, target)
        .ok_or_else(platform::enoent)?;

    backend(fs, target).rename(ctx, olddir_target, oldname, newdir_target, newname, flags)?;

    // If old name still has visible presence on other backend, whiteout it.
    let other = target.other();
    if resolve_backend_inode(&fs.state, source_ino, other).is_some()
        && !super::lookup::is_opaque_against(&fs.state, olddir, other)
    {
        fs.state
            .whiteouts
            .write()
            .unwrap()
            .insert((olddir, oldname_bytes.to_vec(), other));
    }

    mark_metadata_authority(&fs.state, olddir, target);
    mark_metadata_authority(&fs.state, newdir, target);

    // Update dentries.
    fs.state
        .dentries
        .write()
        .unwrap()
        .remove(&(olddir, oldname_bytes.to_vec()));
    fs.state
        .dentries
        .write()
        .unwrap()
        .insert((newdir, newname_bytes.to_vec()), source_ino);

    // Update alias_index.
    fs.state
        .alias_index
        .write()
        .unwrap()
        .entry(source_ino)
        .and_modify(|s| {
            s.remove(&(olddir, oldname_bytes.to_vec()));
            s.insert((newdir, newname_bytes.to_vec()));
        });

    // Update anchor.
    source_node
        .anchor_parent
        .store(newdir, Ordering::Relaxed);
    *source_node.anchor_name.write().unwrap() = newname_bytes.to_vec();

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Name of the hidden staging directory (filtered from emptiness checks).
const STAGING_DIR_NAME: &[u8] = b".dualfs_staging";

/// Check that a directory is empty in the merged view before rmdir.
///
/// Checks both target-side children (from dentries) and non-target-side
/// children (via readdir on the other backend, minus whiteouts/opaque).
fn check_merged_dir_empty(
    fs: &DualFs,
    ctx: Context,
    dir_ino: u64,
    dir_node: &GuestNode,
    target: BackendId,
) -> io::Result<()> {
    // Check target-side: any registered dentries under this dir?
    {
        let dentries = fs.state.dentries.read().unwrap();
        if dentries.keys().any(|(p, _)| *p == dir_ino) {
            return Err(io::Error::from_raw_os_error(libc::ENOTEMPTY));
        }
    }

    // Check non-target-side children (minus whiteouts).
    let other = target.other();
    if super::lookup::is_opaque_against(&fs.state, dir_ino, other) {
        // Directory is opaque against the other backend — no visible children there.
        return Ok(());
    }

    if let Some(other_inode) = dir_node.state.read().unwrap().backend_inode(other) {
        let other_backend = backend(fs, other);
        if let Ok((dh, _)) = other_backend.opendir(ctx, other_inode, 0) {
            let dh_val = dh.unwrap_or(0);
            if let Ok(entries) = other_backend.readdir(ctx, other_inode, dh_val, u32::MAX, 0) {
                let whiteouts = fs.state.whiteouts.read().unwrap();
                for entry in &entries {
                    let name = entry.name.to_vec();
                    if name == b"." || name == b".." {
                        continue;
                    }
                    if dir_ino == ROOT_INODE && name == STAGING_DIR_NAME {
                        continue;
                    }
                    if !whiteouts.contains(&(dir_ino, name, other)) {
                        let _ = other_backend.releasedir(ctx, other_inode, 0, dh_val);
                        return Err(io::Error::from_raw_os_error(libc::ENOTEMPTY));
                    }
                }
            }
            let _ = other_backend.releasedir(ctx, other_inode, 0, dh_val);
        }
    }

    Ok(())
}
