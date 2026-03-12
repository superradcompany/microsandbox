//! Create, mkdir, mknod, symlink, link operations.

use std::ffi::CStr;
use std::io;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};

use super::hooks::{
    CommitEvent, DentryChange, HookCtx, decode_entry, handle_hook_decision, notify_observers,
    run_decision_hooks,
};
use super::lookup::{
    backend, ensure_backend_presence, get_node, mark_metadata_authority, resolve_backend_inode,
};
use super::policy::{DualNamespaceView, HintBag, OpKind, RequestCtx};
use super::types::{AtomicBackendId, BackendId, FileKind, GuestNode, NodeState};
use super::DualFs;
use crate::backends::shared::{init_binary, name_validation, platform};
use crate::{Context, Entry, Extensions, OpenOptions};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Handle create (file creation with open).
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_create(
    fs: &DualFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    mode: u32,
    kill_priv: bool,
    flags: u32,
    umask: u32,
    extensions: Extensions,
) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
    let name_bytes = name.to_bytes();
    name_validation::validate_name(name)?;

    let parent_node = get_node(&fs.state, parent)?;
    let node_state = parent_node.state.read().unwrap().clone();

    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Create,
            guest_inode: parent,
            node_state: node_state.clone(),
            file_kind: parent_node.kind,
            flags,
            name: name_bytes.to_vec(),
            parent_inode: parent,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    // Full pipeline: hooks + plan.
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| h.before_resolve(ctx)),
        decode_entry,
    ) {
        let entry = r?;
        return Ok((entry, None, OpenOptions::empty()));
    }

    let view = DualNamespaceView {
        state: &fs.state,
    };
    let plan = fs.policy.plan(&hook_ctx.req, &view, &hook_ctx.hints)?;
    let target = plan.target_backend().unwrap_or(BackendId::BackendA);

    // Ensure parent has target presence.
    ensure_backend_presence(fs, ctx, parent, target)?;

    // Check existence in merged view.
    check_name_available(fs, parent, name_bytes, target)?;

    // Resolve parent on target.
    let parent_target_inode = resolve_backend_inode(&fs.state, parent, target)
        .ok_or_else(platform::enoent)?;

    // Delegate.
    let (child_entry, child_handle, opts) = backend(fs, target).create(
        ctx,
        parent_target_inode,
        name,
        mode,
        kill_priv,
        flags,
        umask,
        extensions,
    )?;

    // Clear whiteout if one existed.
    clear_whiteout(fs, parent, name_bytes, target);

    mark_metadata_authority(&fs.state, parent, target);

    // Register new node.
    let guest_inode = register_new_node(fs, child_entry.inode, name_bytes, parent, target, FileKind::RegularFile);

    // Create file handle.
    let child_handle_val = child_handle.unwrap_or(0);
    let guest_handle = fs.state.next_handle.fetch_add(1, Ordering::Relaxed);
    let dual_handle = match target {
        BackendId::BackendA => super::types::DualHandle::BackendA {
            guest_inode,
            backend_a_inode: child_entry.inode,
            backend_a_handle: child_handle_val,
        },
        BackendId::BackendB => super::types::DualHandle::BackendB {
            guest_inode,
            backend_b_inode: child_entry.inode,
            backend_b_handle: child_handle_val,
        },
    };
    fs.state
        .file_handles
        .write()
        .unwrap()
        .insert(guest_handle, Arc::new(dual_handle));

    let mut st = child_entry.attr;
    st.st_ino = guest_inode;

    let entry = Entry {
        inode: guest_inode,
        generation: 0,
        attr: st,
        attr_flags: 0,
        attr_timeout: fs.cfg.attr_timeout,
        entry_timeout: fs.cfg.entry_timeout,
    };

    // hooks.after_commit
    notify_observers(&fs.hooks, |h| {
        h.after_commit(&CommitEvent {
            op: OpKind::Create,
            guest_inode,
            transition: None,
            dentry_changes: vec![DentryChange::Added {
                parent,
                name: name_bytes.to_vec(),
                child: guest_inode,
            }],
        });
    });

    Ok((entry, Some(guest_handle), opts))
}

/// Handle mkdir.
pub(crate) fn do_mkdir(
    fs: &DualFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    mode: u32,
    umask: u32,
    extensions: Extensions,
) -> io::Result<Entry> {
    let name_bytes = name.to_bytes();
    name_validation::validate_name(name)?;

    let parent_node = get_node(&fs.state, parent)?;
    let node_state = parent_node.state.read().unwrap().clone();

    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Mkdir,
            guest_inode: parent,
            node_state,
            file_kind: parent_node.kind,
            flags: 0,
            name: name_bytes.to_vec(),
            parent_inode: parent,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| h.before_resolve(ctx)),
        decode_entry,
    ) {
        return r;
    }

    let view = DualNamespaceView { state: &fs.state };
    let plan = fs.policy.plan(&hook_ctx.req, &view, &hook_ctx.hints)?;
    let target = plan.target_backend().unwrap_or(BackendId::BackendA);

    ensure_backend_presence(fs, ctx, parent, target)?;

    // Check if a whiteout existed (means a dir was previously deleted here).
    let had_whiteout = {
        let wh = fs.state.whiteouts.read().unwrap();
        wh.contains(&(parent, name_bytes.to_vec(), target.other()))
    };

    if !had_whiteout {
        check_name_available(fs, parent, name_bytes, target)?;
    }

    let parent_target_inode = resolve_backend_inode(&fs.state, parent, target)
        .ok_or_else(platform::enoent)?;

    let child_entry = backend(fs, target).mkdir(ctx, parent_target_inode, name, mode, umask, extensions)?;

    clear_whiteout(fs, parent, name_bytes, target);
    mark_metadata_authority(&fs.state, parent, target);

    let guest_inode = register_new_node(fs, child_entry.inode, name_bytes, parent, target, FileKind::Directory);

    // If recreating over a deleted dir, make opaque against the other backend.
    if had_whiteout {
        fs.state
            .opaque_dirs
            .write()
            .unwrap()
            .insert((guest_inode, target.other()));
    }

    let mut st = child_entry.attr;
    st.st_ino = guest_inode;

    Ok(Entry {
        inode: guest_inode,
        generation: 0,
        attr: st,
        attr_flags: 0,
        attr_timeout: fs.cfg.attr_timeout,
        entry_timeout: fs.cfg.entry_timeout,
    })
}

/// Handle mknod.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_mknod(
    fs: &DualFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    mode: u32,
    rdev: u32,
    umask: u32,
    extensions: Extensions,
) -> io::Result<Entry> {
    let name_bytes = name.to_bytes();
    name_validation::validate_name(name)?;

    let parent_node = get_node(&fs.state, parent)?;
    let view = DualNamespaceView { state: &fs.state };
    let req = RequestCtx {
        op: OpKind::Mknod,
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
    check_name_available(fs, parent, name_bytes, target)?;

    let parent_target_inode = resolve_backend_inode(&fs.state, parent, target)
        .ok_or_else(platform::enoent)?;

    let child_entry = backend(fs, target).mknod(ctx, parent_target_inode, name, mode, rdev, umask, extensions)?;

    clear_whiteout(fs, parent, name_bytes, target);
    mark_metadata_authority(&fs.state, parent, target);

    let kind = FileKind::from_mode(mode);
    let guest_inode = register_new_node(fs, child_entry.inode, name_bytes, parent, target, kind);

    let mut st = child_entry.attr;
    st.st_ino = guest_inode;

    Ok(Entry {
        inode: guest_inode,
        generation: 0,
        attr: st,
        attr_flags: 0,
        attr_timeout: fs.cfg.attr_timeout,
        entry_timeout: fs.cfg.entry_timeout,
    })
}

/// Handle symlink.
pub(crate) fn do_symlink(
    fs: &DualFs,
    ctx: Context,
    linkname: &CStr,
    parent: u64,
    name: &CStr,
    extensions: Extensions,
) -> io::Result<Entry> {
    let name_bytes = name.to_bytes();
    name_validation::validate_name(name)?;

    let parent_node = get_node(&fs.state, parent)?;
    let view = DualNamespaceView { state: &fs.state };
    let req = RequestCtx {
        op: OpKind::Symlink,
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
    check_name_available(fs, parent, name_bytes, target)?;

    let parent_target_inode = resolve_backend_inode(&fs.state, parent, target)
        .ok_or_else(platform::enoent)?;

    let child_entry = backend(fs, target).symlink(ctx, linkname, parent_target_inode, name, extensions)?;

    clear_whiteout(fs, parent, name_bytes, target);
    mark_metadata_authority(&fs.state, parent, target);

    let guest_inode = register_new_node(fs, child_entry.inode, name_bytes, parent, target, FileKind::Symlink);

    let mut st = child_entry.attr;
    st.st_ino = guest_inode;

    Ok(Entry {
        inode: guest_inode,
        generation: 0,
        attr: st,
        attr_flags: 0,
        attr_timeout: fs.cfg.attr_timeout,
        entry_timeout: fs.cfg.entry_timeout,
    })
}

/// Handle link.
pub(crate) fn do_link(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    newparent: u64,
    newname: &CStr,
) -> io::Result<Entry> {
    let newname_bytes = newname.to_bytes();
    name_validation::validate_name(newname)?;

    if ino == init_binary::INIT_INODE {
        return Err(io::Error::from_raw_os_error(libc::EPERM));
    }

    let source_node = get_node(&fs.state, ino)?;
    let view = DualNamespaceView { state: &fs.state };
    let req = RequestCtx {
        op: OpKind::Link,
        guest_inode: ino,
        node_state: source_node.state.read().unwrap().clone(),
        file_kind: source_node.kind,
        flags: 0,
        name: newname_bytes.to_vec(),
        parent_inode: newparent,
    };
    let plan = fs.policy.plan(&req, &view, &HintBag::new())?;
    let target = plan.target_backend().unwrap_or(BackendId::BackendA);

    // Materialize source if not on target.
    if let Some(current) = source_node.state.read().unwrap().current_backend() {
        if current != target {
            super::materialize::do_materialize(fs, ctx, ino, current, target)?;
        }
    }

    ensure_backend_presence(fs, ctx, newparent, target)?;
    check_name_available(fs, newparent, newname_bytes, target)?;

    let source_target_inode = resolve_backend_inode(&fs.state, ino, target)
        .ok_or_else(platform::einval)?;
    let newparent_target_inode = resolve_backend_inode(&fs.state, newparent, target)
        .ok_or_else(platform::enoent)?;

    let child_entry = backend(fs, target).link(ctx, source_target_inode, newparent_target_inode, newname)?;

    mark_metadata_authority(&fs.state, newparent, target);

    // Record new alias.
    fs.state
        .dentries
        .write()
        .unwrap()
        .insert((newparent, newname_bytes.to_vec()), ino);
    fs.state
        .alias_index
        .write()
        .unwrap()
        .entry(ino)
        .or_default()
        .insert((newparent, newname_bytes.to_vec()));

    source_node.lookup_refs.fetch_add(1, Ordering::Relaxed);

    let mut st = child_entry.attr;
    st.st_ino = ino;

    Ok(Entry {
        inode: ino,
        generation: 0,
        attr: st,
        attr_flags: 0,
        attr_timeout: fs.cfg.attr_timeout,
        entry_timeout: fs.cfg.entry_timeout,
    })
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Register a newly created node in the state tables.
fn register_new_node(
    fs: &DualFs,
    child_inode: u64,
    name: &[u8],
    parent: u64,
    target: BackendId,
    kind: FileKind,
) -> u64 {
    let guest_inode = fs.state.next_inode.fetch_add(1, Ordering::Relaxed);

    let node_state = match target {
        BackendId::BackendA => NodeState::BackendA {
            backend_a_inode: child_inode,
            former_backend_b_inode: None,
        },
        BackendId::BackendB => NodeState::BackendB {
            backend_b_inode: child_inode,
            former_backend_a_inode: None,
        },
    };

    let node = Arc::new(GuestNode {
        guest_inode,
        kind,
        lookup_refs: std::sync::atomic::AtomicU64::new(1),
        anchor_parent: std::sync::atomic::AtomicU64::new(parent),
        anchor_name: std::sync::RwLock::new(name.to_vec()),
        metadata_backend: AtomicBackendId::new(target),
        state: std::sync::RwLock::new(node_state),
        copy_up_lock: Mutex::new(()),
    });

    fs.state.nodes.write().unwrap().insert(guest_inode, node);
    fs.state
        .inode_map(target)
        .write()
        .unwrap()
        .insert(child_inode, guest_inode);
    fs.state
        .dentries
        .write()
        .unwrap()
        .insert((parent, name.to_vec()), guest_inode);
    fs.state
        .alias_index
        .write()
        .unwrap()
        .entry(guest_inode)
        .or_default()
        .insert((parent, name.to_vec()));

    guest_inode
}

/// Check that a name is available in the merged namespace.
fn check_name_available(
    fs: &DualFs,
    parent: u64,
    name: &[u8],
    target: BackendId,
) -> io::Result<()> {
    // If whited out against other backend, the name is "deleted" — available.
    let whited_out = fs
        .state
        .whiteouts
        .read()
        .unwrap()
        .contains(&(parent, name.to_vec(), target.other()));
    if whited_out {
        return Ok(());
    }

    // Check dentry table.
    if fs
        .state
        .dentries
        .read()
        .unwrap()
        .contains_key(&(parent, name.to_vec()))
    {
        return Err(io::Error::from_raw_os_error(libc::EEXIST));
    }

    Ok(())
}

/// Clear a whiteout for a name after successful creation.
fn clear_whiteout(fs: &DualFs, parent: u64, name: &[u8], target: BackendId) {
    fs.state
        .whiteouts
        .write()
        .unwrap()
        .remove(&(parent, name.to_vec(), target.other()));
}
