//! Lookup pipeline, REGISTER, whiteout/opaque checking, and backend pin management.

use std::{
    ffi::CStr,
    io,
    sync::{Arc, Mutex, atomic::Ordering},
};

use super::{
    DualFs,
    hooks::{
        CommitEvent, DentryChange, DispatchStep, HookCtx, StepResult, decode_entry,
        handle_hook_decision, notify_observers, run_decision_hooks,
    },
    policy::{BackendChoice, DualDispatchPlan, DualNamespaceView, HintBag, OpKind, RequestCtx},
    types::{AtomicBackendId, BackendId, DualState, FileKind, GuestNode, NodeState, ROOT_INODE},
};
use crate::{
    Context, Entry,
    backends::shared::{init_binary, name_validation, platform},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Name of the hidden staging directory.
const STAGING_DIR_NAME: &[u8] = b".dualfs_staging";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the full lookup pipeline.
pub(crate) fn do_lookup(fs: &DualFs, ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
    let name_bytes = name.to_bytes();

    // Handle reserved names at root.
    if parent == ROOT_INODE {
        if init_binary::is_init_name(name_bytes) {
            return Ok(init_binary::init_entry(
                fs.cfg.entry_timeout,
                fs.cfg.attr_timeout,
            ));
        }
        if name_bytes == STAGING_DIR_NAME {
            return Err(platform::enoent());
        }
    }

    // Validate name.
    name_validation::validate_name(name)?;

    // Get parent node.
    let parent_node = get_node(&fs.state, parent)?;
    if parent_node.kind != FileKind::Directory {
        return Err(platform::enotdir());
    }

    // Dentry cache check.
    if let Some(entry) = dentry_lookup(fs, parent, name_bytes)? {
        return Ok(entry);
    }

    // Build hook context.
    let node_state = parent_node.state.read().unwrap().clone();
    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Lookup,
            guest_inode: parent,
            node_state: node_state.clone(),
            file_kind: parent_node.kind,
            flags: 0,
            name: name_bytes.to_vec(),
            parent_inode: parent,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    // hooks.before_resolve (already resolved dentry above)
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| h.before_resolve(ctx)),
        decode_entry,
    ) {
        return r;
    }

    // hooks.after_resolve
    let view = DualNamespaceView { state: &fs.state };
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| {
            h.after_resolve(ctx, &view)
        }),
        decode_entry,
    ) {
        return r;
    }

    // hooks.before_plan
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| h.before_plan(ctx)),
        decode_entry,
    ) {
        return r;
    }

    // Plan.
    let plan = fs.policy.plan(&hook_ctx.req, &view, &hook_ctx.hints)?;

    // hooks.after_plan
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| h.after_plan(ctx, &plan)),
        decode_entry,
    ) {
        return r;
    }

    // Dispatch.
    let result = match plan {
        DualDispatchPlan::MergeLookup { precedence } => {
            execute_merge_lookup(fs, ctx, parent, name, precedence, &mut hook_ctx)
        }
        DualDispatchPlan::UseBackendA { .. } => {
            // Single-backend lookup (e.g., BackendAOnly policy).
            execute_single_backend_lookup(fs, ctx, parent, name, BackendId::BackendA, &mut hook_ctx)
        }
        DualDispatchPlan::UseBackendB { .. } => {
            execute_single_backend_lookup(fs, ctx, parent, name, BackendId::BackendB, &mut hook_ctx)
        }
        DualDispatchPlan::Deny { errno } => Err(io::Error::from_raw_os_error(errno)),
        _ => Err(platform::einval()),
    };

    // hooks.after_response
    notify_observers(&fs.hooks, |h| {
        h.after_response(&super::hooks::ResponseEvent {
            op: OpKind::Lookup,
            guest_inode: parent,
            result: result
                .as_ref()
                .map(|_| ())
                .map_err(|e| e.raw_os_error().unwrap_or(libc::EIO)),
            latency: std::time::Duration::ZERO,
        });
    });

    result
}

/// Handle forget for a single inode.
pub(crate) fn do_forget(fs: &DualFs, _ctx: Context, ino: u64, count: u64) {
    if ino == init_binary::INIT_INODE {
        return;
    }
    forget_one(fs, ino, count);
}

/// Handle batch forget.
pub(crate) fn do_batch_forget(fs: &DualFs, _ctx: Context, requests: Vec<(u64, u64)>) {
    for (ino, count) in requests {
        if ino == init_binary::INIT_INODE {
            continue;
        }
        forget_one(fs, ino, count);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Get a GuestNode by guest inode.
pub(crate) fn get_node(state: &DualState, ino: u64) -> io::Result<Arc<GuestNode>> {
    state
        .nodes
        .read()
        .unwrap()
        .get(&ino)
        .cloned()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))
}

/// Resolve a child backend inode for a given backend.
pub(crate) fn resolve_backend_inode(
    state: &DualState,
    guest_inode: u64,
    backend: BackendId,
) -> Option<u64> {
    let nodes = state.nodes.read().unwrap();
    let node = nodes.get(&guest_inode)?;
    node.state.read().unwrap().backend_inode(backend)
}

/// Resolve the active backend inode for read-only direct-dispatch ops.
pub(crate) fn resolve_active_backend_inode(node: &GuestNode) -> (BackendId, u64) {
    let metadata = node.metadata_backend.load(Ordering::Relaxed);
    let state = node.state.read().unwrap();
    match &*state {
        NodeState::Root {
            backend_a_root,
            backend_b_root,
        } => {
            if metadata == BackendId::BackendB {
                (BackendId::BackendB, *backend_b_root)
            } else {
                (BackendId::BackendA, *backend_a_root)
            }
        }
        NodeState::BackendA {
            backend_a_inode, ..
        } => (BackendId::BackendA, *backend_a_inode),
        NodeState::BackendB {
            backend_b_inode, ..
        } => (BackendId::BackendB, *backend_b_inode),
        NodeState::MergedDir {
            backend_a_inode,
            backend_b_inode,
        } => {
            if metadata == BackendId::BackendB {
                (BackendId::BackendB, *backend_b_inode)
            } else {
                (BackendId::BackendA, *backend_a_inode)
            }
        }
        NodeState::Init => unreachable!("INIT_INODE handled by caller"),
    }
}

/// Get the backend reference from DualFs by BackendId.
pub(crate) fn backend(fs: &DualFs, id: BackendId) -> &dyn DynFileSystem {
    match id {
        BackendId::BackendA => fs.backend_a.as_ref(),
        BackendId::BackendB => fs.backend_b.as_ref(),
    }
}

/// Check if a name is whited out for a specific backend.
pub(crate) fn is_whited_out(
    state: &DualState,
    parent: u64,
    name: &[u8],
    hidden_backend: BackendId,
) -> bool {
    state.is_whited_out(parent, name, hidden_backend)
}

/// Check if a directory is opaque against a specific backend.
pub(crate) fn is_opaque_against(
    state: &DualState,
    dir_inode: u64,
    hidden_backend: BackendId,
) -> bool {
    state.is_opaque(dir_inode, hidden_backend)
}

/// Ensure a directory has presence on the target backend (promote if needed).
pub(crate) fn ensure_backend_presence(
    fs: &DualFs,
    ctx: Context,
    dir_guest_inode: u64,
    target: BackendId,
) -> io::Result<()> {
    if dir_guest_inode == ROOT_INODE {
        return Ok(()); // Root always has both.
    }

    let node = get_node(&fs.state, dir_guest_inode)?;
    let state = node.state.read().unwrap();

    match &*state {
        NodeState::Root { .. } | NodeState::MergedDir { .. } => Ok(()),
        NodeState::BackendA { .. } if target == BackendId::BackendA => Ok(()),
        NodeState::BackendB { .. } if target == BackendId::BackendB => Ok(()),
        NodeState::BackendA { .. } | NodeState::BackendB { .. } => {
            drop(state);
            super::materialize::promote_directory_to_merged(fs, ctx, dir_guest_inode, target)
        }
        NodeState::Init => Err(platform::enotdir()),
    }
}

/// Ensure a node's deferred alias linkage is consistent before target-side mutation.
///
/// Readdir auto-registration creates dentry/alias entries lazily. Before performing
/// a target-side unlink or rename, confirm that the alias index includes the
/// (parent, name) link so anchor repair and eviction logic have accurate data.
pub(crate) fn ensure_alias_linked(
    state: &DualState,
    guest_inode: u64,
    parent: u64,
    name: &[u8],
) -> io::Result<()> {
    // Verify the dentry exists.
    let exists = state
        .dentries
        .read()
        .unwrap()
        .contains_key(&(parent, name.to_vec()));
    if !exists {
        return Err(io::Error::from_raw_os_error(libc::ENOENT));
    }

    // Ensure alias_index includes this link (may have been deferred).
    state
        .alias_index
        .write()
        .unwrap()
        .entry(guest_inode)
        .or_default()
        .insert((parent, name.to_vec()));

    Ok(())
}

/// Mark metadata authority on a node.
pub(crate) fn mark_metadata_authority(state: &DualState, guest_inode: u64, target: BackendId) {
    if let Some(node) = state.nodes.read().unwrap().get(&guest_inode) {
        node.metadata_backend.store(target, Ordering::Relaxed);
    }
}

/// Dentry lookup — returns an Entry if the name is already registered.
fn dentry_lookup(fs: &DualFs, parent: u64, name: &[u8]) -> io::Result<Option<Entry>> {
    let child_ino = {
        let dentries = fs.state.dentries.read().unwrap();
        match dentries.get(&(parent, name.to_vec())) {
            Some(&ino) => ino,
            None => return Ok(None),
        }
    };

    let node = get_node(&fs.state, child_ino)?;
    node.lookup_refs.fetch_add(1, Ordering::Relaxed);

    // Get attrs from active backend.
    let st = get_child_attrs(fs, &node, child_ino)?;

    Ok(Some(Entry {
        inode: child_ino,
        generation: 0,
        attr: st,
        attr_flags: 0,
        attr_timeout: fs.cfg.attr_timeout,
        entry_timeout: fs.cfg.entry_timeout,
    }))
}

/// Get attributes of a child node from its active backend.
fn get_child_attrs(fs: &DualFs, node: &GuestNode, guest_inode: u64) -> io::Result<crate::stat64> {
    if guest_inode == init_binary::INIT_INODE {
        return Ok(init_binary::init_stat());
    }

    let state = node.state.read().unwrap();
    match &*state {
        NodeState::Init => Ok(init_binary::init_stat()),
        _ => {
            let (backend_id, child_inode) = match &*state {
                NodeState::Root { backend_a_root, .. } => (BackendId::BackendA, *backend_a_root),
                NodeState::BackendA {
                    backend_a_inode, ..
                } => (BackendId::BackendA, *backend_a_inode),
                NodeState::BackendB {
                    backend_b_inode, ..
                } => (BackendId::BackendB, *backend_b_inode),
                NodeState::MergedDir {
                    backend_a_inode, ..
                } => {
                    let md = node.metadata_backend.load(Ordering::Relaxed);
                    if md == BackendId::BackendB {
                        (
                            BackendId::BackendB,
                            state.backend_inode(BackendId::BackendB).unwrap(),
                        )
                    } else {
                        (BackendId::BackendA, *backend_a_inode)
                    }
                }
                NodeState::Init => unreachable!(),
            };
            drop(state);

            let ctx = Context {
                uid: 0,
                gid: 0,
                pid: 0,
            };
            let (mut st, _) = backend(fs, backend_id).getattr(ctx, child_inode, None)?;
            st.st_ino = guest_inode;
            Ok(st)
        }
    }
}

/// Execute merge lookup with precedence order.
fn execute_merge_lookup(
    fs: &DualFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    precedence: BackendChoice,
    hook_ctx: &mut HookCtx,
) -> io::Result<Entry> {
    let name_bytes = name.to_bytes();

    let (first_id, second_id) = match precedence {
        BackendChoice::BackendBFirst => (BackendId::BackendB, BackendId::BackendA),
        BackendChoice::BackendAFirst => (BackendId::BackendA, BackendId::BackendB),
    };

    // Try preferred backend.
    if !is_whited_out(&fs.state, parent, name_bytes, first_id)
        && !is_opaque_against(&fs.state, parent, first_id)
        && let Some(first_parent) = resolve_backend_inode(&fs.state, parent, first_id)
    {
        let step = DispatchStep {
            backend: first_id,
            op: OpKind::Lookup,
            inode: first_parent,
            handle: None,
        };

        if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
            run_decision_hooks(&fs.hooks, hook_ctx, |h, ctx| h.before_dispatch(ctx, &step)),
            decode_entry,
        ) {
            return r;
        }

        match backend(fs, first_id).lookup(ctx, first_parent, name) {
            Ok(entry) => {
                notify_observers(&fs.hooks, |h| {
                    h.after_dispatch(
                        hook_ctx,
                        &step,
                        &StepResult::Entry(super::hooks::copy_entry(&entry)),
                    );
                });
                return register(fs, ctx, entry, parent, name_bytes, first_id);
            }
            Err(e) if e.raw_os_error() == Some(libc::ENOENT) => {
                notify_observers(&fs.hooks, |h| {
                    h.after_dispatch(
                        hook_ctx,
                        &step,
                        &StepResult::Err(io::Error::from_raw_os_error(libc::ENOENT)),
                    );
                });
                // Fall through to second backend.
            }
            Err(e) => {
                notify_observers(&fs.hooks, |h| {
                    h.after_dispatch(
                        hook_ctx,
                        &step,
                        &StepResult::Err(io::Error::from_raw_os_error(
                            e.raw_os_error().unwrap_or(libc::EIO),
                        )),
                    );
                });
                return Err(e);
            }
        }
    }

    // Try other backend.
    if is_whited_out(&fs.state, parent, name_bytes, second_id)
        || is_opaque_against(&fs.state, parent, second_id)
    {
        return Err(platform::enoent());
    }

    if let Some(second_parent) = resolve_backend_inode(&fs.state, parent, second_id) {
        let step = DispatchStep {
            backend: second_id,
            op: OpKind::Lookup,
            inode: second_parent,
            handle: None,
        };

        if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
            run_decision_hooks(&fs.hooks, hook_ctx, |h, ctx| h.before_dispatch(ctx, &step)),
            decode_entry,
        ) {
            return r;
        }

        match backend(fs, second_id).lookup(ctx, second_parent, name) {
            Ok(entry) => {
                notify_observers(&fs.hooks, |h| {
                    h.after_dispatch(
                        hook_ctx,
                        &step,
                        &StepResult::Entry(super::hooks::copy_entry(&entry)),
                    );
                });
                return register(fs, ctx, entry, parent, name_bytes, second_id);
            }
            Err(e) => {
                notify_observers(&fs.hooks, |h| {
                    h.after_dispatch(
                        hook_ctx,
                        &step,
                        &StepResult::Err(io::Error::from_raw_os_error(
                            e.raw_os_error().unwrap_or(libc::EIO),
                        )),
                    );
                });
                return Err(e);
            }
        }
    }

    Err(platform::enoent())
}

/// Execute single-backend lookup (for BackendAOnly-style policies).
fn execute_single_backend_lookup(
    fs: &DualFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    backend_id: BackendId,
    hook_ctx: &mut HookCtx,
) -> io::Result<Entry> {
    let name_bytes = name.to_bytes();

    let parent_inode =
        resolve_backend_inode(&fs.state, parent, backend_id).ok_or_else(platform::enoent)?;

    let step = DispatchStep {
        backend: backend_id,
        op: OpKind::Lookup,
        inode: parent_inode,
        handle: None,
    };

    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, hook_ctx, |h, ctx| h.before_dispatch(ctx, &step)),
        decode_entry,
    ) {
        return r;
    }

    match backend(fs, backend_id).lookup(ctx, parent_inode, name) {
        Ok(entry) => {
            notify_observers(&fs.hooks, |h| {
                h.after_dispatch(
                    hook_ctx,
                    &step,
                    &StepResult::Entry(super::hooks::copy_entry(&entry)),
                );
            });
            register(fs, ctx, entry, parent, name_bytes, backend_id)
        }
        Err(e) => {
            notify_observers(&fs.hooks, |h| {
                h.after_dispatch(
                    hook_ctx,
                    &step,
                    &StepResult::Err(io::Error::from_raw_os_error(
                        e.raw_os_error().unwrap_or(libc::EIO),
                    )),
                );
            });
            Err(e)
        }
    }
}

/// REGISTER: assign a guest inode for a discovered child backend entry.
pub(crate) fn register(
    fs: &DualFs,
    _ctx: Context,
    child_entry: Entry,
    parent: u64,
    name: &[u8],
    source: BackendId,
) -> io::Result<Entry> {
    let inode_map = fs.state.inode_map(source);

    // Check hardlink dedup.
    {
        let map = inode_map.read().unwrap();
        if let Some(&guest_inode) = map.get(&child_entry.inode) {
            let nodes = fs.state.nodes.read().unwrap();
            if let Some(existing_node) = nodes.get(&guest_inode) {
                existing_node.lookup_refs.fetch_add(1, Ordering::Relaxed);

                // Record dentry and alias.
                drop(nodes);
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

                // Immediately forget the transient lookup ref.
                backend(fs, source).forget(
                    Context {
                        uid: 0,
                        gid: 0,
                        pid: 0,
                    },
                    child_entry.inode,
                    1,
                );

                let mut st = child_entry.attr;
                st.st_ino = guest_inode;

                return Ok(Entry {
                    inode: guest_inode,
                    generation: 0,
                    attr: st,
                    attr_flags: 0,
                    attr_timeout: fs.cfg.attr_timeout,
                    entry_timeout: fs.cfg.entry_timeout,
                });
            }
        }
    }

    // New entry — assign a guest inode.
    let guest_inode = fs.state.next_inode.fetch_add(1, Ordering::Relaxed);
    let kind = FileKind::from_mode(child_entry.attr.st_mode as u32);

    let node_state = match source {
        BackendId::BackendA => NodeState::BackendA {
            backend_a_inode: child_entry.inode,
            former_backend_b_inode: None,
        },
        BackendId::BackendB => NodeState::BackendB {
            backend_b_inode: child_entry.inode,
            former_backend_a_inode: None,
        },
    };

    let node = Arc::new(GuestNode {
        guest_inode,
        kind,
        lookup_refs: std::sync::atomic::AtomicU64::new(1),
        anchor_parent: std::sync::atomic::AtomicU64::new(parent),
        anchor_name: std::sync::RwLock::new(name.to_vec()),
        metadata_backend: AtomicBackendId::new(source),
        state: std::sync::RwLock::new(node_state),
        copy_up_lock: Mutex::new(()),
    });

    fs.state.nodes.write().unwrap().insert(guest_inode, node);
    inode_map
        .write()
        .unwrap()
        .insert(child_entry.inode, guest_inode);
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

    // hooks.after_commit
    notify_observers(&fs.hooks, |h| {
        h.after_commit(&CommitEvent {
            op: OpKind::Lookup,
            guest_inode,
            transition: None,
            dentry_changes: vec![DentryChange::Added {
                parent,
                name: name.to_vec(),
                child: guest_inode,
            }],
        });
    });

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

/// Auto-register a backend entry discovered via readdir.
#[allow(clippy::too_many_arguments)]
pub(crate) fn auto_register_readdir(
    fs: &DualFs,
    ctx: Context,
    backend_inode: u64,
    name: &[u8],
    dtype: u32,
    guest_parent: u64,
    anchor_parent_inode: u64,
    source: BackendId,
) -> Option<u64> {
    // Skip internal staging directory.
    if guest_parent == ROOT_INODE && name == STAGING_DIR_NAME {
        return None;
    }

    let inode_map = fs.state.inode_map(source);

    // Already known?
    {
        let map = inode_map.read().unwrap();
        if let Some(&guest_ino) = map.get(&backend_inode) {
            return Some(guest_ino);
        }
    }

    // Acquire retained child pin via explicit lookup.
    let cname = match std::ffi::CString::new(name) {
        Ok(c) => c,
        Err(_) => return None,
    };
    let _pin_entry = match backend(fs, source).lookup(ctx, anchor_parent_inode, &cname) {
        Ok(e) => e,
        Err(_) => return None,
    };

    let guest_ino = fs.state.next_inode.fetch_add(1, Ordering::Relaxed);
    let kind = FileKind::from_dtype(dtype);

    let node_state = match source {
        BackendId::BackendA => NodeState::BackendA {
            backend_a_inode: backend_inode,
            former_backend_b_inode: None,
        },
        BackendId::BackendB => NodeState::BackendB {
            backend_b_inode: backend_inode,
            former_backend_a_inode: None,
        },
    };

    let node = Arc::new(GuestNode {
        guest_inode: guest_ino,
        kind,
        lookup_refs: std::sync::atomic::AtomicU64::new(0),
        anchor_parent: std::sync::atomic::AtomicU64::new(guest_parent),
        anchor_name: std::sync::RwLock::new(name.to_vec()),
        metadata_backend: AtomicBackendId::new(source),
        state: std::sync::RwLock::new(node_state),
        copy_up_lock: Mutex::new(()),
    });

    fs.state.nodes.write().unwrap().insert(guest_ino, node);
    inode_map.write().unwrap().insert(backend_inode, guest_ino);
    fs.state
        .dentries
        .write()
        .unwrap()
        .insert((guest_parent, name.to_vec()), guest_ino);
    fs.state
        .alias_index
        .write()
        .unwrap()
        .entry(guest_ino)
        .or_default()
        .insert((guest_parent, name.to_vec()));

    Some(guest_ino)
}

/// Forget one guest inode ref-count, evicting if appropriate.
fn forget_one(fs: &DualFs, ino: u64, count: u64) {
    let node = match fs.state.nodes.read().unwrap().get(&ino).cloned() {
        Some(n) => n,
        None => return,
    };

    // CAS loop to prevent wrapping underflow.
    let new = loop {
        let old = node.lookup_refs.load(Ordering::Relaxed);
        let new = old.saturating_sub(count);
        match node
            .lookup_refs
            .compare_exchange(old, new, Ordering::Release, Ordering::Relaxed)
        {
            Ok(_) => break new,
            Err(_) => continue,
        }
    };

    if new == 0 {
        // Check if no aliases remain.
        let aliases_empty = fs
            .state
            .alias_index
            .read()
            .unwrap()
            .get(&ino)
            .is_none_or(|s| s.is_empty());

        if aliases_empty {
            // Evict: release retained child pins.
            let state = node.state.read().unwrap();
            match &*state {
                NodeState::BackendA {
                    backend_a_inode,
                    former_backend_b_inode,
                } => {
                    let ba_ino = *backend_a_inode;
                    let former = *former_backend_b_inode;
                    drop(state);

                    fs.backend_a.forget(
                        Context {
                            uid: 0,
                            gid: 0,
                            pid: 0,
                        },
                        ba_ino,
                        1,
                    );
                    fs.state
                        .backend_a_inode_map
                        .write()
                        .unwrap()
                        .remove(&ba_ino);
                    if let Some(sec_ino) = former {
                        fs.state
                            .backend_b_inode_map
                            .write()
                            .unwrap()
                            .remove(&sec_ino);
                    }
                }
                NodeState::BackendB {
                    backend_b_inode,
                    former_backend_a_inode,
                } => {
                    let bb_ino = *backend_b_inode;
                    let former = *former_backend_a_inode;
                    drop(state);

                    fs.backend_b.forget(
                        Context {
                            uid: 0,
                            gid: 0,
                            pid: 0,
                        },
                        bb_ino,
                        1,
                    );
                    fs.state
                        .backend_b_inode_map
                        .write()
                        .unwrap()
                        .remove(&bb_ino);
                    if let Some(pri_ino) = former {
                        fs.state
                            .backend_a_inode_map
                            .write()
                            .unwrap()
                            .remove(&pri_ino);
                    }
                }
                NodeState::MergedDir {
                    backend_a_inode,
                    backend_b_inode,
                } => {
                    let ba_ino = *backend_a_inode;
                    let bb_ino = *backend_b_inode;
                    drop(state);

                    fs.backend_a.forget(
                        Context {
                            uid: 0,
                            gid: 0,
                            pid: 0,
                        },
                        ba_ino,
                        1,
                    );
                    fs.state
                        .backend_a_inode_map
                        .write()
                        .unwrap()
                        .remove(&ba_ino);
                    fs.backend_b.forget(
                        Context {
                            uid: 0,
                            gid: 0,
                            pid: 0,
                        },
                        bb_ino,
                        1,
                    );
                    fs.state
                        .backend_b_inode_map
                        .write()
                        .unwrap()
                        .remove(&bb_ino);
                }
                NodeState::Root { .. } | NodeState::Init => {
                    drop(state);
                    // Root and Init are never evicted.
                    return;
                }
            }

            fs.state.nodes.write().unwrap().remove(&ino);
            fs.state.alias_index.write().unwrap().remove(&ino);
        }
    }
}

use crate::DynFileSystem;
