//! Open, read, write, flush, release for regular files.

use std::io;
use std::sync::atomic::Ordering;
use std::sync::Arc;

use super::hooks::{
    DispatchStep, HookCtx, StepResult, decode_ok, decode_open, handle_hook_decision,
    notify_observers, run_decision_hooks,
};
use super::lookup::{backend, get_node, resolve_backend_inode};
use super::policy::{DualDispatchPlan, DualNamespaceView, HintBag, OpKind, RequestCtx};
use super::types::{BackendId, DualHandle, NodeState};
use super::DualFs;
use crate::backends::shared::{init_binary, platform};
use crate::{Context, OpenOptions, ZeroCopyReader, ZeroCopyWriter};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Handle open. Full pipeline with policy routing.
pub(crate) fn do_open(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    kill_priv: bool,
    flags: u32,
) -> io::Result<(Option<u64>, OpenOptions)> {
    if ino == init_binary::INIT_INODE {
        return Ok((Some(init_binary::INIT_HANDLE), OpenOptions::KEEP_CACHE));
    }

    let node = get_node(&fs.state, ino)?;

    // Adjust flags for writeback cache.
    let mut flags = flags;
    if fs.state.writeback.load(Ordering::Relaxed) {
        if flags & libc::O_WRONLY as u32 != 0 {
            flags = (flags & !(libc::O_WRONLY as u32)) | libc::O_RDWR as u32;
        }
        flags &= !(libc::O_APPEND as u32);
    }

    let node_state = node.state.read().unwrap().clone();
    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Open,
            guest_inode: ino,
            node_state: node_state.clone(),
            file_kind: node.kind,
            flags,
            name: Vec::new(),
            parent_inode: 0,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    // hooks.before_resolve
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| h.before_resolve(ctx)),
        decode_open,
    ) {
        return r;
    }

    let view = DualNamespaceView {
        state: &fs.state,
    };

    // hooks.after_resolve
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| {
            h.after_resolve(ctx, &view)
        }),
        decode_open,
    ) {
        return r;
    }

    // hooks.before_plan
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| h.before_plan(ctx)),
        decode_open,
    ) {
        return r;
    }

    let plan = fs.policy.plan(&hook_ctx.req, &view, &hook_ctx.hints)?;

    // hooks.after_plan
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| {
            h.after_plan(ctx, &plan)
        }),
        decode_open,
    ) {
        return r;
    }

    // Dispatch.
    match plan {
        DualDispatchPlan::MaterializeToBackendThen {
            source,
            target,
            ..
        } => {
            super::materialize::do_materialize(fs, ctx, ino, source, target)?;
            open_on_backend(fs, ctx, ino, kill_priv, flags, target, &mut hook_ctx)
        }
        DualDispatchPlan::UseBackendA { .. } => {
            open_on_backend(fs, ctx, ino, kill_priv, flags, BackendId::BackendA, &mut hook_ctx)
        }
        DualDispatchPlan::UseBackendB { .. } => {
            open_on_backend(fs, ctx, ino, kill_priv, flags, BackendId::BackendB, &mut hook_ctx)
        }
        DualDispatchPlan::Deny { errno } => Err(io::Error::from_raw_os_error(errno)),
        _ => Err(platform::einval()),
    }
}

/// Handle read. Handle-bound dispatch.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_read(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    handle: u64,
    w: &mut dyn ZeroCopyWriter,
    size: u32,
    offset: u64,
    lock_owner: Option<u64>,
    flags: u32,
) -> io::Result<usize> {
    if ino == init_binary::INIT_INODE {
        return init_binary::read_init(w, &fs.init_file, size, offset);
    }

    let fh = get_file_handle(fs, handle)?;

    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Read,
            guest_inode: ino,
            node_state: NodeState::Init, // Placeholder, handle-bound.
            file_kind: super::types::FileKind::RegularFile,
            flags: 0,
            name: Vec::new(),
            parent_inode: 0,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    let step = DispatchStep {
        backend: fh.backend_id(),
        op: OpKind::Read,
        inode: fh.child_inode(),
        handle: Some(fh.child_handle()),
    };

    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| {
            h.before_dispatch(ctx, &step)
        }),
        super::hooks::decode_usize,
    ) {
        return r;
    }

    let result = match fh.as_ref() {
        DualHandle::BackendA {
            backend_a_inode,
            backend_a_handle,
            ..
        } => fs.backend_a.read(
            ctx,
            *backend_a_inode,
            *backend_a_handle,
            w,
            size,
            offset,
            lock_owner,
            flags,
        ),
        DualHandle::BackendB {
            backend_b_inode,
            backend_b_handle,
            ..
        } => fs.backend_b.read(
            ctx,
            *backend_b_inode,
            *backend_b_handle,
            w,
            size,
            offset,
            lock_owner,
            flags,
        ),
    };

    notify_observers(&fs.hooks, |h| {
        h.after_dispatch(
            &hook_ctx,
            &step,
            &match &result {
                Ok(n) => StepResult::Data(*n),
                Err(e) => StepResult::Err(io::Error::from_raw_os_error(
                    e.raw_os_error().unwrap_or(libc::EIO),
                )),
            },
        );
    });

    result
}

/// Handle write. Handle-bound dispatch.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_write(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    handle: u64,
    r: &mut dyn ZeroCopyReader,
    size: u32,
    offset: u64,
    lock_owner: Option<u64>,
    delayed_write: bool,
    kill_priv: bool,
    flags: u32,
) -> io::Result<usize> {
    if ino == init_binary::INIT_INODE {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }

    let fh = get_file_handle(fs, handle)?;

    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Write,
            guest_inode: ino,
            node_state: NodeState::Init,
            file_kind: super::types::FileKind::RegularFile,
            flags: 0,
            name: Vec::new(),
            parent_inode: 0,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    let step = DispatchStep {
        backend: fh.backend_id(),
        op: OpKind::Write,
        inode: fh.child_inode(),
        handle: Some(fh.child_handle()),
    };

    if let std::ops::ControlFlow::Break(result) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| {
            h.before_dispatch(ctx, &step)
        }),
        super::hooks::decode_usize,
    ) {
        return result;
    }

    let result = match fh.as_ref() {
        DualHandle::BackendA {
            backend_a_inode,
            backend_a_handle,
            ..
        } => fs.backend_a.write(
            ctx,
            *backend_a_inode,
            *backend_a_handle,
            r,
            size,
            offset,
            lock_owner,
            delayed_write,
            kill_priv,
            flags,
        ),
        DualHandle::BackendB {
            backend_b_inode,
            backend_b_handle,
            ..
        } => fs.backend_b.write(
            ctx,
            *backend_b_inode,
            *backend_b_handle,
            r,
            size,
            offset,
            lock_owner,
            delayed_write,
            kill_priv,
            flags,
        ),
    };

    notify_observers(&fs.hooks, |h| {
        h.after_dispatch(
            &hook_ctx,
            &step,
            &match &result {
                Ok(n) => StepResult::Data(*n),
                Err(e) => StepResult::Err(io::Error::from_raw_os_error(
                    e.raw_os_error().unwrap_or(libc::EIO),
                )),
            },
        );
    });

    result
}

/// Handle flush. Handle-bound dispatch.
pub(crate) fn do_flush(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    handle: u64,
    lock_owner: u64,
) -> io::Result<()> {
    let fh = get_file_handle(fs, handle)?;

    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Flush,
            guest_inode: ino,
            node_state: NodeState::Init,
            file_kind: super::types::FileKind::RegularFile,
            flags: 0,
            name: Vec::new(),
            parent_inode: 0,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    let step = DispatchStep {
        backend: fh.backend_id(),
        op: OpKind::Flush,
        inode: fh.child_inode(),
        handle: Some(fh.child_handle()),
    };

    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| {
            h.before_dispatch(ctx, &step)
        }),
        decode_ok,
    ) {
        return r;
    }

    let result = match fh.as_ref() {
        DualHandle::BackendA {
            backend_a_inode,
            backend_a_handle,
            ..
        } => fs.backend_a.flush(ctx, *backend_a_inode, *backend_a_handle, lock_owner),
        DualHandle::BackendB {
            backend_b_inode,
            backend_b_handle,
            ..
        } => fs.backend_b.flush(ctx, *backend_b_inode, *backend_b_handle, lock_owner),
    };

    notify_observers(&fs.hooks, |h| {
        h.after_dispatch(
            &hook_ctx,
            &step,
            &match &result {
                Ok(()) => StepResult::Ok,
                Err(e) => StepResult::Err(io::Error::from_raw_os_error(
                    e.raw_os_error().unwrap_or(libc::EIO),
                )),
            },
        );
    });

    result
}

/// Handle release. Remove handle from table and delegate with hooks.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_release(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    flags: u32,
    handle: u64,
    flush: bool,
    flock_release: bool,
    lock_owner: Option<u64>,
) -> io::Result<()> {
    let fh = match fs.state.file_handles.write().unwrap().remove(&handle) {
        Some(fh) => fh,
        None => return Ok(()),
    };

    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Release,
            guest_inode: ino,
            node_state: NodeState::Init, // Placeholder, handle-bound.
            file_kind: super::types::FileKind::RegularFile,
            flags: 0,
            name: Vec::new(),
            parent_inode: 0,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    let step = DispatchStep {
        backend: fh.backend_id(),
        op: OpKind::Release,
        inode: fh.child_inode(),
        handle: Some(fh.child_handle()),
    };

    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| {
            h.before_dispatch(ctx, &step)
        }),
        decode_ok,
    ) {
        return r;
    }

    let result = match fh.as_ref() {
        DualHandle::BackendA {
            backend_a_inode,
            backend_a_handle,
            ..
        } => {
            fs.backend_a.release(
                ctx,
                *backend_a_inode,
                flags,
                *backend_a_handle,
                flush,
                flock_release,
                lock_owner,
            )
        }
        DualHandle::BackendB {
            backend_b_inode,
            backend_b_handle,
            ..
        } => {
            fs.backend_b.release(
                ctx,
                *backend_b_inode,
                flags,
                *backend_b_handle,
                flush,
                flock_release,
                lock_owner,
            )
        }
    };

    notify_observers(&fs.hooks, |h| {
        h.after_dispatch(
            &hook_ctx,
            &step,
            &match &result {
                Ok(()) => StepResult::Ok,
                Err(e) => StepResult::Err(io::Error::from_raw_os_error(
                    e.raw_os_error().unwrap_or(libc::EIO),
                )),
            },
        );
    });

    result
}

/// Handle readlink. Direct dispatch from node state.
pub(crate) fn do_readlink(fs: &DualFs, ctx: Context, ino: u64) -> io::Result<Vec<u8>> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::einval());
    }

    let node = get_node(&fs.state, ino)?;
    let state = node.state.read().unwrap();

    match &*state {
        NodeState::BackendA {
            backend_a_inode, ..
        } => fs.backend_a.readlink(ctx, *backend_a_inode),
        NodeState::BackendB {
            backend_b_inode, ..
        } => fs.backend_b.readlink(ctx, *backend_b_inode),
        _ => Err(platform::einval()),
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Open a file on a specific backend.
fn open_on_backend(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    kill_priv: bool,
    flags: u32,
    target: BackendId,
    hook_ctx: &mut HookCtx,
) -> io::Result<(Option<u64>, OpenOptions)> {
    let target_inode = resolve_backend_inode(&fs.state, ino, target)
        .ok_or_else(platform::einval)?;

    let step = DispatchStep {
        backend: target,
        op: OpKind::Open,
        inode: target_inode,
        handle: None,
    };

    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, hook_ctx, |h, ctx| {
            h.before_dispatch(ctx, &step)
        }),
        decode_open,
    ) {
        return r;
    }

    let (child_handle, opts) = backend(fs, target).open(ctx, target_inode, kill_priv, flags)?;
    let child_handle_val = child_handle.unwrap_or(0);

    let guest_handle = fs
        .state
        .next_handle
        .fetch_add(1, Ordering::Relaxed);

    let dual_handle = match target {
        BackendId::BackendA => DualHandle::BackendA {
            guest_inode: ino,
            backend_a_inode: target_inode,
            backend_a_handle: child_handle_val,
        },
        BackendId::BackendB => DualHandle::BackendB {
            guest_inode: ino,
            backend_b_inode: target_inode,
            backend_b_handle: child_handle_val,
        },
    };

    fs.state
        .file_handles
        .write()
        .unwrap()
        .insert(guest_handle, Arc::new(dual_handle));

    notify_observers(&fs.hooks, |h| {
        h.after_dispatch(
            hook_ctx,
            &step,
            &StepResult::Handle(guest_handle, opts),
        );
    });

    Ok((Some(guest_handle), opts))
}

/// Get a file handle by guest handle ID.
fn get_file_handle(fs: &DualFs, handle: u64) -> io::Result<Arc<DualHandle>> {
    fs.state
        .file_handles
        .read()
        .unwrap()
        .get(&handle)
        .cloned()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EBADF))
}
