//! Getattr, setattr, access dispatch.

use std::{io, time::Duration};

use super::{
    DualFs,
    hooks::{
        DispatchStep, HookCtx, StepResult, decode_attr, decode_ok, handle_hook_decision,
        notify_observers, run_decision_hooks,
    },
    lookup::{backend, get_node, mark_metadata_authority, resolve_active_backend_inode},
    policy::{DualNamespaceView, HintBag, OpKind, RequestCtx},
    types::BackendId,
};
use crate::{
    Context, SetattrValid,
    backends::shared::{init_binary, platform},
    stat64,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Handle getattr. Direct dispatch from node state, not policy-routed.
pub(crate) fn do_getattr(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    _handle: Option<u64>,
) -> io::Result<(stat64, Duration)> {
    if ino == init_binary::INIT_INODE {
        return Ok((init_binary::init_stat(), fs.cfg.attr_timeout));
    }

    let node = get_node(&fs.state, ino)?;
    let (backend_id, child_inode) = resolve_active_backend_inode(&node);

    // hooks.before_dispatch
    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Getattr,
            guest_inode: ino,
            node_state: node.state.read().unwrap().clone(),
            file_kind: node.kind,
            flags: 0,
            name: Vec::new(),
            parent_inode: 0,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    let step = DispatchStep {
        backend: backend_id,
        op: OpKind::Getattr,
        inode: child_inode,
        handle: None,
    };

    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| {
            h.before_dispatch(ctx, &step)
        }),
        decode_attr,
    ) {
        return r;
    }

    let (mut st, _) = backend(fs, backend_id).getattr(ctx, child_inode, None)?;
    st.st_ino = ino;

    let result: io::Result<(stat64, Duration)> = Ok((st, fs.cfg.attr_timeout));

    // hooks.after_dispatch
    notify_observers(&fs.hooks, |h| {
        h.after_dispatch(
            &hook_ctx,
            &step,
            &match &result {
                Ok((st, ttl)) => StepResult::Attr(*st, *ttl),
                Err(e) => StepResult::Err(io::Error::from_raw_os_error(
                    e.raw_os_error().unwrap_or(libc::EIO),
                )),
            },
        );
    });

    result
}

/// Handle setattr. Full pipeline with policy routing.
pub(crate) fn do_setattr(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    attr: stat64,
    _handle: Option<u64>,
    valid: SetattrValid,
) -> io::Result<(stat64, Duration)> {
    if ino == init_binary::INIT_INODE {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }

    let node = get_node(&fs.state, ino)?;

    let node_state = node.state.read().unwrap().clone();
    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Setattr,
            guest_inode: ino,
            node_state: node_state.clone(),
            file_kind: node.kind,
            flags: 0,
            name: Vec::new(),
            parent_inode: 0,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    // hooks.before_resolve
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| h.before_resolve(ctx)),
        decode_attr,
    ) {
        return r;
    }

    let view = DualNamespaceView { state: &fs.state };

    // hooks.after_resolve
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| {
            h.after_resolve(ctx, &view)
        }),
        decode_attr,
    ) {
        return r;
    }

    // hooks.before_plan
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| h.before_plan(ctx)),
        decode_attr,
    ) {
        return r;
    }

    let plan = fs.policy.plan(&hook_ctx.req, &view, &hook_ctx.hints)?;

    // hooks.after_plan
    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| h.after_plan(ctx, &plan)),
        decode_attr,
    ) {
        return r;
    }

    // Determine target backend.
    let target = plan.target_backend().unwrap_or(BackendId::BackendA);

    // Materialize if needed.
    let current_backend = node.state.read().unwrap().current_backend();
    if let Some(current) = current_backend
        && current != target
    {
        super::materialize::do_materialize(fs, ctx, ino, current, target)?;
    }

    // Dispatch setattr.
    let target_inode = super::lookup::resolve_backend_inode(&fs.state, ino, target)
        .ok_or_else(platform::einval)?;

    let step = DispatchStep {
        backend: target,
        op: OpKind::Setattr,
        inode: target_inode,
        handle: None,
    };

    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| {
            h.before_dispatch(ctx, &step)
        }),
        decode_attr,
    ) {
        return r;
    }

    let (mut st, ttl) = backend(fs, target).setattr(ctx, target_inode, attr, None, valid)?;
    st.st_ino = ino;

    mark_metadata_authority(&fs.state, ino, target);

    // hooks.after_dispatch
    notify_observers(&fs.hooks, |h| {
        h.after_dispatch(&hook_ctx, &step, &StepResult::Attr(st, ttl));
    });

    Ok((st, ttl))
}

/// Handle access. Direct dispatch from node state.
pub(crate) fn do_access(fs: &DualFs, ctx: Context, ino: u64, mask: u32) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        if mask & platform::ACCESS_W_OK != 0 {
            return Err(io::Error::from_raw_os_error(libc::EACCES));
        }
        return Ok(());
    }

    let node = get_node(&fs.state, ino)?;
    let (backend_id, child_inode) = resolve_active_backend_inode(&node);

    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Access,
            guest_inode: ino,
            node_state: node.state.read().unwrap().clone(),
            file_kind: node.kind,
            flags: mask,
            name: Vec::new(),
            parent_inode: 0,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    let step = DispatchStep {
        backend: backend_id,
        op: OpKind::Access,
        inode: child_inode,
        handle: None,
    };

    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| {
            h.before_dispatch(ctx, &step)
        }),
        decode_ok,
    ) {
        return r;
    }

    let result = backend(fs, backend_id).access(ctx, child_inode, mask);

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
