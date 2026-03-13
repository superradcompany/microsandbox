//! Statfs (merge both backends), lseek, fallocate, fsync, fsyncdir.

use std::{io, sync::Arc};

use super::{
    DualFs,
    hooks::{
        DispatchStep, HookCtx, StepResult, decode_ok, handle_hook_decision, notify_observers,
        run_decision_hooks,
    },
    lookup::get_node,
    policy::{HintBag, OpKind, RequestCtx},
    types::{DualHandle, FileKind, NodeState, ROOT_INODE},
};
use crate::{Context, backends::shared::init_binary, statvfs64};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Handle statfs. Core-dispatched: always merges both backends.
pub(crate) fn do_statfs(fs: &DualFs, ctx: Context, _ino: u64) -> io::Result<statvfs64> {
    let root_node = get_node(&fs.state, ROOT_INODE)?;
    let state = root_node.state.read().unwrap();

    let (ba_root, bb_root) = match &*state {
        NodeState::Root {
            backend_a_root,
            backend_b_root,
        } => (*backend_a_root, *backend_b_root),
        _ => return Err(io::Error::from_raw_os_error(libc::EIO)),
    };
    drop(state);

    let ba_stat = fs.backend_a.statfs(ctx, ba_root)?;
    let bb_stat = fs.backend_b.statfs(ctx, bb_root)?;

    let unit = std::cmp::min(
        std::cmp::max(ba_stat.f_frsize, 1),
        std::cmp::max(bb_stat.f_frsize, 1),
    );

    let to_units = |blocks: u64, frsize: u64| -> u64 {
        blocks
            .saturating_mul(std::cmp::max(frsize, 1))
            .saturating_div(unit)
    };

    let mut st: statvfs64 = unsafe { std::mem::zeroed() };

    #[cfg(target_os = "linux")]
    {
        st.f_bsize = unit;
        st.f_frsize = unit;
        st.f_blocks = to_units(ba_stat.f_blocks, ba_stat.f_frsize)
            .saturating_add(to_units(bb_stat.f_blocks, bb_stat.f_frsize));
        st.f_bfree = to_units(ba_stat.f_bfree, ba_stat.f_frsize)
            .saturating_add(to_units(bb_stat.f_bfree, bb_stat.f_frsize));
        st.f_bavail = to_units(ba_stat.f_bavail, ba_stat.f_frsize)
            .saturating_add(to_units(bb_stat.f_bavail, bb_stat.f_frsize));
        st.f_files = ba_stat.f_files.saturating_add(bb_stat.f_files);
        st.f_ffree = ba_stat.f_ffree.saturating_add(bb_stat.f_ffree);
        st.f_favail = ba_stat.f_favail.saturating_add(bb_stat.f_favail);
        st.f_namemax = std::cmp::min(ba_stat.f_namemax, bb_stat.f_namemax);
    }

    #[cfg(target_os = "macos")]
    {
        st.f_bsize = unit;
        st.f_frsize = unit;
        st.f_blocks = to_units(ba_stat.f_blocks as u64, ba_stat.f_frsize)
            .saturating_add(to_units(bb_stat.f_blocks as u64, bb_stat.f_frsize))
            as u32;
        st.f_bfree = to_units(ba_stat.f_bfree as u64, ba_stat.f_frsize)
            .saturating_add(to_units(bb_stat.f_bfree as u64, bb_stat.f_frsize))
            as u32;
        st.f_bavail = to_units(ba_stat.f_bavail as u64, ba_stat.f_frsize)
            .saturating_add(to_units(bb_stat.f_bavail as u64, bb_stat.f_frsize))
            as u32;
        st.f_files = (ba_stat.f_files as u64).saturating_add(bb_stat.f_files as u64) as u32;
        st.f_ffree = (ba_stat.f_ffree as u64).saturating_add(bb_stat.f_ffree as u64) as u32;
        st.f_favail = (ba_stat.f_favail as u64).saturating_add(bb_stat.f_favail as u64) as u32;
        st.f_namemax = std::cmp::min(ba_stat.f_namemax, bb_stat.f_namemax);
    }

    Ok(st)
}

/// Handle fsync. Handle-bound dispatch with hooks.
pub(crate) fn do_fsync(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    datasync: bool,
    handle: u64,
) -> io::Result<()> {
    let fh = get_file_handle(fs, handle)?;

    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Fsync,
            guest_inode: ino,
            node_state: NodeState::Init, // Placeholder, handle-bound.
            file_kind: FileKind::RegularFile,
            flags: 0,
            name: Vec::new(),
            parent_inode: 0,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    let step = DispatchStep {
        backend: fh.backend_id(),
        op: OpKind::Fsync,
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
        } => fs
            .backend_a
            .fsync(ctx, *backend_a_inode, datasync, *backend_a_handle),
        DualHandle::BackendB {
            backend_b_inode,
            backend_b_handle,
            ..
        } => fs
            .backend_b
            .fsync(ctx, *backend_b_inode, datasync, *backend_b_handle),
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

/// Handle fsyncdir. No-op.
pub(crate) fn do_fsyncdir(
    _fs: &DualFs,
    _ctx: Context,
    _ino: u64,
    _datasync: bool,
    _handle: u64,
) -> io::Result<()> {
    Ok(())
}

/// Handle lseek. Handle-bound dispatch with hooks.
pub(crate) fn do_lseek(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    handle: u64,
    offset: u64,
    whence: u32,
) -> io::Result<u64> {
    if ino == init_binary::INIT_INODE {
        // Simple seek for init binary.
        let size = crate::agentd::AGENTD_BYTES.len() as u64;
        return match whence {
            w if w == libc::SEEK_SET as u32 => Ok(offset),
            w if w == libc::SEEK_END as u32 => Ok(size),
            _ => Ok(offset),
        };
    }

    let fh = get_file_handle(fs, handle)?;

    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Lseek,
            guest_inode: ino,
            node_state: NodeState::Init,
            file_kind: FileKind::RegularFile,
            flags: 0,
            name: Vec::new(),
            parent_inode: 0,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    let step = DispatchStep {
        backend: fh.backend_id(),
        op: OpKind::Lseek,
        inode: fh.child_inode(),
        handle: Some(fh.child_handle()),
    };

    if let std::ops::ControlFlow::Break(r) = handle_hook_decision(
        run_decision_hooks(&fs.hooks, &mut hook_ctx, |h, ctx| {
            h.before_dispatch(ctx, &step)
        }),
        super::hooks::decode_usize,
    ) {
        return r.map(|n| n as u64);
    }

    let result = match fh.as_ref() {
        DualHandle::BackendA {
            backend_a_inode,
            backend_a_handle,
            ..
        } => fs
            .backend_a
            .lseek(ctx, *backend_a_inode, *backend_a_handle, offset, whence),
        DualHandle::BackendB {
            backend_b_inode,
            backend_b_handle,
            ..
        } => fs
            .backend_b
            .lseek(ctx, *backend_b_inode, *backend_b_handle, offset, whence),
    };

    notify_observers(&fs.hooks, |h| {
        h.after_dispatch(
            &hook_ctx,
            &step,
            &match &result {
                Ok(n) => StepResult::Data(*n as usize),
                Err(e) => StepResult::Err(io::Error::from_raw_os_error(
                    e.raw_os_error().unwrap_or(libc::EIO),
                )),
            },
        );
    });

    result
}

/// Handle fallocate. Handle-bound dispatch with hooks.
pub(crate) fn do_fallocate(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    handle: u64,
    mode: u32,
    offset: u64,
    length: u64,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }

    let fh = get_file_handle(fs, handle)?;

    let mut hook_ctx = HookCtx {
        req: RequestCtx {
            op: OpKind::Fallocate,
            guest_inode: ino,
            node_state: NodeState::Init,
            file_kind: FileKind::RegularFile,
            flags: 0,
            name: Vec::new(),
            parent_inode: 0,
        },
        hints: HintBag::new(),
        metadata: Default::default(),
    };

    let step = DispatchStep {
        backend: fh.backend_id(),
        op: OpKind::Fallocate,
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
        } => fs.backend_a.fallocate(
            ctx,
            *backend_a_inode,
            *backend_a_handle,
            mode,
            offset,
            length,
        ),
        DualHandle::BackendB {
            backend_b_inode,
            backend_b_handle,
            ..
        } => fs.backend_b.fallocate(
            ctx,
            *backend_b_inode,
            *backend_b_handle,
            mode,
            offset,
            length,
        ),
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

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

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
