//! Extended attribute operations: getxattr, listxattr, setxattr, removexattr.

use std::{ffi::CStr, io};

use super::{
    DualFs,
    lookup::{backend, get_node, mark_metadata_authority, resolve_active_backend_inode},
    policy::{DualNamespaceView, HintBag, OpKind, RequestCtx},
    types::BackendId,
};
use crate::{Context, GetxattrReply, ListxattrReply, backends::shared::init_binary};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Handle getxattr. Direct dispatch from node state.
pub(crate) fn do_getxattr(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    name: &CStr,
    size: u32,
) -> io::Result<GetxattrReply> {
    if ino == init_binary::INIT_INODE {
        return Err(io::Error::from_raw_os_error(libc::ENODATA));
    }

    let node = get_node(&fs.state, ino)?;
    let (backend_id, child_inode) = resolve_active_backend_inode(&node);

    backend(fs, backend_id).getxattr(ctx, child_inode, name, size)
}

/// Handle listxattr. Direct dispatch from node state.
pub(crate) fn do_listxattr(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    size: u32,
) -> io::Result<ListxattrReply> {
    if ino == init_binary::INIT_INODE {
        if size == 0 {
            return Ok(ListxattrReply::Count(0));
        }
        return Ok(ListxattrReply::Names(Vec::new()));
    }

    let node = get_node(&fs.state, ino)?;
    let (backend_id, child_inode) = resolve_active_backend_inode(&node);

    backend(fs, backend_id).listxattr(ctx, child_inode, size)
}

/// Handle setxattr. Full pipeline with policy routing.
pub(crate) fn do_setxattr(
    fs: &DualFs,
    ctx: Context,
    ino: u64,
    name: &CStr,
    value: &[u8],
    flags: u32,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }

    let node = get_node(&fs.state, ino)?;

    let view = DualNamespaceView { state: &fs.state };
    let req = RequestCtx {
        op: OpKind::Setxattr,
        guest_inode: ino,
        node_state: node.state.read().unwrap().clone(),
        file_kind: node.kind,
        flags,
        name: Vec::new(),
        parent_inode: 0,
    };
    let plan = fs.policy.plan(&req, &view, &HintBag::new())?;
    let target = plan.target_backend().unwrap_or(BackendId::BackendA);

    // Materialize if needed.
    let current_backend = node.state.read().unwrap().current_backend();
    if let Some(current) = current_backend
        && current != target
    {
        super::materialize::do_materialize(fs, ctx, ino, current, target)?;
    }

    let target_inode = super::lookup::resolve_backend_inode(&fs.state, ino, target)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;

    backend(fs, target).setxattr(ctx, target_inode, name, value, flags)?;
    mark_metadata_authority(&fs.state, ino, target);

    Ok(())
}

/// Handle removexattr. Full pipeline with policy routing.
pub(crate) fn do_removexattr(fs: &DualFs, ctx: Context, ino: u64, name: &CStr) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Err(io::Error::from_raw_os_error(libc::EACCES));
    }

    let node = get_node(&fs.state, ino)?;

    let view = DualNamespaceView { state: &fs.state };
    let req = RequestCtx {
        op: OpKind::Removexattr,
        guest_inode: ino,
        node_state: node.state.read().unwrap().clone(),
        file_kind: node.kind,
        flags: 0,
        name: Vec::new(),
        parent_inode: 0,
    };
    let plan = fs.policy.plan(&req, &view, &HintBag::new())?;
    let target = plan.target_backend().unwrap_or(BackendId::BackendA);

    // Materialize if needed.
    let current_backend = node.state.read().unwrap().current_backend();
    if let Some(current) = current_backend
        && current != target
    {
        super::materialize::do_materialize(fs, ctx, ino, current, target)?;
    }

    let target_inode = super::lookup::resolve_backend_inode(&fs.state, ino, target)
        .ok_or_else(|| io::Error::from_raw_os_error(libc::EINVAL))?;

    backend(fs, target).removexattr(ctx, target_inode, name)?;
    mark_metadata_authority(&fs.state, ino, target);

    Ok(())
}
