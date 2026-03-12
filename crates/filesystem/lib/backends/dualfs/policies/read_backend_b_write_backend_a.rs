//! Default policy: reads fall through to backend_b, writes go to backend_a.

use std::io;

use crate::backends::dualfs::policy::{
    BackendChoice, BackendOp, DualDispatchPlan, DualDispatchPolicy, DualNamespaceView, HintBag,
    OpKind, RequestCtx,
};
use crate::backends::dualfs::types::{BackendId, NodeState};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Default dispatch policy: read from backend_b, write to backend_a.
///
/// Lookups merge with backend_b precedence. Writes go to backend_a,
/// triggering materialization when the target is backed by backend_b.
pub struct ReadBackendBWriteBackendA;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DualDispatchPolicy for ReadBackendBWriteBackendA {
    fn plan(
        &self,
        req: &RequestCtx,
        _view: &DualNamespaceView<'_>,
        _hints: &HintBag,
    ) -> io::Result<DualDispatchPlan> {
        match req.op {
            OpKind::Lookup => Ok(DualDispatchPlan::MergeLookup {
                precedence: BackendChoice::BackendBFirst,
            }),

            OpKind::Open => {
                let write_flags = libc::O_WRONLY | libc::O_RDWR | libc::O_TRUNC;
                let is_write = (req.flags as i32) & write_flags != 0;

                if is_write {
                    match &req.node_state {
                        NodeState::BackendB { .. } => {
                            Ok(DualDispatchPlan::MaterializeToBackendThen {
                                source: BackendId::BackendB,
                                target: BackendId::BackendA,
                                then: BackendOp::passthrough(),
                            })
                        }
                        NodeState::BackendA { .. }
                        | NodeState::MergedDir { .. }
                        | NodeState::Root { .. } => Ok(DualDispatchPlan::UseBackendA {
                            op: BackendOp::passthrough(),
                        }),
                        NodeState::Init => Ok(DualDispatchPlan::Deny {
                            errno: libc::EACCES,
                        }),
                    }
                } else {
                    match &req.node_state {
                        NodeState::BackendA { .. }
                        | NodeState::MergedDir { .. }
                        | NodeState::Root { .. } => Ok(DualDispatchPlan::UseBackendA {
                            op: BackendOp::passthrough(),
                        }),
                        NodeState::BackendB { .. } => Ok(DualDispatchPlan::UseBackendB {
                            op: BackendOp::passthrough(),
                        }),
                        NodeState::Init => Ok(DualDispatchPlan::Deny {
                            errno: libc::EACCES,
                        }),
                    }
                }
            }

            OpKind::Create
            | OpKind::Mkdir
            | OpKind::Mknod
            | OpKind::Symlink
            | OpKind::Link
            | OpKind::Unlink
            | OpKind::Rmdir
            | OpKind::Rename => Ok(DualDispatchPlan::UseBackendA {
                op: BackendOp::passthrough(),
            }),

            OpKind::Setattr | OpKind::Setxattr | OpKind::Removexattr => {
                match &req.node_state {
                    NodeState::BackendB { .. } => {
                        Ok(DualDispatchPlan::MaterializeToBackendThen {
                            source: BackendId::BackendB,
                            target: BackendId::BackendA,
                            then: BackendOp::passthrough(),
                        })
                    }
                    _ => Ok(DualDispatchPlan::UseBackendA {
                        op: BackendOp::passthrough(),
                    }),
                }
            }

            OpKind::Readdir | OpKind::Readdirplus => Ok(DualDispatchPlan::MergeReaddir {
                precedence: BackendChoice::BackendBFirst,
            }),

            OpKind::Opendir => Ok(DualDispatchPlan::MergeReaddir {
                precedence: BackendChoice::BackendBFirst,
            }),

            // Handle-bound and direct-dispatch ops are not policy-routed.
            // Return UseBackendA as fallback — the core handles routing.
            _ => Ok(DualDispatchPlan::UseBackendA {
                op: BackendOp::passthrough(),
            }),
        }
    }
}
