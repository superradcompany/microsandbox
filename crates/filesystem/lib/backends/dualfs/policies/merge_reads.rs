//! Lookups and readdir merge with backend_a winning ties. Mutations go to backend_a.

use std::io;

use crate::backends::dualfs::policy::{
    BackendChoice, BackendOp, DualDispatchPlan, DualDispatchPolicy, DualNamespaceView, HintBag,
    OpKind, RequestCtx,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Lookups and readdir merge with backend_a winning ties.
/// Mutations go to backend_a.
pub struct MergeReadsBackendAPrecedence;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DualDispatchPolicy for MergeReadsBackendAPrecedence {
    fn plan(
        &self,
        req: &RequestCtx,
        _view: &DualNamespaceView<'_>,
        _hints: &HintBag,
    ) -> io::Result<DualDispatchPlan> {
        match req.op {
            OpKind::Lookup => Ok(DualDispatchPlan::MergeLookup {
                precedence: BackendChoice::BackendAFirst,
            }),

            OpKind::Readdir | OpKind::Readdirplus | OpKind::Opendir => {
                Ok(DualDispatchPlan::MergeReaddir {
                    precedence: BackendChoice::BackendAFirst,
                })
            }

            _ => Ok(DualDispatchPlan::UseBackendA {
                op: BackendOp::passthrough(),
            }),
        }
    }
}
