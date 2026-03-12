//! Reads try backend_a first, fall back to backend_b on ENOENT. Writes go to backend_a.

use std::io;

use crate::backends::dualfs::policy::{
    BackendChoice, BackendOp, DualDispatchPlan, DualDispatchPolicy, DualNamespaceView, HintBag,
    OpKind, RequestCtx,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Reads try backend_a first, fall back to backend_b on ENOENT.
/// Writes go to backend_a.
pub struct BackendAFallbackToBackendBRead;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DualDispatchPolicy for BackendAFallbackToBackendBRead {
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

            // All mutations go to backend_a.
            _ => Ok(DualDispatchPlan::UseBackendA {
                op: BackendOp::passthrough(),
            }),
        }
    }
}
