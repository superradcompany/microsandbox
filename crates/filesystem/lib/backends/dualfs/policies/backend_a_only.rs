//! All policy-routed operations go to backend_a; backend_b is never consulted.

use std::io;

use crate::backends::dualfs::policy::{
    BackendOp, DualDispatchPlan, DualDispatchPolicy, DualNamespaceView, HintBag, RequestCtx,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// All operations go to backend_a. Backend_b is never consulted for lookups,
/// creates, or mutations.
///
/// Note: `statfs` is core-dispatched (not policy-routed) and always merges
/// both backends regardless of policy.
pub struct BackendAOnly;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DualDispatchPolicy for BackendAOnly {
    fn plan(
        &self,
        _req: &RequestCtx,
        _view: &DualNamespaceView<'_>,
        _hints: &HintBag,
    ) -> io::Result<DualDispatchPlan> {
        Ok(DualDispatchPlan::UseBackendA {
            op: BackendOp::passthrough(),
        })
    }
}
