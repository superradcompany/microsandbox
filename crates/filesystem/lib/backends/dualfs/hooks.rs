//! Lifecycle hooks for DualFs dispatch pipeline.
//!
//! Hooks observe and influence dispatch without doing filesystem work.
//! They run at defined pipeline points and can add hints, deny operations,
//! or short-circuit responses.

use std::collections::HashMap;
use std::io;
use std::time::Duration;

use super::policy::{DualDispatchPlan, DualNamespaceView, HintBag, Hint, OpKind, RequestCtx};
use super::types::{BackendId, NodeState};
use crate::{Entry, OpenOptions, stat64};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Lifecycle hooks for observing and influencing dispatch.
///
/// All methods default to `Continue` / no-op. Implement only the methods you need.
#[allow(unused_variables)]
pub trait DualDispatchHook: Send + Sync {
    // ── Decision phases (can deny or short-circuit) ──

    /// Before namespace resolution.
    fn before_resolve(&self, ctx: &mut HookCtx) -> HookDecision {
        HookDecision::Continue
    }

    /// After namespace resolution.
    fn after_resolve(&self, ctx: &mut HookCtx, view: &DualNamespaceView<'_>) -> HookDecision {
        HookDecision::Continue
    }

    /// Before policy.plan(). Can add hints to influence the policy.
    fn before_plan(&self, ctx: &mut HookCtx) -> HookDecision {
        HookDecision::Continue
    }

    /// After policy.plan(). Sees the dispatch plan.
    fn after_plan(&self, ctx: &mut HookCtx, plan: &DualDispatchPlan) -> HookDecision {
        HookDecision::Continue
    }

    /// Before backend dispatch. Last chance to deny or short-circuit.
    fn before_dispatch(&self, ctx: &mut HookCtx, step: &DispatchStep) -> HookDecision {
        HookDecision::Continue
    }

    // ── Observer phases (fire-and-forget) ──

    /// After backend dispatch. Observe-only.
    fn after_dispatch(&self, ctx: &HookCtx, step: &DispatchStep, out: &StepResult) {}

    /// After state commit. Fire-and-forget.
    fn after_commit(&self, event: &CommitEvent) {}

    /// Pre-return observer. Fire-and-forget.
    fn after_response(&self, event: &ResponseEvent) {}
}

/// Mutable context threaded through the hook chain for a single operation.
pub struct HookCtx {
    /// The incoming request.
    pub req: RequestCtx,
    /// Hints accumulated so far.
    pub hints: HintBag,
    /// Operation-level metadata.
    pub metadata: HashMap<String, String>,
}

/// The result of a hook invocation.
#[derive(Debug)]
pub enum HookDecision {
    /// Continue to the next hook / pipeline stage.
    Continue,
    /// Deny the operation with an errno.
    Deny(i32),
    /// Add a hint for the policy.
    AddHint(Hint),
    /// Add multiple hints.
    AddHints(Vec<Hint>),
    /// Short-circuit the pipeline with a synthetic response.
    ShortCircuit(SyntheticResponse),
}

/// Describes a single backend call about to be made.
#[derive(Debug)]
pub struct DispatchStep {
    /// Which backend.
    pub backend: BackendId,
    /// Operation kind.
    pub op: OpKind,
    /// Child backend inode.
    pub inode: u64,
    /// Child backend handle, if applicable.
    pub handle: Option<u64>,
}

/// The result of a single backend call.
#[allow(missing_docs)]
pub enum StepResult {
    Ok,
    Entry(Entry),
    Attr(stat64, Duration),
    Handle(u64, OpenOptions),
    Data(usize),
    Err(io::Error),
}

impl std::fmt::Debug for StepResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StepResult::Ok => write!(f, "Ok"),
            StepResult::Entry(e) => write!(f, "Entry(inode={})", e.inode),
            StepResult::Attr(_, ttl) => write!(f, "Attr(ttl={:?})", ttl),
            StepResult::Handle(h, opts) => write!(f, "Handle({}, {:?})", h, opts),
            StepResult::Data(n) => write!(f, "Data({})", n),
            StepResult::Err(e) => write!(f, "Err({:?})", e),
        }
    }
}

/// A pre-built response for operations that don't need backend calls.
pub enum SyntheticResponse {
    /// Synthetic Entry.
    Entry(Entry),
    /// Synthetic attributes.
    Attr(stat64, Duration),
    /// Synthetic open handle.
    Open(Option<u64>, OpenOptions),
    /// Synthetic read data.
    Data(Vec<u8>),
    /// Synthetic readlink target.
    LinkTarget(Vec<u8>),
    /// Empty success.
    Ok,
}

impl std::fmt::Debug for SyntheticResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SyntheticResponse::Entry(e) => write!(f, "Entry(inode={})", e.inode),
            SyntheticResponse::Attr(_, ttl) => write!(f, "Attr(ttl={:?})", ttl),
            SyntheticResponse::Open(h, opts) => write!(f, "Open({:?}, {:?})", h, opts),
            SyntheticResponse::Data(d) => write!(f, "Data(len={})", d.len()),
            SyntheticResponse::LinkTarget(t) => write!(f, "LinkTarget(len={})", t.len()),
            SyntheticResponse::Ok => write!(f, "Ok"),
        }
    }
}

impl Clone for SyntheticResponse {
    fn clone(&self) -> Self {
        match self {
            SyntheticResponse::Entry(e) => SyntheticResponse::Entry(copy_entry(e)),
            SyntheticResponse::Attr(st, ttl) => SyntheticResponse::Attr(*st, *ttl),
            SyntheticResponse::Open(h, opts) => SyntheticResponse::Open(*h, *opts),
            SyntheticResponse::Data(d) => SyntheticResponse::Data(d.clone()),
            SyntheticResponse::LinkTarget(t) => SyntheticResponse::LinkTarget(t.clone()),
            SyntheticResponse::Ok => SyntheticResponse::Ok,
        }
    }
}

/// Describes a state change that was committed.
#[allow(missing_docs)]
pub struct CommitEvent {
    /// Operation kind.
    pub op: OpKind,
    /// Guest inode.
    pub guest_inode: u64,
    /// State transition that occurred (if any).
    pub transition: Option<(NodeState, NodeState)>,
    /// Dentries added/removed.
    pub dentry_changes: Vec<DentryChange>,
}

/// A single dentry change.
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum DentryChange {
    Added {
        parent: u64,
        name: Vec<u8>,
        child: u64,
    },
    Removed {
        parent: u64,
        name: Vec<u8>,
        child: u64,
    },
}

/// Describes the final response sent to the guest.
pub struct ResponseEvent {
    /// Operation kind.
    pub op: OpKind,
    /// Guest inode.
    pub guest_inode: u64,
    /// Ok or errno.
    pub result: Result<(), i32>,
    /// Latency of the operation.
    pub latency: Duration,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Run decision hooks (before_resolve through before_dispatch).
///
/// Returns the final decision. `AddHint`/`AddHints` are consumed internally.
pub(crate) fn run_decision_hooks<F>(
    hooks: &[std::sync::Arc<dyn DualDispatchHook>],
    ctx: &mut HookCtx,
    mut invoke: F,
) -> HookDecision
where
    F: FnMut(&dyn DualDispatchHook, &mut HookCtx) -> HookDecision,
{
    for hook in hooks {
        match invoke(hook.as_ref(), ctx) {
            HookDecision::Continue => continue,
            HookDecision::Deny(errno) => return HookDecision::Deny(errno),
            HookDecision::ShortCircuit(resp) => return HookDecision::ShortCircuit(resp),
            HookDecision::AddHint(h) => {
                ctx.hints.push(h);
                continue;
            }
            HookDecision::AddHints(hs) => {
                ctx.hints.extend(hs);
                continue;
            }
        }
    }
    HookDecision::Continue
}

/// Notify observer hooks (fire-and-forget).
pub(crate) fn notify_observers<F>(
    hooks: &[std::sync::Arc<dyn DualDispatchHook>],
    invoke: F,
) where
    F: Fn(&dyn DualDispatchHook),
{
    for hook in hooks {
        invoke(hook.as_ref());
    }
}

/// Handle a hook decision, returning `ControlFlow` for the caller.
///
/// `Continue` -> the caller should proceed.
/// `Deny` -> return an error.
/// `ShortCircuit` -> return the synthetic response decoded by `decode`.
pub(crate) fn handle_hook_decision<T, D>(
    decision: HookDecision,
    decode: D,
) -> std::ops::ControlFlow<io::Result<T>>
where
    D: FnOnce(SyntheticResponse) -> io::Result<T>,
{
    match decision {
        HookDecision::Continue => std::ops::ControlFlow::Continue(()),
        HookDecision::Deny(errno) => {
            std::ops::ControlFlow::Break(Err(io::Error::from_raw_os_error(errno)))
        }
        HookDecision::ShortCircuit(resp) => std::ops::ControlFlow::Break(decode(resp)),
        // AddHint/AddHints should have been consumed by run_decision_hooks.
        HookDecision::AddHint(_) | HookDecision::AddHints(_) => std::ops::ControlFlow::Continue(()),
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Decoders
//--------------------------------------------------------------------------------------------------

/// Decode a SyntheticResponse into an Entry.
pub(crate) fn decode_entry(resp: SyntheticResponse) -> io::Result<Entry> {
    match resp {
        SyntheticResponse::Entry(e) => Ok(e),
        _ => Err(crate::backends::shared::platform::einval()),
    }
}

/// Decode a SyntheticResponse into (stat64, Duration).
pub(crate) fn decode_attr(resp: SyntheticResponse) -> io::Result<(stat64, Duration)> {
    match resp {
        SyntheticResponse::Attr(st, ttl) => Ok((st, ttl)),
        _ => Err(crate::backends::shared::platform::einval()),
    }
}

/// Decode a SyntheticResponse into (Option<u64>, OpenOptions).
pub(crate) fn decode_open(resp: SyntheticResponse) -> io::Result<(Option<u64>, OpenOptions)> {
    match resp {
        SyntheticResponse::Open(h, opts) => Ok((h, opts)),
        _ => Err(crate::backends::shared::platform::einval()),
    }
}

/// Decode a SyntheticResponse into Vec<u8>.
#[allow(dead_code)]
pub(crate) fn decode_data(resp: SyntheticResponse) -> io::Result<Vec<u8>> {
    match resp {
        SyntheticResponse::Data(d) => Ok(d),
        SyntheticResponse::LinkTarget(d) => Ok(d),
        _ => Err(crate::backends::shared::platform::einval()),
    }
}

/// Decode a SyntheticResponse into ().
pub(crate) fn decode_ok(resp: SyntheticResponse) -> io::Result<()> {
    match resp {
        SyntheticResponse::Ok => Ok(()),
        _ => Err(crate::backends::shared::platform::einval()),
    }
}

/// Decode a SyntheticResponse into usize (for read/write byte counts).
pub(crate) fn decode_usize(resp: SyntheticResponse) -> io::Result<usize> {
    match resp {
        SyntheticResponse::Data(d) => Ok(d.len()),
        SyntheticResponse::Ok => Ok(0),
        _ => Err(crate::backends::shared::platform::einval()),
    }
}

/// Copy an Entry (all fields are individually Copy but Entry doesn't derive Clone).
pub(crate) fn copy_entry(e: &Entry) -> Entry {
    Entry {
        inode: e.inode,
        generation: e.generation,
        attr: e.attr,
        attr_flags: e.attr_flags,
        attr_timeout: e.attr_timeout,
        entry_timeout: e.entry_timeout,
    }
}
