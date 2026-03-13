//! Dispatch policy traits and plan types.
//!
//! The policy decides how each FUSE operation uses the two child backends.
//! The core calls `policy.plan()` to get a `DualDispatchPlan` and executes
//! it safely.

use std::io;

use super::types::{BackendId, DualState, NodeState};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Decides how each FUSE operation should be dispatched to the two backends.
///
/// Called once per plan-eligible operation, before dispatch. Must be fast (no I/O).
pub trait DualDispatchPolicy: Send + Sync {
    /// Plan the dispatch strategy for the given request.
    fn plan(
        &self,
        req: &RequestCtx,
        view: &DualNamespaceView<'_>,
        hints: &HintBag,
    ) -> io::Result<DualDispatchPlan>;
}

/// Describes the incoming FUSE operation for the policy to inspect.
pub struct RequestCtx {
    /// The FUSE operation kind.
    pub op: OpKind,
    /// Guest inode the operation targets.
    pub guest_inode: u64,
    /// Current backing state of the target node.
    pub node_state: NodeState,
    /// File kind.
    pub file_kind: super::types::FileKind,
    /// Operation-specific flags.
    pub flags: u32,
    /// Name argument (for name-based ops).
    pub name: Vec<u8>,
    /// Parent guest inode (for name-based ops). 0 for inode-only ops.
    pub parent_inode: u64,
}

/// FUSE operation kind.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(missing_docs)]
pub enum OpKind {
    Lookup,
    Getattr,
    Setattr,
    Readlink,
    Open,
    Read,
    Write,
    Create,
    Mkdir,
    Mknod,
    Symlink,
    Link,
    Unlink,
    Rmdir,
    Rename,
    Opendir,
    Readdir,
    Readdirplus,
    Setxattr,
    Getxattr,
    Listxattr,
    Removexattr,
    Flush,
    Release,
    Releasedir,
    Fsync,
    Fsyncdir,
    Access,
    Lseek,
    Fallocate,
    Statfs,
}

/// Read-only view of the namespace state for policy decisions.
pub struct DualNamespaceView<'a> {
    pub(crate) state: &'a DualState,
}

/// Hints accumulated from hooks during the before_plan phase.
pub struct HintBag {
    /// Accumulated hints.
    pub hints: Vec<Hint>,
}

/// A typed hint from a hook to the policy.
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum Hint {
    /// Prefer a specific backend for this operation.
    PreferBackend(BackendId),
    /// Subtree affinity.
    SubtreeAffinity { root_inode: u64, backend: BackendId },
    /// Custom string hint for policy-specific use.
    Custom(String),
}

/// The dispatch plan returned by policy.plan().
#[derive(Debug, Clone)]
#[allow(missing_docs)]
pub enum DualDispatchPlan {
    /// Route the operation to backend_a.
    UseBackendA { op: BackendOp },
    /// Route the operation to backend_b.
    UseBackendB { op: BackendOp },
    /// Try backend_a first; on specified errno(s), fall back to backend_b.
    TryBackendAThenBackendB {
        op: BackendOp,
        fallback_on: Vec<i32>,
    },
    /// Try backend_b first; on specified errno(s), fall back to backend_a.
    TryBackendBThenBackendA {
        op: BackendOp,
        fallback_on: Vec<i32>,
    },
    /// Merge lookup: try both backends with precedence order.
    MergeLookup { precedence: BackendChoice },
    /// Merge readdir results from both backends.
    MergeReaddir { precedence: BackendChoice },
    /// Materialize then execute the operation.
    MaterializeToBackendThen {
        source: BackendId,
        target: BackendId,
        then: BackendOp,
    },
    /// Return a synthetic response without calling any backend.
    Synthetic {
        response: super::hooks::SyntheticResponse,
    },
    /// Deny the operation with an errno.
    Deny { errno: i32 },
}

/// Precedence for merge operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendChoice {
    /// Try backend_a first.
    BackendAFirst,
    /// Try backend_b first.
    BackendBFirst,
}

/// Opaque operation descriptor.
#[derive(Debug, Clone)]
pub struct BackendOp {
    /// Additional flags or overrides for the backend call.
    pub flags: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DualNamespaceView<'_> {
    /// Check if a dentry exists.
    pub fn has_dentry(&self, parent: u64, name: &[u8]) -> bool {
        self.state
            .dentries
            .read()
            .unwrap()
            .contains_key(&(parent, name.to_vec()))
    }

    /// Check if a name is hidden for a specific backend.
    pub fn is_whiteout(&self, parent: u64, name: &[u8], hidden_backend: BackendId) -> bool {
        self.state.is_whited_out(parent, name, hidden_backend)
    }

    /// Check if a directory is opaque against a specific backend.
    pub fn is_opaque(&self, dir_inode: u64, hidden_backend: BackendId) -> bool {
        self.state.is_opaque(dir_inode, hidden_backend)
    }

    /// Get node state for a guest inode.
    pub fn node_state(&self, inode: u64) -> Option<NodeState> {
        self.state
            .nodes
            .read()
            .unwrap()
            .get(&inode)
            .map(|n| n.state.read().unwrap().clone())
    }

    /// Check if a backend_b inode has been seen before.
    pub fn backend_b_inode_known(&self, backend_b_inode: u64) -> bool {
        self.state
            .backend_b_inode_map
            .read()
            .unwrap()
            .contains_key(&backend_b_inode)
    }
}

impl HintBag {
    pub(crate) fn new() -> Self {
        HintBag { hints: Vec::new() }
    }

    /// Add a hint.
    pub fn push(&mut self, hint: Hint) {
        self.hints.push(hint);
    }

    /// Add multiple hints.
    pub fn extend(&mut self, hints: Vec<Hint>) {
        self.hints.extend(hints);
    }
}

impl BackendOp {
    /// Create a passthrough operation with no flag overrides.
    pub fn passthrough() -> Self {
        BackendOp { flags: 0 }
    }
}

impl DualDispatchPlan {
    /// Return the target backend for plans that select a single backend.
    pub(crate) fn target_backend(&self) -> Option<BackendId> {
        match self {
            DualDispatchPlan::UseBackendA { .. } => Some(BackendId::BackendA),
            DualDispatchPlan::UseBackendB { .. } => Some(BackendId::BackendB),
            DualDispatchPlan::MaterializeToBackendThen { target, .. } => Some(*target),
            _ => None,
        }
    }
}
