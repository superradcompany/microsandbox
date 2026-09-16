//! Stable sandbox identity exposed by lifecycle handles.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An opaque, backend-assigned identity for one persisted sandbox.
///
/// Names are reusable labels. This identity is stable for the lifetime of the
/// persisted sandbox and changes when a sandbox is removed and recreated with
/// the same name.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SandboxId(pub(crate) String);

/// One local runtime generation selected before opening a name-addressed control endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg(feature = "local")]
pub(crate) struct SandboxRunIdentity {
    pub(crate) sandbox_id: i32,
    pub(crate) run_id: i32,
    pub(crate) pid: i32,
}

/// Exact source selected for a direct branch before reserving its child.
#[derive(Clone, Debug)]
#[cfg(feature = "local")]
pub(crate) struct BranchSource {
    /// Negotiated capture policy; None preserves an older runtime's full-capture default.
    pub(crate) guest_flush: Option<microsandbox_types::GuestFlush>,
    /// Process-local shared capture. Never serialized or interpreted by older runtimes.
    pub(crate) batch:
        Option<std::sync::Arc<super::branch_batch::CaptureSlot<super::branch_batch::BatchCapture>>>,
    /// Explicit disk integrity policy for this one capture, never inherited by descendants.
    pub(crate) record_integrity: bool,
    pub(crate) name: String,
    pub(crate) run: SandboxRunIdentity,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxId {
    pub(crate) fn local(db_id: i32) -> Self {
        Self(format!("local:{db_id}"))
    }

    pub(crate) fn cloud(id: &str) -> Self {
        Self(format!("cloud:{id}"))
    }

    /// Return the opaque identity as a string.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Display for SandboxId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl AsRef<str> for SandboxId {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}
