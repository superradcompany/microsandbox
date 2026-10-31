//! Sandbox modification: the builders, the dispatch to a backend, and the
//! plan types.
//!
//! A local sandbox is planned and applied by the engine in `local`; a Cloud
//! sandbox by the server, through the cloud backend.

mod builder;
#[cfg(feature = "local")]
mod local;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use builder::{SandboxModificationBuilder, SecretPatchBuilder};
pub use microsandbox_types::modify::{
    ChangeKind, ConfigPlannedChange, ModificationConflict, ModificationDisposition,
    ModificationPolicy, ModificationWarning, PlannedChange, PublishedPortKey,
    ResourceConvergenceState, ResourceKind, ResourceResizeStatus, SandboxModificationPatch,
    SandboxModificationPlan, SecretChangeKind, SecretModificationPatch, SecretPlannedChange,
    SecretSource,
};
