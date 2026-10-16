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
#[cfg(all(feature = "local", test, unix))]
pub(in crate::sandbox) use local::control_request_for_run;
#[cfg(all(feature = "local", target_os = "linux"))]
pub(in crate::sandbox) use local::control_request_for_run_with_memory;
#[cfg(feature = "local")]
pub(in crate::sandbox) use local::control_session_for_run;
#[cfg(feature = "local")]
pub(crate) use local::{
    capture_flush_policy, control_checkpoint_create, control_disk_checkpoint_create,
    control_disk_compact, restore_requested_resources,
};
pub use microsandbox_types::modify::{
    ChangeKind, ConfigPlannedChange, ModificationConflict, ModificationDisposition,
    ModificationPolicy, ModificationWarning, PlannedChange, PublishedPortKey,
    ResourceConvergenceState, ResourceKind, ResourceResizeStatus, SandboxModificationPatch,
    SandboxModificationPlan, SecretChangeKind, SecretModificationPatch, SecretPlannedChange,
    SecretSource,
};
