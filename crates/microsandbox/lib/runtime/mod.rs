//! Sandbox process management.
//!
//! Provides [`ProcessHandle`] for interacting with a running sandbox
//! process and [`spawn_sandbox`] for starting one from a
//! [`crate::sandbox::SandboxConfig`].

pub(crate) mod handle;
pub(crate) mod spawn;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use handle::ProcessHandle;
pub use spawn::{SpawnMode, spawn_sandbox};
