//! Runtime process management.
//!
//! Provides [`SupervisorHandle`] for interacting with a running supervisor
//! process and [`spawn_supervisor`] for starting one from a
//! [`crate::sandbox::SandboxConfig`].

pub(crate) mod handle;
pub(crate) mod spawn;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use handle::SupervisorHandle;
pub use spawn::{SupervisorSpawnMode, spawn_supervisor};
