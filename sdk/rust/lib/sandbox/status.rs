//! Sandbox lifecycle status.

#[cfg(feature = "local")]
pub use microsandbox_db::entity::sandbox::SandboxStatus;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The lifecycle status of a sandbox.
#[cfg(not(feature = "local"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SandboxStatus {
    /// The sandbox has been created but not yet started.
    Created,
    /// A start request has been accepted but is not yet running.
    Starting,
    /// The sandbox is running.
    Running,
    /// The sandbox is draining gracefully.
    Draining,
    /// The sandbox is paused.
    Paused,
    /// The sandbox has stopped.
    Stopped,
    /// The sandbox exited after a failure.
    Crashed,
}
