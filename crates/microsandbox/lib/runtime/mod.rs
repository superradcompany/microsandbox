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
pub(crate) use spawn::{resolve_sandbox_agent_socket_path, sandbox_agent_socket_path_candidates};

/// Resolve the host-side path of a sandbox's agentd relay socket by name.
///
/// Returns the same path the runtime dials internally — the hashed path under
/// the run directory when it fits the platform's Unix-socket length limit, and
/// the legacy name-derived path otherwise.
///
/// Use this when you need to talk to agentd over a *raw byte transport* rather
/// than the frame-protocol client in [`crate::agent`] — for example a
/// transparent relay that splices bytes between a WebSocket and this socket.
/// The path is derived from `name` and the configured home; the sandbox need
/// not be running.
pub fn agent_socket_path(name: &str) -> crate::MicrosandboxResult<std::path::PathBuf> {
    resolve_sandbox_agent_socket_path(name)
}
