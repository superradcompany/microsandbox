//! Sandbox process management.
//!
//! Provides [`ProcessHandle`] for interacting with a running sandbox
//! process and [`spawn_sandbox`] for starting one from a
//! [`crate::sandbox::SandboxConfig`].

pub(crate) mod handle;
// The pure identity helpers stay compiled (and unit-tested) on every platform;
// only Windows has call sites outside the tests.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) mod reap;
pub(crate) mod spawn;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use handle::ProcessHandle;
pub use spawn::{SpawnMode, spawn_sandbox};
pub(crate) use spawn::{
    acquire_sandbox_lifecycle_guard, ensure_named_volumes, remove_sandbox_socket_artifacts_at,
    remove_sandbox_socket_artifacts_for, resolve_sandbox_agent_socket_path,
    resolve_sandbox_agent_socket_path_for, rollback_created_named_volumes,
    sandbox_agent_socket_path_candidates, sandbox_agent_socket_path_candidates_for,
};

/// Resolve the host-side path of a sandbox's agentd relay socket by name.
///
/// Returns the same path the runtime dials internally: the canonical
/// per-sandbox path under the run directory, an existing legacy flat path for
/// an older runtime, or the retained in-sandbox fallback for deep homes.
///
/// Use this when you need to talk to agentd over a *raw byte transport* rather
/// than the frame-protocol client in [`crate::agent`] — for example a
/// transparent relay that splices bytes between a WebSocket and this socket.
/// The path is derived from `name` and the configured home; the sandbox need
/// not be running.
pub fn agent_socket_path(name: &str) -> crate::MicrosandboxResult<std::path::PathBuf> {
    resolve_sandbox_agent_socket_path(name)
}
