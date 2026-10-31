//! Sandbox process management.
//!
//! Provides [`ProcessHandle`] for interacting with a running sandbox
//! process and [`spawn_sandbox`] for starting one from a
//! [`crate::sandbox::SandboxConfig`].

pub(crate) mod handle;
pub(crate) mod launch_contract;
mod launch_input;
mod lifecycle;
#[cfg(feature = "net")]
mod network_slot;
pub(crate) mod owned_volumes;
#[cfg(windows)]
pub(crate) mod ownership;
mod sockets;
// The pure identity helpers stay compiled (and unit-tested) on every platform;
// only Windows has call sites outside the tests.
pub(crate) mod protected_state;
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) mod reap;
pub(crate) mod spawn;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use handle::ProcessHandle;
pub(crate) use lifecycle::acquire_sandbox_lifecycle_guard;
pub(crate) use sockets::{
    default_agent_socket_paths, remove_socket_artifacts_at, resolve_agent_socket_path,
};
pub use spawn::{SpawnMode, spawn_sandbox};

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
    resolve_agent_socket_path(name)
}
