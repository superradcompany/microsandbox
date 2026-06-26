//! Agent communication with the guest VM.
//!
//! [`AgentClient`] is the Rust-ergonomic transport over the sandbox process's
//! agent relay socket. [`AgentBridge`] is a thinner, FFI-shaped façade around
//! it for use by Node/Python/Go bindings.

mod bridge;

use std::ops::Deref;
use std::path::Path;
use std::time::Duration;
use tokio::time::Instant;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Client for communicating with `agentd` through a running sandbox's relay.
pub struct AgentClient(microsandbox_agent_client::AgentClient);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve a sandbox name to its agent socket path and connect.
///
/// The socket lives under the SDK's configured runtime directory at a short,
/// name-derived path. Sandbox names are limited to 128 UTF-8 bytes.
pub async fn connect_sandbox(name: &str) -> AgentClientResult<AgentClient> {
    connect_sandbox_with_timeout(name, Duration::from_secs(10)).await
}

/// Resolve a sandbox name to its agent socket path and connect with an explicit
/// handshake timeout.
///
/// Sandbox names are limited to 128 UTF-8 bytes.
pub async fn connect_sandbox_with_timeout(
    name: &str,
    timeout: Duration,
) -> AgentClientResult<AgentClient> {
    if let Some(message) = crate::sandbox::sandbox_name_validation_message(name) {
        return Err(AgentClientError::InvalidSandboxName(message));
    }

    let mut last_error = None;
    for sock_path in crate::runtime::sandbox_agent_socket_path_candidates(name) {
        if !agent_endpoint_may_exist(&sock_path) {
            continue;
        }

        match AgentClient::connect_with_timeout(&sock_path, timeout).await {
            Ok(client) => return Ok(client),
            Err(error) => last_error = Some(error),
        }
    }

    match last_error {
        Some(error) => Err(error),
        None => Err(AgentClientError::SandboxNotFound(name.to_string())),
    }
}

#[cfg(unix)]
fn agent_endpoint_may_exist(path: &Path) -> bool {
    path.exists()
}

#[cfg(windows)]
fn agent_endpoint_may_exist(_path: &Path) -> bool {
    true
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentClient {
    /// Connect to an arbitrary agent relay socket path.
    pub async fn connect(sock_path: impl AsRef<Path>) -> AgentClientResult<Self> {
        microsandbox_agent_client::AgentClient::connect(sock_path)
            .await
            .map(Self)
    }

    /// Connect to an arbitrary agent relay socket path with an explicit
    /// handshake timeout.
    pub async fn connect_with_timeout(
        sock_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> AgentClientResult<Self> {
        microsandbox_agent_client::AgentClient::connect_with_timeout(sock_path, timeout)
            .await
            .map(Self)
    }

    /// Connect to an arbitrary agent relay socket path with an explicit
    /// handshake deadline.
    pub async fn connect_with_deadline(
        sock_path: impl AsRef<Path>,
        deadline: Instant,
    ) -> AgentClientResult<Self> {
        microsandbox_agent_client::AgentClient::connect_with_deadline(sock_path, deadline)
            .await
            .map(Self)
    }

    /// Resolve a sandbox name to its agent socket path and connect.
    pub async fn connect_sandbox(name: &str) -> AgentClientResult<Self> {
        connect_sandbox(name).await
    }

    /// Resolve a sandbox name to its agent socket path and connect with an
    /// explicit handshake timeout.
    pub async fn connect_sandbox_with_timeout(
        name: &str,
        timeout: Duration,
    ) -> AgentClientResult<Self> {
        connect_sandbox_with_timeout(name, timeout).await
    }

    /// Resolve a sandbox name to its agent relay socket path **without
    /// connecting**.
    ///
    /// Returns the same path [`connect_sandbox`] would dial — the hashed path
    /// under the runtime directory when it fits the platform's Unix-socket
    /// length limit, and the legacy name-derived path otherwise. Useful for
    /// talking to `agentd` over a raw byte transport (e.g. a transparent relay
    /// that splices bytes to/from the socket) instead of this frame client. The
    /// sandbox need not be running.
    pub fn socket_path(name: &str) -> crate::MicrosandboxResult<std::path::PathBuf> {
        crate::runtime::agent_socket_path(name)
    }

    /// Check a message type against an explicit negotiated generation.
    pub fn ensure_version_compat_for(
        t: microsandbox_protocol::message::MessageType,
        negotiated: u8,
    ) -> AgentClientResult<()> {
        microsandbox_agent_client::AgentClient::ensure_version_compat_for(t, negotiated)
    }

    /// Close the connection.
    pub async fn close(self) {
        self.0.close().await;
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Deref for AgentClient {
    type Target = microsandbox_agent_client::AgentClient;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use bridge::{AgentBridge, BridgeFrame, StreamHandle};
pub use microsandbox_agent_client::{AgentClientError, AgentClientResult, AgentProtocol};
pub use microsandbox_protocol::codec::RawFrame;
