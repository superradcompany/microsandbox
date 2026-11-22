//! Agent transport and sandbox endpoint resolution.

use std::ops::Deref;
use std::path::Path;
use std::time::Duration;

use microsandbox_protocol::{
    exec::ExecRequest,
    exec_bindings::{BoundExecRequest, ExecBindingCapability, ExecBindingOverrides},
    message::{Message, MessageType},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::Instant,
};

#[cfg(feature = "local")]
use super::AgentClientError;
use super::AgentClientResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Client for communicating with `agentd` through a running sandbox's relay.
pub struct AgentClient {
    inner: microsandbox_agent_client::OptimizedAgentClient,
    exec_bindings: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentClient {
    /// Send pre-merge origin only when the connected host advertises binding admission.
    /// An established session fixes the destination. A dispatched exec is never retried.
    pub(crate) async fn stream_exec(
        &self,
        command: &ExecRequest,
        explicit_env: &[microsandbox_types::EnvVar],
        explicit_argv: bool,
    ) -> AgentClientResult<(u32, tokio::sync::mpsc::Receiver<Message>)> {
        if self.exec_bindings.is_some() {
            let request = BoundExecRequest {
                command,
                binding_overrides: ExecBindingOverrides {
                    explicit_argv,
                    env_keys: explicit_env.iter().map(|env| env.key.clone()).collect(),
                },
            };
            return self.stream(MessageType::ExecRequest, &request).await;
        }
        self.stream(MessageType::ExecRequest, command).await
    }

    pub(crate) fn exec_binding_boot_id(&self) -> Option<&str> {
        self.exec_bindings.as_deref()
    }

    fn from_transport(inner: microsandbox_agent_client::OptimizedAgentClient) -> Self {
        let exec_bindings = microsandbox_protocol::wire::Envelope::decode(inner.ready_bytes())
            .ok()
            .and_then(|message| message.payload::<ExecBindingCapability>().ok())
            .filter(|ready| ready.relay_exec_bindings == Some(1))
            .and_then(|ready| ready.binding_boot_id)
            .filter(|id| !id.is_empty() && id.len() <= 128);
        Self {
            inner,
            exec_bindings,
        }
    }

    /// Connect to an arbitrary agent relay socket path.
    pub async fn connect(sock_path: impl AsRef<Path>) -> AgentClientResult<Self> {
        microsandbox_agent_client::OptimizedAgentClient::connect(sock_path)
            .await
            .map(Self::from_transport)
    }

    /// Connect over an arbitrary byte-stream transport with an explicit
    /// handshake timeout.
    ///
    /// The stream must be a transparent pipe to a sandbox's agent relay,
    /// such as the cloud's agent WebSocket route adapted to bytes.
    pub async fn connect_stream_with_timeout<S>(
        stream: S,
        timeout: Duration,
    ) -> AgentClientResult<Self>
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        microsandbox_agent_client::OptimizedAgentClient::connect_stream_with_timeout(
            stream, timeout,
        )
        .await
        .map(Self::from_transport)
    }

    /// Connect to an arbitrary agent relay socket path with an explicit
    /// handshake timeout.
    pub async fn connect_with_timeout(
        sock_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> AgentClientResult<Self> {
        microsandbox_agent_client::OptimizedAgentClient::connect_with_timeout(sock_path, timeout)
            .await
            .map(Self::from_transport)
    }

    /// Connect to an arbitrary agent relay socket path with an explicit
    /// handshake deadline.
    pub async fn connect_with_deadline(
        sock_path: impl AsRef<Path>,
        deadline: Instant,
    ) -> AgentClientResult<Self> {
        microsandbox_agent_client::OptimizedAgentClient::connect_with_deadline(sock_path, deadline)
            .await
            .map(Self::from_transport)
    }

    /// Connect to a local relay with bulk payloads kept on the byte stream.
    ///
    /// Shared-memory upgrades are disabled even when the peer advertises them.
    /// Exec signals retain the advertised control route. The deadline bounds
    /// the handshake.
    pub async fn connect_in_band_with_deadline(
        sock_path: impl AsRef<Path>,
        deadline: Instant,
    ) -> AgentClientResult<Self> {
        microsandbox_agent_client::OptimizedAgentClient::connect_in_band_with_deadline(
            sock_path, deadline,
        )
        .await
        .map(Self::from_transport)
    }

    /// Resolve a sandbox name to its agent socket path and connect.
    #[cfg(feature = "local")]
    pub async fn connect_sandbox(name: &str) -> AgentClientResult<Self> {
        connect_sandbox(name).await
    }

    /// Resolve a sandbox name to its agent socket path and connect with an
    /// explicit handshake timeout.
    #[cfg(feature = "local")]
    pub async fn connect_sandbox_with_timeout(
        name: &str,
        timeout: Duration,
    ) -> AgentClientResult<Self> {
        connect_sandbox_with_timeout(name, timeout).await
    }

    /// Resolve a sandbox name to its agent relay socket path **without
    /// connecting**.
    ///
    /// Returns the same path [`connect_sandbox`] would dial: the canonical
    /// per-sandbox runtime path, an existing legacy flat path when talking to
    /// an older runtime, or the retained in-sandbox fallback for deep homes.
    /// Useful for talking to `agentd` over a raw byte transport (e.g. a
    /// transparent relay that splices bytes to/from the socket) instead of
    /// this frame client. The sandbox need not be running.
    #[cfg(feature = "local")]
    pub fn socket_path(name: &str) -> crate::MicrosandboxResult<std::path::PathBuf> {
        crate::runtime::agent_socket_path(name)
    }

    /// Check a message type against an explicit negotiated generation.
    pub fn ensure_version_compat_for(
        t: microsandbox_protocol::message::MessageType,
        negotiated: u8,
    ) -> AgentClientResult<()> {
        microsandbox_agent_client::OptimizedAgentClient::ensure_version_compat_for(t, negotiated)
    }

    /// Close the connection.
    pub async fn close(self) {
        self.inner.close().await;
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Deref for AgentClient {
    type Target = microsandbox_agent_client::OptimizedAgentClient;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve a sandbox name to its agent socket path and connect.
///
/// The socket lives under the SDK's configured runtime directory at a short,
/// name-derived path. Sandbox names are limited to 128 UTF-8 bytes.
#[cfg(feature = "local")]
pub async fn connect_sandbox(name: &str) -> AgentClientResult<AgentClient> {
    connect_sandbox_with_timeout(name, Duration::from_secs(10)).await
}

/// Resolve a sandbox name to its agent socket path and connect with an explicit
/// handshake timeout.
///
/// Sandbox names are limited to 128 UTF-8 bytes.
#[cfg(feature = "local")]
pub async fn connect_sandbox_with_timeout(
    name: &str,
    timeout: Duration,
) -> AgentClientResult<AgentClient> {
    if let Some(message) = crate::sandbox::sandbox_name_validation_message(name) {
        return Err(AgentClientError::InvalidSandboxName(message));
    }

    let mut last_error = None;
    for sock_path in crate::runtime::default_agent_socket_paths(name) {
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

#[cfg(all(feature = "local", unix))]
fn agent_endpoint_may_exist(path: &Path) -> bool {
    path.exists()
}

#[cfg(all(feature = "local", windows))]
fn agent_endpoint_may_exist(_path: &Path) -> bool {
    true
}
