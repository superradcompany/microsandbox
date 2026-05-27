//! Error type for the agent client.

use std::path::PathBuf;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result alias for agent client operations.
pub type AgentClientResult<T> = std::result::Result<T, AgentClientError>;

/// Errors raised by [`AgentClient`](super::AgentClient).
#[derive(Debug, thiserror::Error)]
pub enum AgentClientError {
    /// Failed to open the Unix socket connection to the relay.
    #[error("connect {path}: {source}")]
    Connect {
        /// Socket path that was attempted.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// Handshake with the relay failed (timeout, EOF, or malformed frame).
    #[error("handshake: {0}")]
    Handshake(String),

    /// The sandbox must be restarted before using filesystem or SFTP features.
    ///
    /// TODO(upgrade-0.6): Remove in 0.6.x or later once live-sandbox
    /// compatibility for versions before 0.5 is no longer supported.
    #[error(
        "filesystem and SFTP features need this sandbox to be restarted: this sandbox was started before microsandbox 0.5; stop and start it, then retry"
    )]
    Pre05SandboxRestartRequired,

    /// Sandbox name could not be resolved to an agent socket path.
    #[error("sandbox '{0}' not found")]
    SandboxNotFound(String),

    /// An I/O error occurred on the socket after connect.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A wire-protocol error (framing, CBOR, oversize frame).
    #[error("protocol: {0}")]
    Protocol(#[from] microsandbox_protocol::ProtocolError),

    /// The reader task closed (socket EOF or client closed) before the
    /// in-flight request received its response.
    #[error("reader closed before response for id={0}")]
    ReaderClosed(u32),

    /// The client has been closed.
    #[error("client closed")]
    Closed,
}
