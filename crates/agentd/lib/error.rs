//! Error types for the microsandbox-agentd crate.

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The result type for agentd operations.
pub type AgentdResult<T> = Result<T, AgentdError>;

/// Errors that can occur during agent daemon operations.
#[derive(Debug, Error)]
pub enum AgentdError {
    /// An I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A protocol error.
    #[error("protocol error: {0}")]
    Protocol(#[from] microsandbox_protocol::ProtocolError),

    /// A nix/libc error.
    #[error("nix error: {0}")]
    Nix(#[from] nix::Error),

    /// A JSON serialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// Failed to find the virtio serial port.
    #[error("serial port not found: {0}")]
    SerialPortNotFound(String),

    /// An exec session error.
    #[error("exec session error: {0}")]
    ExecSession(String),

    /// An init error.
    #[error("init error: {0}")]
    Init(String),

    /// Graceful shutdown requested.
    #[error("shutdown")]
    Shutdown,
}
