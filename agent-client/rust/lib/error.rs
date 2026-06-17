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

    /// Sandbox name could not be resolved to an agent socket path.
    #[error("sandbox '{0}' not found")]
    SandboxNotFound(String),

    /// Sandbox name failed SDK validation before socket resolution.
    #[error("invalid sandbox name: {0}")]
    InvalidSandboxName(String),

    /// An I/O error occurred on the socket after connect.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    /// A wire-protocol error (framing, CBOR, oversize frame).
    #[error("protocol: {0}")]
    Protocol(#[from] microsandbox_protocol::ProtocolError),

    /// CBOR encoding or decoding failed.
    #[error("cbor: {0}")]
    Cbor(String),

    /// The supplied packet did not contain exactly one complete transport frame.
    #[error("invalid transport packet: {0}")]
    InvalidPacket(String),

    /// The connected sandbox's runtime is older than the requested feature
    /// needs.
    ///
    /// Raised before any bytes go out, so a feature the runtime is too old to
    /// handle fails on its own without disturbing the rest of the session.
    /// Restarting the sandbox re-provisions agentd at the current version, which
    /// is the fix. See `VERSIONING.md` in `microsandbox-protocol`.
    #[error(
        "the sandbox runtime is too old for '{msg_type}' (needs protocol generation {needs}, the sandbox speaks {peer}); restart the sandbox to update its runtime"
    )]
    UnsupportedOperation {
        /// Wire name of the message type that was gated.
        msg_type: &'static str,
        /// Generation the message type was introduced in.
        needs: u8,
        /// Generation negotiated with the connected sandbox.
        peer: u8,
    },

    /// The reader task closed (socket EOF or client closed) before the
    /// in-flight request received its response.
    #[error("reader closed before response for id={0}")]
    ReaderClosed(u32),

    /// The client has been closed.
    #[error("client closed")]
    Closed,

    /// The relay-assigned correlation ID range has no available IDs.
    #[error("agent correlation id range exhausted")]
    IdRangeExhausted,

    /// The operation is not implemented yet.
    #[error("not implemented: {0}")]
    NotImplemented(&'static str),
}
