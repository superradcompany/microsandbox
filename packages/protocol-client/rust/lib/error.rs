//! Safe errors with explicit local delivery uncertainty.

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Whether this attempt crossed writer admission; never a retry instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Delivery {
    /// No request bytes were submitted for this attempt.
    NotSent,
    /// The peer may have acted, including when only part of a write completed.
    Unknown,
}

/// Transport/router failure, independent of application response errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ErrorKind {
    /// The shared connection was explicitly closed or its last owner dropped.
    #[error("connection closed")]
    Closed,
    /// EOF while idle, before the expected terminal response.
    #[error("peer closed before terminal completion")]
    PeerClosed,
    /// EOF inside a frame, distinct from a clean byte-stream EOF.
    #[error("peer closed inside a frame")]
    TruncatedFrame,
    /// An OS-level read, write, or connect failed.
    #[error("transport I/O failed ({0:?})")]
    Io(std::io::ErrorKind),
    /// Total setup or per-attempt local wait expired.
    #[error("local deadline expired")]
    Timeout,
    /// Malformed framing or envelope.
    #[error("invalid protocol data")]
    InvalidData,
    /// Invalid local range, limits, or options.
    #[error("invalid client configuration")]
    InvalidOptions,
    /// Byte, item, or in-flight capacity is unavailable.
    #[error("client capacity exhausted")]
    Capacity,
    /// All IDs in the negotiated range are reserved or retired.
    #[error("correlation ID range exhausted")]
    IdRangeExhausted,
    /// An explicit ID has no live send permission on this connection.
    #[error("stream is closed or not owned by this connection")]
    StreamClosed,
    /// A typed operation is unavailable on this protocol/generation.
    #[error("operation is unsupported by the peer")]
    UnsupportedOperation,
    /// Native serialization failed without submitting a request.
    #[error("could not encode protocol message")]
    Encode,
}

/// Error with conservative delivery state. Diagnostics never include payloads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("{kind} (delivery: {delivery:?})")]
pub struct ClientError {
    /// Local reason for failure.
    pub kind: ErrorKind,
    /// Whether this particular attempt may have reached the peer.
    pub delivery: Delivery,
}

/// Result shared by generic protocol and transport implementations.
pub type ClientResult<T> = Result<T, ClientError>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ClientError {
    /// A failure known to precede writer admission.
    pub fn new(kind: ErrorKind) -> Self {
        Self {
            kind,
            delivery: Delivery::NotSent,
        }
    }

    /// Attach delivery information for a particular operation attempt.
    pub fn with_delivery(self, delivery: Delivery) -> Self {
        Self { delivery, ..self }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<std::io::Error> for ClientError {
    fn from(error: std::io::Error) -> Self {
        Self::new(ErrorKind::Io(error.kind()))
    }
}

impl From<microsandbox_protocol::wire::WireError> for ClientError {
    fn from(_: microsandbox_protocol::wire::WireError) -> Self {
        Self::new(ErrorKind::InvalidData)
    }
}
