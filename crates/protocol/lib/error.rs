//! Error types for the microsandbox-protocol crate.

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The result type for protocol operations.
pub type ProtocolResult<T> = Result<T, ProtocolError>;

/// Errors that can occur during protocol operations.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// An I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A CBOR serialization error.
    #[error("cbor encode error: {0}")]
    CborEncode(#[from] ciborium::ser::Error<std::io::Error>),

    /// A CBOR deserialization error.
    #[error("cbor decode error: {0}")]
    CborDecode(#[from] ciborium::de::Error<std::io::Error>),

    /// The message frame exceeded the maximum allowed size.
    #[error("frame too large: {size} bytes (max {max})")]
    FrameTooLarge {
        /// The size of the frame.
        size: u32,
        /// The maximum allowed size.
        max: u32,
    },

    /// Unexpected end of stream.
    #[error("unexpected end of stream")]
    UnexpectedEof,
}
