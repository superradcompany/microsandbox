//! Checked-operation errors retaining the actual peer response.

use microsandbox_protocol::{control::ControlError, wire::WireError};
use microsandbox_protocol_client::{ClientError, Delivery, Message};
use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Operation failure distinct from generic routing and application observations.
#[derive(Debug, Error)]
pub enum ControlClientError {
    /// Transport or local admission failure with delivery certainty.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// Invalid locally prepared payload.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// Valid structured peer error, retaining original frame and unknown fields.
    #[error("control operation rejected by peer")]
    Peer {
        /// Exact decoded public error, including unknown future codes.
        error: ControlError,
        /// Original framed response.
        response: Box<Message>,
    },
    /// A response did not match the checked operation's contract.
    #[error("invalid control operation response")]
    InvalidResponse {
        /// Original response remains inspectable without re-encoding.
        response: Box<Message>,
    },
    /// Raw/encoded framed access is unavailable in legacy JSON mode.
    #[error("operation requires framed control (delivery: NotSent)")]
    UnsupportedMode,
    /// Verified runtime continuity failed, or fresh discovery changed format.
    #[error("runtime session changed before request admission (delivery: NotSent)")]
    RuntimeChanged,
    /// Legacy operation rejection. Diagnostics are not structured retry codes;
    /// secret-batch progress is unknown and earlier changes may remain applied.
    #[error("legacy control operation rejected by peer; batch progress unknown")]
    LegacyRemote {
        /// Original response, including the peer's diagnostic and extensions.
        reply: Box<crate::JsonReply>,
    },
    /// A syntactically valid JSON reply violated a checked operation's shape.
    #[error("invalid legacy control operation response")]
    InvalidJsonResponse {
        /// Original response remains inspectable.
        reply: Box<crate::JsonReply>,
    },
}

/// Result from an optional checked control operation.
pub type ControlClientResult<T> = Result<T, ControlClientError>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ControlClientError {
    /// Request admission certainty. A peer's structured effect field can carry
    /// additional mutation information; it never authorizes automatic replay.
    pub fn delivery(&self) -> Delivery {
        match self {
            Self::Client(error) => error.delivery,
            Self::Wire(_) | Self::UnsupportedMode | Self::RuntimeChanged => Delivery::NotSent,
            Self::Peer { .. }
            | Self::InvalidResponse { .. }
            | Self::LegacyRemote { .. }
            | Self::InvalidJsonResponse { .. } => Delivery::Unknown,
        }
    }
}
