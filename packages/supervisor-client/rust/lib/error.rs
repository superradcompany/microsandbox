//! Checked-operation errors retaining the peer's exact response.

use microsandbox_protocol::{supervisor::SupervisorError, wire::WireError};
use microsandbox_protocol_client::{ClientError, Delivery, Message};
use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Failure from a checked supervisor operation.
#[derive(Debug, Error)]
pub enum SupervisorClientError {
    /// Transport, timeout, setup, or local admission failure.
    #[error(transparent)]
    Client(#[from] ClientError),
    /// Invalid locally prepared CBOR payload.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// Valid structured peer rejection with its original frame.
    #[error("supervisor operation rejected by peer")]
    Peer {
        /// Structured failure record.
        error: SupervisorError,
        /// Exact received response.
        response: Box<Message>,
    },
    /// Response name, generation, flags, or payload violated the operation contract.
    #[error("invalid supervisor operation response")]
    InvalidResponse {
        /// Exact received response.
        response: Box<Message>,
    },
}

/// Result from a checked supervisor operation.
pub type SupervisorClientResult<T> = Result<T, SupervisorClientError>;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SupervisorClientError {
    /// Best available request-delivery certainty.
    pub fn delivery(&self) -> Delivery {
        match self {
            Self::Client(error) => error.delivery,
            Self::Wire(_) => Delivery::NotSent,
            Self::Peer { .. } | Self::InvalidResponse { .. } => Delivery::Unknown,
        }
    }
}
