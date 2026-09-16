//! Control generation and handshake limits, separate from the agent protocol.

use serde::{Deserialize, Serialize};

use super::ControlError;
use crate::codec::MAX_FRAME_SIZE;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Current framed host-control generation.
pub const CONTROL_GENERATION: u8 = 1;
/// Stable protocol discriminator; it does not authenticate a peer.
pub const CONTROL_PROTOCOL: &str = "msb.control";
/// The opening frame stays small and zero-prefixed across future generations.
pub const MAX_HANDSHAKE_FRAME_SIZE: u32 = 4096;
/// Maximum outstanding control IDs on a default connection.
pub const DEFAULT_MAX_IN_FLIGHT: u32 = 64;
/// Default deadline for the complete automatic connection setup.
pub const DEFAULT_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
/// Default local request wait, which never cancels or retries a mutation.
pub const DEFAULT_REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
/// Bound for JSON capability responses consumed during discovery.
pub const MAX_DISCOVERY_RESPONSE_SIZE: usize = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Opening framed-control offer. The envelope generation is always one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlHello {
    /// Must equal [`CONTROL_PROTOCOL`].
    pub protocol: String,
    /// Oldest application generation understood by this client.
    pub min_generation: u8,
    /// Newest application generation understood by this client.
    pub max_generation: u8,
    /// Largest application frame this client can accept.
    pub max_frame_size: u32,
    /// Maximum outstanding IDs this client will use.
    pub max_in_flight: u32,
}

/// Selected generation and limits. The welcome envelope is always generation one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlWelcome {
    /// Must equal [`CONTROL_PROTOCOL`].
    pub protocol: String,
    /// Application generation selected from the offer.
    pub generation: u8,
    /// Negotiated application frame ceiling, excluding the length prefix.
    pub max_frame_size: u32,
    /// Negotiated number of outstanding IDs.
    pub max_in_flight: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ControlHello {
    /// Validate the offer without accepting any application operation.
    pub fn validate(&self) -> Result<(), ControlError> {
        if self.protocol != CONTROL_PROTOCOL
            || self.min_generation == 0
            || self.min_generation > self.max_generation
            || !(MAX_HANDSHAKE_FRAME_SIZE..=MAX_FRAME_SIZE).contains(&self.max_frame_size)
            || self.max_in_flight == 0
        {
            return Err(ControlError::rejected(
                "invalid_handshake",
                "invalid control handshake",
            ));
        }
        Ok(())
    }
}

impl ControlWelcome {
    /// Select generation one and the smaller limits for the initial server.
    pub fn negotiate(hello: &ControlHello, max_in_flight: u32) -> Result<Self, ControlError> {
        hello.validate()?;
        if max_in_flight == 0 {
            return Err(ControlError::rejected(
                "internal",
                "invalid server admission limit",
            ));
        }
        if hello.min_generation > CONTROL_GENERATION {
            return Err(ControlError::rejected(
                "unsupported_generation",
                "no shared control generation",
            ));
        }
        Ok(Self {
            protocol: CONTROL_PROTOCOL.into(),
            generation: CONTROL_GENERATION,
            max_frame_size: hello.max_frame_size.min(MAX_FRAME_SIZE),
            max_in_flight: hello.max_in_flight.min(max_in_flight),
        })
    }

    /// Verify the response before admitting the client's first operation.
    pub fn validate_for(&self, hello: &ControlHello) -> Result<(), ControlError> {
        hello.validate()?;
        if self.protocol != CONTROL_PROTOCOL
            || !(hello.min_generation..=hello.max_generation).contains(&self.generation)
            || !(MAX_HANDSHAKE_FRAME_SIZE..=hello.max_frame_size).contains(&self.max_frame_size)
            || self.max_in_flight == 0
            || self.max_in_flight > hello.max_in_flight
        {
            return Err(ControlError::rejected(
                "invalid_handshake",
                "invalid control welcome",
            ));
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ControlHello {
    fn default() -> Self {
        Self {
            protocol: CONTROL_PROTOCOL.into(),
            min_generation: CONTROL_GENERATION,
            max_generation: CONTROL_GENERATION,
            max_frame_size: MAX_FRAME_SIZE,
            max_in_flight: DEFAULT_MAX_IN_FLIGHT,
        }
    }
}
