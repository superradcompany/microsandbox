//! Generation negotiation and resource bounds for the supervisor protocol.

use serde::{Deserialize, Serialize};

use super::{ClientInstanceId, HomeDigest, SupervisorInstanceId};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Four bytes written before the first frame to select supervisor service.
pub const SUPERVISOR_MAGIC: &[u8; 4] = b"MSBS";
/// Oldest supervisor generation understood by this package.
pub const MIN_SUPERVISOR_GENERATION: u8 = 1;
/// Newest supervisor generation understood by this package.
pub const SUPERVISOR_GENERATION: u8 = 1;
/// Stable generation used by hello, welcome, and setup errors.
pub const SUPERVISOR_HANDSHAKE_GENERATION: u8 = 1;
/// Stable protocol discriminator. Local peer authentication remains transport-owned.
pub const SUPERVISOR_PROTOCOL: &str = "msb.supervisor";
/// Hard ceiling for any supervisor frame, excluding its four-byte length prefix.
pub const MAX_SUPERVISOR_FRAME_SIZE: u32 = 1024 * 1024;
/// Ceiling for the opening hello or welcome frame.
pub const MAX_SUPERVISOR_HANDSHAKE_FRAME_SIZE: u32 = 16 * 1024;
/// Default application frame ceiling requested by clients.
pub const DEFAULT_SUPERVISOR_FRAME_SIZE: u32 = 256 * 1024;
/// Default number of concurrent correlation IDs.
pub const DEFAULT_SUPERVISOR_MAX_IN_FLIGHT: u32 = 32;
/// Default number of concurrent watch streams.
pub const DEFAULT_SUPERVISOR_MAX_WATCHES: u32 = 8;
/// Deadline for dial plus preamble and framed negotiation.
pub const DEFAULT_SUPERVISOR_SETUP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
/// Default local unary wait; it never implies cancellation or retry.
pub const DEFAULT_SUPERVISOR_REQUEST_TIMEOUT: std::time::Duration =
    std::time::Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Resource ceilings offered by a client or selected by a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorLimits {
    /// Largest application frame accepted after setup.
    pub max_frame_size: u32,
    /// Maximum outstanding request and stream correlation IDs.
    pub max_in_flight: u32,
    /// Maximum concurrently active watch streams.
    pub max_watches: u32,
}

/// Supervisor launch policy reported to clients.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchProfile {
    /// Sandboxes are supervised without a host jail profile.
    Supervised,
    /// Sandboxes are supervised and launched with the initial Linux jail profile.
    JailedLinuxV1,
}

/// Opening client offer, always carried in a generation-one envelope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorHello {
    /// Must equal [`SUPERVISOR_PROTOCOL`].
    pub protocol: String,
    /// Oldest application generation understood by the client.
    pub min_generation: u8,
    /// Newest application generation understood by the client.
    pub max_generation: u8,
    /// Client package or SDK version for diagnostics.
    pub implementation_version: String,
    /// Per-process client identity used for diagnostics, not authorization.
    pub client_instance_id: ClientInstanceId,
    /// Digest of the canonical microsandbox home this connection targets.
    pub canonical_home_digest: HomeDigest,
    /// Requested connection and watch ceilings.
    pub requested_limits: SupervisorLimits,
    /// Last catalog revision already consumed by a reconnecting client.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_catalog_revision: Option<u64>,
}

/// Selected generation, identity, and resource ceilings.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorWelcome {
    /// Must equal [`SUPERVISOR_PROTOCOL`].
    pub protocol: String,
    /// Application generation selected from the client's offer.
    pub generation: u8,
    /// Supervisor package version for diagnostics.
    pub implementation_version: String,
    /// Identity of this running supervisor instance.
    pub supervisor_instance_id: SupervisorInstanceId,
    /// Digest of the canonical home owned by this endpoint.
    pub canonical_home_digest: HomeDigest,
    /// Effective connection and watch ceilings.
    pub effective_limits: SupervisorLimits,
    /// Latest committed catalog revision.
    pub current_catalog_revision: u64,
    /// Oldest catalog revision retained for watch resumption.
    pub oldest_catalog_revision: u64,
    /// Launch behavior applied to newly started sandboxes.
    pub launch_profile: LaunchProfile,
}

/// Handshake validation failure without transport policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSupervisorHandshake;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SupervisorLimits {
    /// Reject resource values that cannot support one ordinary exchange.
    pub fn validate(self) -> Result<(), InvalidSupervisorHandshake> {
        if !(5..=MAX_SUPERVISOR_FRAME_SIZE).contains(&self.max_frame_size)
            || self.max_in_flight == 0
            || self.max_watches == 0
            || self.max_watches > self.max_in_flight
        {
            return Err(InvalidSupervisorHandshake);
        }
        Ok(())
    }
}

impl SupervisorHello {
    /// Validate an offer before any supervisor operation is admitted.
    pub fn validate(&self) -> Result<(), InvalidSupervisorHandshake> {
        self.requested_limits.validate()?;
        if self.protocol != SUPERVISOR_PROTOCOL
            || self.min_generation == 0
            || self.min_generation > self.max_generation
            || self.implementation_version.is_empty()
        {
            return Err(InvalidSupervisorHandshake);
        }
        Ok(())
    }
}

/// Select the highest supervisor generation shared with a validated offer.
pub fn select_supervisor_generation(
    hello: &SupervisorHello,
) -> Result<u8, InvalidSupervisorHandshake> {
    hello.validate()?;
    let generation = hello.max_generation.min(SUPERVISOR_GENERATION);
    if generation < hello.min_generation {
        return Err(InvalidSupervisorHandshake);
    }
    Ok(generation)
}

impl SupervisorWelcome {
    /// Verify server selection against the exact client offer.
    pub fn validate_for(&self, hello: &SupervisorHello) -> Result<(), InvalidSupervisorHandshake> {
        hello.validate()?;
        self.effective_limits.validate()?;
        if self.protocol != SUPERVISOR_PROTOCOL
            || !(hello.min_generation..=hello.max_generation).contains(&self.generation)
            || self.implementation_version.is_empty()
            || self.canonical_home_digest != hello.canonical_home_digest
            || self.effective_limits.max_frame_size > hello.requested_limits.max_frame_size
            || self.effective_limits.max_in_flight > hello.requested_limits.max_in_flight
            || self.effective_limits.max_watches > hello.requested_limits.max_watches
            || self.oldest_catalog_revision > self.current_catalog_revision
        {
            return Err(InvalidSupervisorHandshake);
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for SupervisorLimits {
    fn default() -> Self {
        Self {
            max_frame_size: DEFAULT_SUPERVISOR_FRAME_SIZE,
            max_in_flight: DEFAULT_SUPERVISOR_MAX_IN_FLIGHT,
            max_watches: DEFAULT_SUPERVISOR_MAX_WATCHES,
        }
    }
}
