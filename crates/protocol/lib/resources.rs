//! Query-bound guest resource observations. These are evidence, not resize outcomes.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Host relay understands resource observations independently of the guest generation.
pub const RESOURCE_OBSERVATION_RELAY_VERSION: u8 = 1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Client-facing Ready extension added by the relay, never by the guest.
///
/// Wrapping the existing advertisement preserves released Ready struct literals.
#[derive(Serialize)]
pub struct ResourceRelayAdvertisement<T> {
    /// Existing guest/connection advertisement.
    #[serde(flatten)]
    pub ready: T,
    /// Supported host routing contract, separate from the guest protocol generation.
    pub relay_resource_observation: u8,
}

/// Partial reader for the host-owned Ready extension; absence means unsupported.
#[derive(Default, Deserialize)]
pub struct ResourceRelayDiscovery {
    /// Unknown versions are not permission to dispatch an observation.
    #[serde(default)]
    pub relay_resource_observation: Option<u8>,
}

/// Payload for `core.resources.observe`; the guest echoes this opaque query identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObserveResources {
    /// Host-selected identity for this particular observation, not an operation target.
    pub query_id: [u8; 16],
}

/// Payload for `core.resources.observed`.
///
/// CPU and memory are sampled independently. The host must check runtime/operation identity
/// before and after the round trip; neither a matching target nor this echo alone is sufficient.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ObservedResources {
    /// Identity copied from the request after sampling, never from cached observations.
    pub query_id: [u8; 16],
    /// Whether the requested CPU prefix is currently online in the guest.
    pub cpu: ResourceObservation<CpuReadiness>,
    /// Whether the virtio-mem region's plugged capacity is currently online in the guest.
    pub memory: ResourceObservation<MemoryReadiness>,
}

/// Explicit availability of one resource observation; unavailable never means applied/refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum ResourceObservation<T> {
    /// A single validated device record.
    Available {
        /// Resource-specific observation.
        value: T,
    },
    /// No usable observation could be made for this query.
    Unavailable {
        /// Stable classification without raw file contents or paths.
        reason: ObservationUnavailable,
    },
}

/// Why an observation is unavailable, independent of the resize operation's outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservationUnavailable {
    /// The kernel/device does not expose this observation contract.
    Unsupported,
    /// A convergence worker or hotplug transition prevented a stable read.
    Busy,
    /// The record violates its schema or capacity invariants.
    Invalid,
    /// More than one matching device prevents unambiguous selection.
    Ambiguous,
    /// The kernel could not read the attribute or device inventory.
    Io,
}

/// Exact CPU prefix reported by the guest's CPU-capacity driver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuReadiness {
    /// Maximum CPU count represented by this device.
    pub possible: u32,
    /// Requested online CPU count currently visible to the driver.
    pub requested_online: u32,
    /// Number of online CPUs at the observation point.
    pub actual_online: u32,
    /// Online IDs are exactly `0..requested_online`, not merely the same count.
    pub exact: bool,
}

/// Guest readiness for the virtio-mem device region, excluding boot memory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryReadiness {
    /// Guest physical start address of the device's region.
    pub address: u64,
    /// Maximum region size in bytes.
    pub region_size: u64,
    /// Requested hotplugged size, excluding boot memory, in bytes.
    pub requested_size: u64,
    /// Plugged size, excluding boot memory, in bytes.
    pub plugged_size: u64,
    /// All currently plugged pages are online; does not imply target equality.
    pub all_online: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CpuReadiness {
    /// Validate scalar invariants; an exact prefix additionally needs the driver's evidence.
    pub fn is_valid(&self) -> bool {
        self.possible > 0
            && self.requested_online > 0
            && self.actual_online > 0
            && self.requested_online <= self.possible
            && self.actual_online <= self.possible
            && (!self.exact || self.actual_online == self.requested_online)
    }
}

impl MemoryReadiness {
    /// Validate the address range and sizes without treating plugged size as online capacity.
    pub fn is_valid(&self) -> bool {
        self.region_size > 0
            && self.address.checked_add(self.region_size).is_some()
            && self.requested_size <= self.region_size
            && self.plugged_size <= self.region_size
    }
}

impl ObservedResources {
    /// Check records before combining them with host identity, target and freshness evidence.
    pub fn is_valid(&self) -> bool {
        let cpu_valid = match &self.cpu {
            ResourceObservation::Available { value } => value.is_valid(),
            ResourceObservation::Unavailable { .. } => true,
        };
        let memory_valid = match &self.memory {
            ResourceObservation::Available { value } => value.is_valid(),
            ResourceObservation::Unavailable { .. } => true,
        };
        cpu_valid && memory_valid
    }
}
