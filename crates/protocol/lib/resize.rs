//! Operation-bound host resize tracking. Guest observations remain a separate protocol.

use microsandbox_types::modify::ResourceResizeStatus;
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Capability-gated generation-two host request, never sent to a guest agent.
pub const RESIZE_REQUEST: &str = "control.resize";
/// Terminal reply to one bounded host resize request.
pub const RESIZE_RESPONSE: &str = "control.resize.result";
/// Maximum retained operations in one runtime incarnation.
pub const MAX_RETAINED_RESIZES: usize = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One resource target. CPU and memory operations have independent identities.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "resource", rename_all = "snake_case")]
pub enum ResizeTarget {
    /// Requested online CPU prefix length.
    Cpus {
        /// CPU count.
        online: u32,
    },
    /// Requested total physical allocation, including boot memory.
    Memory {
        /// Allocation in MiB.
        total_mib: u64,
    },
}

/// Host operation outcome, distinct from resource convergence or missing observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResizeOutcome {
    /// Accepted operation still lacks authoritative application evidence.
    Pending,
    /// Guest application was confirmed while this operation still owned the resource.
    Applied,
    /// A later accepted request replaced this pending operation, including same-target requests.
    Superseded,
}

/// Availability of the evidence used for the latest resource status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResizeObservation {
    /// Fresh query-bound host/guest evidence is available.
    Available,
    /// A required host, relay, guest or kernel observation contract is unavailable.
    Unsupported,
    /// Resident pause prevents a fresh observation; it does not cancel the resize.
    Paused,
    /// Transport loss, an unstable device or invalid evidence prevented confirmation.
    Unavailable,
}

/// Retained result for one resource request in one runtime incarnation.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResizeOperation {
    /// Opaque runtime-selected identity; a later request always receives a different identity.
    pub id: String,
    /// Runtime incarnation; records never acquire authority in a subsequent runtime.
    pub runtime_boot_id: String,
    /// Monotonic resource generation; distinct from unrelated control mutations.
    pub generation: u64,
    /// Original requested target.
    pub requested_target: ResizeTarget,
    /// Target acknowledged by the host, including any device rounding.
    pub accepted_target: ResizeTarget,
    /// Existing requested/actual/enforced/convergence vocabulary.
    pub status: ResourceResizeStatus,
    /// Operation outcome, separate from convergence state.
    pub outcome: ResizeOutcome,
    /// Whether the latest read could acquire authoritative guest evidence.
    pub observation: ResizeObservation,
}

/// Runtime tracking identity and explicit retention limits.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResizeTracking {
    /// Fresh runtime incarnation, not a sandbox name or reusable PID.
    pub runtime_boot_id: String,
    /// Maximum retained records, including the latest operation for each resource.
    pub max_retained: usize,
}

/// A capability-gated read or mutation. No legacy retry follows dispatch.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
pub enum ResizeRequest {
    /// Read runtime identity without mutating anything.
    Hello,
    /// Apply one target. Dispatch is never retried; a lost reply has unknown outcome.
    Apply {
        /// Intended runtime incarnation.
        runtime_boot_id: String,
        /// Desired resource target.
        target: ResizeTarget,
    },
    /// Re-read a retained operation. Missing history never means successful completion.
    Read {
        /// Intended runtime incarnation.
        runtime_boot_id: String,
        /// Exact operation being observed.
        id: String,
    },
    /// Read the latest operation for each resource, without changing targets.
    Current {
        /// Intended runtime incarnation.
        runtime_boot_id: String,
    },
}

/// Bounded reply. Transport errors use the established host control error envelope.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResizeResponse {
    /// Identity and retention contract for this runtime.
    pub tracking: ResizeTracking,
    /// Zero records for Hello/no previous resize, one for Apply/Read, at most two for Current.
    pub operations: Vec<ResizeOperation>,
}
