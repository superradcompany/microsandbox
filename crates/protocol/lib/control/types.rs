//! Shared control records. Their field spellings also preserve legacy JSON.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Empty map payload for state and capability queries.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

/// Facilities available for this runtime and VM configuration.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Capabilities {
    /// Runtime supports online root-disk growth over its extended control API.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub root_disk_grow: bool,
    /// Live CPU target changes are available.
    pub cpu_resize: bool,
    /// Live memory target changes are available.
    pub memory_resize: bool,
    /// Host secret changes are available.
    pub secrets_update: bool,
}

/// Accepted and observed memory quantities, all in MiB.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryState {
    /// Boot allocation.
    pub boot_mib: u64,
    /// Accepted target, which need not have converged yet.
    pub target_mib: u64,
    /// Current guest observation.
    pub current_mib: u64,
    /// Boot-time capacity ceiling.
    pub max_mib: u64,
}

/// CPU capacity, accepted target, observation, and enforcement.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuState {
    /// CPUs possible for this VM boot.
    pub possible: u32,
    /// Accepted online target.
    pub requested_online: u32,
    /// Guest-reported online CPUs.
    pub actual_online: u32,
    /// Host-enforced online CPUs.
    pub enforced: u32,
}

/// Native memory-target payload, without SDK convergence policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MemoryTarget {
    /// Requested total memory in MiB.
    pub total_mib: u64,
}

/// Native CPU-target payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CpuTarget {
    /// Requested online CPUs.
    pub online: u32,
}

/// Secret material that is redacted in diagnostics and cleared on drop.
#[derive(Clone, Serialize, Deserialize, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretValue(pub String);

/// One ordered host secret modification, preserving the JSON operation tags.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum SecretChange {
    /// Replace an existing secret's value.
    Rotate {
        /// Secret identity.
        name: String,
        /// New secret material.
        value: SecretValue,
    },
    /// Remove a secret; absence is a successful no-op.
    Remove {
        /// Secret identity.
        name: String,
    },
    /// Replace an existing secret's allowed hosts.
    SetAllowedHosts {
        /// Secret identity.
        name: String,
        /// Replacement host patterns, in caller order.
        hosts: Vec<String>,
    },
}

/// Sequential, non-transactional secret modifications.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecretsUpdate {
    /// Apply in order and stop at the first operation failure.
    pub changes: Vec<SecretChange>,
}

/// State mutation certainty reported by an operation error.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorEffect {
    /// This operation (or failed batch entry) did not change state.
    None,
    /// A change cannot be ruled out.
    Unknown,
}

/// A recoverable peer error. Codes stay strings for future interoperability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlError {
    /// Stable machine-readable code; preserve unknown future codes.
    pub code: String,
    /// Safe diagnostic text, never a request body or secret value.
    pub message: String,
    /// Certainty for this operation, not a retry instruction.
    pub effect: ErrorEffect,
}

/// Completion of a sequential secret batch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum SecretsResult {
    /// Every entry completed, including successful no-ops.
    Complete {
        /// Number of completed entries.
        applied_count: u32,
    },
    /// Earlier entries completed; remaining entries were not attempted.
    Failed {
        /// Number of completed entries.
        applied_count: u32,
        /// Zero-based failed entry, equal to `applied_count`.
        failed_index: u32,
        /// Certainty here applies to the failed entry only.
        error: ControlError,
    },
}

/// Legacy JSON request, also used as a checked dispatch representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Query available host operations.
    Capabilities,
    /// Set the memory target.
    MemoryTarget {
        /// Requested total memory in MiB.
        total_mib: u64,
    },
    /// Observe memory state.
    MemoryState,
    /// Set the CPU target.
    CpuTarget {
        /// Requested online CPUs.
        online: u32,
    },
    /// Observe CPU state.
    CpuState,
    /// Apply ordered secret modifications.
    SecretsUpdate {
        /// Caller-ordered changes.
        changes: Vec<SecretChange>,
    },
}

/// Existing JSON response with an additive discovery advertisement.
///
/// Omission of `control_protocols` identifies an ordinary legacy response.
/// Raw JSON consumers must retain the original bytes to preserve unknown fields.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct JsonControlResponse {
    /// Whether the operation succeeded.
    pub ok: bool,
    /// Legacy diagnostic; batch progress cannot be inferred from it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    /// Present for memory operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryState>,
    /// Present for CPU operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuState>,
    /// Present for capability discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Capabilities>,
    /// Explicit operation formats, emitted only during discovery.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_protocols: Option<Vec<String>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ControlError {
    /// Construct an error known to precede mutation.
    pub fn rejected(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            effect: ErrorEffect::None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}
