//! Shared control records. Their field spellings also preserve legacy JSON.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Aggregate disk-compaction result shared with SDK-facing types.
pub type DiskCompactionResult = microsandbox_types::DiskCompactionResult;

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

/// Complete generation-two runtime facility inventory.
///
/// [`Capabilities`] remains the released generation-one shape so Rust callers that construct it
/// with a struct literal keep compiling. This additive record is returned to generation-two peers.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeCapabilities {
    /// Runtime supports online root-disk growth over its extended control API.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub root_disk_grow: bool,
    /// Explicit guest writeback policy is accepted by capture and pause operations.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub guest_flush_policy: bool,
    /// Capture accepts an explicit disk-integrity policy.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub optional_disk_integrity: bool,
    /// Direct local branch capture is available.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub branch_create: bool,
    /// Linux descriptor-backed branching is available through the legacy transport exception.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub branch_memfd: bool,
    /// Resident pause and resume are available.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pause_resume: bool,
    /// Explicit disk compaction is available.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disk_compact: bool,
    /// Owned-disk compaction selectors are available.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disk_compact_owned: bool,
    /// Live CPU target changes are available.
    pub cpu_resize: bool,
    /// Live memory target changes are available.
    pub memory_resize: bool,
    /// Host secret changes are available.
    pub secrets_update: bool,
    /// Same-epoch full checkpoint capture is available.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub checkpoint_create: bool,
    /// Live disk-only capture is available.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub disk_checkpoint_create: bool,
}

/// Purpose of a full checkpoint capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointCaptureIntent {
    /// User-requested full snapshot.
    FullSnapshot,
    /// Local idle or park continuation.
    Park,
    /// Transparent continuity operation.
    TransparentTransfer,
}

/// Create one same-epoch full checkpoint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointCreate {
    /// Optional writeback policy; omission preserves released behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_flush: Option<microsandbox_types::GuestFlush>,
    /// Whether disk content hashes are recorded.
    #[serde(default)]
    pub record_integrity: bool,
    /// Caller-selected capture identity.
    pub checkpoint_id: String,
    /// Capture purpose.
    pub intent: CheckpointCaptureIntent,
}

/// Published full-checkpoint state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointState {
    /// Stable checkpoint identity.
    pub checkpoint_id: String,
    /// Content-addressed composite root.
    pub checkpoint_root: String,
    /// Runtime-local installed closure path.
    pub path: PathBuf,
    /// `full` or `incremental` physical-memory mode.
    pub memory_mode: String,
    /// Logical memory bytes represented by the capture.
    pub memory_logical_bytes: u64,
    /// Non-zero memory bytes emitted by the capture.
    pub memory_emitted_bytes: u64,
}

/// Full-checkpoint completion, including a published result whose source recovery failed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointResult {
    /// Published checkpoint when publication completed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointState>,
    /// Source recovery diagnostic after successful publication.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub recovery_error: Option<String>,
}

/// Seal the owned root disk without capturing RAM or execution state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskCheckpointCreate {
    /// Optional writeback policy; omission preserves released behavior.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_flush: Option<microsandbox_types::GuestFlush>,
    /// Caller-selected capture identity.
    pub checkpoint_id: String,
}

/// Complete disk-only capture result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskCheckpointState {
    /// Capture identity echoed from the request.
    pub checkpoint_id: String,
    /// Runtime-owned closure containing the sealed manifests and layers.
    pub path: PathBuf,
    /// Complete root generation.
    pub disk: microsandbox_types::snapshot::disk::DiskGenerationManifest,
    /// Complete owned-volume inventory.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owned_volumes: Vec<microsandbox_types::snapshot::OwnedVolumeCapture>,
}

/// Capture directly into a reserved child-owned local handoff directory.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchCreate {
    /// Optional writeback policy.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_flush: Option<microsandbox_types::GuestFlush>,
    /// Whether disk content hashes are recorded.
    #[serde(default)]
    pub record_integrity: bool,
    /// Unique capture identity.
    pub branch_id: String,
    /// Reserved child sandbox name.
    pub child_name: String,
    /// Cache containing the existing handoff reservation.
    pub memory_cache_dir: PathBuf,
}

/// Completed direct local branch handoff.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BranchResult {
    /// Runtime-owned handoff closure path.
    pub path: PathBuf,
}

/// Pause the runtime, optionally requiring guest writeback first.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pause {
    /// Optional policy; omission preserves the released unit-shaped pause request.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guest_flush: Option<microsandbox_types::GuestFlush>,
}

/// Host-confirmed resident suspension state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PauseState {
    /// Whether a user pause is currently held.
    pub paused: bool,
    /// Whether recovery owns a suspension that ordinary resume must not release.
    pub recovery_required: bool,
    /// Why full capture cannot use this pause.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capture_unavailable: Option<String>,
}

/// Grow the owned root disk and its mounted filesystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootDiskGrow {
    /// Target capacity in bytes.
    pub size_bytes: u64,
}

/// Verified root-disk growth and measured phases.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct RootDiskState {
    /// Committed ext4 capacity in bytes.
    pub filesystem_bytes: u64,
    /// Guest-observed virtio-block capacity in bytes.
    pub device_bytes: u64,
    /// Total operation time in microseconds.
    pub total_us: u64,
    /// VM pause through resume in microseconds.
    pub pause_us: u64,
    /// Guest expansion and verification time in microseconds.
    pub guest_us: u64,
}

/// Compact selected sandbox-owned disk chains.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskCompact {
    /// Disks selected for maintenance.
    #[serde(default)]
    pub target: microsandbox_types::DiskCompactionTarget,
    /// Maximum oldest sealed layers to compact per selected disk.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub layers: Option<u64>,
    /// Resolve without applying the plan.
    #[serde(default)]
    pub dry_run: bool,
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

impl RuntimeCapabilities {
    /// Project the extended inventory onto the frozen generation-one record.
    pub fn generation_one(self) -> Capabilities {
        Capabilities {
            root_disk_grow: self.root_disk_grow,
            cpu_resize: self.cpu_resize,
            memory_resize: self.memory_resize,
            secrets_update: self.secrets_update,
        }
    }
}

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
