// Exact historical type and Debug definitions, extracted from the source tags in manifest.json.
// Do not modernize this fixture; it represents the old consumers.

use serde::{Deserialize, Serialize};

/// A control request from the SDK.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Report which live-control operations this sandbox process supports.
    Capabilities,

    /// Ask the guest to converge on this much total usable memory.
    MemoryTarget {
        /// Desired total memory in MiB.
        total_mib: u64,
    },

    /// Report the current memory sizing without changing anything.
    MemoryState,

    /// Ask the guest to converge on this many online CPUs; the VMM enforces
    /// the ceiling immediately regardless of guest cooperation.
    CpuTarget {
        /// Desired online CPU count.
        online: u32,
    },

    /// Report the current CPU sizing without changing anything.
    CpuState,

    /// Apply live secret changes to the host network/secrets layer.
    /// Values never reach agentd or the guest; the placeholders the guest
    /// already holds keep working against the updated host-side state.
    SecretsUpdate {
        /// Ordered changes to apply. The first failure aborts the batch.
        changes: Vec<SecretLiveChange>,
    },
}

/// One live secret change carried by [`ControlRequest::SecretsUpdate`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "change", rename_all = "snake_case")]
pub enum SecretLiveChange {
    /// Replace the host-side value of an existing secret.
    Rotate {
        /// Secret identity (the guest environment variable name).
        name: String,
        /// New secret material. Redacted in `Debug`; never logged.
        value: SecretValue,
    },

    /// Stop resolving and injecting a secret for future connections.
    Remove {
        /// Secret identity (the guest environment variable name).
        name: String,
    },

    /// Replace the allowed-host patterns of an existing secret.
    SetAllowedHosts {
        /// Secret identity (the guest environment variable name).
        name: String,
        /// Host patterns (`host`, `*.host`, or `*`).
        hosts: Vec<String>,
    },
}

/// Raw secret material in transit over the control socket. Wrapped so any
/// `Debug`-formatted request or error path shows `[redacted]` instead of the
/// value, and zeroized on drop so the plaintext does not linger in freed
/// memory after the rotation batch is applied.
#[derive(Clone, Serialize, Deserialize, zeroize::ZeroizeOnDrop)]
#[serde(transparent)]
pub struct SecretValue(pub String);

/// The reply to any control request.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ControlResponse {
    /// Whether the request was accepted.
    pub ok: bool,

    /// Failure detail when `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Memory sizing, present for memory requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryControlState>,

    /// CPU sizing, present for CPU requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuControlState>,

    /// Supported operations, present for capability requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<ControlCapabilities>,
}

/// Live-control operations supported by this sandbox process, carried in
/// [`ControlResponse`]. Runtimes that predate this op only served the socket
/// when they could resize, so the SDK treats a missing reply as
/// resize-capable and secrets-incapable.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct ControlCapabilities {
    /// Live CPU online/offline targets are available.
    pub cpu_resize: bool,

    /// Live memory targets through virtio-mem are available.
    pub memory_resize: bool,

    /// Live secret rotation, removal, and allowed-host updates are available.
    pub secrets_update: bool,
}

/// Memory sizing carried in [`ControlResponse`], all in MiB.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct MemoryControlState {
    /// Memory the VM booted with.
    pub boot_mib: u64,

    /// Total memory the host asked the guest to converge on.
    pub target_mib: u64,

    /// Total memory currently usable by the guest.
    pub current_mib: u64,

    /// Boot-time ceiling for live growth.
    pub max_mib: u64,
}

/// CPU sizing carried in [`ControlResponse`].
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct CpuControlState {
    /// CPUs possible in this boot.
    pub possible: u32,

    /// Online count the host asked the guest to converge on.
    pub requested_online: u32,

    /// Online count the guest driver last reported.
    pub actual_online: u32,

    /// Online count the VMM currently enforces.
    pub enforced: u32,
}

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}
