//! Host-side runtime control socket protocol.
//!
//! Live VM mutations that are host/VMM-owned (memory resize through
//! virtio-mem, CPU online targets, and secret reconfiguration in the host
//! network layer) cannot go through agentd: the guest is untrusted and the
//! knobs live host-side. The sandbox process serves them instead next to the
//! agent endpoint — a unix socket on unix hosts, a named pipe on Windows.
//! Each connection carries one JSON request and response line. Legacy requests
//! and versioned envelopes both enter the same runtime-owned executor.
//!
//! Secret requests may carry raw secret values (rotation needs the new
//! material), so request lines are never logged and [`SecretValue`] redacts
//! itself in `Debug` output; errors carry secret names only.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Extension of legacy per-sandbox control sockets (`<sandbox>.sock` becomes
/// `<sandbox>.control.sock`). Canonical sockets use sibling `control.sock`.
pub const CONTROL_SOCKET_EXTENSION: &str = "control.sock";

/// Initial version of the fenced runtime-control envelope.
pub const CONTROL_PROTOCOL_VERSION: u16 = 1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A control request from the SDK.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ControlRequest {
    /// Seal only the owned root disk; never capture guest RAM or execution state.
    DiskCheckpointCreate {
        /// Optional writeback policy. Absent preserves released clients' behavior.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        guest_flush: Option<microsandbox_types::GuestFlush>,
        /// Caller-selected safe capture identity.
        checkpoint_id: String,
    },
    /// Capture directly into a reserved child-owned local handoff directory.
    BranchCreate {
        /// Optional writeback policy; mandatory storage barriers cannot be disabled.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        guest_flush: Option<microsandbox_types::GuestFlush>,
        /// Opt into disk content hashes; RAM remains an unhashed local backing.
        #[serde(default)]
        record_integrity: bool,
        /// Unique capture identity matching the child's reservation.
        branch_id: String,
        /// Reserved sandbox name in this runtime's backend, never a host path.
        child_name: String,
        /// Cache in which the caller holds its handoff lock; must match the source runtime.
        memory_cache_dir: PathBuf,
    },
    /// Linux branch capture with one empty memory descriptor attached to the request.
    /// The distinct operation prevents older runtimes from ignoring descriptor ownership.
    BranchCreateMemfd {
        /// Optional writeback policy, independent of memory backing.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        guest_flush: Option<microsandbox_types::GuestFlush>,
        /// Opt into disk content hashes; independent of memory descriptor ownership.
        #[serde(default)]
        record_integrity: bool,
        /// Unique capture identity matching the child's reservation.
        branch_id: String,
        /// Reserved sandbox name in this runtime's backend.
        child_name: String,
        /// Backend-resolved cache holding the existing handoff reservation.
        memory_cache_dir: PathBuf,
        /// Transport-owned handle; never deserialized from a numeric descriptor in JSON.
        #[serde(skip)]
        backing: Option<std::sync::Arc<std::fs::File>>,
    },
    /// Retain a resident pause until an explicit resume or stop.
    Pause,
    /// Pause with an explicit policy; older runtimes reject this operation rather than
    /// ignoring a field on the released unit-shaped pause request.
    PauseWithGuestFlush {
        /// Writeback requirement to establish before pausing.
        guest_flush: microsandbox_types::GuestFlush,
    },
    /// Resume a user-owned resident pause.
    Resume,
    /// Inspect user pause and full-capture availability without entering the guest.
    PauseState,
    /// Grow the owned root disk and mounted ext4 filesystem without rebooting.
    RootDiskGrow {
        /// Target capacity in bytes.
        size_bytes: u64,
    },
    /// Explicitly consolidate sealed layers of the selected root and sandbox-owned disks.
    DiskCompact {
        /// Select all eligible disks by default, or an explicit guest mount path/root.
        #[serde(default)]
        target: microsandbox_types::DiskCompactionTarget,
        /// Up to this many oldest sealed layers per disk, including the base; minimum two.
        layers: Option<usize>,
        /// Resolve the selection without changing disk state.
        #[serde(default)]
        dry_run: bool,
    },
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

    /// Produce one same-epoch full checkpoint and return the source to its prior running
    /// state after root-last publication.
    CheckpointCreate {
        /// Optional writeback policy. Absent retains released capture semantics.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        guest_flush: Option<microsandbox_types::GuestFlush>,
        /// Opt into disk content hashes; RAM objects remain content-addressed.
        #[serde(default)]
        record_integrity: bool,
        /// Caller-selected safe checkpoint identity.
        checkpoint_id: String,
        /// Why this checkpoint is being captured.
        intent: CheckpointCaptureIntent,
    },
}

/// Purpose of a runtime checkpoint capture.
#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckpointCaptureIntent {
    /// User-requested full snapshot.
    FullSnapshot,
    /// Local idle/park continuation.
    Park,
    /// Transparent continuity operation.
    TransparentTransfer,
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
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ControlResponse {
    /// In-process completion metadata for the framed adapter; never emitted in JSON.
    #[serde(skip)]
    pub secret_result: Option<microsandbox_protocol::control::SecretsResult>,
    /// Available transports on this same endpoint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub control_protocols: Option<Vec<String>>,
    /// Completed local handoff, deliberately not a portable checkpoint identity.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub branch: Option<PathBuf>,
    /// Resident pause status for lifecycle operations.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pause: Option<PauseControlState>,
    /// Guest-observed root capacities after successful filesystem expansion.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_disk: Option<RootDiskGrowthResult>,
    /// Explicit disk-compaction result or dry-run projection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compaction: Option<crate::checkpoint::DiskCompactionResult>,
    /// Whether the request was accepted.
    pub ok: bool,

    /// Failure detail when `ok` is false.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// Stable machine-readable failure class.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,

    /// Memory sizing, present for memory requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory: Option<MemoryControlState>,

    /// CPU sizing, present for CPU requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cpu: Option<CpuControlState>,

    /// Supported operations, present for capability requests.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<ControlCapabilities>,

    /// Published checkpoint result, present for checkpoint operations and for a post-publication
    /// failure such as an unsuccessful source resume.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint: Option<CheckpointControlState>,
    /// Sealed disk-only capture, with no RAM or execution-state closure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_checkpoint: Option<DiskCheckpointControlState>,
}

/// Published checkpoint information returned by the runtime control executor.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CheckpointControlState {
    /// Stable checkpoint identity.
    pub checkpoint_id: String,
    /// Content-addressed composite checkpoint root.
    pub checkpoint_root: String,
    /// Runtime-local installed closure path.
    pub path: PathBuf,
    /// Whether capture emitted a complete or incremental physical memory generation.
    pub memory_mode: String,
    /// Logical memory bytes represented by the capture.
    pub memory_logical_bytes: u64,
    /// Non-zero memory bytes written during this capture.
    pub memory_emitted_bytes: u64,
}

/// Immutable disk closure returned after a live root-head rollover.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiskCheckpointControlState {
    /// Capture identity echoed from the request.
    pub checkpoint_id: String,
    /// Runtime-owned closure, independent of the source's new writable head.
    pub path: PathBuf,
    /// Complete base-to-head disk generation; contains no memory or device payloads.
    pub disk: microsandbox_image::checkpoint::DiskGenerationManifest,
    /// Complete lifetime-owned backing sealed at the same root-disk cut.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owned_volumes: Vec<microsandbox_image::snapshot::OwnedVolumeCapture>,
}

/// Verified capacity and measured phases of a completed online root growth.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootDiskGrowthResult {
    /// Committed ext4 capacity in bytes.
    pub filesystem_bytes: u64,
    /// Guest-observed virtio-block capacity in bytes.
    pub device_bytes: u64,
    /// Total runtime operation time, including preflight and persistence.
    pub total_us: u64,
    /// VM pause through resume; excludes online filesystem expansion.
    pub pause_us: u64,
    /// Guest expansion and verification time after VM resume.
    pub guest_us: u64,
}

/// Live-control operations supported by this sandbox process, carried in
/// [`ControlResponse`]. Runtimes that predate this op only served the socket
/// when they could resize, so the SDK treats a missing reply as
/// resize-capable and secrets-incapable.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
pub struct ControlCapabilities {
    /// Explicit guest writeback policy and same-pause filesystem coverage checks.
    #[serde(default)]
    pub guest_flush_policy: bool,
    /// Capture accepts an explicit disk-integrity policy and unhashed disk manifests.
    #[serde(default)]
    pub optional_disk_integrity: bool,
    /// Direct local branch capture is supported on this host.
    #[serde(default)]
    pub branch_create: bool,
    /// Linux request-side descriptor transfer for ephemeral branch backing.
    #[serde(default)]
    pub branch_memfd: bool,
    /// Resident pause/resume with identity-preserving clock correction.
    #[serde(default)]
    pub pause_resume: bool,
    /// Host control supports root growth; guest capability is checked before mutation.
    #[serde(default)]
    pub root_disk_grow: bool,
    /// Explicit root-disk prefix compaction is supported.
    #[serde(default)]
    pub disk_compact: bool,
    /// Root/owned-disk selectors and per-disk up-to layer limits are supported.
    /// Absence means callers must not send the expanded default to an older root-only runtime.
    #[serde(default)]
    pub disk_compact_owned: bool,
    /// Live CPU online/offline targets are available.
    pub cpu_resize: bool,

    /// Live memory targets through virtio-mem are available.
    pub memory_resize: bool,

    /// Live secret rotation, removal, and allowed-host updates are available.
    pub secrets_update: bool,

    /// Same-epoch composite checkpoint capture is available.
    #[serde(default)]
    pub checkpoint_create: bool,
    /// Disk-only live capture is available without full-state admission.
    #[serde(default)]
    pub disk_checkpoint_create: bool,
}

/// Host-confirmed resident suspension state.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PauseControlState {
    /// Whether a user pause is currently held.
    pub paused: bool,
    /// Whether a failed operation has fenced ordinary resume and mutations.
    pub recovery_required: bool,
    /// Why full capture cannot use this pause, if guest preparation is unavailable.
    pub capture_unavailable: Option<String>,
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

/// Fenced control request carried by the versioned host-control protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEnvelope {
    /// Runtime-control protocol version.
    pub protocol_version: u16,
    /// Caller-generated idempotency key.
    pub request_id: String,
    /// Immutable identity of the intended runtime process boot.
    pub runtime_boot_id: String,
    /// Optional compare-and-swap revision.
    pub expected_revision: Option<u64>,
    /// Stable operation identity when this request belongs to longer work.
    pub operation_id: Option<String>,
    /// Typed control command.
    pub command: ControlRequest,
}

/// Runtime lifecycle projected through control responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLifecycle {
    /// Guest vCPUs and admitted workers may run.
    Running,
    /// One executor-owned operation is establishing a quiesced boundary.
    Quiescing,
    /// Execution is paused and externally visible writers remain fenced.
    Quiesced,
    /// Runtime is permanently fenced from further work.
    Retiring,
}

/// Identity and concurrency state returned with fenced responses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeControlState {
    /// Immutable identity of this process boot.
    pub runtime_boot_id: String,
    /// Monotonic successful-mutation revision.
    pub revision: u64,
    /// Current lifecycle projection.
    pub lifecycle: RuntimeLifecycle,
}

/// Reply to a [`ControlEnvelope`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEnvelopeResponse {
    /// Correlated request id.
    pub request_id: String,
    /// Runtime identity/revision observed after executing the command.
    pub runtime: RuntimeControlState,
    /// Existing command response payload.
    pub response: ControlResponse,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[redacted]")
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The control socket path that belongs to the given agent socket path.
pub fn control_socket_path_for(agent_sock: &std::path::Path) -> PathBuf {
    crate::ipc::control_socket_path_for(agent_sock)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_value_debug_is_redacted() {
        let request = ControlRequest::SecretsUpdate {
            changes: vec![SecretLiveChange::Rotate {
                name: "API_KEY".into(),
                value: SecretValue("sentinel-secret-value".into()),
            }],
        };

        let debug = format!("{request:?}");
        assert!(!debug.contains("sentinel-secret-value"));
        assert!(debug.contains("[redacted]"));
        assert!(debug.contains("API_KEY"));
    }

    #[test]
    fn secrets_update_round_trips_through_json() {
        let request = ControlRequest::SecretsUpdate {
            changes: vec![
                SecretLiveChange::Rotate {
                    name: "API_KEY".into(),
                    value: SecretValue("new-material".into()),
                },
                SecretLiveChange::Remove {
                    name: "OLD_KEY".into(),
                },
                SecretLiveChange::SetAllowedHosts {
                    name: "API_KEY".into(),
                    hosts: vec!["api.example.com".into(), "*".into()],
                },
            ],
        };

        let json = serde_json::to_string(&request).unwrap();
        let parsed: ControlRequest = serde_json::from_str(&json).unwrap();
        let ControlRequest::SecretsUpdate { changes } = parsed else {
            panic!("expected secrets_update");
        };
        assert_eq!(changes.len(), 3);
        let SecretLiveChange::Rotate { name, value } = &changes[0] else {
            panic!("expected rotate");
        };
        assert_eq!(name, "API_KEY");
        assert_eq!(value.0, "new-material");
    }

    #[test]
    fn capabilities_response_serializes_flags() {
        let response = ControlResponse {
            ok: true,
            capabilities: Some(ControlCapabilities {
                guest_flush_policy: true,
                optional_disk_integrity: true,
                root_disk_grow: true,
                cpu_resize: true,
                memory_resize: false,
                secrets_update: true,
                checkpoint_create: true,
                disk_checkpoint_create: true,
                branch_create: true,
                branch_memfd: false,
                pause_resume: true,
                disk_compact: true,
                disk_compact_owned: true,
            }),
            ..Default::default()
        };

        let json = serde_json::to_string(&response).unwrap();
        assert!(json.contains("\"secrets_update\":true"));
        assert!(json.contains("\"memory_resize\":false"));
        assert!(json.contains("\"disk_compact_owned\":true"));

        let parsed: ControlResponse = serde_json::from_str(&json).unwrap();
        assert!(parsed.capabilities.unwrap().secrets_update);
    }

    #[test]
    fn checkpoint_disk_integrity_defaults_off_and_round_trips_opt_in() {
        for enabled in [false, true] {
            let mut request = serde_json::json!({
                "op": "checkpoint_create", "checkpoint_id": "fixture", "intent": "full_snapshot"
            });
            if enabled {
                request["record_integrity"] = serde_json::json!(true);
            }
            let parsed: ControlRequest = serde_json::from_value(request).unwrap();
            let ControlRequest::CheckpointCreate {
                record_integrity, ..
            } = parsed
            else {
                panic!("expected full checkpoint request");
            };
            assert_eq!(record_integrity, enabled);
            assert_eq!(
                serde_json::to_value(parsed).unwrap()["record_integrity"],
                enabled
            );
        }
    }

    #[test]
    fn legacy_responses_without_capabilities_still_parse() {
        let parsed: ControlResponse = serde_json::from_str(r#"{"ok":true}"#).unwrap();
        assert!(parsed.ok);
        assert!(parsed.capabilities.is_none());
    }

    #[test]
    fn compaction_target_defaults_to_all_and_roundtrips_explicit_selection() {
        use microsandbox_types::DiskCompactionTarget;

        let omitted: ControlRequest =
            serde_json::from_str(r#"{"op":"disk_compact","layers":3}"#).unwrap();
        assert!(matches!(
            omitted,
            ControlRequest::DiskCompact {
                target: DiskCompactionTarget::All,
                layers: Some(3),
                dry_run: false,
            }
        ));
        for target in [
            DiskCompactionTarget::All,
            DiskCompactionTarget::Root,
            DiskCompactionTarget::Disk {
                guest_path: "/data".into(),
            },
        ] {
            let encoded = serde_json::to_string(&ControlRequest::DiskCompact {
                target: target.clone(),
                layers: Some(999),
                dry_run: true,
            })
            .unwrap();
            let decoded: ControlRequest = serde_json::from_str(&encoded).unwrap();
            assert!(matches!(decoded, ControlRequest::DiskCompact {
                target: actual, layers: Some(999), dry_run: true,
            } if actual == target));
        }
        assert!(
            serde_json::from_str::<ControlRequest>(
                r#"{"op":"disk_compact","target":{"kind":"disk"}}"#
            )
            .is_err()
        );
    }

    #[test]
    fn root_only_runtime_does_not_advertise_owned_compaction() {
        let old: ControlCapabilities = serde_json::from_str(
            r#"{"cpu_resize":false,"memory_resize":false,"secrets_update":false,"disk_compact":true}"#
        ).unwrap();
        assert!(old.disk_compact);
        assert!(!old.disk_compact_owned);
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "runner")]
pub use crate::runner::control::{ControlContext, spawn_control_listener};
