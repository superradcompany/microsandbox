//! Core protocol message payloads.

use serde::{Deserialize, Serialize};

use crate::transport::{BulkTransportReady, LocalTransportReady, RelayLeaseReady};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Complete-frame workload barrier with logical control/data admission classes.
///
/// Version 1 was an unreleased development contract that charged stdin to control. Its captured
/// debt cannot be reinterpreted by this contract; full restore rejects that development state.
pub const WORKLOAD_TRANSPORT_BARRIER_VERSION: u8 = 2;
/// Maximum outstanding command/control wire bytes, including frame headers.
pub const WORKLOAD_TRANSPORT_CONTROL_BYTES: u64 = 8 * 1024 * 1024;
/// Maximum outstanding command/control frames, excluding retained workload payloads.
pub const WORKLOAD_TRANSPORT_CONTROL_FRAMES: u64 = 256;
/// Maximum outstanding data wire bytes, including raw bulk, stdin and inline FS/TCP payloads.
pub const WORKLOAD_TRANSPORT_BULK_BYTES: u64 = 32 * 1024 * 1024;
/// Maximum outstanding data records/messages, including ordered empty EOF messages.
///
/// Together with control frames, this fits the existing 512-entry guest input
/// queues even when all admitted traffic targets one stalled consumer.
pub const WORKLOAD_TRANSPORT_BULK_FRAMES: u64 = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Payload for `core.ready` messages.
///
/// Sent by the guest agent to signal that it has finished initialization
/// and is ready to receive commands. Includes timing data for boot
/// performance measurement.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Ready {
    /// `CLOCK_BOOTTIME` nanoseconds captured at the start of `main()`.
    ///
    /// Represents how long the kernel took to boot before userspace started.
    pub boot_time_ns: u64,

    /// Nanoseconds spent in `init::init()` (mounting filesystems).
    pub init_time_ns: u64,

    /// `CLOCK_BOOTTIME` nanoseconds captured just before sending this message.
    ///
    /// Represents total time from kernel boot to agent readiness.
    pub ready_time_ns: u64,

    /// The agent's package version (`CARGO_PKG_VERSION`), for diagnostics.
    ///
    /// Additive and optional: an older agent that predates this field decodes to
    /// an empty string, and an older host ignores it. Empty means unknown. This
    /// is the runtime's self-reported product version; the protocol generation is
    /// carried separately in the message envelope's `v`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub agent_version: String,

    /// Bound internal data-plane topology, when agentd negotiated one at boot.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bulk_transport: Option<BulkTransportReady>,

    /// Optional topology-independent relay correlation-range lease capability.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay_lease: Option<RelayLeaseReady>,

    /// Optional SDK-to-runtime transport capability injected by a local Unix relay.
    ///
    /// Agentd leaves this absent because local shared memory is below the guest protocol.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub local_transport: Option<LocalTransportReady>,

    /// Internal host-to-guest complete-frame barriers and aggregate input credit.
    ///
    /// Absence does not change ordinary generation-8 clients. Full capture and
    /// pause require the supported contract instead of assuming frame safety.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_transport_barrier_version: Option<u8>,
}

/// Payload for `core.clock.sync` messages.
///
/// Sent by the host to ask the guest agent to step `CLOCK_REALTIME` to the
/// host's current wall-clock time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClockSync {
    /// Host Unix timestamp in nanoseconds.
    pub unix_time_nanos: u64,
}

/// Payload for `core.ping` messages.
///
/// Sent by the host to verify that agentd is reachable. A ping is maintenance
/// traffic and does not refresh the sandbox idle timer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ping {}

/// Payload for `core.pong` messages.
///
/// Sent by agentd in response to `core.ping`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Pong {}

/// Payload for `core.touch` messages.
///
/// Sent by the host to explicitly refresh the sandbox idle timer without
/// starting an exec, filesystem, or TCP session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Touch {}

/// Payload for `core.touched` messages.
///
/// Sent by agentd in response to `core.touch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Touched {
    /// Activity sequence after the explicit touch was recorded.
    pub activity_seq: u64,
}

/// Payload for `core.workload.freeze` messages.
///
/// The attempt identity makes retries idempotent and prevents one checkpoint
/// operation from accidentally releasing another operation's freeze.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadFreeze {
    /// External virtiofs tags whose writeback boundary must be proved by the guest.
    #[serde(default)]
    pub external_mount_tags: Vec<String>,
    /// Stable checkpoint attempt identity selected by the host.
    pub attempt_id: String,
    /// Complete ordinary frames admitted by the host before gating user input.
    pub host_input: WorkloadTransportPosition,
}

/// Payload for `core.workload.frozen` messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadFrozen {
    /// Attempt identity whose workload boundary is now frozen.
    pub attempt_id: String,
    /// Complete dedicated bulk wire bytes emitted before the guest writer parked.
    ///
    /// Zero for combined transport, whose primary stream already orders output
    /// before this acknowledgement. The host drains to this cut before pausing.
    pub guest_bulk_bytes_target: u64,
    /// Absolute input limits captured with this boundary, not a fresh window.
    pub input_credit: WorkloadTransportCredit,
    /// Guest virtiofs dirty pages reached backing storage after the workload freeze.
    /// Older guests omit this evidence and cannot capture external mounts safely.
    #[serde(default)]
    pub external_mounts_synced: bool,
}

/// Cumulative ordinary input admitted at complete frame or record boundaries.
///
/// These counters survive restore. Guest-accepted input is captured guest state;
/// host-queued input that has not been admitted remains source-owned.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadTransportPosition {
    /// Command/control wire bytes admitted, including length/header bytes.
    /// Payload-bearing messages and raw bulk use `bulk_bytes` on either physical port.
    pub control_bytes: u64,
    /// Command/control frames admitted, excluding payload messages and raw bulk.
    pub control_frames: u64,
    /// Data wire bytes admitted, including stdin, inline payloads, and complete raw bulk headers.
    pub bulk_bytes: u64,
    /// Data records/messages admitted, including ordered EOF.
    pub bulk_frames: u64,
}

/// Absolute aggregate input grants in `core.workload.transport.credit`.
///
/// Grants advance only as guest consumers release admitted input. Updates may be
/// coalesced; applying one twice never grants additional capacity. Both byte and
/// frame limits bound retained data without making lifecycle progress depend on
/// a workload consuming stdin or a network socket becoming writable.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadTransportCredit {
    /// Cumulative command/control wire-byte limit.
    pub control_bytes: u64,
    /// Cumulative command/control frame limit.
    pub control_frames: u64,
    /// Cumulative data wire-byte limit across both physical ports.
    pub bulk_bytes: u64,
    /// Cumulative data record/message limit across both physical ports.
    pub bulk_frames: u64,
}

/// Payload for `core.workload.thaw` messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadThaw {
    /// Attempt identity that established the freeze being released.
    pub attempt_id: String,
    /// Continue the source, or activate a restored guest with fresh host-client ownership.
    pub mode: WorkloadThawMode,
}

/// How a captured workload returns to execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadThawMode {
    /// Continue the source without changing any connected client or stream.
    Continue,
    /// Detach inherited host clients without killing their captured processes.
    Restore,
}

/// Payload for `core.workload.thawed` messages.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkloadThawed {
    /// Attempt identity whose workload boundary is now runnable.
    pub attempt_id: String,
}

/// Root disk growth target, in bytes, used for preflight and apply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootDiskGrow {
    /// Desired ext4 size; must be an aligned, nondecreasing target.
    pub size_bytes: u64,
}

/// Observed capacities of the guest root filesystem and its block device.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RootDiskState {
    /// ext4 superblock size, including filesystem metadata.
    pub filesystem_bytes: u64,
    /// Capacity observed by the guest block driver.
    pub device_bytes: u64,
}

/// Payload for `core.error` messages.
///
/// Sent when a peer can identify a recoverable protocol error for a specific
/// correlation ID. Unrecoverable frame-level errors, such as stream
/// desynchronization or impossible frame lengths, should close the transport
/// instead.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoreError {
    /// Machine-readable error kind.
    pub kind: CoreErrorKind,

    /// Human-readable diagnostic message.
    pub message: String,

    /// Wire message type involved in the error, when it could be determined.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub offending_type: Option<String>,

    /// Attempt-scoped freezer disposition. Absence is ambiguous, not proof that no work froze.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_failure: Option<WorkloadFailure>,
}

/// Additional recovery information for a workload control error.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkloadFailure {
    /// Attempt whose request failed.
    pub attempt_id: String,
    /// Whether a freeze was rejected before any freezer operation or needs recovery.
    pub disposition: WorkloadFailureDisposition,
}

/// Freezer failure dispositions; unknown future values never authorize a fallback.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkloadFailureDisposition {
    /// No freezer exists and no freeze was attempted.
    Unavailable,
    /// The caller must obtain a confirmed thaw before treating the workload as running.
    RecoveryRequired,
    /// Unrecognized additional information from a newer agent.
    #[serde(other)]
    Unknown,
}

/// Machine-readable `core.error` categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreErrorKind {
    /// The protocol message envelope could not be decoded.
    MalformedMessage,

    /// The message type is unknown to the peer.
    UnsupportedMessageType,

    /// The message requires a newer protocol generation than the peer supports.
    UnsupportedProtocolGeneration,

    /// The frame flags do not match the message type.
    InvalidFlags,

    /// The message payload could not be decoded or failed validation.
    InvalidPayload,

    /// The message refers to an unknown, closed, or incompatible session.
    InvalidSession,

    /// The peer understands the request but the runtime cannot provide its capability.
    CapabilityUnavailable,
}

/// Payload for `core.init.resolved` messages.
///
/// Sent by agentd after the guest rootfs is ready to resolve init-time facts,
/// but before user volume mounts are attached. The host uses this to install
/// early runtime state that depends on guest-resolved values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitResolved {
    /// Default guest user for sandbox commands.
    pub default_user: ResolvedUser,
}

/// A guest user and group resolved by agentd.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ResolvedUser {
    /// Effective default guest user id for sandbox commands.
    pub uid: u32,

    /// Effective default guest group id for sandbox commands.
    pub gid: u32,
}

/// Payload for `core.init.ack` messages.
///
/// Sent by the host after it has consumed the init context and completed any
/// dependent setup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InitAck {}

/// Payload for `core.relay.client.disconnected` messages.
///
/// Sent by the host relay when one SDK client socket disconnects. The
/// guest agent uses the assigned correlation ID range to clean up resources
/// owned by that client, such as open filesystem handles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RelayClientDisconnected {
    /// First correlation ID assigned to the disconnected client.
    pub id_start: u32,

    /// Exclusive upper bound of the disconnected client's ID range.
    pub id_end_exclusive: u32,

    /// Exact leased range owner being removed. Absent only for legacy unleased peers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub incarnation: Option<[u8; 16]>,
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::{Ready, RelayClientDisconnected};

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct LegacyReady {
        boot_time_ns: u64,
        init_time_ns: u64,
        ready_time_ns: u64,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        agent_version: String,
    }

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct LegacyRelayClientDisconnected {
        id_start: u32,
        id_end_exclusive: u32,
    }

    #[test]
    fn ready_without_transport_capabilities_is_byte_compatible() {
        let legacy = LegacyReady {
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            agent_version: "0.6.8".into(),
        };
        let current = Ready {
            boot_time_ns: legacy.boot_time_ns,
            init_time_ns: legacy.init_time_ns,
            ready_time_ns: legacy.ready_time_ns,
            agent_version: legacy.agent_version.clone(),
            bulk_transport: None,
            relay_lease: None,
            local_transport: None,
            workload_transport_barrier_version: None,
        };
        let mut legacy_bytes = Vec::new();
        ciborium::into_writer(&legacy, &mut legacy_bytes).unwrap();
        let mut current_bytes = Vec::new();
        ciborium::into_writer(&current, &mut current_bytes).unwrap();

        assert_eq!(current_bytes, legacy_bytes);
        let decoded: Ready = ciborium::from_reader(legacy_bytes.as_slice()).unwrap();
        assert!(decoded.bulk_transport.is_none());
        assert!(decoded.relay_lease.is_none());
        assert!(decoded.local_transport.is_none());
        assert!(decoded.workload_transport_barrier_version.is_none());
    }

    #[test]
    fn relay_disconnect_without_incarnation_is_byte_compatible() {
        let legacy = LegacyRelayClientDisconnected {
            id_start: 1,
            id_end_exclusive: 1024,
        };
        let current = RelayClientDisconnected {
            id_start: legacy.id_start,
            id_end_exclusive: legacy.id_end_exclusive,
            incarnation: None,
        };
        let mut legacy_bytes = Vec::new();
        ciborium::into_writer(&legacy, &mut legacy_bytes).unwrap();
        let mut current_bytes = Vec::new();
        ciborium::into_writer(&current, &mut current_bytes).unwrap();

        assert_eq!(current_bytes, legacy_bytes);
        let decoded: RelayClientDisconnected =
            ciborium::from_reader(legacy_bytes.as_slice()).unwrap();
        assert_eq!(decoded.id_start, current.id_start);
        assert_eq!(decoded.id_end_exclusive, current.id_end_exclusive);
        assert_eq!(decoded.incarnation, None);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod workload_tests {
    use super::*;

    #[test]
    fn workload_barrier_payloads_roundtrip_without_resetting_counters() {
        let position = WorkloadTransportPosition {
            control_bytes: 73 * WORKLOAD_TRANSPORT_CONTROL_BYTES,
            control_frames: 20_000,
            bulk_bytes: 91 * WORKLOAD_TRANSPORT_BULK_BYTES,
            bulk_frames: 30_000,
        };
        let freeze = WorkloadFreeze {
            external_mount_tags: Vec::new(),
            attempt_id: "captured-generation".into(),
            host_input: position,
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&freeze, &mut bytes).unwrap();
        let decoded: WorkloadFreeze = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(decoded, freeze);

        // A restored guest may still own most of the window as pending stdin.
        // Carry absolute grants, not a reset that would admit that much again.
        let frozen = WorkloadFrozen {
            external_mounts_synced: false,
            attempt_id: freeze.attempt_id,
            guest_bulk_bytes_target: 987_654_321,
            input_credit: WorkloadTransportCredit {
                control_bytes: position.control_bytes + 100,
                control_frames: position.control_frames + 2,
                bulk_bytes: position.bulk_bytes + 200,
                bulk_frames: position.bulk_frames + 3,
            },
        };
        bytes.clear();
        ciborium::into_writer(&frozen, &mut bytes).unwrap();
        let decoded: WorkloadFrozen = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(decoded, frozen);
    }

    #[test]
    fn superseded_development_freeze_payloads_do_not_imply_safe_boundaries() {
        let old = serde_json::json!({"attempt_id":"old-development-capture"});
        assert!(serde_json::from_value::<WorkloadFreeze>(old.clone()).is_err());
        assert!(serde_json::from_value::<WorkloadFrozen>(old).is_err());
    }

    #[test]
    fn unknown_barrier_capability_is_preserved_for_explicit_negotiation() {
        let ready = Ready {
            workload_transport_barrier_version: Some(99),
            ..Ready::default()
        };
        let mut bytes = Vec::new();
        ciborium::into_writer(&ready, &mut bytes).unwrap();
        let decoded: Ready = ciborium::from_reader(bytes.as_slice()).unwrap();
        assert_eq!(decoded.workload_transport_barrier_version, Some(99));
        assert_ne!(
            decoded.workload_transport_barrier_version,
            Some(WORKLOAD_TRANSPORT_BARRIER_VERSION)
        );
    }

    #[test]
    fn input_window_fits_a_maximum_primary_frame() {
        let credit = WorkloadTransportCredit {
            control_bytes: WORKLOAD_TRANSPORT_CONTROL_BYTES,
            control_frames: WORKLOAD_TRANSPORT_CONTROL_FRAMES,
            bulk_bytes: WORKLOAD_TRANSPORT_BULK_BYTES,
            bulk_frames: WORKLOAD_TRANSPORT_BULK_FRAMES,
        };
        assert!(credit.control_bytes >= crate::codec::MAX_FRAME_SIZE as u64 + 4);
        assert!(credit.control_frames > 0);
        assert!(credit.bulk_frames > 0);
    }

    #[test]
    fn freezer_error_details_are_additive_and_unknown_details_are_not_unavailable() {
        let old = serde_json::json!({"kind":"capability_unavailable", "message":"freezer failed"});
        let decoded: CoreError = serde_json::from_value(old.clone()).unwrap();
        assert!(decoded.workload_failure.is_none());
        let mut new = old;
        new["workload_failure"] =
            serde_json::json!({"attempt_id":"a", "disposition":"future_state"});
        let decoded: CoreError = serde_json::from_value(new.clone()).unwrap();
        assert_eq!(
            decoded.workload_failure.unwrap().disposition,
            WorkloadFailureDisposition::Unknown
        );

        #[derive(Deserialize)]
        struct OldCoreError {
            kind: CoreErrorKind,
            message: String,
        }
        let old_reader: OldCoreError = serde_json::from_value(new).unwrap();
        assert_eq!(old_reader.kind, CoreErrorKind::CapabilityUnavailable);
        assert_eq!(old_reader.message, "freezer failed");
    }
}
