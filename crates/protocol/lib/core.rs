//! Core protocol message payloads.

use serde::{Deserialize, Serialize};

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
}
