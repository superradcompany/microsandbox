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
