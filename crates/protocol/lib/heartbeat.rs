//! Heartbeat data for the guest agent.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Heartbeat data written to `/.msb/heartbeat.json` inside the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Monotonic sequence incremented for every heartbeat write.
    pub heartbeat_seq: u64,

    /// Monotonic sequence incremented for every meaningful activity event.
    pub activity_seq: u64,

    /// Timestamp of this heartbeat.
    pub timestamp: DateTime<Utc>,

    /// Timestamp of the last meaningful activity event.
    pub last_activity: DateTime<Utc>,

    /// Number of currently active exec sessions.
    pub active_exec_sessions: u32,

    /// Number of currently active filesystem stream sessions.
    pub active_fs_streams: u32,

    /// Number of currently active TCP stream sessions.
    pub active_tcp_streams: u32,

    /// Cumulative activity counters.
    pub activity_counters: ActivityCounters,
}

/// Cumulative counters for meaningful sandbox activity.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct ActivityCounters {
    /// Meaningful host-to-guest protocol messages.
    pub host_messages: u64,

    /// Meaningful guest-to-host protocol messages.
    pub guest_messages: u64,

    /// Bytes emitted by exec stdout, stderr, or PTY output.
    pub exec_output_bytes: u64,

    /// Bytes moved by filesystem streaming.
    pub fs_bytes: u64,

    /// Bytes moved by TCP streaming.
    pub tcp_bytes: u64,
}
