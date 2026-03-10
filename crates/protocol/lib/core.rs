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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
}
