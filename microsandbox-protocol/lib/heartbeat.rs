//! Heartbeat data for the guest agent.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Heartbeat data written to `/.msb/heartbeat.json` inside the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Heartbeat {
    /// Timestamp of this heartbeat.
    pub timestamp: DateTime<Utc>,

    /// Number of currently active exec sessions.
    pub active_sessions: u32,

    /// Timestamp of the last message received from the host.
    pub last_activity: DateTime<Utc>,
}
