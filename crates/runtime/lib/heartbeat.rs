//! Host-side heartbeat reader for idle detection.
//!
//! The guest agent (agentd) writes `/.msb/heartbeat.json` every 5 seconds.
//! On the host, this file appears in the sandbox runtime directory via the
//! virtiofs mount. The sandbox process reads it to detect idle sandboxes.

use std::path::{Path, PathBuf};

use chrono::Utc;
use microsandbox_protocol::heartbeat::Heartbeat;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Reads heartbeat data from the host-side runtime directory.
pub struct HeartbeatReader {
    /// Path to the heartbeat.json file on the host.
    path: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HeartbeatReader {
    /// Create a new heartbeat reader for the given runtime directory.
    pub fn new(runtime_dir: &Path) -> Self {
        Self {
            path: runtime_dir.join("heartbeat.json"),
        }
    }

    /// Read and parse the heartbeat file.
    ///
    /// Returns `None` if the file doesn't exist or can't be parsed
    /// (e.g., agentd hasn't started writing yet).
    pub fn read(&self) -> Option<Heartbeat> {
        let content = std::fs::read_to_string(&self.path).ok()?;
        serde_json::from_str(&content).ok()
    }

    /// Check whether the sandbox is idle based on the heartbeat.
    ///
    /// Returns `true` if `last_activity` is older than `timeout_secs`.
    /// Returns `false` if the heartbeat file doesn't exist (agent still booting).
    pub fn is_idle(&self, timeout_secs: u64) -> bool {
        let heartbeat = match self.read() {
            Some(hb) => hb,
            None => return false,
        };

        let elapsed = Utc::now()
            .signed_duration_since(heartbeat.last_activity)
            .num_seconds();

        elapsed >= 0 && elapsed as u64 >= timeout_secs
    }
}
