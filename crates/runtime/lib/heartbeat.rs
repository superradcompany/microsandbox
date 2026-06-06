//! Host-side heartbeat reader for idle detection.
//!
//! The guest agent (agentd) writes `/.msb/heartbeat.json` every second.
//! On the host, this file appears in the sandbox runtime directory via the
//! virtiofs mount. The sandbox process reads it to detect idle sandboxes.

use std::path::{Path, PathBuf};

use chrono::Utc;
use microsandbox_protocol::heartbeat::Heartbeat;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const HEARTBEAT_FILE: &str = "heartbeat.json";
const HEARTBEAT_TMP_FILE: &str = "heartbeat.tmp";

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
            path: runtime_dir.join(HEARTBEAT_FILE),
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
    /// Returns `true` if no exec is in flight and `last_activity` is older than
    /// `timeout_secs`. Returns `false` if the heartbeat file doesn't exist
    /// (agent still booting).
    pub fn is_idle(&self, timeout_secs: u64) -> bool {
        let heartbeat = match self.read() {
            Some(hb) => hb,
            None => return false,
        };

        // `last_activity` only advances on host→guest messages, so a long exec
        // that takes no input (a build, a `sleep`) ages past the timeout below
        // while still running — the timer alone would reclaim it mid-exec.
        if heartbeat.active_sessions > 0 {
            return false;
        }

        let elapsed = Utc::now()
            .signed_duration_since(heartbeat.last_activity)
            .num_seconds();

        elapsed >= 0 && elapsed as u64 >= timeout_secs
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Clear heartbeat files from a previous sandbox run.
pub fn clear_stale(runtime_dir: &Path) -> std::io::Result<()> {
    remove_file_if_exists(&runtime_dir.join(HEARTBEAT_FILE))?;
    remove_file_if_exists(&runtime_dir.join(HEARTBEAT_TMP_FILE))?;
    Ok(())
}

fn remove_file_if_exists(path: &Path) -> std::io::Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::{Duration, Utc};
    use microsandbox_protocol::heartbeat::Heartbeat;

    use super::*;

    #[test]
    fn clear_stale_removes_previous_run_heartbeat_files() {
        let dir = tempfile::tempdir().unwrap();
        let heartbeat_path = dir.path().join(HEARTBEAT_FILE);
        let tmp_path = dir.path().join(HEARTBEAT_TMP_FILE);
        let stale_time = Utc::now() - Duration::seconds(120);
        let heartbeat = Heartbeat {
            timestamp: stale_time,
            active_sessions: 0,
            last_activity: stale_time,
        };

        std::fs::write(&heartbeat_path, serde_json::to_vec(&heartbeat).unwrap()).unwrap();
        std::fs::write(&tmp_path, b"stale").unwrap();

        let reader = HeartbeatReader::new(dir.path());
        assert!(reader.is_idle(60));

        clear_stale(dir.path()).unwrap();

        assert!(!heartbeat_path.exists());
        assert!(!tmp_path.exists());
        assert!(!reader.is_idle(60));
    }

    #[test]
    fn in_flight_exec_is_never_idle_despite_stale_last_activity() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join(HEARTBEAT_FILE);
        let stale = Utc::now() - Duration::seconds(120);
        let reader = HeartbeatReader::new(dir.path());

        let write = |active_sessions| {
            let hb = Heartbeat {
                timestamp: Utc::now(),
                active_sessions,
                last_activity: stale,
            };
            std::fs::write(&path, serde_json::to_vec(&hb).unwrap()).unwrap();
        };

        // An exec is running; `last_activity` is 120s stale because the host
        // sent the guest nothing, but the sandbox is busy and must not be idle.
        write(1);
        assert!(!reader.is_idle(60));

        // Negative control: same staleness with no exec in flight IS idle.
        write(0);
        assert!(reader.is_idle(60));
    }
}
