//! Periodic heartbeat writer for the guest agent.

use std::io;
use std::path::Path;
use std::sync::{Condvar, Mutex};

use microsandbox_protocol::heartbeat::Heartbeat;

use crate::error::AgentdResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Path to the heartbeat JSON file (under [`microsandbox_protocol::RUNTIME_MOUNT_POINT`]).
const HEARTBEAT_PATH: &str = "/.msb/heartbeat.json";

/// Path to the temporary heartbeat file (for atomic rename).
const HEARTBEAT_TMP_PATH: &str = "/.msb/heartbeat.tmp";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Coordinates the heartbeat writer with same-epoch workload checkpoints.
#[derive(Default)]
pub(crate) struct HeartbeatControl {
    state: Mutex<HeartbeatState>,
    changed: Condvar,
}

#[derive(Default)]
struct HeartbeatState {
    paused: bool,
    writing: bool,
}

pub(crate) struct HeartbeatWriteGuard<'a> {
    control: &'a HeartbeatControl,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HeartbeatControl {
    /// Stop new heartbeat replacements and wait for an in-flight atomic write to finish.
    pub(crate) fn pause(&self) -> io::Result<()> {
        let mut state = self.state.lock().unwrap();
        state.paused = true;
        while state.writing {
            state = self.changed.wait(state).unwrap();
        }
        drop(state);

        // A failed write can leave the temporary path behind. It must not enter the captured FUSE
        // namespace because a new sandbox intentionally starts without that transient object.
        match std::fs::remove_file(HEARTBEAT_TMP_PATH) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => {
                self.resume();
                Err(error)
            }
        }
    }

    /// Resume the heartbeat pulse after checkpoint failure or workload thaw.
    pub(crate) fn resume(&self) {
        let mut state = self.state.lock().unwrap();
        state.paused = false;
        self.changed.notify_all();
    }

    /// Enter one atomic heartbeat replacement, or skip it while checkpoint capture owns the gate.
    pub(crate) fn begin_write(&self) -> Option<HeartbeatWriteGuard<'_>> {
        let mut state = self.state.lock().unwrap();
        if state.paused {
            return None;
        }
        state.writing = true;
        Some(HeartbeatWriteGuard { control: self })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for HeartbeatWriteGuard<'_> {
    fn drop(&mut self) {
        let mut state = self.control.state.lock().unwrap();
        state.writing = false;
        self.control.changed.notify_all();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Atomically writes the heartbeat JSON to `/.msb/heartbeat.json`.
///
/// Deliberately synchronous: the liveness pulse runs on a dedicated OS thread
/// (see [`crate::agent`]) so a saturated async runtime can never starve it.
/// Blocking `std::fs` keeps that thread fully independent of Tokio.
pub fn write_heartbeat(heartbeat: &Heartbeat) -> AgentdResult<()> {
    let json = serde_json::to_vec(heartbeat)?;

    std::fs::write(HEARTBEAT_TMP_PATH, json)?;
    std::fs::rename(HEARTBEAT_TMP_PATH, HEARTBEAT_PATH)?;

    Ok(())
}

/// Returns `true` if the heartbeat directory exists (i.e., the runtime mount is available).
pub fn heartbeat_dir_exists() -> bool {
    Path::new(microsandbox_protocol::RUNTIME_MOUNT_POINT).is_dir()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use super::*;

    #[test]
    fn checkpoint_pause_drains_writer_and_blocks_new_heartbeats() {
        let control = Arc::new(HeartbeatControl::default());
        let writer = control.begin_write().unwrap();
        let paused = Arc::clone(&control);
        let pause = std::thread::spawn(move || paused.pause().unwrap());

        for _ in 0..100 {
            if control.state.lock().unwrap().paused {
                break;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert!(control.state.lock().unwrap().paused);
        assert!(!pause.is_finished());

        drop(writer);
        pause.join().unwrap();
        assert!(control.begin_write().is_none());

        control.resume();
        assert!(control.begin_write().is_some());
    }
}
