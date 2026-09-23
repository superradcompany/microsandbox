//! Virtio serial port discovery and bounded workload input admission.

use std::sync::{Arc, Mutex};
use std::{fs, path::PathBuf};

use microsandbox_protocol::core::{WorkloadTransportCredit, WorkloadTransportPosition};
use tokio::sync::Notify;

use crate::error::{AgentdError, AgentdResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The sysfs path where virtio ports are listed.
const VIRTIO_PORTS_PATH: &str = "/sys/class/virtio-ports";

/// Re-export the canonical control and bulk port names from the protocol crate.
pub use microsandbox_protocol::{AGENT_BULK_PORT_NAME, AGENT_PORT_NAME};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Logical admission class, independent of the physical port. Raw records, stdin and inline
/// FS/TCP payloads use Bulk; command metadata and leases retain separate Control capacity.
#[derive(Clone, Copy, Debug)]
pub(crate) enum InputLane {
    Control,
    Bulk,
}

/// Cumulative flow-control state stays in captured guest RAM across restore. A new host starts
/// from the descriptor's position; retained input refunds the same ledger as it is consumed.
#[derive(Clone, Debug)]
pub(crate) struct InputWindow(Arc<InputState>);

#[derive(Debug)]
struct InputState {
    ledger: Mutex<InputLedger>,
    refunded: Notify,
}

#[derive(Debug)]
struct InputLedger {
    position: WorkloadTransportPosition,
    credit: WorkloadTransportCredit,
    exhausted: bool,
}

/// One admitted allocation, retained until its bytes are consumed or deliberately discarded.
#[derive(Debug)]
pub(crate) struct InputCharge {
    window: InputWindow,
    lane: InputLane,
    bytes: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl InputWindow {
    pub(crate) fn new(credit: WorkloadTransportCredit) -> Self {
        Self(Arc::new(InputState {
            ledger: Mutex::new(InputLedger {
                position: WorkloadTransportPosition::default(),
                credit,
                exhausted: false,
            }),
            refunded: Notify::new(),
        }))
    }

    pub(crate) fn position(&self) -> WorkloadTransportPosition {
        self.0
            .ledger
            .lock()
            .expect("input ledger poisoned")
            .position
    }

    pub(crate) fn credit(&self) -> AgentdResult<WorkloadTransportCredit> {
        let ledger = self.0.ledger.lock().expect("input ledger poisoned");
        if ledger.exhausted {
            return Err(AgentdError::ExecSession(
                "transport input counter exhausted".into(),
            ));
        }
        Ok(ledger.credit)
    }

    pub(crate) fn admit(&self, lane: InputLane, bytes: usize) -> AgentdResult<InputCharge> {
        let bytes = u64::try_from(bytes)
            .map_err(|_| AgentdError::ExecSession("transport frame length overflow".into()))?;
        let mut ledger = self.0.ledger.lock().expect("input ledger poisoned");
        let (old_bytes, old_frames, byte_limit, frame_limit) = match lane {
            InputLane::Control => (
                ledger.position.control_bytes,
                ledger.position.control_frames,
                ledger.credit.control_bytes,
                ledger.credit.control_frames,
            ),
            InputLane::Bulk => (
                ledger.position.bulk_bytes,
                ledger.position.bulk_frames,
                ledger.credit.bulk_bytes,
                ledger.credit.bulk_frames,
            ),
        };
        let next_bytes = old_bytes.checked_add(bytes);
        let next_frames = old_frames.checked_add(1);
        let (Some(next_bytes), Some(next_frames)) = (next_bytes, next_frames) else {
            return Err(AgentdError::ExecSession(
                "transport input counter exhausted".into(),
            ));
        };
        if ledger.exhausted || next_bytes > byte_limit || next_frames > frame_limit {
            return Err(AgentdError::ExecSession(
                "host exceeded its transport admission credit".into(),
            ));
        }
        match lane {
            InputLane::Control => {
                ledger.position.control_bytes = next_bytes;
                ledger.position.control_frames = next_frames;
            }
            InputLane::Bulk => {
                ledger.position.bulk_bytes = next_bytes;
                ledger.position.bulk_frames = next_frames;
            }
        }
        drop(ledger);
        Ok(InputCharge {
            window: self.clone(),
            lane,
            bytes,
        })
    }

    pub(crate) async fn refunded(&self) {
        self.0.refunded.notified().await;
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for InputCharge {
    fn drop(&mut self) {
        // This short ledger update never waits on guest I/O. Keeping the token with the buffer
        // also refunds cancellation, errors, and EOF without a separate per-payload message.
        let mut ledger = self.window.0.ledger.lock().expect("input ledger poisoned");
        let (bytes, frames) = match self.lane {
            InputLane::Control => (ledger.credit.control_bytes, ledger.credit.control_frames),
            InputLane::Bulk => (ledger.credit.bulk_bytes, ledger.credit.bulk_frames),
        };
        let (Some(bytes), Some(frames)) = (bytes.checked_add(self.bytes), frames.checked_add(1))
        else {
            ledger.exhausted = true;
            self.window.0.refunded.notify_one();
            return;
        };
        match self.lane {
            InputLane::Control => {
                ledger.credit.control_bytes = bytes;
                ledger.credit.control_frames = frames;
            }
            InputLane::Bulk => {
                ledger.credit.bulk_bytes = bytes;
                ledger.credit.bulk_frames = frames;
            }
        }
        drop(ledger);
        // Notify coalesces repeated refunds while the actor batches a credit update. An idle
        // guest has no periodic credit timer, and even one small refund wakes a blocked host.
        self.window.0.refunded.notify_one();
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Discovers the device path for a virtio serial port by its name.
///
/// Scans `/sys/class/virtio-ports/` entries, reads each `name` file,
/// and returns `/dev/{port_id}` for the matching port.
pub fn find_serial_port(name: &str) -> AgentdResult<PathBuf> {
    let ports_dir = PathBuf::from(VIRTIO_PORTS_PATH);

    let entries = fs::read_dir(&ports_dir).map_err(|e| {
        AgentdError::SerialPortNotFound(format!("cannot read {VIRTIO_PORTS_PATH}: {e}"))
    })?;

    for entry in entries {
        let entry = entry?;
        let name_file = entry.path().join("name");

        if let Ok(port_name) = fs::read_to_string(&name_file)
            && port_name.trim() == name
        {
            let port_id = entry.file_name();
            return Ok(PathBuf::from("/dev").join(port_id));
        }
    }

    Err(AgentdError::SerialPortNotFound(format!(
        "no virtio port with name '{name}' found"
    )))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn window() -> InputWindow {
        InputWindow::new(WorkloadTransportCredit {
            control_bytes: 8,
            control_frames: 2,
            bulk_bytes: 16,
            bulk_frames: 2,
        })
    }

    #[test]
    fn input_capacity_follows_consumption_not_decode_and_bounds_empty_messages() {
        let window = window();
        let first = window.admit(InputLane::Control, 4).unwrap();
        let second = window.admit(InputLane::Control, 4).unwrap();
        let at_cut = window.position();
        assert_eq!(at_cut.control_bytes, 8);
        assert_eq!(window.credit().unwrap().control_bytes, 8);
        assert!(window.admit(InputLane::Control, 1).is_err());
        assert_eq!(
            window.position(),
            at_cut,
            "rejection must not advance position"
        );
        drop(first);
        let next = window.admit(InputLane::Control, 1).unwrap();
        assert!(
            window.admit(InputLane::Control, 1).is_err(),
            "frame capacity is independent of bytes"
        );
        drop((second, next));
        assert_eq!(window.credit().unwrap().control_bytes, 17);
        assert_eq!(window.credit().unwrap().control_frames, 5);
    }

    #[test]
    fn inherited_input_refunds_the_same_cumulative_ledger_after_restore() {
        let window = window();
        let inherited = window.admit(InputLane::Bulk, 15).unwrap();
        let source_position = window.position();
        let restored_view = window.clone();
        // Moving a retained session to the detached table must not grant a fresh window.
        assert_eq!(restored_view.position(), source_position);
        assert!(restored_view.admit(InputLane::Bulk, 2).is_err());
        // Captured input keeps its debt, but cannot prevent the fresh host from starting an exec.
        let command = restored_view.admit(InputLane::Control, 8).unwrap();
        drop(command);
        drop(inherited);
        let fresh = restored_view.admit(InputLane::Bulk, 16).unwrap();
        assert_eq!(restored_view.position().bulk_bytes, 31);
        drop(fresh);
    }

    #[test]
    fn logical_classes_are_independent_and_counter_overflow_fails_closed() {
        let window = window();
        let control = window.admit(InputLane::Control, 8).unwrap();
        let bulk = window.admit(InputLane::Bulk, 16).unwrap();
        assert!(window.admit(InputLane::Bulk, 1).is_err());
        drop(control);
        assert_eq!(window.credit().unwrap().bulk_bytes, 16);
        drop(bulk);
        {
            let mut ledger = window.0.ledger.lock().unwrap();
            ledger.position.control_bytes = u64::MAX;
            ledger.credit.control_bytes = u64::MAX;
        }
        assert!(window.admit(InputLane::Control, 1).is_err());
    }

    #[test]
    fn dropping_a_cancelled_or_failed_input_refunds_exactly_one_frame() {
        let window = window();
        let before = window.credit().unwrap();
        let cancelled = window.admit(InputLane::Control, 3).unwrap();
        drop(cancelled);
        let after = window.credit().unwrap();
        assert_eq!(after.control_bytes, before.control_bytes + 3);
        assert_eq!(after.control_frames, before.control_frames + 1);
        assert_eq!(after.bulk_bytes, before.bulk_bytes);
        assert_eq!(after.bulk_frames, before.bulk_frames);
        assert_eq!(window.position().control_frames, 1);
    }

    #[tokio::test]
    async fn refund_notifications_are_idle_until_small_progress_and_coalesce() {
        let window = window();
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), window.refunded())
                .await
                .is_err()
        );
        let first = window.admit(InputLane::Control, 1).unwrap();
        let second = window.admit(InputLane::Control, 1).unwrap();
        drop((first, second));
        tokio::time::timeout(std::time::Duration::from_millis(100), window.refunded())
            .await
            .unwrap();
        assert_eq!(window.credit().unwrap().control_bytes, 10);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), window.refunded())
                .await
                .is_err()
        );
    }
}
