//! Per-execution output windows; waiting here never blocks the agent control loop.

use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, Ordering},
};

use microsandbox_protocol::exec::EXEC_OUTPUT_EVENT_OVERHEAD;
use tokio::sync::Semaphore;

use crate::{AgentdError, AgentdResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug)]
/// Shared output allowance and cumulative acknowledgement state for one execution.
pub(crate) struct OutputWindow {
    /// Remaining output allowance in payload bytes plus per-chunk overhead.
    available: Semaphore,
    /// Whether a restored session has lost its reader and may produce output without waiting.
    detached: AtomicBool,
    /// Published and acknowledged charges, protected together against invalid acknowledgements.
    offsets: Mutex<Offsets>,
}

#[derive(Debug, Default)]
struct Offsets {
    /// Cumulative output charge reserved before publishing chunks.
    sent: u64,
    /// Cumulative output charge acknowledged by the reader.
    consumed: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OutputWindow {
    pub(crate) fn new(bytes: Option<u32>) -> AgentdResult<Option<Arc<Self>>> {
        bytes
            .map(|bytes| {
                if bytes <= EXEC_OUTPUT_EVENT_OVERHEAD {
                    return Err(AgentdError::ExecSession(format!(
                        "exec output window must be greater than {EXEC_OUTPUT_EVENT_OVERHEAD} bytes"
                    )));
                }
                Ok(Arc::new(Self {
                    available: Semaphore::new(bytes as usize),
                    detached: AtomicBool::new(false),
                    offsets: Mutex::new(Offsets::default()),
                }))
            })
            .transpose()
    }

    /// Called only by the output reader, before publishing its next chunk.
    pub(crate) async fn acquire(&self, payload_bytes: usize) -> bool {
        if self.detached.load(Ordering::Acquire) {
            return true;
        }
        let charge = payload_bytes as u32 + EXEC_OUTPUT_EVENT_OVERHEAD;
        let Ok(permit) = self.available.acquire_many(charge).await else {
            return self.detached.load(Ordering::Acquire);
        };
        let mut offsets = self.offsets.lock().unwrap();
        let Some(sent) = offsets.sent.checked_add(u64::from(charge)) else {
            return false;
        };
        offsets.sent = sent;
        permit.forget();
        true
    }

    /// Cumulative acknowledgements cannot enlarge the original window or be replayed.
    pub(crate) fn acknowledge(&self, consumed: u64) -> AgentdResult<()> {
        let mut offsets = self.offsets.lock().unwrap();
        if consumed < offsets.consumed || consumed > offsets.sent {
            return Err(AgentdError::ExecSession(
                "invalid exec output acknowledgement offset".into(),
            ));
        }
        let returned = consumed - offsets.consumed;
        offsets.consumed = consumed;
        self.available.add_permits(returned as usize);
        Ok(())
    }

    pub(crate) fn is_drained(&self) -> bool {
        let offsets = self.offsets.lock().unwrap();
        offsets.sent == offsets.consumed
    }

    /// Restored inherited sessions no longer have the original SDK reader.
    pub(crate) fn detach(&self) {
        self.detached.store(true, Ordering::Release);
        self.available.close();
    }

    pub(crate) fn close(&self) {
        self.available.close();
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    const TEST_OUTPUT_LIMIT: u32 = 64 * 1024;

    #[tokio::test]
    async fn acknowledgements_cannot_expand_capacity_or_be_replayed_or_forged() {
        let window = OutputWindow::new(Some(TEST_OUTPUT_LIMIT)).unwrap().unwrap();
        assert!(
            window
                .acquire(TEST_OUTPUT_LIMIT as usize - EXEC_OUTPUT_EVENT_OVERHEAD as usize)
                .await
        );
        let pending = window.acquire(1);
        tokio::pin!(pending);
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(10), &mut pending)
                .await
                .is_err()
        );
        assert!(
            window
                .acknowledge(u64::from(TEST_OUTPUT_LIMIT) + 1)
                .is_err()
        );
        assert_eq!(window.available.available_permits(), 0);
        window.acknowledge(1024).unwrap();
        window.acknowledge(1024).unwrap();
        assert!(pending.await);
        assert_eq!(
            window.available.available_permits(),
            1024 - 1 - EXEC_OUTPUT_EVENT_OVERHEAD as usize
        );
        assert!(window.acknowledge(1023).is_err());
        window.close();
        assert!(!window.acquire(1).await);
        window.detach();
        assert!(window.acquire(1).await);
    }
}
