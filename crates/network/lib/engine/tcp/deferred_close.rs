//! Graceful TCP shutdown after a host relay exits with queued data.

use std::time::Duration;

use smoltcp::socket::tcp;
use tokio::time::Instant;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Allow slow readers to drain, but bound retention when they stop making progress.
const DRAIN_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Tracks progress while flushing a departed relay's remaining bytes into smoltcp.
#[derive(Default)]
pub(crate) struct DeferredClose {
    last_progress: Option<Instant>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DeferredClose {
    /// Close after all relay bytes are queued, or reset after a sustained stall.
    ///
    /// `written` counts bytes accepted by smoltcp in this relay pass. Once all
    /// relay data is queued, smoltcp itself sends those bytes before the FIN.
    pub(crate) fn finish(&mut self, socket: &mut tcp::Socket<'_>, pending: bool, written: usize) {
        if !pending {
            self.last_progress = None;
            socket.close();
            return;
        }

        let now = Instant::now();
        let last_progress = self.last_progress.get_or_insert(now);
        if written > 0 {
            *last_progress = now;
        } else if now.duration_since(*last_progress) >= DRAIN_IDLE_TIMEOUT {
            self.last_progress = None;
            socket.abort();
        }
    }

    /// Time until a stalled drain must be checked, even without network wakeups.
    pub(crate) fn poll_delay(&self) -> Option<Duration> {
        self.last_progress
            .map(|last| DRAIN_IDLE_TIMEOUT.saturating_sub(last.elapsed()))
    }
}
