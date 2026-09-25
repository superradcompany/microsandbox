//! Admission health for a blocked console input write.

use std::time::Duration;

use tokio::sync::watch;
use tokio::time::Instant;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const INPUT_STALL_TIMEOUT: Duration = Duration::from_secs(60);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One physical writer owns a single capacity wait across scheduling and delivery.
/// Dropping that wait clears the lane stall on delivery, shutdown, or cancellation.
pub(super) struct InputStall<'a> {
    state: &'a watch::Sender<bool>,
    deadline: Instant,
    paused_at: Option<Instant>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> InputStall<'a> {
    pub(super) fn new(state: &'a watch::Sender<bool>, timeout: Duration) -> Self {
        Self {
            state,
            deadline: Instant::now() + timeout,
            paused_at: None,
        }
    }

    /// Exclude intentionally parked time without clearing an already active stall.
    pub(super) fn set_paused(&mut self, paused: bool) {
        if paused {
            self.paused_at.get_or_insert_with(Instant::now);
        } else if let Some(started) = self.paused_at.take() {
            self.deadline += started.elapsed();
        }
    }

    /// Mark the lane stalled once, then keep waiting without polling. This
    /// future never completes; capacity notifications drive delivery retries.
    pub(super) async fn watch(&self) {
        if self.paused_at.is_none() && !*self.state.borrow() {
            tokio::time::sleep_until(self.deadline).await;
            self.state.send_replace(true);
            tracing::warn!(
                "agent relay: input stalled; rejecting new connections until delivery resumes"
            );
        }

        std::future::pending::<()>().await;
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for InputStall<'_> {
    fn drop(&mut self) {
        self.state.send_if_modified(|stalled| {
            if *stalled {
                *stalled = false;
                tracing::info!("agent relay: input resumed; reopening client admission");
                true
            } else {
                false
            }
        });
    }
}
