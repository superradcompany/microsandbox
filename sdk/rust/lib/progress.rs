//! Best-effort creation telemetry. The creation result, not stream EOF, determines success.

use tokio::sync::mpsc;

pub use microsandbox_runtime::startup_progress::{StartupPhase, StartupProgress};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Progress from image preparation through VM activation.
#[derive(Clone, Debug, serde::Serialize)]
#[serde(tag = "kind", content = "progress", rename_all = "snake_case")]
pub enum CreationProgress {
    /// Existing per-layer image preparation progress.
    Pull(microsandbox_image::PullProgress),
    /// Runtime preparation or activation progress.
    Startup(StartupProgress),
}

/// Bounded progress stream. Dropping this handle does not cancel creation.
pub struct CreationProgressHandle {
    receiver: mpsc::Receiver<CreationProgress>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CreationProgressHandle {
    /// Receive the next event. Events may coalesce or be omitted for slow consumers.
    pub async fn recv(&mut self) -> Option<CreationProgress> {
        self.receiver.recv().await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn channel() -> (CreationProgressHandle, mpsc::Sender<CreationProgress>) {
    let (sender, receiver) = mpsc::channel(256);
    (CreationProgressHandle { receiver }, sender)
}

pub(crate) fn report(
    observer: &Option<mpsc::WeakSender<CreationProgress>>,
    event: CreationProgress,
) {
    if let Some(sender) = observer.as_ref().and_then(mpsc::WeakSender::upgrade) {
        let _ = sender.try_send(event);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn ignored_full_or_dropped_progress_never_blocks_the_producer() {
        let (mut events, sender) = channel();
        let weak = Some(sender.downgrade());
        for _ in 0..10000 {
            report(
                &weak,
                CreationProgress::Startup(StartupProgress::phase(StartupPhase::Activating)),
            );
        }
        assert!(events.recv().await.is_some());
        drop(events);
        report(
            &weak,
            CreationProgress::Startup(StartupProgress::phase(StartupPhase::Activating)),
        );
        drop(sender);
        assert!(weak.unwrap().upgrade().is_none());
    }

    #[test]
    fn startup_serialization_preserves_unknown_totals() {
        let event =
            CreationProgress::Startup(StartupProgress::phase(StartupPhase::SyncingMemoryBacking));
        let json = serde_json::to_value(event).unwrap();
        assert_eq!(json["kind"], "startup");
        assert_eq!(json["progress"]["phase"], "syncing_memory_backing");
        assert!(json["progress"]["total_bytes"].is_null());
    }
}
