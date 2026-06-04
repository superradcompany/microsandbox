//! Per-exporter worker task: owns its buffer, batches collections, runs
//! exports.
//!
//! One worker exists per registered [`MetricsExporter`]. The driver
//! broadcasts each [`MetricsCollection`] over a shared channel; every worker
//! consumes it independently into its own bounded [`VecDeque`] (drop-oldest
//! on overflow). Scheduled flushes are driven by an in-worker ticker; the
//! driver triggers explicit flushes by broadcasting a unit value on the
//! flush-signal channel.
//!
//! Shutdown is structural: when the driver drops its broadcast Senders, every
//! worker observes [`RecvError::Closed`], exits its loop, runs a final flush,
//! calls `exporter.shutdown()`, and returns the result. The driver collects
//! those results from its [`JoinSet`].
//!
//! All buffer state is task-local — no `Mutex` required.

use std::{
    collections::VecDeque,
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::sync::broadcast;

use crate::error::{MetricsCollectorError, MetricsCollectorResult};

use super::builder::MetricsExporterConfig;
use super::driver::MetricsErrorPolicy;
use super::types::{MetricsCollection, MetricsExportBatch, MetricsExporter};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-exporter task state — fully owned, no shared mutability needed.
pub(crate) struct ExporterWorker {
    exporter: Arc<dyn MetricsExporter>,
    config: MetricsExporterConfig,
    buffer: VecDeque<MetricsCollection>,
    dropped_count: u64,
    data_rx: broadcast::Receiver<Arc<MetricsCollection>>,
    flush_signal_rx: broadcast::Receiver<()>,
    /// Number of consecutive failed exports since the last success.
    /// Drives the exponential-backoff delay between retries.
    consecutive_failures: u32,
    /// When set, scheduled flushes are skipped until this deadline passes.
    /// Cleared on the next successful export. Driver-triggered flushes
    /// (explicit `RunningCollector::flush()`) bypass this gate so a
    /// caller can force-retry after fixing the upstream problem.
    next_retry_after: Option<Instant>,
}

/// Cap on the exponential backoff multiplier. With base = `flush_interval`,
/// the worst-case delay between retries is `flush_interval × 2^MAX`. At
/// the default 10s flush interval that's ~5 minutes, which is long enough
/// to ride out a typical backend outage without hammering and short
/// enough that recovery is visible to operators.
const MAX_BACKOFF_EXP: u32 = 5;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExporterWorker {
    /// Assemble a worker. Spawn its [`Self::run`] future onto a `JoinSet` to
    /// start it.
    pub(crate) fn new(
        exporter: Arc<dyn MetricsExporter>,
        config: MetricsExporterConfig,
        data_rx: broadcast::Receiver<Arc<MetricsCollection>>,
        flush_signal_rx: broadcast::Receiver<()>,
    ) -> Self {
        Self {
            exporter,
            config,
            buffer: VecDeque::new(),
            dropped_count: 0,
            data_rx,
            flush_signal_rx,
            consecutive_failures: 0,
            next_retry_after: None,
        }
    }

    /// The worker's task loop. Consumes broadcast collections into the local
    /// buffer, runs flushes on the scheduled ticker and on driver-triggered
    /// signals, and — when the data channel closes — runs one final flush plus
    /// `exporter.shutdown()` before returning the aggregated result.
    pub(crate) async fn run(mut self) -> MetricsCollectorResult<()> {
        use broadcast::error::RecvError;

        let mut flush_ticker = tokio::time::interval(self.config.flush_interval);
        flush_ticker.tick().await; // skip the immediate first tick

        loop {
            tokio::select! {
                recv = self.data_rx.recv() => match recv {
                    Ok(arc) => self.buffer_collection((*arc).clone()),
                    Err(RecvError::Lagged(n)) => {
                        self.dropped_count = self.dropped_count.saturating_add(n);
                    }
                    Err(RecvError::Closed) => break,
                },
                signal = self.flush_signal_rx.recv() => match signal {
                    // Explicit driver-triggered flushes bypass the backoff
                    // gate; the caller's intent is "try right now, the
                    // upstream may have recovered".
                    Ok(()) | Err(RecvError::Lagged(_)) => self.flush_now().await,
                    Err(RecvError::Closed) => break,
                },
                _ = flush_ticker.tick() => {
                    if self.scheduled_flush_blocked_by_backoff() {
                        continue;
                    }
                    self.flush_now().await;
                }
            }
        }

        // Final flush + exporter shutdown — the worker's return value is what
        // the driver's JoinSet collects.
        self.drain_pending();
        let flush_result = self.run_export().await;
        let shutdown_result = self.exporter.shutdown().await;
        flush_result.and(shutdown_result)
    }

    /// Drain pending broadcast values into the buffer, run an export, and
    /// apply the error policy on failure. Used for both scheduled and
    /// driver-triggered flushes.
    async fn flush_now(&mut self) {
        self.drain_pending();
        match self.run_export().await {
            Ok(()) => {
                if self.consecutive_failures > 0 || self.next_retry_after.is_some() {
                    tracing::info!("metrics exporter recovered; resetting backoff");
                }
                self.consecutive_failures = 0;
                self.next_retry_after = None;
            }
            Err(error) => match self.config.error_policy {
                MetricsErrorPolicy::LogAndContinue => {
                    self.consecutive_failures = self.consecutive_failures.saturating_add(1);
                    self.schedule_next_retry();
                    tracing::warn!(
                        consecutive_failures = self.consecutive_failures,
                        %error,
                        "metrics exporter export failed; backing off"
                    );
                }
            },
        }
    }

    /// Decide whether a scheduled-flush tick should skip this round because
    /// the backoff deadline hasn't elapsed yet. Data still accumulates in
    /// the buffer (subject to the drop-oldest cap) until either an
    /// explicit driver flush succeeds or the next eligible scheduled tick.
    fn scheduled_flush_blocked_by_backoff(&self) -> bool {
        self.next_retry_after
            .is_some_and(|deadline| Instant::now() < deadline)
    }

    /// Compute and stash the next-retry deadline using exponential
    /// backoff capped at `flush_interval × 2^MAX_BACKOFF_EXP`. The first
    /// failure waits `2 × flush_interval` (so the next scheduled tick is
    /// just skipped); subsequent failures double each time.
    fn schedule_next_retry(&mut self) {
        let exp = (self.consecutive_failures.saturating_sub(1)).min(MAX_BACKOFF_EXP);
        let mult = 1u32 << exp;
        let delay = self.config.flush_interval.saturating_mul(mult);
        self.next_retry_after = Some(Instant::now() + delay);
    }

    /// Append a collection to the local buffer, evicting the oldest entry
    /// when the buffer is already at its configured cap (drop-oldest).
    fn buffer_collection(&mut self, collection: MetricsCollection) {
        let cap = self.config.max_buffered_collections;
        if self.buffer.len() >= cap {
            self.buffer.pop_front();
            self.dropped_count = self.dropped_count.saturating_add(1);
        }
        self.buffer.push_back(collection);
    }

    /// Pull everything currently buffered in the broadcast receiver into the
    /// local buffer so a flush sees the freshest data.
    fn drain_pending(&mut self) {
        use broadcast::error::TryRecvError;

        loop {
            match self.data_rx.try_recv() {
                Ok(arc) => self.buffer_collection((*arc).clone()),
                Err(TryRecvError::Lagged(n)) => {
                    self.dropped_count = self.dropped_count.saturating_add(n);
                }
                Err(TryRecvError::Empty | TryRecvError::Closed) => break,
            }
        }
    }

    /// Drain the buffer and the drop counter into an [`MetricsExportBatch`]
    /// ready to hand to the exporter. Returns `None` if there's nothing to
    /// report (empty buffer and zero drops).
    fn take_batch(&mut self) -> Option<MetricsExportBatch> {
        if self.buffer.is_empty() && self.dropped_count == 0 {
            return None;
        }
        let collections = self.buffer.drain(..).collect();
        let dropped_collection_count = std::mem::take(&mut self.dropped_count);
        Some(MetricsExportBatch {
            collections,
            dropped_collection_count,
        })
    }

    /// Put a failed export's collections back at the front of the buffer so
    /// the next flush attempt retries them. If the restored data plus what's
    /// arrived since exceeds the buffer cap, oldest entries are dropped and
    /// counted — repeated failures eventually shed old data rather than
    /// growing unbounded.
    fn restore_failed_batch(&mut self, batch: &MetricsExportBatch) {
        let cap = self.config.max_buffered_collections;
        let mut restored: VecDeque<MetricsCollection> = batch.collections.iter().cloned().collect();
        restored.append(&mut self.buffer);
        self.buffer = restored;
        self.dropped_count = self
            .dropped_count
            .saturating_add(batch.dropped_collection_count);
        while self.buffer.len() > cap {
            self.buffer.pop_front();
            self.dropped_count = self.dropped_count.saturating_add(1);
        }
    }

    /// Take whatever is buffered, hand it to the exporter with the
    /// configured timeout, and on failure restore the batch so the next flush
    /// retries it.
    async fn run_export(&mut self) -> MetricsCollectorResult<()> {
        let Some(batch) = self.take_batch() else {
            return Ok(());
        };
        let batch_arc = Arc::new(batch);
        let result = tokio::time::timeout(
            self.config.export_timeout,
            self.exporter.export(batch_arc.clone()),
        )
        .await
        .map_err(|_| Self::timeout_error("metrics exporter export", self.config.export_timeout))
        .and_then(|result| result);

        if result.is_err() {
            self.restore_failed_batch(&batch_arc);
        }
        result
    }

    /// Build a `MetricsCollectorError` for an operation that exceeded its timeout.
    fn timeout_error(operation: &str, timeout: Duration) -> MetricsCollectorError {
        MetricsCollectorError::Custom(format!("{operation} timed out after {timeout:?}"))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::mocks::collection;
    use super::*;
    use tokio::sync::mpsc;

    fn worker_with_cap(cap: usize) -> ExporterWorker {
        let (data_tx, data_rx) = broadcast::channel(16);
        let (flush_tx, flush_rx) = broadcast::channel(1);
        drop(data_tx);
        drop(flush_tx);
        // Suppress unused warning on mpsc — only used by other test modules.
        let _: Option<mpsc::Sender<()>> = None;
        ExporterWorker {
            exporter: Arc::new(NoopExporter),
            config: MetricsExporterConfig {
                flush_interval: Duration::from_secs(10),
                max_buffered_collections: cap,
                export_timeout: Duration::from_secs(30),
                error_policy: MetricsErrorPolicy::LogAndContinue,
            },
            buffer: VecDeque::new(),
            dropped_count: 0,
            data_rx,
            flush_signal_rx: flush_rx,
            consecutive_failures: 0,
            next_retry_after: None,
        }
    }

    struct NoopExporter;
    #[async_trait::async_trait]
    impl MetricsExporter for NoopExporter {
        async fn export(&self, _batch: Arc<MetricsExportBatch>) -> MetricsCollectorResult<()> {
            Ok(())
        }
    }

    fn sandbox_ids(worker: &ExporterWorker) -> Vec<i32> {
        worker
            .buffer
            .iter()
            .map(|c| c.sandboxes[0].sandbox_id)
            .collect()
    }

    fn worker_with_flush_interval(interval: Duration) -> ExporterWorker {
        let mut w = worker_with_cap(8);
        w.config.flush_interval = interval;
        w
    }

    #[test]
    fn schedule_next_retry_uses_capped_exponential_backoff() {
        let mut worker = worker_with_flush_interval(Duration::from_secs(1));
        // First failure → 1×.
        worker.consecutive_failures = 1;
        worker.schedule_next_retry();
        let d = worker.next_retry_after.unwrap() - Instant::now();
        assert!(d <= Duration::from_secs(1) + Duration::from_millis(10));
        assert!(d > Duration::from_millis(990));

        // Sixth failure → 2^5 = 32×.
        worker.consecutive_failures = 6;
        worker.schedule_next_retry();
        let d = worker.next_retry_after.unwrap() - Instant::now();
        assert!(d <= Duration::from_secs(32) + Duration::from_millis(10));
        assert!(d > Duration::from_secs(31));

        // Tenth failure stays at the same cap.
        worker.consecutive_failures = 10;
        worker.schedule_next_retry();
        let d = worker.next_retry_after.unwrap() - Instant::now();
        assert!(d <= Duration::from_secs(32) + Duration::from_millis(10));
    }

    #[tokio::test]
    async fn flush_now_increments_failures_and_arms_backoff_on_error() {
        struct AlwaysFail;
        #[async_trait::async_trait]
        impl MetricsExporter for AlwaysFail {
            async fn export(&self, _batch: Arc<MetricsExportBatch>) -> MetricsCollectorResult<()> {
                Err(MetricsCollectorError::Custom(
                    "simulated transport error".into(),
                ))
            }
        }
        let mut worker = worker_with_flush_interval(Duration::from_secs(1));
        worker.exporter = Arc::new(AlwaysFail);
        worker.buffer_collection(collection(1));

        worker.flush_now().await;
        assert_eq!(worker.consecutive_failures, 1);
        assert!(worker.next_retry_after.is_some());
        // Batch is restored to the buffer front for the next attempt.
        assert_eq!(sandbox_ids(&worker), vec![1]);

        worker.flush_now().await;
        assert_eq!(worker.consecutive_failures, 2);
    }

    #[tokio::test]
    async fn flush_now_resets_backoff_on_success() {
        let mut worker = worker_with_flush_interval(Duration::from_secs(1));
        worker.consecutive_failures = 3;
        worker.next_retry_after = Some(Instant::now() + Duration::from_secs(10));
        worker.buffer_collection(collection(1));

        worker.flush_now().await; // NoopExporter returns Ok.

        assert_eq!(worker.consecutive_failures, 0);
        assert!(worker.next_retry_after.is_none());
    }

    #[test]
    fn scheduled_flush_blocked_by_backoff_respects_deadline() {
        let mut worker = worker_with_flush_interval(Duration::from_secs(10));
        assert!(!worker.scheduled_flush_blocked_by_backoff());
        worker.next_retry_after = Some(Instant::now() + Duration::from_secs(5));
        assert!(worker.scheduled_flush_blocked_by_backoff());
        // Past the deadline → flush is no longer blocked.
        worker.next_retry_after = Some(Instant::now() - Duration::from_secs(1));
        assert!(!worker.scheduled_flush_blocked_by_backoff());
    }

    #[test]
    fn buffer_collection_drops_oldest_when_full() {
        let mut worker = worker_with_cap(2);
        worker.buffer_collection(collection(1));
        worker.buffer_collection(collection(2));
        worker.buffer_collection(collection(3));

        assert_eq!(sandbox_ids(&worker), vec![2, 3]);
        assert_eq!(worker.dropped_count, 1);
    }

    #[test]
    fn take_batch_drains_and_resets_drop_count() {
        let mut worker = worker_with_cap(2);
        worker.buffer_collection(collection(1));
        worker.buffer_collection(collection(2));
        worker.buffer_collection(collection(3));

        let batch = worker.take_batch().expect("pending batch");
        assert_eq!(batch.collections.len(), 2);
        assert_eq!(batch.dropped_collection_count, 1);
        assert!(worker.take_batch().is_none());
    }

    #[test]
    fn take_batch_is_none_when_empty() {
        let mut worker = worker_with_cap(4);
        assert!(worker.take_batch().is_none());
    }

    #[test]
    fn restore_failed_batch_prepends_collections() {
        let mut worker = worker_with_cap(3);
        worker.buffer_collection(collection(3));
        let failed = MetricsExportBatch {
            collections: vec![collection(1), collection(2)],
            dropped_collection_count: 0,
        };

        worker.restore_failed_batch(&failed);
        assert_eq!(sandbox_ids(&worker), vec![1, 2, 3]);
    }

    #[test]
    fn restore_failed_batch_caps_to_limit_and_carries_drop_count() {
        let mut worker = worker_with_cap(2);
        worker.buffer_collection(collection(9));
        let failed = MetricsExportBatch {
            collections: vec![collection(1), collection(2)],
            dropped_collection_count: 1,
        };

        worker.restore_failed_batch(&failed);
        assert_eq!(sandbox_ids(&worker), vec![2, 9]);
        assert_eq!(worker.dropped_count, 2);
    }
}
