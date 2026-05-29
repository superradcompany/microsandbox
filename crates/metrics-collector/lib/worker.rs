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

use std::{collections::VecDeque, sync::Arc, time::Duration};

use tokio::sync::broadcast;

use crate::builder::MetricsExporterConfig;
use crate::driver::MetricsErrorPolicy;
use crate::error::{MetricsCollectorError, MetricsCollectorResult};
use crate::types::{MetricsCollection, MetricsExportBatch, MetricsExporter};

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
}

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
                    Ok(()) | Err(RecvError::Lagged(_)) => self.flush_now().await,
                    Err(RecvError::Closed) => break,
                },
                _ = flush_ticker.tick() => self.flush_now().await,
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
        if let Err(error) = self.run_export().await {
            match self.config.error_policy {
                MetricsErrorPolicy::LogAndContinue => {
                    tracing::warn!(%error, "metrics exporter export failed");
                }
            }
        }
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
    use super::*;
    use crate::mocks::collection;
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
        }
    }

    struct NoopExporter;
    impl MetricsExporter for NoopExporter {
        fn export(
            &self,
            _batch: Arc<MetricsExportBatch>,
        ) -> futures::future::BoxFuture<'static, MetricsCollectorResult<()>> {
            Box::pin(async { Ok(()) })
        }
    }

    fn sandbox_ids(worker: &ExporterWorker) -> Vec<i32> {
        worker
            .buffer
            .iter()
            .map(|c| c.sandboxes[0].sandbox_id)
            .collect()
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
