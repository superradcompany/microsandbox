//! Format-agnostic metrics collector.
//!
//! Lifecycle is encoded in types:
//!
//! - [`MetricsCollectorBuilder`] — configuration.
//! - [`MetricsCollector`] — built but not started; carries exporters
//!   and config, owns nothing async.
//! - [`RunningCollector`] — returned by [`MetricsCollector::start`]; holds
//!   the command channel sender and the run loop's [`JoinHandle`]. The run
//!   loop owns every other piece of runtime state (broadcast Sender, worker
//!   [`JoinSet`], flush-signal Sender) as local variables — nothing escapes,
//!   nothing needs `Arc`/`Mutex`.
//!
//! `flush()` is fire-and-forget (sends a command, returns immediately).
//! `shutdown(self)` is the confirm-it-worked path: it sends a shutdown
//! command, awaits the run loop, and returns the aggregated worker results.

use std::{sync::Arc, time::Duration};

use tokio::{
    sync::{broadcast, mpsc},
    task::{JoinHandle, JoinSet},
};

use crate::builder::{MetricsCollectorBuilder, MetricsExporterConfig};
use crate::error::{MetricsCollectorError, MetricsCollectorResult};
use crate::reader::CollectFn;
use crate::types::MetricsExporter;
use crate::worker::ExporterWorker;

#[cfg(test)]
use crate::types::MetricsCollection;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Capacity of the driver's command channel. Commands are sparse so a small
/// buffer suffices.
const CMD_CHANNEL_CAPACITY: usize = 8;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Error handling policy for scheduled exporter exports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MetricsErrorPolicy {
    /// Log scheduled export failures and keep collecting.
    LogAndContinue,
}

/// A built-but-not-started metrics collector. Call
/// [`MetricsCollector::start`] to spawn the run loop and return a
/// [`RunningCollector`] handle.
pub struct MetricsCollector {
    collect_interval: Duration,
    collect_fn: CollectFn,
    collectors: Vec<(Arc<dyn MetricsExporter>, MetricsExporterConfig)>,
}

/// Handle to a running collector. Use [`Self::flush`] to trigger an immediate
/// export across all workers, and [`Self::shutdown`] to stop the driver,
/// drain all workers, and collect their results.
pub struct RunningCollector {
    cmd_tx: mpsc::Sender<CollectorCmd>,
    join: JoinHandle<MetricsCollectorResult<()>>,
}

/// Validated configuration handed to [`MetricsCollector::from_config`]
/// by the builder.
pub(crate) struct CollectorConfig {
    pub(crate) collect_interval: Duration,
    pub(crate) collect_fn: CollectFn,
    pub(crate) collectors: Vec<(Arc<dyn MetricsExporter>, MetricsExporterConfig)>,
}

/// Commands the run loop accepts over its `cmd_rx`.
enum CollectorCmd {
    /// Trigger an immediate export on every worker (fire-and-forget).
    Flush,
    /// Shut down: drop the data channel so workers run their final flush +
    /// exporter shutdown, then exit. The run loop drains the JoinSet and
    /// returns the aggregated result.
    Shutdown,
    /// Push a collection directly onto the broadcast stream.
    #[cfg(test)]
    InjectForTest(MetricsCollection),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MetricsCollector {
    /// Create a new metrics collector builder reading from the named shm
    /// registry. The registry name is derived from `$MSB_HOME` by the
    /// microsandbox runtime (see `microsandbox_metrics::MetricsRegistry`).
    pub fn builder(registry_name: impl Into<String>) -> MetricsCollectorBuilder {
        MetricsCollectorBuilder::new(registry_name.into())
    }

    /// Construct a driver from validated configuration. Called by the builder.
    pub(crate) fn from_config(config: CollectorConfig) -> Self {
        Self {
            collect_interval: config.collect_interval,
            collect_fn: config.collect_fn,
            collectors: config.collectors,
        }
    }

    /// Spawn the run loop and per-exporter workers. Consumes the driver.
    ///
    /// `async` because the driver needs a Tokio runtime to spawn its tasks
    /// onto. Marking the signature `async` lets the type system enforce that
    /// requirement at the call site instead of returning an error at runtime.
    pub async fn start(self) -> MetricsCollectorResult<RunningCollector> {
        let (cmd_tx, cmd_rx) = mpsc::channel(CMD_CHANNEL_CAPACITY);
        let join = tokio::spawn(self.run(cmd_rx));

        Ok(RunningCollector { cmd_tx, join })
    }

    /// The driver's run loop: produce a collection on every tick, react to
    /// commands from the running handle, and orchestrate worker shutdown.
    async fn run(self, mut cmd_rx: mpsc::Receiver<CollectorCmd>) -> MetricsCollectorResult<()> {
        let Self {
            collect_interval,
            collect_fn,
            collectors,
        } = self;

        let broadcast_capacity = collectors
            .iter()
            .map(|(_, cfg)| cfg.max_buffered_collections)
            .max()
            .unwrap_or(1);
        let (data_tx, _) = broadcast::channel(broadcast_capacity);
        let (flush_signal_tx, _) = broadcast::channel::<()>(1);

        // Spawn one worker task per registered exporter. Their JoinSet is purely
        // local to this loop — nothing else can reach it.
        let mut tasks: JoinSet<MetricsCollectorResult<()>> = JoinSet::new();
        for (collector, cfg) in collectors {
            let worker = ExporterWorker::new(
                collector,
                cfg,
                data_tx.subscribe(),
                flush_signal_tx.subscribe(),
            );
            tasks.spawn(worker.run());
        }

        let mut collect_ticker = tokio::time::interval(collect_interval);
        collect_ticker.tick().await; // skip the immediate first tick

        'main: loop {
            tokio::select! {
                _ = collect_ticker.tick() => {
                    match (collect_fn)().await {
                        Ok(collection) => {
                            let _ = data_tx.send(Arc::new(collection));
                        }
                        Err(error) => {
                            tracing::warn!(%error, "metrics collect failed");
                        }
                    }
                }
                cmd = cmd_rx.recv() => match cmd {
                    Some(CollectorCmd::Flush) => {
                        let _ = flush_signal_tx.send(());
                    }
                    Some(CollectorCmd::Shutdown) | None => break 'main,
                    #[cfg(test)]
                    Some(CollectorCmd::InjectForTest(collection)) => {
                        let _ = data_tx.send(Arc::new(collection));
                    }
                }
            }
        }

        // Drop the broadcast Senders so every worker sees Closed, runs its final
        // flush + exporter.shutdown(), and returns. Then drain the JoinSet.
        drop(data_tx);
        drop(flush_signal_tx);

        let mut first_error: Option<MetricsCollectorError> = None;
        while let Some(join_result) = tasks.join_next().await {
            match join_result {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    if first_error.is_none() {
                        first_error = Some(error);
                    }
                }
                Err(err) if err.is_panic() => {
                    if first_error.is_none() {
                        first_error = Some(MetricsCollectorError::Custom(
                            "metrics exporter worker panicked".into(),
                        ));
                    }
                }
                Err(_) => {} // cancelled — ignore
            }
        }

        first_error.map_or(Ok(()), Err)
    }
}

impl RunningCollector {
    /// Trigger an immediate export on every worker. Fire-and-forget: returns
    /// immediately, does not wait for workers to complete the flush. Use
    /// [`Self::shutdown`] when you need to confirm results.
    pub fn flush(&self) {
        let _ = self.cmd_tx.try_send(CollectorCmd::Flush);
    }

    /// Stop the driver: each worker runs a final flush, calls
    /// `exporter.shutdown()`, and exits. Returns the first error any worker
    /// reported, or `Ok(())` if all succeeded.
    pub async fn shutdown(self) -> MetricsCollectorResult<()> {
        let _ = self.cmd_tx.send(CollectorCmd::Shutdown).await;
        match self.join.await {
            Ok(result) => result,
            Err(err) if err.is_panic() => Err(MetricsCollectorError::Custom(
                "metrics driver task panicked".into(),
            )),
            Err(_) => Err(MetricsCollectorError::Custom(
                "metrics driver task was cancelled".into(),
            )),
        }
    }

    /// Test-only: push a collection directly onto the broadcast stream by
    /// routing through the driver's command channel.
    #[cfg(test)]
    pub(crate) async fn inject_for_test(&self, collection: MetricsCollection) {
        let _ = self
            .cmd_tx
            .send(CollectorCmd::InjectForTest(collection))
            .await;
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        time::Duration,
    };

    use super::*;
    use crate::builder::MetricsExporterConfig;
    use crate::mocks::{RecordingExporter, collection};

    #[tokio::test]
    async fn injected_collections_are_exported_on_shutdown() {
        let collector = Arc::new(RecordingExporter::default());
        let handle = MetricsCollector::builder("test")
            .register(collector.clone())
            .build()
            .unwrap()
            .start()
            .await
            .unwrap();

        handle.inject_for_test(collection(1)).await;
        handle.inject_for_test(collection(2)).await;
        handle.shutdown().await.unwrap();

        let batches = collector.batches();
        let total: usize = batches.iter().map(|b| b.collections.len()).sum();
        let total_dropped: u64 = batches.iter().map(|b| b.dropped_collection_count).sum();
        assert_eq!(total, 2);
        assert_eq!(total_dropped, 0);
    }

    #[tokio::test]
    async fn buffer_limit_drops_oldest_and_reports_drop_count() {
        let collector = Arc::new(RecordingExporter::default());
        let cfg = MetricsExporterConfig::default().max_buffered_collections(2);
        let handle = MetricsCollector::builder("test")
            .register_with(collector.clone(), cfg)
            .build()
            .unwrap()
            .start()
            .await
            .unwrap();

        handle.inject_for_test(collection(1)).await;
        handle.inject_for_test(collection(2)).await;
        handle.inject_for_test(collection(3)).await;
        handle.shutdown().await.unwrap();

        let batches = collector.batches();
        let total: usize = batches.iter().map(|b| b.collections.len()).sum();
        let total_dropped: u64 = batches.iter().map(|b| b.dropped_collection_count).sum();
        assert_eq!(total, 2);
        assert_eq!(total_dropped, 1);
    }

    #[tokio::test]
    async fn failed_collector_does_not_block_others() {
        let failing = Arc::new(RecordingExporter::default());
        failing.fail_exports.store(true, Ordering::Release);
        let healthy = Arc::new(RecordingExporter::default());

        let handle = MetricsCollector::builder("test")
            .register(failing.clone())
            .register(healthy.clone())
            .build()
            .unwrap()
            .start()
            .await
            .unwrap();

        handle.inject_for_test(collection(1)).await;
        let result = handle.shutdown().await;

        assert!(result.is_err(), "failing collector should surface error");
        assert!(failing.batches().is_empty());
        assert_eq!(healthy.batches().len(), 1);
    }

    #[tokio::test]
    async fn shutdown_calls_collector_shutdown() {
        let collector = Arc::new(RecordingExporter::default());
        let handle = MetricsCollector::builder("test")
            .register(collector.clone())
            .build()
            .unwrap()
            .start()
            .await
            .unwrap();

        handle.inject_for_test(collection(1)).await;
        handle.shutdown().await.unwrap();

        let total: usize = collector
            .batches()
            .iter()
            .map(|b| b.collections.len())
            .sum();
        assert_eq!(total, 1);
        assert_eq!(collector.shutdown_count.load(Ordering::Acquire), 1);
    }

    #[tokio::test]
    async fn scheduled_loop_collects_and_flushes() {
        let counter = Arc::new(AtomicUsize::new(0));
        let collect_counter = counter.clone();
        let collector = Arc::new(RecordingExporter::default());
        let cfg = MetricsExporterConfig::default().flush_interval(Duration::from_millis(20));
        let handle = MetricsCollector::builder("test")
            .collect_interval(Duration::from_millis(5))
            .register_with(collector.clone(), cfg)
            .collect_with(move || {
                let count = collect_counter.fetch_add(1, Ordering::AcqRel) + 1;
                async move { Ok(collection(count as i32)) }
            })
            .build()
            .unwrap()
            .start()
            .await
            .unwrap();

        tokio::time::sleep(Duration::from_millis(60)).await;
        handle.shutdown().await.unwrap();

        assert!(!collector.batches().is_empty());
        assert!(counter.load(Ordering::Acquire) > 0);
    }

    #[tokio::test]
    async fn explicit_flush_triggers_export() {
        let collector = Arc::new(RecordingExporter::default());
        let cfg = MetricsExporterConfig::default().flush_interval(Duration::from_secs(60));
        let handle = MetricsCollector::builder("test")
            .register_with(collector.clone(), cfg)
            .build()
            .unwrap()
            .start()
            .await
            .unwrap();

        handle.inject_for_test(collection(1)).await;
        handle.flush();
        tokio::time::sleep(Duration::from_millis(20)).await;

        let pre_shutdown = collector.batches().len();
        handle.shutdown().await.unwrap();
        assert!(
            pre_shutdown >= 1,
            "expected flush() to trigger an export before shutdown"
        );
    }
}
