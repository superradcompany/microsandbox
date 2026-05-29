//! Shared test fixtures for the metrics collector unit tests.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use futures::future::BoxFuture;
use microsandbox_metrics::SandboxMetrics;

use crate::error::{MetricsCollectorError, MetricsCollectorResult};

use super::types::{MetricsCollection, MetricsExportBatch, MetricsExporter, SandboxMetricSnapshot};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// An exporter that records exported batches for assertions.
#[derive(Default)]
pub(crate) struct RecordingExporter {
    /// Batches recorded by successful exports.
    batches: Mutex<Vec<MetricsExportBatch>>,

    /// When set, [`MetricsExporter::export`] fails instead of recording.
    pub(crate) fail_exports: AtomicBool,

    /// Number of [`MetricsExporter::shutdown`] calls observed.
    pub(crate) shutdown_count: AtomicUsize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RecordingExporter {
    /// Snapshot the batches exported so far.
    pub(crate) fn batches(&self) -> Vec<MetricsExportBatch> {
        self.batches
            .lock()
            .expect("RecordingExporter batches lock poisoned")
            .clone()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl MetricsExporter for Arc<RecordingExporter> {
    fn export(
        &self,
        batch: Arc<MetricsExportBatch>,
    ) -> BoxFuture<'static, MetricsCollectorResult<()>> {
        let collector = self.clone();
        Box::pin(async move {
            if collector.fail_exports.load(Ordering::Acquire) {
                return Err(MetricsCollectorError::Custom("export failed".into()));
            }
            collector
                .batches
                .lock()
                .expect("RecordingExporter batches lock poisoned")
                .push((*batch).clone());
            Ok(())
        })
    }

    fn shutdown(&self) -> BoxFuture<'static, MetricsCollectorResult<()>> {
        let collector = self.clone();
        Box::pin(async move {
            collector.shutdown_count.fetch_add(1, Ordering::AcqRel);
            Ok(())
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a single-sandbox metrics collection seeded by `seq`.
pub(crate) fn collection(seq: i32) -> MetricsCollection {
    MetricsCollection {
        collected_at: chrono::Utc::now(),
        sandboxes: vec![SandboxMetricSnapshot {
            sandbox_id: seq,
            run_id: seq * 10,
            pid: 1000 + seq,
            name: format!("sandbox-{seq}"),
            metrics: SandboxMetrics {
                cpu_percent: seq as f32,
                memory_bytes: 1,
                memory_limit_bytes: 2,
                disk_read_bytes: 3,
                disk_write_bytes: 4,
                net_rx_bytes: 5,
                net_tx_bytes: 6,
                uptime: Duration::from_secs(seq as u64),
                timestamp: chrono::Utc::now(),
            },
        }],
    }
}
