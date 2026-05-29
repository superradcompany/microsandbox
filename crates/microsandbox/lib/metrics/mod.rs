//! Format-agnostic metrics collection APIs.
//!
//! The collector fans active shared-memory metrics out to registered
//! exporters, each running in its own worker task with its own bounded buffer,
//! flush cadence, export timeout, and error policy. Exporters are user code:
//! they implement [`MetricsExporter`], receive neutral [`MetricsExportBatch`]
//! values, and decide how to write them to any destination.
//!
//! [`MetricsReader`] performs one-shot reads over the same shared-memory
//! registry, independent of the collector.
//!
//! # Lifecycle
//!
//! Encoded in types — calling [`MetricsCollector::start`] consumes the
//! collector and returns a [`RunningCollector`]; calling
//! [`RunningCollector::shutdown`] consumes the handle. Both are compile-time
//! errors to call twice.
//!
//! ```text
//!   [Builder] ─build()?─► [MetricsCollector] ─start().await?─► [RunningCollector]
//!                                                                          │
//!                                                          flush()  (fire-and-forget)
//!                                                          shutdown(self).await
//! ```
//!
//! # Architecture
//!
//! ```text
//!   handle.flush() / handle.shutdown(self).await
//!                   │
//!                   ▼  mpsc<CollectorCmd>
//!   ┌─ run loop ─────────────────────────────────────────────┐
//!   │  collect_ticker → collect_fn → broadcast::send(data)   │
//!   │  cmd Flush      → broadcast::send(())   (flush signal) │
//!   │  cmd Shutdown   → drop senders → drain JoinSet         │
//!   └────┬───────────────────────────────────────┬───────────┘
//!        │                                       │
//!        ▼ broadcast<Arc<MetricsCollection>>     ▼ broadcast<()>
//!          (drop-oldest; lag = drop count)         (cap 1)
//!        │                                       │
//!        ▼                                       ▼
//!   ┌─────────────┐ ┌─────────────┐ ┌─────────────┐
//!   │  worker 1   │ │  worker 2   │…│  worker N   │
//!   │  VecDeque   │ │  VecDeque   │ │  VecDeque   │
//!   │  + flush    │ │  + flush    │ │  + flush    │
//!   │    ticker   │ │    ticker   │ │    ticker   │
//!   │  → export() │ │  → export() │ │  → export() │
//!   └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
//!          │               │               │
//!          └─── JoinSet (results aggregated by run loop) ──┘
//! ```
//!
//! Two broadcast channels carry two different reliability contracts:
//!
//! - **Data** is intentionally **lossy**. When a worker can't keep up, the
//!   ring rotates and that worker sees `RecvError::Lagged(n)` — the count
//!   flows into its next [`MetricsExportBatch::dropped_collection_count`].
//! - **Flush signal** is a single-slot broadcast — explicit
//!   [`RunningCollector::flush`] just bumps it; coalesced flushes are fine.
//!
//! Shutdown is structural: dropping the broadcast Senders signals every
//! worker via `RecvError::Closed`. Each worker runs a final flush, calls
//! `exporter.shutdown()`, and returns the result. The collector's run loop
//! collects every result from its `JoinSet` and aggregates the first error.
//!
//! Every worker owns its [`std::collections::VecDeque`] buffer outright. The
//! run loop owns the broadcast Senders, the flush-signal Sender, and the
//! JoinSet — all as local variables in an async function. **Nothing escapes,
//! nothing needs `Arc` or `Mutex`.** Each registered exporter has its own
//! [`MetricsExporterConfig`] (flush interval, buffer cap, export timeout,
//! error policy), so a slow or failing exporter can't delay another
//! exporter's exports or the collector's collect cadence.
//!
//! Submodules: `reader` (the shared-memory reader), `worker` (per-exporter
//! task that owns its buffer and runs exports), `driver` (the run loop +
//! [`MetricsCollector`] / [`RunningCollector`] types), and `builder` (the
//! builder, [`MetricsExporterConfig`], and configuration defaults).

mod builder;
mod driver;
mod reader;
mod worker;

use crate::MicrosandboxResult;
pub use crate::sandbox::SandboxMetrics;
pub use builder::{
    DEFAULT_COLLECT_INTERVAL, DEFAULT_EXPORT_TIMEOUT, DEFAULT_FLUSH_INTERVAL,
    DEFAULT_MAX_BUFFERED_COLLECTIONS, MetricsCollectorBuilder, MetricsExporterConfig,
};
pub use driver::{MetricsCollector, MetricsErrorPolicy, RunningCollector};
use futures::future::BoxFuture;
pub use reader::MetricsReader;
use std::sync::Arc;

#[cfg(test)]
mod mocks;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Metrics plus shared-memory identity metadata for one active sandbox slot.
#[derive(Clone, Debug, PartialEq)]
pub struct SandboxMetricSnapshot {
    /// Catalog sandbox id.
    pub sandbox_id: i32,

    /// Catalog run id.
    pub run_id: i32,

    /// Runtime process id that owns the metrics slot.
    pub pid: i32,

    /// Sandbox name.
    pub name: String,

    /// Resource metrics sample.
    pub metrics: SandboxMetrics,
}

/// One shared-memory metrics collection for all active sandboxes.
#[derive(Clone, Debug, PartialEq)]
pub struct MetricsCollection {
    /// Wall-clock time when the collection was produced.
    pub collected_at: chrono::DateTime<chrono::Utc>,

    /// Active sandbox metrics snapshots.
    pub sandboxes: Vec<SandboxMetricSnapshot>,
}

/// A buffered metrics export batch delivered to a registered exporter.
#[derive(Clone, Debug, PartialEq)]
pub struct MetricsExportBatch {
    /// Buffered collections in oldest-to-newest order.
    pub collections: Vec<MetricsCollection>,

    /// Number of older collections dropped from this exporter's buffer before this batch.
    pub dropped_collection_count: u64,
}

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// User-implemented metrics exporter.
pub trait MetricsExporter: Send + Sync + 'static {
    /// Export a buffered metrics batch.
    fn export(&self, batch: Arc<MetricsExportBatch>) -> BoxFuture<'static, MicrosandboxResult<()>>;

    /// Shut down any exporter-owned resources.
    fn shutdown(&self) -> BoxFuture<'static, MicrosandboxResult<()>> {
        Box::pin(async { Ok(()) })
    }
}
