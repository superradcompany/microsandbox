//! Metrics collector orchestrator. Polls the microsandbox shared-memory
//! metrics registry, buffers per-exporter, and fans batches out to
//! registered exporters.
//!
//! See `docs/msb-metrics-binary-plan.md` for the architecture and the
//! `msb-metrics` binary that ships in this crate's `bin/main.rs`.
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

#![warn(missing_docs)]

mod builder;
mod driver;
mod error;
mod reader;
mod types;
mod worker;

#[cfg(test)]
mod mocks;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use builder::{
    DEFAULT_COLLECT_INTERVAL, DEFAULT_EXPORT_TIMEOUT, DEFAULT_FLUSH_INTERVAL,
    DEFAULT_MAX_BUFFERED_COLLECTIONS, MetricsCollectorBuilder, MetricsExporterConfig,
};
pub use driver::{MetricsCollector, MetricsErrorPolicy, RunningCollector};
pub use error::{MetricsCollectorError, MetricsCollectorResult};
pub use microsandbox_metrics::{SandboxMetricSnapshot, SandboxMetrics};
pub use types::{MetricsCollection, MetricsExportBatch, MetricsExporter};
