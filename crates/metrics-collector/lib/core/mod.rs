//! Core machinery of the metrics collector orchestrator: builder,
//! run-loop driver, per-exporter worker, the shm reader, and the data
//! types passed between the collector and registered exporters.
//!
//! Backend implementations live in [`crate::exporters`] and consume the
//! types re-exported from this module.

mod builder;
mod driver;
mod label_cache;
mod label_source;
mod reader;
mod types;
mod worker;

#[cfg(test)]
pub(crate) mod mocks;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use builder::{
    DEFAULT_COLLECT_INTERVAL, DEFAULT_EXPORT_TIMEOUT, DEFAULT_FLUSH_INTERVAL,
    DEFAULT_MAX_BUFFERED_COLLECTIONS, MetricsCollectorBuilder, MetricsExporterConfig,
};
pub use driver::{MetricsCollector, MetricsErrorPolicy, RunningCollector};
pub use label_source::{CatalogLabelSource, LabelSource};
pub use types::{
    MetricsCollection, MetricsExportBatch, MetricsExporter, SandboxLabels, SandboxMetricSnapshot,
};
