//! Public types: batches, collections, exporter trait.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;

pub use microsandbox_metrics::SandboxMetricSnapshot;

use crate::error::MetricsCollectorResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-sandbox labels resolved from the catalog: `sandbox_id` → that sandbox's
/// ordered `(key, value)` pairs. Each entry is shared via `Arc` so cloning a
/// collection (per exporter buffer) only bumps refcounts.
pub type SandboxLabels = HashMap<i32, Arc<Vec<(String, String)>>>;

/// One shared-memory metrics collection for all active sandboxes.
#[derive(Clone, Debug, PartialEq)]
pub struct MetricsCollection {
    /// Wall-clock time when the collection was produced.
    pub collected_at: chrono::DateTime<chrono::Utc>,

    /// Active sandbox metrics snapshots.
    pub sandboxes: Vec<SandboxMetricSnapshot>,

    /// Per-sandbox labels. Empty when label enrichment is disabled or a sandbox
    /// has no labels; exporters look up entries by
    /// `SandboxMetricSnapshot::sandbox_id`.
    pub labels: SandboxLabels,
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
#[async_trait]
pub trait MetricsExporter: Send + Sync + 'static {
    /// Export a buffered metrics batch.
    async fn export(&self, batch: Arc<MetricsExportBatch>) -> MetricsCollectorResult<()>;

    /// Shut down any exporter-owned resources.
    async fn shutdown(&self) -> MetricsCollectorResult<()> {
        Ok(())
    }
}
