//! Public types: batches, collections, exporter trait.

use std::collections::HashMap;
use std::sync::Arc;

use futures::future::BoxFuture;

pub use microsandbox_metrics::SandboxMetricSnapshot;

use crate::error::MetricsCollectorResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One shared-memory metrics collection for all active sandboxes.
#[derive(Clone, Debug, PartialEq)]
pub struct MetricsCollection {
    /// Wall-clock time when the collection was produced.
    pub collected_at: chrono::DateTime<chrono::Utc>,

    /// Active sandbox metrics snapshots.
    pub sandboxes: Vec<SandboxMetricSnapshot>,

    /// Per-sandbox labels (`sandbox_id` → ordered `(key, value)` pairs), resolved
    /// from the catalog. Empty when label enrichment is disabled or a sandbox has
    /// no labels; exporters look up entries by `SandboxMetricSnapshot::sandbox_id`.
    pub labels: HashMap<i32, Arc<Vec<(String, String)>>>,
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
    fn export(
        &self,
        batch: Arc<MetricsExportBatch>,
    ) -> BoxFuture<'static, MetricsCollectorResult<()>>;

    /// Shut down any exporter-owned resources.
    fn shutdown(&self) -> BoxFuture<'static, MetricsCollectorResult<()>> {
        Box::pin(async { Ok(()) })
    }
}
