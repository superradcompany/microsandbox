//! Reading active sandbox metrics from the shared-memory registry.

use std::{collections::HashMap, sync::Arc};

use futures::future::BoxFuture;
use microsandbox_metrics::{LiveMetric, MetricsError, MetricsRegistry};

use crate::{MicrosandboxResult, config, sandbox::SandboxMetrics};

use super::{MetricsCollection, SandboxMetricSnapshot};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A pluggable source of metrics collections for the run loop.
pub(super) type CollectFn =
    Arc<dyn Fn() -> BoxFuture<'static, MicrosandboxResult<MetricsCollection>> + Send + Sync>;

/// Reader for active sandbox metrics held in the shared-memory registry.
///
/// [`MetricsReader::collect`] also backs the collector driver as its default
/// collection source.
#[derive(Clone, Debug)]
pub struct MetricsReader {
    /// Name of the shared-memory metrics registry to read from.
    registry_name: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MetricsReader {
    /// Create a reader bound to the configured metrics registry.
    pub fn new() -> Self {
        Self {
            registry_name: config::config().metrics_registry_shm_name(),
        }
    }

    /// Get the latest metrics snapshot for every active sandbox, keyed by name.
    pub async fn all(&self) -> MicrosandboxResult<HashMap<String, SandboxMetrics>> {
        Ok(self
            .snapshots()
            .await?
            .into_iter()
            .map(|snapshot| (snapshot.name, snapshot.metrics))
            .collect())
    }

    /// Collect active sandbox metrics from shared memory once.
    pub async fn collect(&self) -> MicrosandboxResult<MetricsCollection> {
        Ok(MetricsCollection {
            collected_at: chrono::Utc::now(),
            sandboxes: self.snapshots().await?,
        })
    }

    /// Get active sandbox metrics snapshots with identity metadata.
    pub async fn snapshots(&self) -> MicrosandboxResult<Vec<SandboxMetricSnapshot>> {
        let Some(registry) = self.open_registry()? else {
            return Ok(Vec::new());
        };

        let snapshot = registry.active_snapshot().map_err(metrics_error)?;
        Ok(snapshot
            .into_iter()
            .map(SandboxMetricSnapshot::from)
            .collect())
    }

    /// Build the driver's default collection source backed by [`MetricsReader`].
    pub(super) fn default_collect_fn() -> CollectFn {
        let reader = Self::new();
        Arc::new(move || {
            let reader = reader.clone();
            Box::pin(async move { reader.collect().await })
        })
    }

    fn open_registry(&self) -> MicrosandboxResult<Option<MetricsRegistry>> {
        match MetricsRegistry::open(&self.registry_name) {
            Ok(registry) => Ok(Some(registry)),
            Err(MetricsError::Io(ref e)) if e.raw_os_error() == Some(libc::ENOENT) => Ok(None),
            Err(err) => Err(metrics_error(err)),
        }
    }
}

fn metrics_error(err: MetricsError) -> crate::MicrosandboxError {
    crate::MicrosandboxError::Custom(format!("metrics registry: {err}"))
}

impl Default for MetricsReader {
    fn default() -> Self {
        Self::new()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<LiveMetric> for SandboxMetricSnapshot {
    fn from(live: LiveMetric) -> Self {
        Self {
            sandbox_id: live.sandbox_id,
            run_id: live.run_id,
            pid: live.pid,
            name: live.name,
            metrics: SandboxMetrics {
                cpu_percent: live.cpu_percent,
                memory_bytes: live.memory_bytes,
                memory_limit_bytes: live.memory_limit_bytes,
                disk_read_bytes: live.disk_read_bytes,
                disk_write_bytes: live.disk_write_bytes,
                net_rx_bytes: live.net_rx_bytes,
                net_tx_bytes: live.net_tx_bytes,
                uptime: live.uptime,
                timestamp: live.timestamp,
            },
        }
    }
}
