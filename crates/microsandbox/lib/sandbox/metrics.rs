//! Sandbox metrics APIs backed by the shared-memory live registry.

use std::collections::HashMap;
use std::time::Duration;

use futures::stream;
use microsandbox_db::DbReadConnection;
use microsandbox_metrics::{LiveMetric, MetricsRegistry};

use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Sandbox, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Point-in-time metrics for a running sandbox.
#[derive(Clone, Debug, PartialEq)]
pub struct SandboxMetrics {
    /// CPU usage as a percentage across all host CPUs.
    pub cpu_percent: f32,
    /// Resident memory usage in bytes.
    pub memory_bytes: u64,
    /// Configured guest memory limit in bytes.
    pub memory_limit_bytes: u64,
    /// Cumulative disk bytes read by the sandbox process.
    pub disk_read_bytes: u64,
    /// Cumulative disk bytes written by the sandbox process.
    pub disk_write_bytes: u64,
    /// Cumulative network bytes delivered from the runtime to the guest.
    pub net_rx_bytes: u64,
    /// Cumulative network bytes transmitted from the guest into the runtime.
    pub net_tx_bytes: u64,
    /// Sandbox uptime at the moment the sample was taken.
    pub uptime: Duration,
    /// Timestamp of the sample.
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Get the latest metrics snapshot for this running sandbox.
    ///
    /// Returns [`MicrosandboxError::MetricsDisabled`] when the sandbox
    /// was created with metrics sampling disabled
    /// (`metrics_sample_interval_ms == None`).
    pub async fn metrics(&self) -> MicrosandboxResult<SandboxMetrics> {
        if self.config.effective_metrics_interval().is_none() {
            return Err(MicrosandboxError::MetricsDisabled(self.config.name.clone()));
        }
        let db = crate::db::init_global().await?.read();
        metrics_for_sandbox(db, self.db_id, &self.config).await
    }

    /// Stream metrics snapshots at the requested interval.
    pub fn metrics_stream(
        &self,
        interval: Duration,
    ) -> impl futures::Stream<Item = MicrosandboxResult<SandboxMetrics>> + Send + 'static {
        use futures::StreamExt;

        if self.config.effective_metrics_interval().is_none() {
            let name = self.config.name.clone();
            return stream::once(async move { Err(MicrosandboxError::MetricsDisabled(name)) })
                .left_stream();
        }

        let db_id = self.db_id;
        let config = self.config.clone();
        let interval = if interval.is_zero() {
            Duration::from_millis(1)
        } else {
            interval
        };

        stream::unfold(tokio::time::interval(interval), move |mut ticker| {
            let config = config.clone();
            async move {
                ticker.tick().await;
                let pools = crate::db::init_global().await;
                let item = match pools {
                    Ok(pools) => metrics_for_sandbox(pools.read(), db_id, &config).await,
                    Err(err) => Err(err),
                };
                Some((item, ticker))
            }
        })
        .right_stream()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Get the latest metrics for every running sandbox at once.
pub async fn all_sandbox_metrics() -> MicrosandboxResult<HashMap<String, SandboxMetrics>> {
    let Some(registry) = open_registry()? else {
        return Ok(HashMap::new());
    };

    let snapshot = registry.active_snapshot().map_err(metrics_error)?;
    Ok(snapshot
        .into_iter()
        .map(|live| {
            let metrics = to_sandbox_metrics(&live, None);
            (live.name, metrics)
        })
        .collect())
}

pub(super) async fn metrics_for_sandbox(
    db: &DbReadConnection,
    sandbox_id: i32,
    config: &SandboxConfig,
) -> MicrosandboxResult<SandboxMetrics> {
    let run = super::load_active_run(db, sandbox_id)
        .await?
        .ok_or_else(|| {
            MicrosandboxError::Custom(format!(
                "sandbox {sandbox_id} is not running; metrics are unavailable"
            ))
        })?;

    let registry = open_registry()?.ok_or_else(|| {
        MicrosandboxError::Custom(format!(
            "sandbox {sandbox_id} has no live metrics slot (registry unavailable)"
        ))
    })?;

    // Run-id lookup only. Falling back to sandbox-id would surface a Stale
    // slot from a prior run, since it carries the same sandbox_id — readers
    // would observe prior-run counters attributed to the current run.
    let Some(live) = registry.get_by_run_id(run.id).map_err(metrics_error)? else {
        return Err(MicrosandboxError::Custom(format!(
            "sandbox {sandbox_id} has no live metrics slot"
        )));
    };

    Ok(to_sandbox_metrics(&live, Some(config)))
}

fn open_registry() -> MicrosandboxResult<Option<MetricsRegistry>> {
    let name = crate::config::config().metrics_registry_shm_name();
    match MetricsRegistry::open(&name) {
        Ok(reg) => Ok(Some(reg)),
        Err(microsandbox_metrics::MetricsError::Io(ref e))
            if e.raw_os_error() == Some(libc::ENOENT) =>
        {
            Ok(None)
        }
        Err(err) => Err(metrics_error(err)),
    }
}

fn to_sandbox_metrics(live: &LiveMetric, config: Option<&SandboxConfig>) -> SandboxMetrics {
    SandboxMetrics {
        cpu_percent: live.cpu_percent,
        memory_bytes: live.memory_bytes,
        memory_limit_bytes: match (live.memory_limit_bytes, config) {
            (0, Some(config)) => memory_limit_bytes(config),
            (bytes, _) => bytes,
        },
        disk_read_bytes: live.disk_read_bytes,
        disk_write_bytes: live.disk_write_bytes,
        net_rx_bytes: live.net_rx_bytes,
        net_tx_bytes: live.net_tx_bytes,
        uptime: live.uptime,
        timestamp: live.timestamp,
    }
}

fn metrics_error(err: microsandbox_metrics::MetricsError) -> MicrosandboxError {
    MicrosandboxError::Custom(format!("metrics registry: {err}"))
}

fn memory_limit_bytes(config: &SandboxConfig) -> u64 {
    u64::from(config.memory_mib) * 1024 * 1024
}
