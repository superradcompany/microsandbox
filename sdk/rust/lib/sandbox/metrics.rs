//! Sandbox metrics APIs backed by the shared-memory live registry.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use futures::stream;
use microsandbox_db::DbReadConnection;
use microsandbox_metrics::{LiveMetric, MetricsRegistry};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::{
    MicrosandboxError, MicrosandboxResult,
    backend::{Backend, LocalBackend, sandbox::MetricsStream},
    db::entity::sandbox as sandbox_entity,
};

use super::{Sandbox, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Point-in-time metrics for a running sandbox.
#[derive(Clone, Debug, PartialEq)]
pub struct SandboxMetrics {
    /// CPU usage as a percentage across all host CPUs.
    pub cpu_percent: f32,
    /// Cumulative guest vCPU execution time across all vCPUs.
    pub vcpu_time_ns: u64,
    /// Resident memory usage in bytes.
    pub memory_bytes: u64,
    /// Guest-available memory in bytes when reported by the guest.
    pub memory_available_bytes: Option<u64>,
    /// Host-resident guest memory in bytes for capacity diagnostics.
    pub memory_host_resident_bytes: Option<u64>,
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
    /// Guest-visible OCI upper filesystem used bytes when available.
    pub upper_used_bytes: Option<u64>,
    /// Guest-visible OCI upper filesystem free bytes when available.
    pub upper_free_bytes: Option<u64>,
    /// Host-allocated bytes for the writable upper image when available.
    pub upper_host_allocated_bytes: Option<u64>,
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
    /// (`metrics_sample_interval_ms == None`). **Local backend only** —
    /// cloud routes return [`MicrosandboxError::Unsupported`].
    pub async fn metrics(&self) -> MicrosandboxResult<SandboxMetrics> {
        self.backend()
            .sandboxes()
            .metrics(self.backend().clone(), self.name(), self.config())
            .await
    }

    /// Stream metrics snapshots at the requested interval. **Local backend only**.
    /// Cloud routes yield a single [`MicrosandboxError::Unsupported`].
    pub fn metrics_stream(
        &self,
        interval: Duration,
    ) -> impl futures::Stream<Item = MicrosandboxResult<SandboxMetrics>> + Send + 'static {
        self.backend().sandboxes().metrics_stream(
            self.backend().clone(),
            self.name().to_string(),
            self.config().clone(),
            interval,
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: backend-trait dispatch
//--------------------------------------------------------------------------------------------------

/// Local-backend metrics fetch keyed by sandbox name. Called from the
/// [`SandboxBackend::metrics`](crate::backend::SandboxBackend::metrics) impl on
/// [`LocalBackend`](crate::backend::LocalBackend).
pub(crate) async fn local_metrics(
    local: &LocalBackend,
    name: &str,
    config: &SandboxConfig,
) -> MicrosandboxResult<SandboxMetrics> {
    if config.effective_metrics_interval().is_none() {
        return Err(MicrosandboxError::MetricsDisabled(name.to_string()));
    }
    let pools = local.db().await?;
    let model = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(name))
        .one(pools.read())
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.to_string()))?;
    metrics_for_sandbox(pools.read(), local, model.id, config).await
}

/// Local-backend streaming metrics. Called from the
/// [`SandboxBackend::metrics_stream`](crate::backend::SandboxBackend::metrics_stream)
/// impl on [`LocalBackend`](crate::backend::LocalBackend).
pub(crate) fn local_metrics_stream(
    backend: Arc<dyn Backend>,
    name: String,
    config: SandboxConfig,
    interval: Duration,
) -> MetricsStream {
    if config.effective_metrics_interval().is_none() {
        return Box::pin(stream::once(async move {
            Err(MicrosandboxError::MetricsDisabled(name))
        }));
    }

    let interval = if interval.is_zero() {
        Duration::from_millis(1)
    } else {
        interval
    };

    Box::pin(stream::unfold(
        (tokio::time::interval(interval), backend, name, config),
        move |(mut ticker, backend, name, config)| async move {
            ticker.tick().await;
            let item = match backend.as_local() {
                Some(local) => match local.db().await {
                    Ok(pools) => match sandbox_entity::Entity::find()
                        .filter(sandbox_entity::Column::Name.eq(&name))
                        .one(pools.read())
                        .await
                    {
                        Ok(Some(model)) => {
                            metrics_for_sandbox(pools.read(), local, model.id, &config).await
                        }
                        Ok(None) => Err(MicrosandboxError::SandboxNotFound(name.clone())),
                        Err(e) => Err(e.into()),
                    },
                    Err(err) => Err(err),
                },
                None => Err(MicrosandboxError::Unsupported {
                    feature: "Sandbox::metrics_stream on cloud".into(),
                    available_when: "when cloud metrics land".into(),
                }),
            };
            Some((item, (ticker, backend, name, config)))
        },
    ))
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Get the latest metrics snapshot for every running sandbox.
pub async fn all_sandbox_metrics(
    local: &LocalBackend,
) -> MicrosandboxResult<HashMap<String, SandboxMetrics>> {
    let Some(registry) = open_registry(local)? else {
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
    local: &LocalBackend,
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

    let registry = open_registry(local)?.ok_or_else(|| {
        MicrosandboxError::Custom(format!(
            "sandbox {sandbox_id} has no live metrics slot (registry unavailable)"
        ))
    })?;

    let Some(live) = registry.get_by_run_id(run.id).map_err(metrics_error)? else {
        return Err(MicrosandboxError::Custom(format!(
            "sandbox {sandbox_id} has no live metrics slot"
        )));
    };

    Ok(to_sandbox_metrics(&live, Some(config)))
}

fn open_registry(local: &LocalBackend) -> MicrosandboxResult<Option<MetricsRegistry>> {
    let name = local.config().metrics_registry_shm_name();
    match MetricsRegistry::open(&name) {
        Ok(reg) => Ok(Some(reg)),
        Err(microsandbox_metrics::MetricsError::Io(ref e)) if is_missing_registry_io_error(e) => {
            Ok(None)
        }
        Err(err) => Err(metrics_error(err)),
    }
}

fn is_missing_registry_io_error(err: &std::io::Error) -> bool {
    err.kind() == std::io::ErrorKind::NotFound || err.raw_os_error() == Some(libc::ENOENT)
}

fn to_sandbox_metrics(live: &LiveMetric, config: Option<&SandboxConfig>) -> SandboxMetrics {
    SandboxMetrics {
        cpu_percent: live.cpu_percent,
        vcpu_time_ns: live.vcpu_time_ns,
        memory_bytes: live.memory_bytes,
        memory_available_bytes: live.memory_available_bytes,
        memory_host_resident_bytes: live.memory_host_resident_bytes,
        memory_limit_bytes: match (live.memory_limit_bytes, config) {
            (0, Some(config)) => memory_limit_bytes(config),
            (bytes, _) => bytes,
        },
        disk_read_bytes: live.disk_read_bytes,
        disk_write_bytes: live.disk_write_bytes,
        net_rx_bytes: live.net_rx_bytes,
        net_tx_bytes: live.net_tx_bytes,
        upper_used_bytes: live.upper_used_bytes,
        upper_free_bytes: live.upper_free_bytes,
        upper_host_allocated_bytes: live.upper_host_allocated_bytes,
        uptime: live.uptime,
        timestamp: live.timestamp,
    }
}

fn metrics_error(err: microsandbox_metrics::MetricsError) -> MicrosandboxError {
    MicrosandboxError::Custom(format!("metrics registry: {err}"))
}

fn memory_limit_bytes(config: &SandboxConfig) -> u64 {
    u64::from(config.spec.resources.memory_mib) * 1024 * 1024
}

#[cfg(test)]
mod tests {
    use super::is_missing_registry_io_error;

    #[test]
    fn missing_registry_accepts_error_kind_not_found() {
        let err = std::io::Error::new(std::io::ErrorKind::NotFound, "missing mapping");

        assert!(is_missing_registry_io_error(&err));
    }

    #[test]
    fn missing_registry_accepts_unix_enoent() {
        let err = std::io::Error::from_raw_os_error(libc::ENOENT);

        assert!(is_missing_registry_io_error(&err));
    }

    #[test]
    fn missing_registry_rejects_other_io_errors() {
        let err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "denied");

        assert!(!is_missing_registry_io_error(&err));
    }
}
