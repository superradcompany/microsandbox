//! Sandbox metrics APIs backed by the shared-memory live registry.

use std::collections::{HashMap, HashSet};
use std::num::NonZero;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use futures::stream;
use microsandbox_db::DbReadConnection;
use microsandbox_metrics::{LiveMetric, LiveMetricState, MetricsRegistry};
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

/// Presentation-level state of a sandbox metrics row.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SandboxMetricsState {
    /// The runtime owns its slot, is alive, and its sample is fresh.
    Running,
    /// The runtime is alive but no sample landed within three sampling
    /// intervals — the sampler is wedged or the host is starved.
    Stalled,
    /// The runtime exited (cleanly or not); the metrics are the preserved
    /// terminal sample, not a live reading.
    Exited,
}

/// One sandbox's live metrics joined with catalog config context.
///
/// Unlike a bare [`SandboxMetrics`], a report resolves the allocation
/// denominators (`cpus`, `memory_limit_bytes`) from the catalog's *active*
/// config, so live resizes are reflected without re-stamping the
/// shared-memory slot.
#[derive(Clone, Debug)]
pub struct SandboxMetricsReport {
    /// Sandbox name.
    pub name: String,
    /// Catalog sandbox id.
    pub sandbox_id: i32,
    /// Catalog run id that produced the sample.
    pub run_id: i32,
    /// Row state derived from slot state, owner liveness, and sample age.
    pub state: SandboxMetricsState,
    /// vCPUs allocated per the catalog config, when resolvable.
    pub cpus: Option<u32>,
    /// The metrics sample.
    pub metrics: SandboxMetrics,
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
    // Prefer the catalog's active config over the caller-supplied one so
    // limits reflect accepted live resizes, not the boot-time spec.
    let effective = model_effective_config(&model).unwrap_or_else(|| config.clone());
    metrics_for_sandbox(pools.read(), local, model.id, &effective).await
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
                            let effective =
                                model_effective_config(&model).unwrap_or_else(|| config.clone());
                            metrics_for_sandbox(pools.read(), local, model.id, &effective).await
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

/// Get the latest metrics snapshot for every running sandbox from the active local backend.
pub async fn all_sandbox_metrics() -> MicrosandboxResult<HashMap<String, SandboxMetrics>> {
    let backend = crate::backend::default_backend();
    let local = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::Unsupported {
            feature: "all_sandbox_metrics on cloud".into(),
            available_when: "when cloud metrics land".into(),
        })?;
    all_sandbox_metrics_local(local).await
}

/// Get the latest metrics snapshot for every running sandbox from an explicit local backend.
pub async fn all_sandbox_metrics_local(
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

/// Build a metrics report for every sandbox present in the live registry,
/// joining each row with its catalog config.
///
/// `include_exited` keeps rows whose slot is stale — exited sandboxes whose
/// terminal sample is preserved until the slot is reused. Rows for sandboxes
/// that were removed from the catalog are always dropped.
pub async fn all_sandbox_metrics_reports_local(
    local: &LocalBackend,
    include_exited: bool,
) -> MicrosandboxResult<Vec<SandboxMetricsReport>> {
    let Some(registry) = open_registry(local)? else {
        return Ok(Vec::new());
    };
    let snapshot = if include_exited {
        registry.snapshot()
    } else {
        registry.active_snapshot()
    }
    .map_err(metrics_error)?;

    // A sandbox restarted since its last run can own two slots: the stale
    // one from the previous run and the active one. Keep the active row, or
    // the freshest stale one. Keyed by (id, name) so a ghost slot from a
    // removed sandbox with a recycled id never displaces the real row.
    let mut best: HashMap<(i32, String), LiveMetric> = HashMap::new();
    for live in snapshot {
        let key = (live.sandbox_id, live.name.clone());
        match best.get(&key) {
            Some(existing)
                if slot_rank(existing) > slot_rank(&live)
                    || (slot_rank(existing) == slot_rank(&live)
                        && existing.timestamp >= live.timestamp) => {}
            _ => {
                best.insert(key, live);
            }
        }
    }

    let ids: Vec<i32> = best.keys().map(|(id, _)| *id).collect();
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    let pools = local.db().await?;
    let models = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Id.is_in(ids))
        .all(pools.read())
        .await?;
    // Require the slot's inline name to match the catalog row: ids are
    // recycled after removal, so a ghost slot from a deleted sandbox can
    // share an id with (and must not masquerade as) a current sandbox.
    let known: HashSet<(i32, &str)> = models
        .iter()
        .map(|model| (model.id, model.name.as_str()))
        .collect();
    let configs: HashMap<i32, SandboxConfig> = models
        .iter()
        .filter_map(|model| model_effective_config(model).map(|config| (model.id, config)))
        .collect();

    let mut reports: Vec<SandboxMetricsReport> = best
        .into_values()
        .filter(|live| known.contains(&(live.sandbox_id, live.name.as_str())))
        .map(|live| {
            let config = configs.get(&live.sandbox_id);
            report_from_live(live, config)
        })
        .collect();
    reports.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(reports)
}

/// Build a metrics report for one sandbox by name, in any state.
///
/// Unlike [`Sandbox::metrics`], this answers for exited sandboxes too (the
/// report's state says so). Returns `Ok(None)` when the sandbox exists but
/// has no slot in the registry — never sampled, or the slot was reused.
pub async fn sandbox_metrics_report_local(
    local: &LocalBackend,
    name: &str,
) -> MicrosandboxResult<Option<SandboxMetricsReport>> {
    let pools = local.db().await?;
    let model = sandbox_entity::Entity::find()
        .filter(sandbox_entity::Column::Name.eq(name))
        .one(pools.read())
        .await?
        .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.to_string()))?;

    let Some(registry) = open_registry(local)? else {
        return Ok(None);
    };
    // Match on name as well as id: catalog row ids are recycled after
    // removal, so a ghost slot from a deleted sandbox can share the id.
    let Some(live) = registry
        .get_by_sandbox_identity(model.id, Some(&model.name))
        .map_err(metrics_error)?
    else {
        return Ok(None);
    };
    let config = model_effective_config(&model);
    Ok(Some(report_from_live(live, config.as_ref())))
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
        // The slot value is stamped once at reservation, so it goes stale
        // after a live resize; the catalog config wins when resolvable.
        memory_limit_bytes: match config.map(memory_limit_bytes).filter(|&limit| limit != 0) {
            Some(limit) => limit,
            None => live.memory_limit_bytes,
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

/// Parse the config that best describes the sandbox's current allocation:
/// the active-config snapshot when one is recorded, else the desired config.
fn model_effective_config(model: &sandbox_entity::Model) -> Option<SandboxConfig> {
    model
        .active_config
        .as_deref()
        .and_then(|json| serde_json::from_str(json).ok())
        .or_else(|| serde_json::from_str(&model.config).ok())
}

fn slot_rank(live: &LiveMetric) -> u8 {
    match live.state {
        LiveMetricState::Active => 1,
        LiveMetricState::Stale => 0,
    }
}

fn report_from_live(live: LiveMetric, config: Option<&SandboxConfig>) -> SandboxMetricsReport {
    let state = classify_state(&live, config);
    let cpus = config.map(|config| u32::from(config.spec.resources.vcpus));
    let metrics = to_sandbox_metrics(&live, config);
    SandboxMetricsReport {
        name: live.name,
        sandbox_id: live.sandbox_id,
        run_id: live.run_id,
        state,
        cpus,
        metrics,
    }
}

/// Derive the row state. Stale slots are exited by definition; active slots
/// are stalled when no sample landed within three sampling intervals
/// (minimum 3s), mirroring the sampler's own guest-freshness policy.
fn classify_state(live: &LiveMetric, config: Option<&SandboxConfig>) -> SandboxMetricsState {
    match live.state {
        LiveMetricState::Stale => SandboxMetricsState::Exited,
        LiveMetricState::Active => {
            let interval_ms = config
                .and_then(|config| config.effective_metrics_interval())
                .map(NonZero::get)
                .unwrap_or(1000);
            let stall_after_ms = interval_ms.saturating_mul(3).max(3000);
            let age_ms = Utc::now()
                .signed_duration_since(live.timestamp)
                .num_milliseconds();
            if age_ms > stall_after_ms as i64 {
                SandboxMetricsState::Stalled
            } else {
                SandboxMetricsState::Running
            }
        }
    }
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
