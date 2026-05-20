//! Sandbox metrics APIs backed by the shared-memory live registry.

use std::collections::HashMap;
use std::time::Duration;

use futures::stream;
use microsandbox_db::DbReadConnection;
use microsandbox_metrics::{LiveMetric, MetricsRegistry};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::{
    MicrosandboxError, MicrosandboxResult,
    db::entity::{run as run_entity, sandbox as sandbox_entity},
};

use super::{Sandbox, SandboxConfig, SandboxStatus};

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

/// Get the latest metrics snapshot for every running sandbox.
pub async fn all_sandbox_metrics() -> MicrosandboxResult<HashMap<String, SandboxMetrics>> {
    let pools = crate::db::init_global().await?;
    let db = pools.read();
    let sandboxes = sandbox_entity::Entity::find()
        .filter(
            sandbox_entity::Column::Status.is_in([SandboxStatus::Running, SandboxStatus::Draining]),
        )
        .order_by_asc(sandbox_entity::Column::Name)
        .all(db)
        .await?;

    let mut reconciled = Vec::with_capacity(sandboxes.len());
    for sandbox in sandboxes {
        let model = super::reconcile_sandbox_runtime_state(pools, sandbox).await?;
        if !matches!(
            model.status,
            SandboxStatus::Running | SandboxStatus::Draining
        ) {
            continue;
        }
        reconciled.push(model);
    }

    if reconciled.is_empty() {
        return Ok(HashMap::new());
    }

    // Bulk-load active runs so we can match registry slots by run_id when
    // present (cheaper and more precise than re-querying per sandbox).
    let sandbox_ids: Vec<i32> = reconciled.iter().map(|m| m.id).collect();
    let active_runs = run_entity::Entity::find()
        .filter(run_entity::Column::SandboxId.is_in(sandbox_ids.iter().copied()))
        .filter(run_entity::Column::Status.eq(run_entity::RunStatus::Running))
        .order_by_desc(run_entity::Column::StartedAt)
        .all(db)
        .await?;
    let mut run_by_sandbox: HashMap<i32, run_entity::Model> = HashMap::new();
    for run in active_runs {
        run_by_sandbox.entry(run.sandbox_id).or_insert(run);
    }

    let snapshot = open_registry_snapshot()?;

    let mut metrics = HashMap::with_capacity(reconciled.len());
    for sandbox in reconciled {
        let config: SandboxConfig = serde_json::from_str(&sandbox.config)?;
        if config.effective_metrics_interval().is_none() {
            continue;
        }

        // Without an active `run` row the sandbox is mid-startup or in a
        // transient state; either way there is no current run to match in
        // the registry. Skip rather than fall back to sandbox_id matching,
        // which would surface a Stale slot from a prior run as if it were
        // the current sandbox's metrics.
        let Some(run_id) = run_by_sandbox.get(&sandbox.id).map(|r| r.id) else {
            continue;
        };
        let live = snapshot.as_ref().and_then(|s| find_live(s, run_id));

        let Some(live) = live else {
            // Running but no slot yet — sampler might not be up. Skip rather
            // than fabricate zero data.
            continue;
        };

        metrics.insert(sandbox.name, to_sandbox_metrics(&live, &config));
    }

    Ok(metrics)
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

    Ok(to_sandbox_metrics(&live, config))
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

fn open_registry_snapshot() -> MicrosandboxResult<Option<Vec<LiveMetric>>> {
    match open_registry()? {
        Some(reg) => Ok(Some(reg.snapshot().map_err(metrics_error)?)),
        None => Ok(None),
    }
}

fn find_live(snapshot: &[LiveMetric], run_id: i32) -> Option<LiveMetric> {
    // Strict run_id match only. A Stale slot from a prior run shares the
    // sandbox_id and would otherwise bleed into the current sandbox's
    // reading; callers without a run_id should skip the sandbox.
    snapshot.iter().find(|m| m.run_id == run_id).cloned()
}

fn to_sandbox_metrics(live: &LiveMetric, config: &SandboxConfig) -> SandboxMetrics {
    SandboxMetrics {
        cpu_percent: live.cpu_percent,
        memory_bytes: live.memory_bytes,
        memory_limit_bytes: if live.memory_limit_bytes > 0 {
            live.memory_limit_bytes
        } else {
            memory_limit_bytes(config)
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
