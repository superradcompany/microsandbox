//! Sandbox metrics APIs backed by the shared-memory live registry.

use std::collections::{HashMap, HashSet};
use std::num::NonZero;
use std::time::{Duration, Instant};

use futures::stream;
use microsandbox_db::DbReadConnection;
use microsandbox_metrics::{LiveMetric, MetricsRegistry};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::db::entity::{run as run_entity, sandbox as sandbox_entity};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Sandbox, SandboxConfig, SandboxStatus};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const FIRST_METRICS_POLL_INTERVAL: Duration = Duration::from_millis(50);
const FIRST_METRICS_MIN_WAIT: Duration = Duration::from_millis(500);
const FIRST_METRICS_MAX_WAIT: Duration = Duration::from_secs(10);
const FIRST_METRICS_INTERVAL_MULTIPLIER: u32 = 3;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Point-in-time metrics for a running sandbox.
#[derive(Clone, Debug, PartialEq)]
pub struct SandboxMetrics {
    /// Guest vCPU usage as a percentage.
    pub cpu_percent: f32,
    /// Cumulative guest vCPU execution time across all vCPUs.
    pub vcpu_time_ns: u64,
    /// Guest-used memory in bytes.
    pub memory_bytes: u64,
    /// Guest-available memory in bytes when reported by the guest.
    pub memory_available_bytes: Option<u64>,
    /// Host-resident guest memory in bytes for capacity diagnostics.
    pub memory_host_resident_bytes: Option<u64>,
    /// Configured guest memory limit in bytes.
    pub memory_limit_bytes: u64,
    /// Cumulative guest logical storage bytes read.
    pub disk_read_bytes: u64,
    /// Cumulative guest logical storage bytes written.
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

struct MetricsStreamState {
    ticker: tokio::time::Interval,
    db: Option<DbReadConnection>,
    run_id: Option<i32>,
    registry: Option<MetricsRegistry>,
    seen_sample: bool,
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

        let state = MetricsStreamState {
            ticker: tokio::time::interval(interval),
            db: None,
            run_id: None,
            registry: None,
            seen_sample: false,
        };

        stream::unfold(state, move |mut state| {
            let config = config.clone();
            async move {
                state.ticker.tick().await;
                let item = metrics_stream_tick(&mut state, db_id, &config).await;
                Some((item, state))
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

    let pools = crate::db::init_global().await?;
    let db = pools.read();
    let sandboxes = sandbox_entity::Entity::find()
        .filter(
            sandbox_entity::Column::Status.is_in([SandboxStatus::Running, SandboxStatus::Draining]),
        )
        .all(db)
        .await?;

    if sandboxes.is_empty() {
        return Ok(HashMap::new());
    }

    let sandbox_ids: Vec<i32> = sandboxes.iter().map(|sandbox| sandbox.id).collect();
    let sandbox_names: HashMap<i32, String> = sandboxes
        .into_iter()
        .map(|sandbox| (sandbox.id, sandbox.name))
        .collect();
    let runs = run_entity::Entity::find()
        .filter(run_entity::Column::SandboxId.is_in(sandbox_ids.iter().copied()))
        .filter(run_entity::Column::Status.eq(run_entity::RunStatus::Running))
        .order_by_desc(run_entity::Column::StartedAt)
        .all(db)
        .await?;

    let mut seen_sandboxes = HashSet::new();
    let mut run_names = HashMap::with_capacity(runs.len());
    for run in runs {
        if !seen_sandboxes.insert(run.sandbox_id) {
            continue;
        }
        if let Some(name) = sandbox_names.get(&run.sandbox_id) {
            run_names.insert(run.id, name.clone());
        }
    }

    let snapshot = registry.active_snapshot().map_err(metrics_error)?;
    let mut out = HashMap::with_capacity(run_names.len());
    for live in snapshot {
        let Some(name) = run_names.get(&live.run_id) else {
            continue;
        };
        let metrics = to_sandbox_metrics(&live, None);
        out.insert(name.clone(), metrics);
    }
    Ok(out)
}

pub(super) async fn metrics_for_sandbox(
    db: &DbReadConnection,
    sandbox_id: i32,
    config: &SandboxConfig,
) -> MicrosandboxResult<SandboxMetrics> {
    let run = super::load_active_run(db, sandbox_id)
        .await?
        .ok_or_else(|| MicrosandboxError::MetricsUnavailable(config.name.clone()))?;

    let registry = open_registry()?
        .ok_or_else(|| MicrosandboxError::MetricsUnavailable(config.name.clone()))?;

    // Run-id lookup only. Falling back to sandbox-id would surface a Stale
    // slot from a prior run, since it carries the same sandbox_id — readers
    // would observe prior-run counters attributed to the current run.
    let deadline = Instant::now() + first_metrics_wait_timeout(config.effective_metrics_interval());
    let live = loop {
        if let Some(live) = registry.get_by_run_id(run.id).map_err(metrics_error)? {
            break live;
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(MicrosandboxError::MetricsUnavailable(config.name.clone()));
        }

        tokio::time::sleep(FIRST_METRICS_POLL_INTERVAL.min(remaining)).await;
    };

    Ok(to_sandbox_metrics(&live, Some(config)))
}

async fn metrics_stream_tick(
    state: &mut MetricsStreamState,
    sandbox_id: i32,
    config: &SandboxConfig,
) -> MicrosandboxResult<SandboxMetrics> {
    if state.db.is_none() {
        state.db = Some(crate::db::init_global().await?.read().clone());
    }

    let db = state.db.as_ref().expect("stream DB initialized");
    if state.run_id.is_none() {
        let run = super::load_active_run(db, sandbox_id)
            .await?
            .ok_or_else(|| MicrosandboxError::MetricsUnavailable(config.name.clone()))?;
        state.run_id = Some(run.id);
    }

    if state.registry.is_none() {
        state.registry = Some(
            open_registry()?
                .ok_or_else(|| MicrosandboxError::MetricsUnavailable(config.name.clone()))?,
        );
    }

    let run_id = state.run_id.expect("stream run id initialized");
    let registry = state
        .registry
        .as_ref()
        .expect("stream metrics registry initialized");
    let deadline = Instant::now() + first_metrics_wait_timeout(config.effective_metrics_interval());
    let live = loop {
        if let Some(live) = registry.get_by_run_id(run_id).map_err(metrics_error)? {
            break live;
        }

        if state.seen_sample {
            state.run_id = None;
            state.registry = None;
            return Err(MicrosandboxError::MetricsUnavailable(config.name.clone()));
        }

        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            state.run_id = None;
            state.registry = None;
            return Err(MicrosandboxError::MetricsUnavailable(config.name.clone()));
        }

        tokio::time::sleep(FIRST_METRICS_POLL_INTERVAL.min(remaining)).await;
    };
    state.seen_sample = true;

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

fn first_metrics_wait_timeout(interval: Option<NonZero<u64>>) -> Duration {
    let Some(interval) = interval else {
        return Duration::ZERO;
    };

    Duration::from_millis(interval.get())
        .saturating_mul(FIRST_METRICS_INTERVAL_MULTIPLIER)
        .clamp(FIRST_METRICS_MIN_WAIT, FIRST_METRICS_MAX_WAIT)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_metrics_wait_timeout_scales_with_sample_interval() {
        let interval = NonZero::new(1_000).unwrap();

        assert_eq!(
            first_metrics_wait_timeout(Some(interval)),
            Duration::from_secs(3)
        );
    }

    #[test]
    fn first_metrics_wait_timeout_is_bounded() {
        assert_eq!(
            first_metrics_wait_timeout(Some(NonZero::new(1).unwrap())),
            FIRST_METRICS_MIN_WAIT
        );
        assert_eq!(
            first_metrics_wait_timeout(Some(NonZero::new(60_000).unwrap())),
            FIRST_METRICS_MAX_WAIT
        );
        assert_eq!(first_metrics_wait_timeout(None), Duration::ZERO);
    }
}
