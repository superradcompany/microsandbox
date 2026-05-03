//! Sandbox metrics APIs backed by persisted runtime samples.

use std::collections::HashMap;
use std::time::Duration;

use futures::stream;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::{
    MicrosandboxError, MicrosandboxResult,
    db::entity::{sandbox as sandbox_entity, sandbox_metric as sandbox_metric_entity},
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
    /// (`metrics_sample_interval_ms == 0`).
    pub async fn metrics(&self) -> MicrosandboxResult<SandboxMetrics> {
        if self.config.metrics_sample_interval_ms == 0 {
            return Err(MicrosandboxError::MetricsDisabled(self.config.name.clone()));
        }
        let db =
            crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;
        metrics_for_sandbox(db, self.db_id, memory_limit_bytes(&self.config)).await
    }

    /// Stream metrics snapshots at the requested interval.
    pub fn metrics_stream(
        &self,
        interval: Duration,
    ) -> impl futures::Stream<Item = MicrosandboxResult<SandboxMetrics>> + Send + 'static {
        let db_id = self.db_id;
        let memory_limit_bytes = memory_limit_bytes(&self.config);
        let sandbox_name = self.config.name.clone();
        let metrics_disabled = self.config.metrics_sample_interval_ms == 0;
        let interval = if interval.is_zero() {
            Duration::from_millis(1)
        } else {
            interval
        };

        stream::unfold(
            (tokio::time::interval(interval), false, metrics_disabled),
            move |(mut ticker, mut emitted, disabled)| {
                let sandbox_name = sandbox_name.clone();
                async move {
                    if disabled {
                        if emitted {
                            return None;
                        }
                        emitted = true;
                        return Some((
                            Err(MicrosandboxError::MetricsDisabled(sandbox_name)),
                            (ticker, emitted, disabled),
                        ));
                    }
                    ticker.tick().await;
                    let db = crate::db::init_global(Some(
                        crate::config::config().database.max_connections,
                    ))
                    .await;
                    let item = match db {
                        Ok(db) => metrics_for_sandbox(db, db_id, memory_limit_bytes).await,
                        Err(err) => Err(err),
                    };
                    Some((item, (ticker, emitted, disabled)))
                }
            },
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Get the latest metrics snapshot for every running sandbox.
pub async fn all_sandbox_metrics() -> MicrosandboxResult<HashMap<String, SandboxMetrics>> {
    let db = crate::db::init_global(Some(crate::config::config().database.max_connections)).await?;
    let sandboxes = sandbox_entity::Entity::find()
        .filter(
            sandbox_entity::Column::Status.is_in([SandboxStatus::Running, SandboxStatus::Draining]),
        )
        .order_by_asc(sandbox_entity::Column::Name)
        .all(db)
        .await?;

    let mut metrics = HashMap::with_capacity(sandboxes.len());
    for sandbox in sandboxes {
        let sandbox = super::reconcile_sandbox_runtime_state(db, sandbox).await?;
        if !matches!(
            sandbox.status,
            SandboxStatus::Running | SandboxStatus::Draining
        ) {
            continue;
        }

        let config: SandboxConfig = serde_json::from_str(&sandbox.config)?;
        if config.metrics_sample_interval_ms == 0 {
            continue;
        }
        let snapshot = metrics_for_sandbox(db, sandbox.id, memory_limit_bytes(&config)).await?;
        metrics.insert(sandbox.name, snapshot);
    }

    Ok(metrics)
}

pub(super) async fn metrics_for_sandbox(
    db: &sea_orm::DatabaseConnection,
    sandbox_id: i32,
    memory_limit_bytes: u64,
) -> MicrosandboxResult<SandboxMetrics> {
    let run = super::load_active_run(db, sandbox_id)
        .await?
        .ok_or_else(|| {
            MicrosandboxError::Custom(format!(
                "sandbox {sandbox_id} is not running; metrics are unavailable"
            ))
        })?;

    let started_at = run
        .started_at
        .map(|dt| dt.and_utc())
        .unwrap_or_else(chrono::Utc::now);

    let metric = latest_metric(db, sandbox_id).await?;
    let timestamp = metric
        .as_ref()
        .and_then(|row| row.sampled_at.or(row.created_at))
        .map(|dt| dt.and_utc())
        .unwrap_or_else(chrono::Utc::now);
    let uptime = timestamp
        .signed_duration_since(started_at)
        .to_std()
        .unwrap_or_default();

    Ok(SandboxMetrics {
        cpu_percent: metric
            .as_ref()
            .and_then(|row| row.cpu_percent)
            .unwrap_or(0.0),
        memory_bytes: metric
            .as_ref()
            .and_then(|row| row.memory_bytes)
            .map_or(0, i64_to_u64),
        memory_limit_bytes,
        disk_read_bytes: metric
            .as_ref()
            .and_then(|row| row.disk_read_bytes)
            .map_or(0, i64_to_u64),
        disk_write_bytes: metric
            .as_ref()
            .and_then(|row| row.disk_write_bytes)
            .map_or(0, i64_to_u64),
        net_rx_bytes: metric
            .as_ref()
            .and_then(|row| row.net_rx_bytes)
            .map_or(0, i64_to_u64),
        net_tx_bytes: metric
            .as_ref()
            .and_then(|row| row.net_tx_bytes)
            .map_or(0, i64_to_u64),
        uptime,
        timestamp,
    })
}

async fn latest_metric(
    db: &sea_orm::DatabaseConnection,
    sandbox_id: i32,
) -> MicrosandboxResult<Option<sandbox_metric_entity::Model>> {
    sandbox_metric_entity::Entity::find()
        .filter(sandbox_metric_entity::Column::SandboxId.eq(sandbox_id))
        .order_by_desc(sandbox_metric_entity::Column::SampledAt)
        .order_by_desc(sandbox_metric_entity::Column::Id)
        .one(db)
        .await
        .map_err(Into::into)
}

fn memory_limit_bytes(config: &SandboxConfig) -> u64 {
    u64::from(config.memory_mib) * 1024 * 1024
}

fn i64_to_u64(value: i64) -> u64 {
    u64::try_from(value).unwrap_or_default()
}
