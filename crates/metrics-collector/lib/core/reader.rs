//! Internal `CollectFn` machinery: opens the named shm registry on every
//! tick and reads its active snapshot.
//!
//! The umbrella crate exposes a higher-level `MetricsReader` for ad-hoc
//! SDK reads; this module wraps `MetricsRegistry` directly so the
//! orchestrator stays decoupled from the umbrella.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use futures::future::BoxFuture;
use microsandbox_metrics::{MetricsError, MetricsRegistry};

use crate::error::MetricsCollectorResult;

use super::label_source::LabelSource;
use super::types::{MetricsCollection, SandboxMetricSnapshot};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A pluggable source of metrics collections for the run loop.
pub(crate) type CollectFn =
    Arc<dyn Fn() -> BoxFuture<'static, MetricsCollectorResult<MetricsCollection>> + Send + Sync>;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a `CollectFn` that opens the named shm registry on each tick and
/// reads its active snapshot. Returns an empty collection if the registry
/// hasn't been created yet (no sandboxes running).
pub(crate) fn registry_collect_fn(registry_name: String) -> CollectFn {
    Arc::new(move || {
        let name = registry_name.clone();
        Box::pin(async move {
            let collected_at = chrono::Utc::now();
            let sandboxes = match MetricsRegistry::open(&name) {
                Ok(registry) => registry
                    .active_snapshot()?
                    .into_iter()
                    .map(SandboxMetricSnapshot::from)
                    .collect(),
                Err(MetricsError::Io(ref e)) if e.raw_os_error() == Some(libc::ENOENT) => {
                    Vec::new()
                }
                Err(err) => return Err(err.into()),
            };
            Ok(MetricsCollection {
                collected_at,
                sandboxes,
                labels: HashMap::new(),
            })
        })
    })
}

/// Run the base collect, then resolve and attach per-sandbox labels.
///
/// Label resolution is non-fatal: if the source errors, the collection is
/// emitted with no labels rather than dropping the whole tick's metrics. Labels
/// are additive enrichment, not a precondition for shipping metrics.
async fn enriched_collection(
    base: CollectFn,
    source: Arc<dyn LabelSource>,
) -> MetricsCollectorResult<MetricsCollection> {
    let mut collection = base().await?;
    let ids: HashSet<i32> = collection.sandboxes.iter().map(|s| s.sandbox_id).collect();
    match source.labels_for(ids).await {
        Ok(labels) => collection.labels = labels,
        Err(error) => {
            tracing::warn!(%error, "label resolution failed; emitting metrics without labels");
        }
    }
    Ok(collection)
}

/// Wrap a base `CollectFn` so each tick's collection is enriched with
/// per-sandbox labels resolved from a [`LabelSource`].
pub(crate) fn enrich_with_labels(base: CollectFn, source: Arc<dyn LabelSource>) -> CollectFn {
    Arc::new(move || Box::pin(enriched_collection(base.clone(), source.clone())))
}

/// Wrap a base `CollectFn` to drop snapshots whose most recent sample is older
/// than `max_age` (measured against the collection's `collected_at`).
///
/// A running sandbox writes a sample roughly once per second, so a slot that
/// has gone quiet belongs to a sandbox that stopped without its slot being
/// released — e.g. the runtime process was SIGKILL'd before its exit observer
/// ran and no host reaper freed the slot. Such a slot stays `Active` holding a
/// frozen final sample, and `active_snapshot` keeps returning it, so without
/// this filter the collector re-exports that frozen value on every tick
/// forever. See https://github.com/superradcompany/microsandbox/issues/941.
///
/// This only *skips* the snapshot (it does not release the slot): staleness is
/// a safe signal to stop emitting, but not to reclaim — a live sandbox whose
/// sampler merely stalled must reappear once it resumes, and slot reclamation
/// needs PID liveness, which is the reaper's job.
pub(crate) fn filter_stale_samples(base: CollectFn, max_age: Duration) -> CollectFn {
    Arc::new(move || {
        let base = base.clone();
        Box::pin(async move {
            let mut collection = base().await?;
            let collected_at = collection.collected_at;
            let before = collection.sandboxes.len();
            collection.sandboxes.retain(|s| {
                // A negative age (sample stamped just ahead of our clock) is
                // treated as fresh; only a sample older than max_age is dropped.
                collected_at
                    .signed_duration_since(s.metrics.timestamp)
                    .to_std()
                    .map(|age| age <= max_age)
                    .unwrap_or(true)
            });
            let dropped = before - collection.sandboxes.len();
            if dropped > 0 {
                tracing::debug!(
                    dropped,
                    "skipped stale sandbox snapshot(s): slot still Active but sampling stopped"
                );
            }
            Ok(collection)
        })
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// In-memory [`LabelSource`] returning labels for known ids only.
    struct MapSource(super::super::types::SandboxLabels);

    #[async_trait::async_trait]
    impl LabelSource for MapSource {
        async fn labels_for(
            &self,
            sandbox_ids: HashSet<i32>,
        ) -> MetricsCollectorResult<super::super::types::SandboxLabels> {
            let mut out = HashMap::new();
            for id in sandbox_ids {
                if let Some(labels) = self.0.get(&id) {
                    out.insert(id, labels.clone());
                }
            }
            Ok(out)
        }
    }

    #[tokio::test]
    async fn enrich_attaches_labels_by_sandbox_id() {
        let source = Arc::new(MapSource(HashMap::from([(
            1,
            Arc::new(vec![("user.id".to_string(), "alice".to_string())]),
        )])));

        // Base collect fn returns sandbox 1 (labelled) and 2 (unlabelled).
        let base: CollectFn = Arc::new(|| {
            Box::pin(async {
                let mut c = super::super::mocks::collection(1);
                c.sandboxes
                    .push(super::super::mocks::collection(2).sandboxes.remove(0));
                Ok(c)
            })
        });

        let enriched = enrich_with_labels(base, source);
        let collection = enriched().await.unwrap();

        assert_eq!(
            collection.labels.get(&1).map(|l| l.as_slice()),
            Some([("user.id".to_string(), "alice".to_string())].as_slice())
        );
        // Sandbox 2 has no labels, so no entry is added.
        assert!(collection.labels.get(&2).is_none());
    }

    #[tokio::test]
    async fn filter_drops_snapshots_older_than_max_age() {
        use microsandbox_metrics::{SandboxMetricSnapshot, SandboxMetrics};

        use super::super::types::MetricsCollection;

        let now = chrono::Utc::now();
        let snap = |id: i32, age_secs: i64| SandboxMetricSnapshot {
            sandbox_id: id,
            run_id: id,
            pid: id,
            name: format!("s{id}"),
            metrics: SandboxMetrics {
                cpu_percent: 0.0,
                memory_bytes: 0,
                memory_limit_bytes: 0,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                net_rx_bytes: 0,
                net_tx_bytes: 0,
                uptime: Duration::ZERO,
                timestamp: now - chrono::Duration::seconds(age_secs),
            },
        };
        // One fresh sandbox (1s old) and one stale (120s old).
        let snaps = vec![snap(1, 1), snap(2, 120)];
        let base: CollectFn = Arc::new(move || {
            let snaps = snaps.clone();
            Box::pin(async move {
                Ok(MetricsCollection {
                    collected_at: now,
                    sandboxes: snaps,
                    labels: HashMap::new(),
                })
            })
        });

        let filtered = filter_stale_samples(base, Duration::from_secs(30));
        let collection = filtered().await.unwrap();

        assert_eq!(
            collection.sandboxes.len(),
            1,
            "stale snapshot must be dropped"
        );
        assert_eq!(collection.sandboxes[0].sandbox_id, 1);
    }
}
