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
use microsandbox_metrics::{MetricsError, MetricsRegistryReader, REGISTRY_ABI_VERSION};

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
pub(crate) fn registry_collect_fn(registries: Vec<(String, u32)>) -> CollectFn {
    Arc::new(move || {
        let registries = registries.clone();
        Box::pin(async move {
            let collected_at = chrono::Utc::now();
            let mut snapshots = Vec::new();

            for (name, abi_version) in registries {
                let registry = match MetricsRegistryReader::open(&name, abi_version) {
                    Ok(registry) => registry,
                    Err(MetricsError::Io(ref error))
                        if error.kind() == std::io::ErrorKind::NotFound
                            || error.raw_os_error() == Some(libc::ENOENT) =>
                    {
                        continue;
                    }
                    Err(error) if abi_version != REGISTRY_ABI_VERSION => {
                        tracing::warn!(
                            registry = %name,
                            abi_version,
                            %error,
                            "skipping unreadable legacy metrics registry"
                        );
                        continue;
                    }
                    Err(error) => return Err(error.into()),
                };

                for snapshot in registry.active_snapshot()? {
                    snapshots.push((abi_version, SandboxMetricSnapshot::from(snapshot)));
                }
            }

            let sandboxes = merge_snapshots(snapshots);

            Ok(MetricsCollection {
                collected_at,
                sandboxes,
                labels: HashMap::new(),
            })
        })
    })
}

fn merge_snapshots(
    snapshots: impl IntoIterator<Item = (u32, SandboxMetricSnapshot)>,
) -> Vec<SandboxMetricSnapshot> {
    let mut merged = HashMap::new();

    for (abi_version, snapshot) in snapshots {
        let identity = (snapshot.sandbox_id, snapshot.run_id);
        let replace = merged
            .get(&identity)
            .is_none_or(|(existing_version, _)| abi_version >= *existing_version);
        if replace {
            merged.insert(identity, (abi_version, snapshot));
        }
    }

    let mut snapshots = merged
        .into_values()
        .map(|(_, snapshot)| snapshot)
        .collect::<Vec<_>>();
    snapshots.sort_by(|left, right| {
        (left.sandbox_id, left.run_id, &left.name).cmp(&(
            right.sandbox_id,
            right.run_id,
            &right.name,
        ))
    });

    snapshots
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
    use microsandbox_metrics::MetricsRegistry;

    use super::*;

    fn unique_registry_name(tag: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        let short_tag = &tag[..tag.len().min(5)];

        format!("/mcr-{short_tag}-{:x}", nanos & 0xffff_ffff)
    }

    #[cfg(unix)]
    fn unlink_registry(name: &str) {
        let name = std::ffi::CString::new(name).unwrap();

        unsafe { libc::shm_unlink(name.as_ptr()) };
    }

    #[cfg(target_os = "windows")]
    fn unlink_registry(_name: &str) {}

    fn snapshot(sandbox_id: i32, run_id: i32, name: &str) -> SandboxMetricSnapshot {
        let mut snapshot = super::super::mocks::collection(sandbox_id)
            .sandboxes
            .remove(0);
        snapshot.run_id = run_id;
        snapshot.name = name.to_string();
        snapshot
    }

    #[test]
    fn merge_prefers_the_newest_abi_for_one_runtime() {
        let snapshots = merge_snapshots([
            (2, snapshot(1, 10, "legacy")),
            (REGISTRY_ABI_VERSION, snapshot(1, 10, "current")),
            (2, snapshot(2, 20, "legacy-only")),
        ]);

        assert_eq!(snapshots.len(), 2);
        assert_eq!(snapshots[0].name, "current");
        assert_eq!(snapshots[1].name, "legacy-only");
    }

    #[tokio::test]
    async fn missing_registries_produce_an_empty_collection() {
        let collect = registry_collect_fn(vec![
            (unique_registry_name("missing-v2"), 2),
            (
                unique_registry_name("missing-current"),
                REGISTRY_ABI_VERSION,
            ),
        ]);

        let collection = collect().await.unwrap();

        assert!(collection.sandboxes.is_empty());
    }

    #[tokio::test]
    async fn unreadable_legacy_registry_does_not_block_current_collection() {
        let name = unique_registry_name("wrong-abi");
        let registry = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let collect = registry_collect_fn(vec![
            (name.clone(), 2),
            (name.clone(), REGISTRY_ABI_VERSION),
        ]);

        let collection = collect().await.unwrap();

        assert!(collection.sandboxes.is_empty());
        drop(registry);
        unlink_registry(&name);
    }

    #[tokio::test]
    async fn registry_that_disappears_between_ticks_becomes_empty() {
        let name = unique_registry_name("disappears");
        let registry = MetricsRegistry::open_or_create(&name, 1).unwrap();
        let collect = registry_collect_fn(vec![(name.clone(), REGISTRY_ABI_VERSION)]);

        assert!(collect().await.unwrap().sandboxes.is_empty());
        unlink_registry(&name);
        assert!(collect().await.unwrap().sandboxes.is_empty());

        drop(registry);
    }

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
        assert!(!collection.labels.contains_key(&2));
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
                vcpu_time_ns: 0,
                memory_bytes: 0,
                memory_available_bytes: None,
                memory_host_resident_bytes: None,
                memory_limit_bytes: 0,
                disk_read_bytes: 0,
                disk_write_bytes: 0,
                net_rx_bytes: 0,
                net_tx_bytes: 0,
                upper_used_bytes: None,
                upper_free_bytes: None,
                upper_host_allocated_bytes: None,
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
