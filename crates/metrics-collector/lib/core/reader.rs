//! Internal `CollectFn` machinery: opens the named shm registry on every
//! tick and reads its active snapshot.
//!
//! The umbrella crate exposes a higher-level `MetricsReader` for ad-hoc
//! SDK reads; this module wraps `MetricsRegistry` directly so the
//! orchestrator stays decoupled from the umbrella.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

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
}
