//! Internal `CollectFn` machinery: opens the named shm registry on every
//! tick and reads its active snapshot.
//!
//! The umbrella crate exposes a higher-level `MetricsReader` for ad-hoc
//! SDK reads; this module wraps `MetricsRegistry` directly so the
//! orchestrator stays decoupled from the umbrella.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use futures::future::BoxFuture;
use microsandbox_db::DbReadConnection;
use microsandbox_metrics::{MetricsError, MetricsRegistry};
use tokio::sync::Mutex;

use crate::error::MetricsCollectorResult;

use super::label_cache::LabelCache;
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

/// Wrap a base `CollectFn` so each collection is enriched with per-sandbox
/// labels read from the catalog.
///
/// Maintains a [`LabelCache`] across ticks: one sqlite read per newly-seen
/// sandbox, with presence-based eviction against the active snapshot. A failed
/// catalog read fails the tick (the run loop logs and retries next tick).
pub(crate) fn enrich_with_labels(base: CollectFn, db: Arc<DbReadConnection>) -> CollectFn {
    let cache = Arc::new(Mutex::new(LabelCache::new()));
    Arc::new(move || {
        let base = base.clone();
        let db = db.clone();
        let cache = cache.clone();
        Box::pin(async move {
            let mut collection = base().await?;

            let active: HashSet<i32> = collection.sandboxes.iter().map(|s| s.sandbox_id).collect();

            let mut cache = cache.lock().await;
            cache.sync(&active);

            let mut labels = HashMap::with_capacity(active.len());
            for sandbox_id in active {
                let set = cache.get_or_fetch(sandbox_id, db.as_ref()).await?;
                if !set.is_empty() {
                    labels.insert(sandbox_id, set);
                }
            }
            collection.labels = labels;
            Ok(collection)
        })
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_db::entity::{sandbox, sandbox_label};
    use microsandbox_db::{DbReadConnection, DbWriteConnection};
    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Set};

    use super::*;

    #[tokio::test]
    async fn enrich_attaches_labels_by_sandbox_id() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.db");

        // Seed a sandbox and a label via a write connection.
        let write = DbWriteConnection::open(
            &db_path,
            std::time::Duration::from_secs(30),
            std::time::Duration::from_secs(5),
        )
        .await
        .unwrap();
        Migrator::up(write.inner(), None).await.unwrap();
        sandbox::ActiveModel {
            id: Set(1),
            name: Set("s1".to_string()),
            config: Set("{}".to_string()),
            status: Set(sandbox::SandboxStatus::Running),
            created_at: Set(None),
            updated_at: Set(None),
        }
        .insert(write.inner())
        .await
        .unwrap();
        sandbox_label::ActiveModel {
            sandbox_id: Set(1),
            key: Set("user.id".to_string()),
            value: Set("alice".to_string()),
        }
        .insert(write.inner())
        .await
        .unwrap();

        let read = Arc::new(
            DbReadConnection::open(
                &db_path,
                2,
                std::time::Duration::from_secs(30),
                std::time::Duration::from_secs(5),
            )
            .await
            .unwrap(),
        );

        // Base collect fn returns sandbox 1 (labelled) and 2 (unlabelled).
        let base: CollectFn = Arc::new(|| {
            Box::pin(async {
                let mut c = super::super::mocks::collection(1);
                c.sandboxes
                    .push(super::super::mocks::collection(2).sandboxes.remove(0));
                Ok(c)
            })
        });

        let enriched = enrich_with_labels(base, read);
        let collection = enriched().await.unwrap();

        assert_eq!(
            collection.labels.get(&1).map(|l| l.as_slice()),
            Some([("user.id".to_string(), "alice".to_string())].as_slice())
        );
        // Sandbox 2 has no labels, so no entry is added.
        assert!(collection.labels.get(&2).is_none());
    }
}
