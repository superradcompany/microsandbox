//! In-process cache of per-sandbox labels for the metrics read path.
//!
//! On each tick the collector reads the active sandboxes from shared memory and
//! needs their labels (set at create time, stored in the `sandbox_labels`
//! catalog table) to attach as attributes. This cache keeps one sqlite read per
//! newly-seen sandbox; everything else is an in-memory hit.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use microsandbox_db::entity::sandbox_label;
use sea_orm::{ColumnTrait, ConnectionTrait, EntityTrait, QueryFilter};

use crate::error::MetricsCollectorResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One sandbox's labels as `(key, value)` pairs, ordered by key for stable
/// output.
pub(crate) type LabelSet = Vec<(String, String)>;

/// Caches each active sandbox's labels, keyed on `sandbox_id`.
///
/// Labels are immutable per sandbox, so a cached entry is never stale. Eviction
/// is purely presence-based: [`sync`](Self::sync) drops entries whose sandbox is
/// no longer in the shm snapshot, bounding the cache to the active sandbox
/// count. There is no TTL, max-size, or LRU.
#[derive(Default)]
pub(crate) struct LabelCache {
    by_sandbox_id: HashMap<i32, Arc<LabelSet>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LabelCache {
    /// An empty cache.
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// Drop cached entries for sandboxes absent from the current snapshot. Call
    /// once per tick, before any [`get_or_fetch`](Self::get_or_fetch).
    pub(crate) fn sync(&mut self, active: &HashSet<i32>) {
        self.by_sandbox_id.retain(|id, _| active.contains(id));
    }

    /// Labels for `sandbox_id`: an in-memory hit, otherwise one sqlite read.
    ///
    /// A sandbox with no labels caches an empty set; that is the normal case for
    /// an unlabeled sandbox, not an error.
    pub(crate) async fn get_or_fetch<C: ConnectionTrait>(
        &mut self,
        sandbox_id: i32,
        db: &C,
    ) -> MetricsCollectorResult<Arc<LabelSet>> {
        if let Some(set) = self.by_sandbox_id.get(&sandbox_id) {
            return Ok(set.clone());
        }

        let mut rows = sandbox_label::Entity::find()
            .filter(sandbox_label::Column::SandboxId.eq(sandbox_id))
            .all(db)
            .await?;
        rows.sort_by(|a, b| a.key.cmp(&b.key));

        let set = Arc::new(
            rows.into_iter()
                .map(|row| (row.key, row.value))
                .collect::<LabelSet>(),
        );
        self.by_sandbox_id.insert(sandbox_id, set.clone());
        Ok(set)
    }

    /// Number of cached sandboxes. Test helper for asserting eviction.
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.by_sandbox_id.len()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_db::entity::sandbox;
    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Database, DatabaseConnection, Set};

    use super::*;

    /// Open a fresh temp-file sqlite DB with the catalog schema applied.
    async fn open_db(dir: &tempfile::TempDir) -> DatabaseConnection {
        let path = dir.path().join("test.db");
        let url = format!("sqlite://{}?mode=rwc", path.display());
        let db = Database::connect(url).await.unwrap();
        Migrator::up(&db, None).await.unwrap();
        db
    }

    /// Insert a parent sandbox row; labels reference it via a foreign key.
    async fn insert_sandbox(db: &DatabaseConnection, id: i32) {
        sandbox::ActiveModel {
            id: Set(id),
            name: Set(format!("sandbox-{id}")),
            config: Set("{}".to_string()),
            active_config: Set(None),
            status: Set(sandbox::SandboxStatus::Running),
            ephemeral: Set(false),
            created_at: Set(None),
            updated_at: Set(None),
        }
        .insert(db)
        .await
        .unwrap();
    }

    async fn insert_label(db: &DatabaseConnection, sandbox_id: i32, key: &str, value: &str) {
        sandbox_label::ActiveModel {
            sandbox_id: Set(sandbox_id),
            key: Set(key.to_string()),
            value: Set(value.to_string()),
        }
        .insert(db)
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn get_or_fetch_reads_then_caches() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(&dir).await;
        insert_sandbox(&db, 1).await;
        insert_sandbox(&db, 2).await;
        insert_label(&db, 1, "user.id", "alice").await;
        insert_label(&db, 1, "tier", "web").await;
        insert_label(&db, 2, "user.id", "bob").await;

        let mut cache = LabelCache::new();

        // Sorted by key.
        let s1 = cache.get_or_fetch(1, &db).await.unwrap();
        assert_eq!(
            *s1,
            vec![
                ("tier".to_string(), "web".to_string()),
                ("user.id".to_string(), "alice".to_string()),
            ]
        );
        let s2 = cache.get_or_fetch(2, &db).await.unwrap();
        assert_eq!(*s2, vec![("user.id".to_string(), "bob".to_string())]);

        // Unlabeled sandbox caches an empty set, no error.
        let s3 = cache.get_or_fetch(3, &db).await.unwrap();
        assert!(s3.is_empty());
        assert_eq!(cache.len(), 3);
    }

    #[tokio::test]
    async fn cached_entry_is_not_re_read() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(&dir).await;
        insert_sandbox(&db, 1).await;
        insert_label(&db, 1, "user.id", "alice").await;

        let mut cache = LabelCache::new();
        let first = cache.get_or_fetch(1, &db).await.unwrap();
        assert_eq!(first.len(), 1);

        // Delete the row underneath the cache; a cache hit must not re-read.
        sandbox_label::Entity::delete_many()
            .filter(sandbox_label::Column::SandboxId.eq(1))
            .exec(&db)
            .await
            .unwrap();

        let cached = cache.get_or_fetch(1, &db).await.unwrap();
        assert_eq!(cached.len(), 1, "cache hit should not re-query the db");
    }

    #[tokio::test]
    async fn sync_evicts_absent_sandboxes_then_refetches() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(&dir).await;
        insert_sandbox(&db, 1).await;
        insert_label(&db, 1, "user.id", "alice").await;

        let mut cache = LabelCache::new();
        cache.get_or_fetch(1, &db).await.unwrap();
        cache.get_or_fetch(2, &db).await.unwrap();
        assert_eq!(cache.len(), 2);

        // Sandbox 1 left the snapshot: evict it, keep 2.
        cache.sync(&HashSet::from([2]));
        assert_eq!(cache.len(), 1);

        // Re-create the row and confirm the next get_or_fetch re-reads.
        sandbox_label::Entity::delete_many()
            .filter(sandbox_label::Column::SandboxId.eq(1))
            .exec(&db)
            .await
            .unwrap();
        insert_label(&db, 1, "tier", "worker").await;
        let refetched = cache.get_or_fetch(1, &db).await.unwrap();
        assert_eq!(*refetched, vec![("tier".to_string(), "worker".to_string())]);
    }
}
