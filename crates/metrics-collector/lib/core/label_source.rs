//! Per-sandbox label resolution for the metrics read path.
//!
//! [`LabelSource`] abstracts *where* labels come from, so the collect loop and
//! the builder depend on a trait rather than a database connection. The
//! production implementation ([`DbLabelSource`]) reads the sqlite database
//! and caches per sandbox; tests can inject an in-memory map instead.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use microsandbox_db::pool::DEFAULT_BUSY_TIMEOUT_SECS;
use microsandbox_db::{DbReadConnection, DbTarget};
use tokio::sync::Mutex;
use tracing::{info, warn};

use crate::error::MetricsCollectorResult;

use super::label_cache::{LabelCache, LabelSet};
use super::types::SandboxLabels;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Read connections opened against the database for label lookups.
const READ_CONNECTIONS: u32 = 2;

/// How long to wait for a database connection before giving up for this tick
/// (retried on the next one).
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// Resolves the labels for the active sandboxes on each collection tick.
///
/// Decouples enrichment from storage: the run loop holds an `Arc<dyn
/// LabelSource>` and never sees a database. Implementations are consulted once
/// per tick with the current snapshot's sandbox ids.
#[async_trait]
pub trait LabelSource: Send + Sync {
    /// Return the labels for the given sandbox ids. Sandboxes with no labels may
    /// be omitted from the returned map.
    async fn labels_for(&self, sandbox_ids: HashSet<i32>) -> MetricsCollectorResult<SandboxLabels>;
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A [`LabelSource`] backed by the sqlite database.
///
/// Connects lazily and retries: if the database is not yet present (e.g.
/// msb-metrics started before msb initialized `$MSB_HOME`), each tick emits no
/// labels and tries again, so enrichment switches on automatically once the
/// database appears. Reads go through an internal cache (one sqlite read per
/// newly-seen sandbox, presence-based eviction).
pub struct DbLabelSource {
    /// Database target: the sqlite file path, or a `libsql://` server URL
    /// when `MSB_DATABASE_URL` points this host at a database server.
    target: DbTarget,

    /// Label keys dropped from emitted metrics. The labels stay in the database
    /// (still visible to `msb inspect`); they are only withheld from metric
    /// attributes so an operator can cap series cardinality on noisy keys.
    exclude_keys: HashSet<String>,

    state: Mutex<State>,
}

/// Mutable state guarded by a single lock; the collect loop is sequential, so
/// there is never contention.
struct State {
    /// The database connection, opened on first successful use.
    db: Option<DbReadConnection>,

    /// Per-sandbox label cache.
    cache: LabelCache,

    /// True while emitting without labels because the database is unavailable.
    /// Gates logging so a persistent outage warns once, not every tick.
    degraded: bool,
}

impl DbLabelSource {
    /// Build a database-backed source over a database target: the sqlite file
    /// path, or a `libsql://` server URL. The connection is opened lazily on
    /// first use.
    pub fn new(target: impl Into<DbTarget>) -> Self {
        Self {
            target: target.into(),
            exclude_keys: HashSet::new(),
            state: Mutex::new(State {
                db: None,
                cache: LabelCache::new(),
                degraded: false,
            }),
        }
    }

    /// Withhold the given label keys from emitted metrics. Cumulative with any
    /// previously set keys.
    pub fn with_excluded_keys(mut self, keys: impl IntoIterator<Item = String>) -> Self {
        self.exclude_keys.extend(keys);
        self
    }
}

#[async_trait]
impl LabelSource for DbLabelSource {
    async fn labels_for(&self, sandbox_ids: HashSet<i32>) -> MetricsCollectorResult<SandboxLabels> {
        let mut state = self.state.lock().await;

        // Lazily (re)connect. A failure here is expected before msb has
        // initialized `$MSB_HOME`; emit no labels and retry on the next tick
        // rather than disabling enrichment for the process lifetime.
        if state.db.is_none() {
            match DbReadConnection::open(
                self.target.clone(),
                READ_CONNECTIONS,
                CONNECT_TIMEOUT,
                Duration::from_secs(DEFAULT_BUSY_TIMEOUT_SECS),
            )
            .await
            {
                Ok(db) => state.db = Some(db),
                Err(error) => {
                    if !state.degraded {
                        warn!(
                            %error,
                            db = %self.target,
                            "database unavailable; emitting metrics without labels (will retry)"
                        );
                        state.degraded = true;
                    }
                    return Ok(SandboxLabels::new());
                }
            }
        }

        // Resolve labels. Scope the split-borrow of `db` + `cache` so the guard
        // is free again for the `degraded` bookkeeping below.
        let resolved = {
            let State { db, cache, .. } = &mut *state;
            let db = db.as_ref().expect("connection ensured above");
            resolve_labels(db, cache, &sandbox_ids, &self.exclude_keys).await
        };

        match resolved {
            Ok(labels) => {
                if state.degraded {
                    info!("database available again; resuming label enrichment");
                    state.degraded = false;
                }
                Ok(labels)
            }
            Err(error) => {
                // A query failure (e.g. the schema is not migrated yet) is also
                // non-fatal: emit without labels and retry. The connection is
                // kept; it will see the table once msb migrates the same file.
                if !state.degraded {
                    warn!(%error, "database query failed; emitting metrics without labels (will retry)");
                    state.degraded = true;
                }
                Ok(SandboxLabels::new())
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Sync the cache to the active snapshot, then resolve each sandbox's labels.
async fn resolve_labels(
    db: &DbReadConnection,
    cache: &mut LabelCache,
    sandbox_ids: &HashSet<i32>,
    exclude_keys: &HashSet<String>,
) -> MetricsCollectorResult<SandboxLabels> {
    cache.sync(sandbox_ids);

    let mut labels = SandboxLabels::with_capacity(sandbox_ids.len());
    for &sandbox_id in sandbox_ids {
        let set = apply_exclusions(cache.get_or_fetch(sandbox_id, db).await?, exclude_keys);
        if !set.is_empty() {
            labels.insert(sandbox_id, set);
        }
    }
    Ok(labels)
}

/// Drop excluded keys from a cached label set.
///
/// The cache holds the full label set; exclusion is an emit-time policy, so it
/// is applied here rather than baked into the cache. Returns the input `Arc`
/// untouched (no allocation) when nothing is excluded for this sandbox, which is
/// the common case.
fn apply_exclusions(set: Arc<LabelSet>, exclude_keys: &HashSet<String>) -> Arc<LabelSet> {
    if exclude_keys.is_empty() || !set.iter().any(|(key, _)| exclude_keys.contains(key)) {
        return set;
    }
    Arc::new(
        set.iter()
            .filter(|(key, _)| !exclude_keys.contains(key))
            .cloned()
            .collect(),
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_db::DbWriteConnection;
    use microsandbox_db::entity::{sandbox, sandbox_label};
    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, Set};

    use super::*;

    /// Create the database at `db_path` with one labelled sandbox.
    async fn seed_catalog(db_path: &std::path::Path) {
        std::fs::create_dir_all(db_path.parent().unwrap()).unwrap();
        let write = DbWriteConnection::open(
            db_path,
            CONNECT_TIMEOUT,
            Duration::from_secs(DEFAULT_BUSY_TIMEOUT_SECS),
        )
        .await
        .unwrap();
        Migrator::up(write.inner(), None).await.unwrap();
        sandbox::ActiveModel {
            id: Set(1),
            name: Set("s1".to_string()),
            config: Set("{}".to_string()),
            active_config: Set(None),
            status: Set(sandbox::SandboxStatus::Running),
            ephemeral: Set(false),
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
    }

    #[test]
    fn apply_exclusions_drops_only_matching_keys() {
        let set = Arc::new(vec![
            ("user.id".to_string(), "alice".to_string()),
            (
                "org.opencontainers.image.revision".to_string(),
                "abc123".to_string(),
            ),
        ]);
        let exclude = HashSet::from(["org.opencontainers.image.revision".to_string()]);

        let filtered = apply_exclusions(set, &exclude);
        assert_eq!(
            filtered.as_slice(),
            [("user.id".to_string(), "alice".to_string())].as_slice()
        );
    }

    #[test]
    fn apply_exclusions_returns_same_arc_when_nothing_matches() {
        let set = Arc::new(vec![("user.id".to_string(), "alice".to_string())]);

        // Empty exclude set and a non-matching exclude set both skip allocation.
        let unchanged = apply_exclusions(set.clone(), &HashSet::new());
        assert!(Arc::ptr_eq(&set, &unchanged));

        let unmatched = apply_exclusions(set.clone(), &HashSet::from(["other".to_string()]));
        assert!(Arc::ptr_eq(&set, &unmatched));
    }

    #[tokio::test]
    async fn excluded_keys_are_withheld_from_resolved_labels() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("db").join("msb.db");
        seed_catalog(&db_path).await;

        // Add a second, noisy label to the same sandbox.
        let write = DbWriteConnection::open(
            &db_path,
            CONNECT_TIMEOUT,
            Duration::from_secs(DEFAULT_BUSY_TIMEOUT_SECS),
        )
        .await
        .unwrap();
        sandbox_label::ActiveModel {
            sandbox_id: Set(1),
            key: Set("org.opencontainers.image.revision".to_string()),
            value: Set("abc123".to_string()),
        }
        .insert(write.inner())
        .await
        .unwrap();

        let source = DbLabelSource::new(db_path)
            .with_excluded_keys(["org.opencontainers.image.revision".to_string()]);

        let labels = source.labels_for(HashSet::from([1])).await.unwrap();
        assert_eq!(
            labels.get(&1).map(|l| l.as_slice()),
            Some([("user.id".to_string(), "alice".to_string())].as_slice())
        );
    }

    #[tokio::test]
    async fn emits_no_labels_until_db_appears_then_recovers() {
        let dir = tempfile::tempdir().unwrap();
        // Parent `db/` dir does not exist yet → the database is absent.
        let db_path = dir.path().join("db").join("msb.db");
        let source = DbLabelSource::new(db_path.clone());

        // Absent database: no labels, but no error (the tick still ships metrics).
        let labels = source.labels_for(HashSet::from([1])).await.unwrap();
        assert!(labels.is_empty());

        // The database comes up with a labelled sandbox.
        seed_catalog(&db_path).await;

        // The next tick picks it up without a restart.
        let labels = source.labels_for(HashSet::from([1])).await.unwrap();
        assert_eq!(
            labels.get(&1).map(|l| l.as_slice()),
            Some([("user.id".to_string(), "alice".to_string())].as_slice())
        );
    }
}
