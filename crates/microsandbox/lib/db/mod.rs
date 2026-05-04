//! Database connection pool and entity definitions.
//!
//! Provides dual-pool access for global (`~/.microsandbox/db/msb.db`) and
//! project-local (`.microsandbox/db/msb.db`) databases. Migrations are
//! automatically applied on first connection.

pub use microsandbox_db::entity;

use std::{
    future::Future,
    path::{Path, PathBuf},
    time::Duration,
};

use microsandbox_migration::{Migrator, MigratorTrait};
use sea_orm::{DatabaseConnection, DatabaseTransaction, TransactionTrait};
use tokio::sync::OnceCell;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Read pool + dedicated single-connection write pool for the same SQLite
/// file. SQLite is single-writer system-wide, so a multi-connection pool
/// fighting for the writer lock just generates `SQLITE_BUSY` and (under
/// deferred transactions) `SQLITE_BUSY_SNAPSHOT`. Funnelling all writes
/// from one process through a single connection turns within-process
/// contention into an in-process queue (deterministic) instead of
/// SQLite-level lock contention (probabilistic, retry-required). Reads
/// keep the wider pool — WAL mode lets readers run concurrently.
struct DbPools {
    read: DatabaseConnection,
    write: DatabaseConnection,
}

static GLOBAL_POOL: OnceCell<DbPools> = OnceCell::const_new();
static PROJECT_POOL: OnceCell<(PathBuf, DbPools)> = OnceCell::const_new();

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Initialize the global database connection pool at `~/.microsandbox/db/msb.db`.
///
/// Migrations are applied automatically. This is idempotent — calling it
/// multiple times returns the existing pool. Returns the **read** pool;
/// writes go through a separate dedicated connection accessed via
/// [`with_retry_transaction`].
pub async fn init_global(
    max_connections: Option<u32>,
) -> MicrosandboxResult<&'static DatabaseConnection> {
    let pools = GLOBAL_POOL
        .get_or_try_init(|| async {
            let base = dirs::home_dir().ok_or_else(|| {
                crate::MicrosandboxError::Custom("cannot determine home directory".into())
            })?;

            let db_dir = base
                .join(microsandbox_utils::BASE_DIR_NAME)
                .join(microsandbox_utils::DB_SUBDIR);

            let database = &crate::config::config().database;
            connect_and_migrate_pools(
                &db_dir,
                max_connections.unwrap_or(crate::config::DEFAULT_MAX_CONNECTIONS),
                database.connect_timeout_secs,
                database.busy_timeout_secs,
            )
            .await
        })
        .await?;
    Ok(&pools.read)
}

/// Initialize a project-local database connection pool at `<project>/.microsandbox/db/msb.db`.
///
/// Migrations are applied automatically. This is idempotent — calling it
/// multiple times returns the existing pool. Returns an error if called
/// with a different project directory than the first call. Returns the
/// **read** pool; writes go through a separate dedicated connection
/// accessed via [`with_retry_transaction`].
pub async fn init_project(
    project_dir: impl AsRef<Path>,
    max_connections: Option<u32>,
) -> MicrosandboxResult<&'static DatabaseConnection> {
    let requested = project_dir.as_ref().to_path_buf();

    let pair = PROJECT_POOL
        .get_or_try_init(|| async {
            let db_dir = requested
                .join(microsandbox_utils::BASE_DIR_NAME)
                .join(microsandbox_utils::DB_SUBDIR);

            let database = &crate::config::config().database;
            let pools = connect_and_migrate_pools(
                &db_dir,
                max_connections.unwrap_or(crate::config::DEFAULT_MAX_CONNECTIONS),
                database.connect_timeout_secs,
                database.busy_timeout_secs,
            )
            .await?;
            Ok::<_, crate::MicrosandboxError>((requested.clone(), pools))
        })
        .await?;

    // Verify the requested project matches the initialized one.
    if pair.0 != requested {
        return Err(crate::MicrosandboxError::Custom(format!(
            "project pool already initialized for '{}', cannot reinitialize for '{}'",
            pair.0.display(),
            requested.display(),
        )));
    }

    Ok(&pair.1.read)
}

/// Get the global read pool.
///
/// Returns `None` if [`init_global`] has not been called yet.
pub fn global() -> Option<&'static DatabaseConnection> {
    GLOBAL_POOL.get().map(|p| &p.read)
}

/// Get the project-local read pool.
///
/// Returns `None` if [`init_project`] has not been called yet.
pub fn project() -> Option<&'static DatabaseConnection> {
    PROJECT_POOL.get().map(|(_, p)| &p.read)
}

/// Look up the write pool that pairs with a given read-pool reference.
///
/// `with_retry_transaction` accepts the read pool that callers already
/// have a reference to (since that's what `init_global`/`init_project`
/// return) and routes the actual write through the matching dedicated
/// single-connection write pool. Pointer equality on the read pool
/// reference is the cheapest way to disambiguate global vs project
/// without changing every call site to thread a different handle.
///
/// Falls back to the input reference when the caller's pool isn't one
/// of ours (e.g. ad-hoc test connections).
fn write_pool_for(read_db: &DatabaseConnection) -> &DatabaseConnection {
    if let Some(pools) = GLOBAL_POOL.get()
        && std::ptr::eq(&pools.read, read_db)
    {
        return &pools.write;
    }
    if let Some((_, pools)) = PROJECT_POOL.get()
        && std::ptr::eq(&pools.read, read_db)
    {
        return &pools.write;
    }
    read_db
}

/// Run a write transaction with automatic retry on `SQLITE_BUSY` and
/// `SQLITE_BUSY_SNAPSHOT`. Prefer this over `db.transaction(...)` or raw
/// `Entity::insert(...).exec(db)` for any DB write so retry policy stays
/// centralised.
///
/// `f` is invoked once per attempt with a freshly opened transaction.
/// Return `Ok((txn, value))` to commit, or any `Err` to roll back (the
/// helper drops the transaction on failure, which sea-orm rolls back).
/// The closure must be callable multiple times: clone owned data inside
/// the body so retries see fresh values.
pub async fn with_retry_transaction<F, Fut, T>(
    db: &DatabaseConnection,
    name: &'static str,
    f: F,
) -> MicrosandboxResult<T>
where
    F: Fn(DatabaseTransaction) -> Fut,
    Fut: Future<Output = MicrosandboxResult<(DatabaseTransaction, T)>> + Send,
    T: Send,
{
    let write_db = write_pool_for(db);
    retry_on_busy(name, || async {
        let txn = write_db.begin().await?;
        let (txn, value) = f(txn).await?;
        txn.commit().await?;
        Ok(value)
    })
    .await
}

/// Retry an arbitrary DB-only operation on `SQLITE_BUSY` (5) and
/// `SQLITE_BUSY_SNAPSHOT` (517). Backs off exponentially up to
/// `MAX_BUSY_RETRY_ATTEMPTS` total tries. Prefer [`with_retry_transaction`]
/// for normal write operations; this lower-level helper is for cases that
/// don't fit the transaction shape.
pub async fn retry_on_busy<F, Fut, T>(name: &'static str, mut f: F) -> MicrosandboxResult<T>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = MicrosandboxResult<T>>,
{
    const MAX_BUSY_RETRY_ATTEMPTS: u32 = 8;
    const INITIAL_DELAY: Duration = Duration::from_millis(10);
    const MAX_DELAY: Duration = Duration::from_millis(500);

    let mut delay = INITIAL_DELAY;
    for attempt in 1..=MAX_BUSY_RETRY_ATTEMPTS {
        match f().await {
            Ok(value) => {
                if attempt > 1 {
                    tracing::debug!(operation = name, attempt, "db busy retry succeeded");
                }
                return Ok(value);
            }
            Err(err) if is_sqlite_busy(&err) && attempt < MAX_BUSY_RETRY_ATTEMPTS => {
                tracing::debug!(
                    operation = name,
                    attempt,
                    delay_ms = delay.as_millis() as u64,
                    "db busy, retrying"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_DELAY);
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("loop returns or errors before exhausting attempts")
}

fn is_sqlite_busy(err: &crate::MicrosandboxError) -> bool {
    matches!(
        err,
        MicrosandboxError::Database(db_err)
            if microsandbox_db::retry::is_sqlite_busy(db_err)
    )
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Open both pools (read + dedicated single-connection writer) for the
/// SQLite file at `db_dir/msb.db` and run migrations on the writer.
async fn connect_and_migrate_pools(
    db_dir: &Path,
    max_connections: u32,
    connect_timeout_secs: u64,
    busy_timeout_secs: u64,
) -> MicrosandboxResult<DbPools> {
    tokio::fs::create_dir_all(db_dir).await?;

    let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);

    // Open the writer first and run migrations on it. WAL mode and
    // foreign-key enforcement are persisted in the database header /
    // session state, so once this connects every subsequent connection
    // (including the read pool) sees the right configuration.
    let write = build_pool(&db_path, 1, connect_timeout_secs, busy_timeout_secs).await?;
    Migrator::up(&write, None).await?;

    // Read pool: sized for concurrent readers. WAL allows readers to run
    // while a write is in progress.
    let read = build_pool(
        &db_path,
        max_connections,
        connect_timeout_secs,
        busy_timeout_secs,
    )
    .await?;

    Ok(DbPools { read, write })
}

async fn build_pool(
    db_path: &Path,
    max_connections: u32,
    connect_timeout_secs: u64,
    busy_timeout_secs: u64,
) -> MicrosandboxResult<DatabaseConnection> {
    microsandbox_db::pool::build_pool(
        db_path,
        max_connections,
        Duration::from_secs(connect_timeout_secs),
        Duration::from_secs(busy_timeout_secs),
    )
    .await
    .map_err(|e| MicrosandboxError::Custom(format!("connect to {}: {e}", db_path.display())))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};

    use super::*;

    #[tokio::test]
    async fn test_connect_and_migrate_creates_db_and_tables() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");

        let conn = connect_and_migrate_pools(&db_dir, 1, 1, 5)
            .await
            .unwrap()
            .read;

        // DB file should exist on disk.
        assert!(db_dir.join(microsandbox_utils::DB_FILENAME).exists());

        // All 12 tables should be present.
        let rows = conn
            .query_all(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'seaql_%' AND name != 'sqlite_sequence' ORDER BY name",
            ))
            .await
            .unwrap();

        let table_names: Vec<String> = rows
            .iter()
            .map(|r| r.try_get_by_index::<String>(0).unwrap())
            .collect();

        let expected = vec![
            "config",
            "image_ref",
            "layer",
            "manifest",
            "manifest_layer",
            "run",
            "sandbox",
            "sandbox_metric",
            "sandbox_rootfs",
            "snapshot",
            "volume",
        ];

        assert_eq!(table_names, expected);
    }

    #[tokio::test]
    async fn test_connect_and_migrate_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");

        let conn1 = connect_and_migrate_pools(&db_dir, 1, 1, 5)
            .await
            .unwrap()
            .read;

        // Running migrations again on the same DB should succeed.
        Migrator::up(&conn1, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_and_migrate_recovers_from_partial_storage_migration() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");
        tokio::fs::create_dir_all(&db_dir).await.unwrap();

        let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

        let conn = Database::connect(&db_url).await.unwrap();

        conn.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA foreign_keys = ON;",
        ))
        .await
        .unwrap();

        // Apply only migrations 1 and 2 so migration 3 is still pending.
        Migrator::up(&conn, Some(2)).await.unwrap();

        // Simulate a half-applied migration 3: the storage tables and the first
        // snapshot index exist, but migration 3 itself was never recorded.
        conn.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "CREATE TABLE IF NOT EXISTS volume (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                quota_mib INTEGER,
                size_bytes BIGINT,
                labels TEXT,
                created_at DATETIME,
                updated_at DATETIME
            )",
        ))
        .await
        .unwrap();

        conn.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "CREATE TABLE IF NOT EXISTS snapshot (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                sandbox_id INTEGER,
                size_bytes BIGINT,
                description TEXT,
                created_at DATETIME,
                FOREIGN KEY (sandbox_id) REFERENCES sandbox(id) ON DELETE SET NULL
            )",
        ))
        .await
        .unwrap();

        conn.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "CREATE UNIQUE INDEX idx_snapshots_name_sandbox_unique ON snapshot (name, sandbox_id)",
        ))
        .await
        .unwrap();

        let pending_before = conn
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) FROM seaql_migrations WHERE version = 'm20260305_000003_create_storage_tables'",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<i64>(0)
            .unwrap();
        assert_eq!(pending_before, 0);

        drop(conn);

        let recovered = connect_and_migrate_pools(&db_dir, 1, 1, 5)
            .await
            .unwrap()
            .read;

        let migration_row_count = recovered
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) FROM seaql_migrations WHERE version = 'm20260305_000003_create_storage_tables'",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<i64>(0)
            .unwrap();
        assert_eq!(migration_row_count, 1);

        let index_count = recovered
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'index'
                   AND name IN (
                       'idx_snapshots_name_sandbox_unique',
                       'idx_snapshots_name_unique_no_sandbox'
                   )",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<i64>(0)
            .unwrap();
        assert_eq!(index_count, 2);
    }
}
