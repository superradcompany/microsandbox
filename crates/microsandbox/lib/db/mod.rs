//! Database connection pool and entity definitions.
//!
//! Provides dual-pool access for global (`~/.microsandbox/db/msb.db`) and
//! project-local (`.microsandbox/db/msb.db`) databases. Migrations are
//! automatically applied on first connection.

pub use microsandbox_db::entity;

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use microsandbox_migration::{Migrator, MigratorTrait};
use sea_orm::{ConnectOptions, Database, DatabaseConnection};
use tokio::sync::OnceCell;

use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

static GLOBAL_POOL: OnceCell<DatabaseConnection> = OnceCell::const_new();
static PROJECT_POOL: OnceCell<(PathBuf, DatabaseConnection)> = OnceCell::const_new();

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Initialize the global database connection pool at `~/.microsandbox/db/msb.db`.
///
/// Migrations are applied automatically. This is idempotent — calling it
/// multiple times returns the existing pool.
pub async fn init_global(
    max_connections: Option<u32>,
) -> MicrosandboxResult<&'static DatabaseConnection> {
    GLOBAL_POOL
        .get_or_try_init(|| async {
            let db_dir = microsandbox_utils::resolve_home().join(microsandbox_utils::DB_SUBDIR);

            connect_and_migrate(
                &db_dir,
                max_connections.unwrap_or(crate::config::DEFAULT_MAX_CONNECTIONS),
                crate::config::config().database.connect_timeout_secs,
            )
            .await
        })
        .await
}

/// Initialize a project-local database connection pool at `<project>/.microsandbox/db/msb.db`.
///
/// Migrations are applied automatically. This is idempotent — calling it
/// multiple times returns the existing pool. Returns an error if called
/// with a different project directory than the first call.
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

            let conn = connect_and_migrate(
                &db_dir,
                max_connections.unwrap_or(crate::config::DEFAULT_MAX_CONNECTIONS),
                crate::config::config().database.connect_timeout_secs,
            )
            .await?;
            Ok::<_, crate::MicrosandboxError>((requested.clone(), conn))
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

    Ok(&pair.1)
}

/// Get the global database connection pool.
///
/// Returns `None` if [`init_global`] has not been called yet.
pub fn global() -> Option<&'static DatabaseConnection> {
    GLOBAL_POOL.get()
}

/// Get the project-local database connection pool.
///
/// Returns `None` if [`init_project`] has not been called yet.
pub fn project() -> Option<&'static DatabaseConnection> {
    PROJECT_POOL.get().map(|(_, conn)| conn)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

async fn connect_and_migrate(
    db_dir: &Path,
    max_connections: u32,
    connect_timeout_secs: u64,
) -> MicrosandboxResult<DatabaseConnection> {
    tokio::fs::create_dir_all(db_dir).await?;

    let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);
    let db_path_str = db_path.to_str().ok_or_else(|| {
        crate::MicrosandboxError::Custom(format!(
            "database path is not valid UTF-8: {}",
            db_path.display()
        ))
    })?;
    let db_url = format!("sqlite://{db_path_str}?mode=rwc");

    let mut opts = ConnectOptions::new(&db_url);
    opts.max_connections(max_connections)
        .connect_timeout(Duration::from_secs(connect_timeout_secs))
        .sqlx_logging(false);

    let conn = Database::connect(opts).await?;

    // Enable WAL journal mode, busy timeout, and foreign key enforcement.
    // WAL prevents SQLITE_BUSY when multiple processes (CLI + sandbox runtimes)
    // access the same database concurrently.
    use sea_orm::ConnectionTrait;
    conn.execute(sea_orm::Statement::from_string(
        sea_orm::DatabaseBackend::Sqlite,
        microsandbox_utils::SQLITE_PRAGMAS,
    ))
    .await?;

    Migrator::up(&conn, None).await?;

    Ok(conn)
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

        let conn = connect_and_migrate(&db_dir, 1, 1).await.unwrap();

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
            "snapshot_index",
            "volume",
        ];

        assert_eq!(table_names, expected);
    }

    #[tokio::test]
    async fn test_connect_and_migrate_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");

        let conn1 = connect_and_migrate(&db_dir, 1, 1).await.unwrap();

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

        let recovered = connect_and_migrate(&db_dir, 1, 1).await.unwrap();

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

        // The legacy snapshot indexes are dropped by the
        // `m20260501_000001_create_snapshot_index` migration, which
        // also drops the legacy `snapshot` table. After full recovery
        // they should be gone, replaced by the new `snapshot_index`
        // table and its own indexes.
        let legacy_index_count = recovered
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
        assert_eq!(legacy_index_count, 0);

        let new_index_count = recovered
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type = 'index'
                   AND name IN (
                       'idx_snapshot_index_name',
                       'idx_snapshot_index_parent',
                       'idx_snapshot_index_image'
                   )",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<i64>(0)
            .unwrap();
        assert_eq!(new_index_count, 3);
    }
}
