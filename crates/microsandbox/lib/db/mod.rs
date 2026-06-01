//! Global database connection pool init and accessor.
//!
//! Opens both pools (read + write) for `~/.microsandbox/db/msb.db` and
//! runs migrations on the writer. Returns [`DbPools`] from
//! `microsandbox-db`; callers pick `pools.read()` (a [`DbReadConnection`])
//! or `pools.write()` (a [`DbWriteConnection`]) based on the operation.
//! The type system blocks accidental writes against the read pool.
//!
//! [`DbReadConnection`]: microsandbox_db::DbReadConnection
//! [`DbWriteConnection`]: microsandbox_db::DbWriteConnection

pub use microsandbox_db::entity;

#[cfg(unix)]
use std::{
    fs::{File, OpenOptions},
    os::fd::AsRawFd,
};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use microsandbox_db::pool::DbPools;
use microsandbox_migration::{Migrator, MigratorTrait};
use tokio::sync::OnceCell;

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Statics
//--------------------------------------------------------------------------------------------------

static GLOBAL_POOL: OnceCell<DbPools> = OnceCell::const_new();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct MigrationLock {
    #[cfg(unix)]
    file: File,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Initialize the global database pools at `~/.microsandbox/db/msb.db`.
///
/// Migrations are applied automatically. Idempotent — repeat calls
/// return the existing pools. All tuning (max_connections,
/// connect_timeout, busy_timeout) is read from `~/.microsandbox/config.json`.
pub async fn init_global() -> MicrosandboxResult<&'static DbPools> {
    GLOBAL_POOL
        .get_or_try_init(|| async {
            let db_dir = microsandbox_utils::resolve_home().join(microsandbox_utils::DB_SUBDIR);

            connect_and_migrate(&db_dir).await
        })
        .await
}

/// Get the global pools, or `None` if [`init_global`] has not run.
pub fn global() -> Option<&'static DbPools> {
    GLOBAL_POOL.get()
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Open both pools for `db_dir/msb.db` and run migrations on the writer.
///
/// The write pool connects first so WAL mode (persisted in the database
/// header) is set before the read pool opens. Tuning is read from the
/// global config.
async fn connect_and_migrate(db_dir: &Path) -> MicrosandboxResult<DbPools> {
    tokio::fs::create_dir_all(db_dir).await?;
    let _migration_lock = acquire_migration_lock(db_dir).await?;

    let database = &crate::config::config().database;
    let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);
    let pools = DbPools::open(
        &db_path,
        database.max_connections,
        Duration::from_secs(database.connect_timeout_secs),
        Duration::from_secs(database.busy_timeout_secs),
    )
    .await
    .map_err(|e| MicrosandboxError::Custom(format!("connect to {}: {e}", db_path.display())))?;

    Migrator::up(pools.write().inner(), None).await?;

    Ok(pools)
}

async fn acquire_migration_lock(db_dir: &Path) -> MicrosandboxResult<MigrationLock> {
    let path = db_dir.join(format!(
        "{}.migration.lock",
        microsandbox_utils::DB_FILENAME
    ));
    tokio::task::spawn_blocking(move || MigrationLock::acquire(path))
        .await
        .map_err(|e| MicrosandboxError::Runtime(format!("migration lock task failed: {e}")))?
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MigrationLock {
    #[cfg(unix)]
    fn acquire(path: PathBuf) -> MicrosandboxResult<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|e| {
                MicrosandboxError::Runtime(format!("open migration lock {}: {e}", path.display()))
            })?;

        let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
        if ret != 0 {
            return Err(MicrosandboxError::Runtime(format!(
                "lock migration file {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self { file })
    }

    #[cfg(not(unix))]
    fn acquire(_path: PathBuf) -> MicrosandboxResult<Self> {
        Ok(Self {})
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
impl Drop for MigrationLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
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

        let pools = connect_and_migrate(&db_dir).await.unwrap();
        let conn = pools.read();

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
            "sandbox_labels",
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

        let pools = connect_and_migrate(&db_dir).await.unwrap();

        // Running migrations again on the same DB should succeed.
        Migrator::up(pools.write().inner(), None).await.unwrap();
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

        let recovered = connect_and_migrate(&db_dir).await.unwrap();

        let migration_row_count = recovered
            .read()
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

        let legacy_index_count = recovered
            .read()
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
            .read()
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

    #[tokio::test]
    async fn test_connect_and_migrate_updates_legacy_oci_rootfs_source() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");
        tokio::fs::create_dir_all(&db_dir).await.unwrap();

        let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let conn = Database::connect(&db_url).await.unwrap();

        Migrator::up(&conn, Some(2)).await.unwrap();
        conn.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO sandbox (name, config, status) VALUES (?, ?, ?)",
            [
                "legacy".into(),
                r#"{"name":"legacy","image":{"Oci":"ubuntu"}}"#.into(),
                "Stopped".into(),
            ],
        ))
        .await
        .unwrap();
        drop(conn);

        let pools = connect_and_migrate(&db_dir).await.unwrap();
        let config_json = pools
            .read()
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT config FROM sandbox WHERE name = 'legacy'",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<String>(0)
            .unwrap();

        let value: serde_json::Value = serde_json::from_str(&config_json).unwrap();
        assert_eq!(value["image"]["Oci"]["reference"], "ubuntu");
        assert_eq!(value["image"]["Oci"]["upper_size_mib"], 4096);

        let decoded: crate::sandbox::SandboxConfig = serde_json::from_str(&config_json).unwrap();
        assert_eq!(decoded.image.oci_reference(), Some("ubuntu"));
        assert_eq!(decoded.image.oci_upper_size_mib(), Some(4096));
    }

    #[tokio::test]
    async fn test_connect_and_migrate_serializes_concurrent_migrations() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");
        tokio::fs::create_dir_all(&db_dir).await.unwrap();

        let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let conn = Database::connect(&db_url).await.unwrap();

        Migrator::up(&conn, Some(2)).await.unwrap();
        conn.execute(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            "INSERT INTO sandbox (name, config, status) VALUES (?, ?, ?)",
            [
                "legacy".into(),
                r#"{"name":"legacy","image":{"Oci":"ubuntu"}}"#.into(),
                "Stopped".into(),
            ],
        ))
        .await
        .unwrap();
        drop(conn);

        let (first, second) =
            tokio::join!(connect_and_migrate(&db_dir), connect_and_migrate(&db_dir));

        first.unwrap();
        second.unwrap();

        let conn = Database::connect(&db_url).await.unwrap();
        let migration_count = conn
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) FROM seaql_migrations",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<i64>(0)
            .unwrap();

        assert_eq!(migration_count, 10);
    }
}
