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
/// multiple times returns the existing pool. Pool settings are read from
/// `config::config().database`.
pub async fn init_global() -> MicrosandboxResult<&'static DatabaseConnection> {
    GLOBAL_POOL
        .get_or_try_init(|| async {
            let base = dirs::home_dir().ok_or_else(|| {
                crate::MicrosandboxError::Custom("cannot determine home directory".into())
            })?;

            let db_dir = base
                .join(microsandbox_utils::BASE_DIR_NAME)
                .join(microsandbox_utils::DB_SUBDIR);

            let db_cfg = &crate::config::config().database;
            connect_and_migrate(
                &db_dir,
                db_cfg.max_connections,
                Duration::from_secs(db_cfg.connect_timeout_secs),
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
) -> MicrosandboxResult<&'static DatabaseConnection> {
    let requested = project_dir.as_ref().to_path_buf();

    let pair = PROJECT_POOL
        .get_or_try_init(|| async {
            let db_dir = requested
                .join(microsandbox_utils::BASE_DIR_NAME)
                .join(microsandbox_utils::DB_SUBDIR);

            let db_cfg = &crate::config::config().database;
            let conn = connect_and_migrate(
                &db_dir,
                db_cfg.max_connections,
                Duration::from_secs(db_cfg.connect_timeout_secs),
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
    connect_timeout: Duration,
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
    configure_sqlite_connect_options(&mut opts, max_connections, connect_timeout);

    let conn = Database::connect(opts).await?;
    Migrator::up(&conn, None).await?;

    Ok(conn)
}

fn configure_sqlite_connect_options(
    opts: &mut ConnectOptions,
    max_connections: u32,
    connect_timeout: Duration,
) {
    // The global microsandbox DB is shared across short-lived CLI processes and
    // long-lived sandbox runtimes. WAL mode plus a busy timeout makes that
    // multi-process pattern much more reliable than the default rollback
    // journal on Linux hosts.
    opts.max_connections(max_connections)
        .connect_timeout(connect_timeout)
        .map_sqlx_sqlite_opts(|sqlx_opts| {
            sqlx_opts
                .foreign_keys(true)
                .busy_timeout(Duration::from_secs(5))
                .pragma("journal_mode", "WAL")
        });
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, Database, Statement};

    use super::*;

    #[tokio::test]
    async fn test_connect_and_migrate_creates_db_and_tables() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");

        let conn = connect_and_migrate(&db_dir, 1, Duration::from_secs(30))
            .await
            .unwrap();

        // DB file should exist on disk.
        assert!(db_dir.join(microsandbox_utils::DB_FILENAME).exists());

        // All 13 tables should be present.
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
            "image",
            "index",
            "layer",
            "manifest",
            "manifest_layer",
            "run",
            "sandbox",
            "sandbox_image",
            "sandbox_metric",
            "snapshot",
            "volume",
        ];

        assert_eq!(table_names, expected);
    }

    #[tokio::test]
    async fn test_connect_and_migrate_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");

        let conn1 = connect_and_migrate(&db_dir, 1, Duration::from_secs(30))
            .await
            .unwrap();

        // Running migrations again on the same DB should succeed.
        Migrator::up(&conn1, None).await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_and_migrate_recovers_from_partial_storage_migration() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");
        std::fs::create_dir_all(&db_dir).unwrap();

        let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());
        let conn = Database::connect(&db_url).await.unwrap();

        Migrator::up(&conn, Some(2)).await.unwrap();

        conn.execute_unprepared(
            r#"
            CREATE TABLE IF NOT EXISTS "volume" (
                "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
                "name" text NOT NULL UNIQUE,
                "quota_mib" integer,
                "size_bytes" bigint,
                "labels" text,
                "created_at" datetime_text,
                "updated_at" datetime_text
            );
            CREATE TABLE IF NOT EXISTS "snapshot" (
                "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
                "name" text NOT NULL,
                "sandbox_id" integer,
                "size_bytes" bigint,
                "description" text,
                "created_at" datetime_text,
                FOREIGN KEY ("sandbox_id") REFERENCES "sandbox" ("id") ON DELETE SET NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS "idx_snapshots_name_sandbox_unique" ON "snapshot" ("name", "sandbox_id");
            "#,
        )
        .await
        .unwrap();

        drop(conn);

        let conn = connect_and_migrate(&db_dir, 1, Duration::from_secs(30))
            .await
            .unwrap();

        let migrations = conn
            .query_all(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                "SELECT version FROM seaql_migrations ORDER BY version",
            ))
            .await
            .unwrap();

        let migration_names: Vec<String> = migrations
            .iter()
            .map(|row| row.try_get_by_index::<String>(0).unwrap())
            .collect();

        assert_eq!(
            migration_names,
            vec![
                "m20260305_000001_create_image_tables",
                "m20260305_000002_create_sandbox_tables",
                "m20260305_000003_create_storage_tables",
                "m20260305_000004_create_sandbox_images_table",
            ]
        );

        let indexes = conn
            .query_all(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type = 'index' AND name LIKE 'idx_snapshots%' ORDER BY name",
            ))
            .await
            .unwrap();

        let index_names: Vec<String> = indexes
            .iter()
            .map(|row| row.try_get_by_index::<String>(0).unwrap())
            .collect();

        assert_eq!(
            index_names,
            vec![
                "idx_snapshots_name_sandbox_unique",
                "idx_snapshots_name_unique_no_sandbox",
            ]
        );
    }
}
