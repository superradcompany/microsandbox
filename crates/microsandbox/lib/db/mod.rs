//! Database connection pool and entity definitions.
//!
//! Provides dual-pool access for global (`~/.microsandbox/db/msb.db`) and
//! project-local (`.microsandbox/db/msb.db`) databases. Migrations are
//! automatically applied on first connection.

#[allow(missing_docs)]
pub use microsandbox_db::entity;

use std::path::{Path, PathBuf};

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
pub async fn init_global(max_connections: Option<u32>) -> MicrosandboxResult<&'static DatabaseConnection> {
    GLOBAL_POOL
        .get_or_try_init(|| async {
            let base = dirs::home_dir()
                .ok_or_else(|| crate::MicrosandboxError::Custom("cannot determine home directory".into()))?;

            let db_dir = base
                .join(microsandbox_utils::BASE_DIR_NAME)
                .join(microsandbox_utils::DB_SUBDIR);

            connect_and_migrate(&db_dir, max_connections.unwrap_or(crate::config::DEFAULT_MAX_CONNECTIONS)).await
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

            let conn = connect_and_migrate(&db_dir, max_connections.unwrap_or(crate::config::DEFAULT_MAX_CONNECTIONS)).await?;
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
    opts.max_connections(max_connections);

    let conn = Database::connect(opts).await?;
    Migrator::up(&conn, None).await?;

    Ok(conn)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, Statement};

    use super::*;

    #[tokio::test]
    async fn test_connect_and_migrate_creates_db_and_tables() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");

        let conn = connect_and_migrate(&db_dir, 1).await.unwrap();

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
            "microvm",
            "msbnet",
            "sandbox",
            "sandbox_metric",
            "snapshot",
            "supervisor",
            "volume",
        ];

        assert_eq!(table_names, expected);
    }

    #[tokio::test]
    async fn test_connect_and_migrate_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");

        let conn1 = connect_and_migrate(&db_dir, 1).await.unwrap();

        // Running migrations again on the same DB should succeed.
        Migrator::up(&conn1, None).await.unwrap();
    }
}
