//! Private, verified SQLite copies published only after successful completion.

#[cfg(unix)]
use std::fs::File;
use std::path::Path;

use sea_orm::{ConnectionTrait, DatabaseConnection, DbBackend, DbErr, Statement};
use sqlx::{Connection, Row, SqliteConnection, sqlite::SqliteConnectOptions};

use crate::private_storage::{ensure_private_database_directory, harden_database_files};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Write an exclusive private staging file, validate it, and publish without replacing a backup.
/// A killed process can leave a hidden staging file; it never creates a completed backup name.
pub async fn create_private_backup(
    db: &DatabaseConnection,
    destination: &Path,
) -> Result<(), DbErr> {
    create_with_observer(db, destination, |_| Ok(())).await
}

async fn create_with_observer(
    db: &DatabaseConnection,
    destination: &Path,
    mut observe: impl FnMut(&Path) -> Result<(), DbErr>,
) -> Result<(), DbErr> {
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure_private_database_directory(parent).map_err(storage_error)?;
    let parent = std::fs::canonicalize(parent).map_err(storage_error)?;
    let name = destination
        .file_name()
        .ok_or_else(|| DbErr::Custom("backup has no filename".into()))?;
    let destination = parent.join(name);
    // No ordinary backup filename exists until SQLite has succeeded and quick_check passed.
    // NamedTempFile uses exclusive creation and 0600 on Unix. Clear inherited Darwin ACLs
    // before SQLite writes anything, and keep all abandoned output behind the same boundary.
    let stage = tempfile::Builder::new()
        .prefix(".msb-db-incomplete-")
        .tempfile_in(&parent)
        .map_err(storage_error)?;
    harden_database_files(stage.path()).map_err(storage_error)?;
    observe(stage.path())?;
    db.execute_raw(Statement::from_sql_and_values(
        DbBackend::Sqlite,
        "VACUUM INTO ?",
        [stage.path().to_string_lossy().into_owned().into()],
    ))
    .await?;
    observe(stage.path())?;
    validate_backup(stage.path()).await?;
    stage.as_file().sync_all().map_err(storage_error)?;
    stage
        .persist_noclobber(&destination)
        .map_err(|e| storage_error(e.error))?;
    #[cfg(unix)]
    File::open(parent)
        .and_then(|file| file.sync_all())
        .map_err(storage_error)?;
    Ok(())
}

/// Validate a nonempty existing backup without creating files or changing journal mode.
pub async fn validate_backup(path: &Path) -> Result<(), DbErr> {
    let path = crate::private_storage::prepare_database_file(path, false).map_err(storage_error)?;
    if std::fs::metadata(&path).map_err(storage_error)?.len() == 0 {
        return Err(DbErr::Custom("SQLite backup is empty or incomplete".into()));
    }
    let options = SqliteConnectOptions::new()
        .filename(&path)
        .read_only(true)
        .create_if_missing(false);
    let mut connection = SqliteConnection::connect_with(&options)
        .await
        .map_err(storage_error)?;
    let result = sqlx::query("PRAGMA quick_check")
        .fetch_all(&mut connection)
        .await;
    connection.close().await.map_err(storage_error)?;
    let rows = result.map_err(storage_error)?;
    if rows.len() != 1 || rows[0].try_get::<String, _>(0).map_err(storage_error)? != "ok" {
        return Err(DbErr::Custom("SQLite backup failed quick_check".into()));
    }
    Ok(())
}

fn storage_error(error: impl std::fmt::Display) -> DbErr {
    DbErr::Custom(format!("private catalog backup: {error}"))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
#[path = "backup_tests.rs"]
mod tests;
