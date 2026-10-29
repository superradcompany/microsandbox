//! Canonical SQLite connection builder shared by every microsandbox process.
//!
//! Both the host CLI and the in-VM runtime open the same SQLite file and
//! must apply identical PRAGMAs (WAL, busy timeout, foreign keys,
//! synchronous=NORMAL). Centralising the builder keeps that contract in one place — when a new PRAGMA is needed, this is the only file to edit.

use std::{path::Path, time::Duration};

use sea_orm::{DatabaseConnection, SqlxSqliteConnector};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

use crate::connection::{DbReadConnection, DbWriteConnection};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default `busy_timeout` PRAGMA value used when a caller has no
/// user-facing knob to plumb (e.g. the in-VM runtime, where the host
/// owns DB-tuning policy and the runtime is not user-configurable).
pub const DEFAULT_BUSY_TIMEOUT_SECS: u64 = 5;

/// Read pool + dedicated single-connection write pool for the same SQLite
/// file. SQLite is single-writer system-wide, so a multi-connection pool
/// fighting for the writer lock just generates `SQLITE_BUSY` and (under
/// deferred transactions) `SQLITE_BUSY_SNAPSHOT`. Funnelling all writes
/// from one process through a single connection turns within-process
/// contention into an in-process queue (deterministic) instead of
/// SQLite-level lock contention (probabilistic, retry-required). Reads
/// keep the wider pool — WAL mode lets readers run concurrently.
#[derive(Debug)]
pub struct DbPools {
    read: DbReadConnection,
    write: DbWriteConnection,
}

impl DbPools {
    /// Open both pools for the SQLite file at `db_path` with shared PRAGMAs.
    ///
    /// The write pool connects first so WAL mode (persisted in the database
    /// header) is set before the read pool opens. `max_read_connections`
    /// sizes only the read pool; the write pool is always single-connection
    /// by design.
    pub async fn open(
        db_path: &Path,
        max_read_connections: u32,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> Result<Self, sqlx::Error> {
        let write = DbWriteConnection::open(db_path, connect_timeout, busy_timeout).await?;
        let read =
            DbReadConnection::open(db_path, max_read_connections, connect_timeout, busy_timeout)
                .await?;
        Ok(Self { read, write })
    }

    /// Borrow the read pool (multi-connection).
    pub fn read(&self) -> &DbReadConnection {
        &self.read
    }

    /// Borrow the write pool (single-connection, retries handled inside).
    pub fn write(&self) -> &DbWriteConnection {
        &self.write
    }
}

/// Open a sqlx-backed SQLite pool wrapped as a sea-orm `DatabaseConnection`.
///
/// PRAGMAs are applied to every connection in the pool via
/// `SqliteConnectOptions`, so callers don't need to issue any setup SQL.
///
/// `busy_timeout` is how long SQLite will spin internally on a contended
/// lock before returning `SQLITE_BUSY`. It interacts with the
/// application-level retry policy: a longer busy timeout reduces retry
/// volume at the cost of higher tail latency on contention.
///
/// `create_if_missing` controls whether opening a non-existent DB file creates
/// it. The write side (owned by `msb`) creates the catalog; read-only consumers
/// (e.g. `msb-metrics`) pass `false` so they never author or pre-empt it.
pub(crate) async fn build_pool(
    db_path: &Path,
    max_connections: u32,
    connect_timeout: Duration,
    busy_timeout: Duration,
    create_if_missing: bool,
) -> Result<DatabaseConnection, sqlx::Error> {
    let db_path = crate::private_storage::prepare_database_file(db_path, create_if_missing)
        .map_err(sqlx::Error::Io)?;

    let connect_options = SqliteConnectOptions::new()
        .filename(&db_path)
        .create_if_missing(false)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(busy_timeout)
        .foreign_keys(true)
        .synchronous(SqliteSynchronous::Normal);

    // Concurrent first opens can return BUSY while enabling WAL, even with SQLite's
    // busy timeout. Retry the entire connection setup within the caller's deadline.
    let pool = tokio::time::timeout(
        connect_timeout,
        crate::retry::retry_on_busy(|| {
            SqlitePoolOptions::new()
                .max_connections(max_connections)
                .acquire_timeout(connect_timeout)
                .connect_with(connect_options.clone())
        }),
    )
    .await
    .map_err(|_| sqlx::Error::PoolTimedOut)??;

    harden_database_files(&db_path).map_err(sqlx::Error::Io)?;

    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};
    use sqlx::{ConnectOptions, Executor};

    use super::*;

    #[tokio::test]
    async fn catalog_open_retries_busy_setup_within_connect_timeout() {
        let root = tempfile::tempdir().unwrap();
        let path = crate::private_storage::prepare_database_file(&root.path().join("msb.db"), true)
            .unwrap();
        let mut owner = SqliteConnectOptions::new()
            .filename(&path)
            .journal_mode(SqliteJournalMode::Delete)
            .connect()
            .await
            .unwrap();
        owner
            .execute(
                "CREATE TABLE retained(value); INSERT INTO retained VALUES (42); BEGIN EXCLUSIVE",
            )
            .await
            .unwrap();

        let error = build_pool(
            &path,
            1,
            Duration::from_millis(50),
            Duration::from_millis(1),
            false,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, sqlx::Error::PoolTimedOut), "{error}");

        let opening = build_pool(
            &path,
            1,
            Duration::from_secs(5),
            Duration::from_millis(1),
            false,
        );
        tokio::pin!(opening);
        assert!(
            tokio::time::timeout(Duration::from_millis(50), &mut opening)
                .await
                .is_err(),
            "opening should wait while the existing catalog is locked"
        );

        owner.execute("COMMIT").await.unwrap();
        let pool = opening.await.unwrap();

        let row = pool
            .query_one_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT value FROM retained",
            ))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(row.try_get_by_index::<i64>(0).unwrap(), 42);
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
pub use crate::private_storage::{PRIVATE_DATABASE_DIRECTORY_MODE, PRIVATE_DATABASE_FILE_MODE};
pub use crate::private_storage::{ensure_private_database_directory, harden_database_files};
