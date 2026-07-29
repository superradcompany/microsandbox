//! Canonical SQLite pool builders shared by every microsandbox process.
//!
//! Both the host CLI and the in-VM runtime open the same SQLite file and
//! must apply identical PRAGMAs. Centralising the builders keeps that
//! contract in one place — when a new PRAGMA is needed, this is the only
//! file to edit.
//!
//! The write side carries the writer-establishment PRAGMAs (WAL journal
//! mode, `synchronous=NORMAL`) and may create the file. The read side opens
//! with `SQLITE_OPEN_READONLY`, so the engine rejects writes on that lane;
//! WAL mode persists in the database header, so read connections never need
//! to (and must not) issue journal-mode or synchronous PRAGMAs themselves.

use std::{path::Path, time::Duration};

use sea_orm::{DatabaseConnection, SqlxSqliteConnector};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default `busy_timeout` PRAGMA value used when a caller has no
/// user-facing knob to plumb (e.g. the in-VM runtime, where the host
/// owns DB-tuning policy and the runtime is not user-configurable).
pub const DEFAULT_BUSY_TIMEOUT_SECS: u64 = 5;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open the single-connection write pool for the SQLite file at `db_path`.
///
/// Creates the file if missing and establishes WAL mode (persisted in the
/// database header) plus `synchronous=NORMAL`. `busy_timeout` is how long
/// SQLite spins internally on a contended lock before returning
/// `SQLITE_BUSY`; it interacts with the application-level retry policy — a
/// longer busy timeout reduces retry volume at the cost of higher tail
/// latency under contention.
pub(crate) async fn build_write_pool(
    db_path: &Path,
    connect_timeout: Duration,
    busy_timeout: Duration,
) -> Result<DatabaseConnection, sqlx::Error> {
    let connect_options = SqliteConnectOptions::new()
        .filename(db_path)
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .busy_timeout(busy_timeout)
        .foreign_keys(true)
        .synchronous(SqliteSynchronous::Normal);

    connect(connect_options, 1, connect_timeout).await
}

/// Open the read-only pool for the SQLite file at `db_path`.
///
/// `SQLITE_OPEN_READONLY` makes the engine reject writes on this lane, and a
/// missing file is an error rather than being created. Deliberately no
/// journal-mode or synchronous PRAGMAs: those are writer-establishment
/// settings, and WAL is already persistent in the file.
pub(crate) async fn build_read_pool(
    db_path: &Path,
    max_connections: u32,
    connect_timeout: Duration,
    busy_timeout: Duration,
) -> Result<DatabaseConnection, sqlx::Error> {
    let connect_options = SqliteConnectOptions::new()
        .filename(db_path)
        .read_only(true)
        .busy_timeout(busy_timeout)
        .foreign_keys(true);

    connect(connect_options, max_connections, connect_timeout).await
}

/// Open a sqlx-backed SQLite pool wrapped as a sea-orm `DatabaseConnection`.
///
/// PRAGMAs are applied to every connection in the pool via
/// `SqliteConnectOptions`, so callers don't need to issue any setup SQL. The
/// pool eagerly establishes one connection, so open errors (missing file for
/// read-only opens, unwritable directory) surface here rather than on first
/// use.
async fn connect(
    connect_options: SqliteConnectOptions,
    max_connections: u32,
    connect_timeout: Duration,
) -> Result<DatabaseConnection, sqlx::Error> {
    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(connect_timeout)
        .connect_with(connect_options)
        .await?;

    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}
