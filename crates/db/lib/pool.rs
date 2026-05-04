//! Canonical SQLite connection builder shared by every microsandbox process.
//!
//! Both the host CLI and the in-VM runtime open the same SQLite file and
//! must apply identical PRAGMAs (WAL, busy timeout, foreign keys,
//! synchronous=NORMAL). Centralising the builder keeps that contract in
//! one place — when a new PRAGMA is needed, this is the only file to edit.

use std::{path::Path, time::Duration};

use sea_orm::{DatabaseConnection, SqlxSqliteConnector};
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};

/// Default `busy_timeout` PRAGMA value used when a caller has no
/// user-facing knob to plumb (e.g. the in-VM runtime, where the host
/// owns DB-tuning policy and the runtime is not user-configurable).
pub const DEFAULT_BUSY_TIMEOUT_SECS: u64 = 5;

/// Open a sqlx-backed SQLite pool wrapped as a sea-orm `DatabaseConnection`.
///
/// PRAGMAs are applied to every connection in the pool via
/// `SqliteConnectOptions`, so callers don't need to issue any setup SQL.
///
/// `busy_timeout` is how long SQLite will spin internally on a contended
/// lock before returning `SQLITE_BUSY`. It interacts with the
/// application-level retry policy: a longer busy timeout reduces retry
/// volume at the cost of higher tail latency on contention.
pub async fn build_pool(
    db_path: &Path,
    max_connections: u32,
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

    let pool = SqlitePoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(connect_timeout)
        .connect_with(connect_options)
        .await?;

    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}
