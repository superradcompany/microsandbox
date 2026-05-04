//! SQLite-specific error classification used by retry layers.
//!
//! Lives in this crate (rather than the host) because it pattern-matches
//! on `sqlx::Error` directly — sqlx is already a dep here, and we don't
//! want to re-add it to `microsandbox` just for an error sniff.

use sea_orm::{DbErr, RuntimeErr};

/// SQLite extended error codes for "another writer holds the lock".
///
/// Returned to the application after the per-connection `busy_timeout`
/// PRAGMA expires; the application-level retry layer translates this
/// into exponential backoff.
const SQLITE_BUSY: &str = "5";
const SQLITE_BUSY_SNAPSHOT: &str = "517";

/// Returns `true` if `err` is a SQLite `BUSY` / `BUSY_SNAPSHOT` error
/// from any of the sea-orm variants that wrap a sqlx database error.
pub fn is_sqlite_busy(err: &DbErr) -> bool {
    let runtime_err = match err {
        DbErr::Conn(e) | DbErr::Exec(e) | DbErr::Query(e) => e,
        _ => return false,
    };
    let RuntimeErr::SqlxError(sqlx::Error::Database(db_err)) = runtime_err else {
        return false;
    };
    matches!(
        db_err.code().as_deref(),
        Some(SQLITE_BUSY) | Some(SQLITE_BUSY_SNAPSHOT)
    )
}
