//! SQLite-specific error classification and retry loop used by write paths.
//!
//! Lives in this crate (rather than the host) because it pattern-matches
//! on `sqlx::Error` directly — sqlx is already a dep here, and we don't
//! want to re-add it to `microsandbox` just for an error sniff.

use std::{future::Future, time::Duration};

use sea_orm::{DbErr, RuntimeErr};

/// SQLite extended error codes for "another writer holds the lock".
///
/// Returned to the application after the per-connection `busy_timeout`
/// PRAGMA expires; the application-level retry layer translates this
/// into exponential backoff.
const SQLITE_BUSY: &str = "5";
const SQLITE_BUSY_SNAPSHOT: &str = "517";

const MAX_BUSY_RETRY_ATTEMPTS: u32 = 8;
const INITIAL_DELAY: Duration = Duration::from_millis(10);
const MAX_DELAY: Duration = Duration::from_millis(500);

/// Returns `true` if `err` is a SQLite `BUSY` / `BUSY_SNAPSHOT` error
/// from any of the sea-orm variants that wrap a sqlx database error.
pub fn is_sqlite_busy(err: &DbErr) -> bool {
    let runtime_err = match err {
        DbErr::Conn(e) | DbErr::Exec(e) | DbErr::Query(e) => e,
        _ => return false,
    };
    let RuntimeErr::SqlxError(sqlx_err) = runtime_err else {
        return false;
    };
    let sqlx::Error::Database(db_err) = sqlx_err.as_ref() else {
        return false;
    };
    matches!(
        db_err.code().as_deref(),
        Some(SQLITE_BUSY) | Some(SQLITE_BUSY_SNAPSHOT)
    )
}

/// Trait for application error types so the retry layer can recognise
/// SQLite-busy failures wrapped inside larger error enums.
///
/// Implemented for [`DbErr`] out of the box. Host crates that wrap
/// `DbErr` in their own error type (e.g. `MicrosandboxError`,
/// `RuntimeError`) should implement this trait by delegating to
/// [`is_sqlite_busy`] on the wrapped `DbErr` — otherwise the retry
/// layer cannot tell which errors are transient.
pub trait IsSqliteBusy {
    /// Whether this error represents a transient SQLite busy/lock state.
    fn is_sqlite_busy(&self) -> bool;
}

impl IsSqliteBusy for DbErr {
    fn is_sqlite_busy(&self) -> bool {
        is_sqlite_busy(self)
    }
}

/// Retry a database operation on SQLite `BUSY` / `BUSY_SNAPSHOT` with
/// exponential backoff, capped at a small fixed number of attempts.
///
/// `f` is invoked once per attempt and must produce a fresh future each
/// call (so it can be retried with a clean transaction or query). `E` must
/// implement [`IsSqliteBusy`] so the loop can distinguish transient busy
/// errors from permanent failures.
///
/// Tracing context: callers that want operation context in retry warnings
/// should wrap the call in a `tracing::info_span!` or apply `#[instrument]`
/// to the calling function — the warnings emitted here pick up the current
/// span automatically.
pub async fn retry_on_busy<F, Fut, T, E>(mut f: F) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = Result<T, E>>,
    E: IsSqliteBusy,
{
    let mut delay = INITIAL_DELAY;
    for attempt in 1..=MAX_BUSY_RETRY_ATTEMPTS {
        match f().await {
            Ok(value) => {
                if attempt > 1 {
                    tracing::warn!(attempts = attempt, "db busy resolved after retries");
                }
                return Ok(value);
            }
            Err(err) if err.is_sqlite_busy() && attempt < MAX_BUSY_RETRY_ATTEMPTS => {
                tracing::warn!(
                    attempt,
                    delay_ms = delay.as_millis() as u64,
                    "SQLITE_BUSY, retrying"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_DELAY);
            }
            Err(err) if err.is_sqlite_busy() => {
                tracing::error!(
                    attempts = attempt,
                    "SQLITE_BUSY exhausted retries, giving up"
                );
                return Err(err);
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("loop returns or errors before exhausting attempts")
}

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, DatabaseBackend, Statement, TransactionTrait};

    use super::*;

    #[test]
    fn non_sqlite_errors_are_not_busy() {
        assert!(!is_sqlite_busy(&DbErr::Custom("not a driver error".into())));
        assert!(!is_sqlite_busy(&DbErr::Exec(RuntimeErr::Internal(
            "not a sqlx error".into()
        ))));
    }

    /// Drives a genuine `SQLITE_BUSY` through the sqlx driver so this test
    /// pins the exact error shape the current sea-orm/sqlx versions produce
    /// (`DbErr::Exec(RuntimeErr::SqlxError(Arc<sqlx::Error::Database>))`
    /// with code "5"). A hand-built error would keep passing even if a
    /// driver upgrade changed how busy surfaces — and then the retry layer
    /// would silently stop retrying under cross-process contention.
    #[tokio::test]
    async fn real_sqlite_busy_is_classified() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("busy.db");

        let holder = crate::connection::DbWriteConnection::open(
            &db_path,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        holder
            .inner()
            .execute_unprepared("CREATE TABLE t (id INTEGER PRIMARY KEY)")
            .await
            .unwrap();

        // Take the SQLite write lock and hold it: an INSERT inside an
        // uncommitted transaction keeps the lock until commit/rollback.
        let txn = holder.inner().begin().await.unwrap();
        txn.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "INSERT INTO t (id) VALUES (1)",
        ))
        .await
        .unwrap();

        // Second connection with a near-zero busy_timeout so BUSY surfaces
        // immediately instead of spinning inside SQLite. Bypass the
        // retry-wrapped `ConnectionTrait` impl via `inner()` — the point is
        // to classify the raw error, not to exercise the backoff loop.
        let contender = crate::connection::DbWriteConnection::open(
            &db_path,
            Duration::from_secs(5),
            Duration::from_millis(1),
        )
        .await
        .unwrap();
        let err = contender
            .inner()
            .execute_raw(Statement::from_string(
                DatabaseBackend::Sqlite,
                "INSERT INTO t (id) VALUES (2)",
            ))
            .await
            .unwrap_err();

        assert!(
            is_sqlite_busy(&err),
            "expected SQLITE_BUSY classification, got: {err:?}"
        );

        txn.rollback().await.unwrap();
    }
}
