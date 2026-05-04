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
    let RuntimeErr::SqlxError(sqlx::Error::Database(db_err)) = runtime_err else {
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
/// `name` is used purely for tracing. `f` is invoked once per attempt and
/// must produce a fresh future each call (so it can be retried with a
/// clean transaction or query). `E` must implement [`IsSqliteBusy`] so the
/// loop can distinguish transient busy errors from permanent failures.
pub async fn retry_on_busy<F, Fut, T, E>(name: &'static str, mut f: F) -> Result<T, E>
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
                    tracing::debug!(operation = name, attempt, "db busy retry succeeded");
                }
                return Ok(value);
            }
            Err(err) if err.is_sqlite_busy() && attempt < MAX_BUSY_RETRY_ATTEMPTS => {
                tracing::debug!(
                    operation = name,
                    attempt,
                    delay_ms = delay.as_millis() as u64,
                    "db busy, retrying"
                );
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(MAX_DELAY);
            }
            Err(err) => return Err(err),
        }
    }
    unreachable!("loop returns or errors before exhausting attempts")
}
