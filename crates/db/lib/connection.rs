//! Typed wrappers around `sea_orm::DatabaseConnection`.
//!
//! Splits a connection into [`DbReadConnection`] and [`DbWriteConnection`]
//! so the type system enforces which pool a given operation hits. SQLite is
//! single-writer system-wide; routing every write through a dedicated
//! single-connection write pool turns intra-process contention into an
//! in-process queue rather than `SQLITE_BUSY` retries.
//!
//! Both types implement [`sea_orm::ConnectionTrait`], so existing query
//! builders (`Entity::find().all(db)`, `Entity::insert(...).exec(db)`, etc.)
//! work without source changes — callers just pick the right type for the
//! operation.

use std::{future::Future, path::Path, time::Duration};

use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, DbErr, ExecResult,
    QueryResult, Statement, TransactionTrait,
};
use sqlx::SqlitePool;

use crate::{DbTarget, pool, retry, retry::IsSqliteBusy, stats::DbStats, target::TargetKind};

/// Read pool. Multi-connection; concurrent reads enabled by WAL mode.
///
/// `ConnectionTrait` is implemented so SELECTs work transparently. Writes
/// also technically execute (sea-orm has no read-only enforcement at the
/// trait level), but doing so via this type defeats the purpose — write
/// paths must take a [`DbWriteConnection`] argument.
///
/// `Clone` is cheap: the inner `DatabaseConnection` holds an `Arc` over
/// the underlying sqlx pool, so clones share connection state.
#[derive(Debug, Clone)]
pub struct DbReadConnection {
    inner: DatabaseConnection,
    pool: Option<SqlitePool>,
    stats: DbStats,
}

/// Write pool. Single connection; serialises in-process writes so the
/// SQLite writer lock is never contested from within one process.
///
/// Cross-process contention with other writers (e.g. the in-VM runtime)
/// still exists and is absorbed by the `busy_timeout` PRAGMA + the
/// retry-on-busy transaction helpers (added in a follow-up step).
///
/// `Clone` is cheap: the inner `DatabaseConnection` holds an `Arc` over
/// the underlying sqlx pool, so clones share the same single connection.
#[derive(Debug, Clone)]
pub struct DbWriteConnection {
    inner: DatabaseConnection,
    pool: Option<SqlitePool>,
    stats: DbStats,
}

/// How long a single remote database request may run, derived from the
/// busy timeout so server-side lock waits fit inside the request bound.
fn remote_request_timeout(busy_timeout: Duration) -> Duration {
    busy_timeout.max(Duration::from_secs(crate::pool::DEFAULT_BUSY_TIMEOUT_SECS)) * 6
}

/// When `err` is a pool-acquisition timeout: count it, log the pool's live
/// occupancy, and rewrite the message to name the pool that was exhausted.
/// Every other error (including `SQLITE_BUSY`) passes through untouched so
/// busy classification keeps working.
fn note_pool_timeout(
    err: DbErr,
    kind: &'static str,
    pool: Option<&SqlitePool>,
    stats: &DbStats,
) -> DbErr {
    if !retry::is_pool_timeout(&err) {
        return err;
    }
    stats.record_pool_timeout();
    match pool {
        Some(pool) => {
            let (size, idle) = (pool.size(), pool.num_idle());
            tracing::warn!(
                pool = kind,
                connections = size,
                idle,
                "db pool acquisition timed out"
            );
            DbErr::Custom(format!(
                "{kind} pool exhausted ({size} connections, {idle} idle): {err}"
            ))
        }
        None => {
            tracing::warn!(pool = kind, "db pool acquisition timed out");
            DbErr::Custom(format!("{kind} pool exhausted: {err}"))
        }
    }
}

impl DbReadConnection {
    /// Wrap a sea-orm connection as a read pool.
    pub fn new(inner: DatabaseConnection) -> Self {
        Self {
            inner,
            pool: None,
            stats: DbStats::new(),
        }
    }

    /// Open a stand-alone read pool for a database target — a SQLite file
    /// path (bare or `sqlite://`), or a `libsql://` server URL.
    ///
    /// The file backend is read-only: opening a non-existent DB fails rather
    /// than creating it, so a read consumer never authors or pre-empts the
    /// database owned by `msb`. On a server target, `max_connections` bounds
    /// concurrent in-flight reads and `connect_timeout` bounds admission.
    pub async fn open(
        target: impl Into<DbTarget>,
        max_connections: u32,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> Result<Self, DbErr> {
        match target.into().kind() {
            TargetKind::File(path) => {
                Self::open_file(path, max_connections, connect_timeout, busy_timeout).await
            }
            TargetKind::Remote(url) => {
                Self::open_remote(url, max_connections, connect_timeout, busy_timeout).await
            }
            TargetKind::Unsupported(raw) => Err(crate::unsupported_target(raw)),
        }
    }

    /// Open the read side of the file backend at `db_path`.
    async fn open_file(
        db_path: &Path,
        max_connections: u32,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> Result<Self, DbErr> {
        let (inner, pool) = pool::build_pool(
            db_path,
            max_connections,
            connect_timeout,
            busy_timeout,
            false,
        )
        .await
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::SqlxError(e)))?;
        Ok(Self {
            inner,
            pool: Some(pool),
            stats: DbStats::new(),
        })
    }

    /// Open the read side of the remote backend at the normalized `url`.
    async fn open_remote(
        url: &str,
        max_connections: u32,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> Result<Self, DbErr> {
        let request_timeout = remote_request_timeout(busy_timeout);
        let inner =
            crate::remote::open_read(url, max_connections, connect_timeout, request_timeout)
                .await?;
        Ok(Self {
            inner,
            pool: None,
            stats: DbStats::new(),
        })
    }

    /// Borrow the underlying sea-orm connection.
    pub fn inner(&self) -> &DatabaseConnection {
        &self.inner
    }

    /// Counters recorded by this connection (shared across clones).
    pub fn stats(&self) -> &DbStats {
        &self.stats
    }
}

impl DbWriteConnection {
    /// Wrap a sea-orm connection as a write pool.
    pub fn new(inner: DatabaseConnection) -> Self {
        Self {
            inner,
            pool: None,
            stats: DbStats::new(),
        }
    }

    /// Open a stand-alone single-connection write pool for a database target —
    /// a SQLite file path (bare or `sqlite://`), or a `libsql://` server URL.
    ///
    /// Used by callers that don't need a paired read pool (e.g. the in-VM
    /// runtime, which only writes run records). Single-connection on both
    /// backends; on a server target `connect_timeout` bounds admission waits
    /// and `busy_timeout` derives the per-request bound.
    pub async fn open(
        target: impl Into<DbTarget>,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> Result<Self, DbErr> {
        match target.into().kind() {
            TargetKind::File(path) => Self::open_file(path, connect_timeout, busy_timeout).await,
            TargetKind::Remote(url) => Self::open_remote(url, connect_timeout, busy_timeout).await,
            TargetKind::Unsupported(raw) => Err(crate::unsupported_target(raw)),
        }
    }

    /// Open the write side of the file backend at `db_path`.
    async fn open_file(
        db_path: &Path,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> Result<Self, DbErr> {
        let (inner, pool) = pool::build_pool(db_path, 1, connect_timeout, busy_timeout, true)
            .await
            .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::SqlxError(e)))?;
        Ok(Self {
            inner,
            pool: Some(pool),
            stats: DbStats::new(),
        })
    }

    /// Open the write side of the remote backend at the normalized `url`.
    async fn open_remote(
        url: &str,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> Result<Self, DbErr> {
        let request_timeout = remote_request_timeout(busy_timeout);
        let inner = crate::remote::open_write(url, connect_timeout, request_timeout).await?;
        Ok(Self {
            inner,
            pool: None,
            stats: DbStats::new(),
        })
    }

    /// Borrow the underlying sea-orm connection.
    pub fn inner(&self) -> &DatabaseConnection {
        &self.inner
    }

    /// Counters recorded by this connection (shared across clones).
    pub fn stats(&self) -> &DbStats {
        &self.stats
    }

    /// Run a multi-statement atomic write inside a transaction with
    /// automatic retry on `SQLITE_BUSY` / `SQLITE_BUSY_SNAPSHOT`. Use this
    /// when you need several writes to commit (or roll back) as a unit.
    /// Single-statement writes don't need this — auto-commit `.exec(db)`
    /// already retries via the `ConnectionTrait` impl below.
    ///
    /// `f` is invoked once per attempt with a freshly opened transaction.
    /// Return `Ok((txn, value))` to commit, or any `Err` to roll back (the
    /// helper drops the transaction on failure, which sea-orm rolls back).
    /// The closure must be callable multiple times: clone owned data inside
    /// the body so retries see fresh values.
    ///
    /// Generic over the closure's error type `E` so callers can return
    /// app-level errors directly (e.g. `MicrosandboxError`) provided
    /// `E: From<DbErr> + IsSqliteBusy`.
    pub async fn transaction<F, Fut, T, E>(&self, f: F) -> Result<T, E>
    where
        F: Fn(DatabaseTransaction) -> Fut,
        Fut: Future<Output = Result<(DatabaseTransaction, T), E>> + Send,
        T: Send,
        E: From<DbErr> + IsSqliteBusy,
    {
        if matches!(
            self.inner,
            sea_orm::DatabaseConnection::ProxyDatabaseConnection(_)
        ) {
            return self.remote_transaction(f).await;
        }

        retry::retry_on_busy_with_stats(
            || async {
                let txn = self.inner.begin().await?;
                let (txn, value) = f(txn).await?;
                txn.commit().await?;
                Ok(value)
            },
            Some(&self.stats),
        )
        .await
    }

    /// Transaction path for the remote backend.
    ///
    /// sea-orm's proxy transaction hooks cannot return errors, so a hook-run
    /// COMMIT could fail silently and report a non-durable write as
    /// committed. BEGIN/COMMIT/ROLLBACK therefore run as ordinary statements
    /// here — their failures propagate — while the admission permit is held
    /// across the whole transaction so no other writer interleaves.
    async fn remote_transaction<F, Fut, T, E>(&self, f: F) -> Result<T, E>
    where
        F: Fn(DatabaseTransaction) -> Fut,
        Fut: Future<Output = Result<(DatabaseTransaction, T), E>> + Send,
        T: Send,
        E: From<DbErr> + IsSqliteBusy,
    {
        retry::retry_on_busy_with_stats(
            || async {
                self.inner
                    .execute_unprepared("BEGIN IMMEDIATE")
                    .await
                    .map_err(E::from)?;

                let txn = self.inner.begin().await.map_err(E::from)?;
                match f(txn).await {
                    Ok((txn, value)) => {
                        txn.commit().await.map_err(E::from)?;
                        if let Err(err) = self.inner.execute_unprepared("COMMIT").await {
                            let _ = self.inner.execute_unprepared("ROLLBACK").await;
                            return Err(E::from(err));
                        }
                        Ok(value)
                    }
                    Err(err) => {
                        let _ = self.inner.execute_unprepared("ROLLBACK").await;
                        Err(err)
                    }
                }
            },
            Some(&self.stats),
        )
        .await
    }
}

#[async_trait::async_trait]
impl ConnectionTrait for DbReadConnection {
    fn get_database_backend(&self) -> DbBackend {
        self.inner.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        self.inner
            .execute(stmt)
            .await
            .map_err(|e| note_pool_timeout(e, "read", self.pool.as_ref(), &self.stats))
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        self.inner
            .execute_unprepared(sql)
            .await
            .map_err(|e| note_pool_timeout(e, "read", self.pool.as_ref(), &self.stats))
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.inner
            .query_one(stmt)
            .await
            .map_err(|e| note_pool_timeout(e, "read", self.pool.as_ref(), &self.stats))
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        self.inner
            .query_all(stmt)
            .await
            .map_err(|e| note_pool_timeout(e, "read", self.pool.as_ref(), &self.stats))
    }

    fn support_returning(&self) -> bool {
        self.inner.support_returning()
    }

    fn is_mock_connection(&self) -> bool {
        self.inner.is_mock_connection()
    }
}

// Auto-retry every auto-commit operation on the writer pool. Sea-orm
// callers (`Entity::insert(...).exec(db)` etc.) ultimately funnel through
// these `ConnectionTrait` methods, so wrapping them in `retry_on_busy`
// gives every single-statement write inter-process retry semantics
// without per-call-site code.
//
// `Statement` is `Clone`, so the closure can produce a fresh future on
// each retry. Multi-statement atomic work still uses `transaction()`
// above (which retries the whole closure body); statements *inside* a
// transaction call `ConnectionTrait` methods on `DatabaseTransaction`,
// not on this type, so no double-retry occurs.
#[async_trait::async_trait]
impl ConnectionTrait for DbWriteConnection {
    fn get_database_backend(&self) -> DbBackend {
        self.inner.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        retry::retry_on_busy_with_stats(
            || async { self.inner.execute(stmt.clone()).await },
            Some(&self.stats),
        )
        .await
        .map_err(|e| note_pool_timeout(e, "write", self.pool.as_ref(), &self.stats))
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        retry::retry_on_busy_with_stats(
            || async { self.inner.execute_unprepared(sql).await },
            Some(&self.stats),
        )
        .await
        .map_err(|e| note_pool_timeout(e, "write", self.pool.as_ref(), &self.stats))
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        retry::retry_on_busy_with_stats(
            || async { self.inner.query_one(stmt.clone()).await },
            Some(&self.stats),
        )
        .await
        .map_err(|e| note_pool_timeout(e, "write", self.pool.as_ref(), &self.stats))
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        retry::retry_on_busy_with_stats(
            || async { self.inner.query_all(stmt.clone()).await },
            Some(&self.stats),
        )
        .await
        .map_err(|e| note_pool_timeout(e, "write", self.pool.as_ref(), &self.stats))
    }

    fn support_returning(&self) -> bool {
        self.inner.support_returning()
    }

    fn is_mock_connection(&self) -> bool {
        self.inner.is_mock_connection()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn write_open_accepts_bare_string_paths() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");

        let target = db_path.to_string_lossy().into_owned();
        DbWriteConnection::open(&target, TIMEOUT, TIMEOUT)
            .await
            .unwrap();
        assert!(db_path.exists());
    }

    #[tokio::test]
    async fn write_open_accepts_sqlite_scheme_targets() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");

        let target = format!("sqlite://{}", db_path.display());
        DbWriteConnection::open(&target, TIMEOUT, TIMEOUT)
            .await
            .unwrap();
        assert!(db_path.exists());
    }

    #[tokio::test]
    async fn open_unknown_scheme_is_a_clear_error() {
        let err = DbWriteConnection::open("postgres://127.0.0.1:5432/db", TIMEOUT, TIMEOUT)
            .await
            .unwrap_err();
        assert!(
            err.to_string().contains("not a supported database target"),
            "got: {err}"
        );
    }

    // A remote target must reach the connect path (and fail there when
    // nothing listens), not die in parsing.
    #[tokio::test]
    async fn open_libsql_url_dispatches_to_the_remote_backend() {
        let err = DbWriteConnection::open(
            "libsql://127.0.0.1:9",
            Duration::from_millis(300),
            Duration::from_millis(300),
        )
        .await
        .unwrap_err();
        let message = err.to_string();
        assert!(
            !message.contains("not a supported database target"),
            "libsql target must not be rejected as unsupported: {message}"
        );
        assert!(
            !message.contains("`libsql` feature"),
            "libsql target must not hit the missing-feature error: {message}"
        );
    }

    #[tokio::test]
    async fn read_open_does_not_create_db() {
        // Existing directory, missing DB file.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");

        let result = DbReadConnection::open(&db_path, 1, TIMEOUT, TIMEOUT).await;

        assert!(result.is_err(), "read open should fail on a missing db");
        assert!(
            !db_path.exists(),
            "read open must not create the catalog db file"
        );
    }

    #[tokio::test]
    async fn write_open_creates_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");

        let conn = DbWriteConnection::open(&db_path, TIMEOUT, TIMEOUT).await;

        assert!(conn.is_ok(), "write open should succeed");
        assert!(
            db_path.exists(),
            "write open should create the catalog db file"
        );
    }

    #[tokio::test]
    async fn pool_timeout_is_attributed_and_counted() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");

        // Single-connection write pool with a short acquire timeout.
        let conn = DbWriteConnection::open(&db_path, Duration::from_millis(100), TIMEOUT)
            .await
            .unwrap();

        // Hold the only connection so the next operation must time out
        // acquiring from the pool.
        let _txn = conn.inner().begin().await.unwrap();

        let err = conn.execute_unprepared("SELECT 1").await.unwrap_err();

        assert!(
            err.to_string().contains("write pool exhausted"),
            "error should name the exhausted pool, got: {err}"
        );
        assert!(
            !retry::is_sqlite_busy(&err),
            "an attributed pool timeout must not classify as SQLITE_BUSY"
        );
        assert_eq!(conn.stats().snapshot().pool_timeouts, 1);
        assert_eq!(conn.stats().snapshot().busy_retries, 0);
    }

    #[tokio::test]
    async fn sqlite_busy_passes_through_unchanged() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");

        let a = DbWriteConnection::open(&db_path, TIMEOUT, Duration::from_millis(10))
            .await
            .unwrap();
        let b = DbWriteConnection::open(&db_path, TIMEOUT, Duration::from_millis(10))
            .await
            .unwrap();

        // Hold the SQLite writer lock from `a` via an open transaction.
        let txn = a.inner().begin().await.unwrap();
        txn.execute_unprepared("CREATE TABLE held (x INTEGER)")
            .await
            .unwrap();

        // Bypass the retry wrapper so we see the raw error `b` gets.
        let err = b
            .inner()
            .execute_unprepared("CREATE TABLE blocked (x INTEGER)")
            .await
            .unwrap_err();

        assert!(
            retry::is_sqlite_busy(&err),
            "contended write should classify as SQLITE_BUSY, got: {err}"
        );
        assert!(
            !retry::is_pool_timeout(&err),
            "SQLITE_BUSY must not classify as a pool timeout"
        );
    }
}
