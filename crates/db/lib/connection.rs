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

use crate::{pool, retry, retry::IsSqliteBusy};

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
pub struct DbReadConnection(DatabaseConnection);

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
pub struct DbWriteConnection(DatabaseConnection);

impl DbReadConnection {
    /// Wrap a sea-orm connection as a read pool.
    pub fn new(inner: DatabaseConnection) -> Self {
        Self(inner)
    }

    /// Open a stand-alone read pool at `db_path` with shared PRAGMAs.
    pub async fn open(
        db_path: &Path,
        max_connections: u32,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> Result<Self, sqlx::Error> {
        let conn =
            pool::build_pool(db_path, max_connections, connect_timeout, busy_timeout).await?;
        Ok(Self(conn))
    }

    /// Borrow the underlying sea-orm connection.
    pub fn inner(&self) -> &DatabaseConnection {
        &self.0
    }
}

impl DbWriteConnection {
    /// Wrap a sea-orm connection as a write pool.
    pub fn new(inner: DatabaseConnection) -> Self {
        Self(inner)
    }

    /// Open a stand-alone single-connection write pool at `db_path`.
    ///
    /// Used by callers that don't need a paired read pool (e.g. the in-VM
    /// runtime, which only writes run records).
    pub async fn open(
        db_path: &Path,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> Result<Self, sqlx::Error> {
        let conn = pool::build_pool(db_path, 1, connect_timeout, busy_timeout).await?;
        Ok(Self(conn))
    }

    /// Borrow the underlying sea-orm connection.
    pub fn inner(&self) -> &DatabaseConnection {
        &self.0
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
        retry::retry_on_busy(|| async {
            let txn = self.0.begin().await?;
            let (txn, value) = f(txn).await?;
            txn.commit().await?;
            Ok(value)
        })
        .await
    }
}

#[async_trait::async_trait]
impl ConnectionTrait for DbReadConnection {
    fn get_database_backend(&self) -> DbBackend {
        self.0.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        self.0.execute(stmt).await
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        self.0.execute_unprepared(sql).await
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.0.query_one(stmt).await
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        self.0.query_all(stmt).await
    }

    fn support_returning(&self) -> bool {
        self.0.support_returning()
    }

    fn is_mock_connection(&self) -> bool {
        self.0.is_mock_connection()
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
        self.0.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        retry::retry_on_busy(|| async { self.0.execute(stmt.clone()).await }).await
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        retry::retry_on_busy(|| async { self.0.execute_unprepared(sql).await }).await
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        retry::retry_on_busy(|| async { self.0.query_one(stmt.clone()).await }).await
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        retry::retry_on_busy(|| async { self.0.query_all(stmt.clone()).await }).await
    }

    fn support_returning(&self) -> bool {
        self.0.support_returning()
    }

    fn is_mock_connection(&self) -> bool {
        self.0.is_mock_connection()
    }
}
