//! Single database handle with engine-enforced read/write separation.
//!
//! [`DbConnection`] wraps two lanes over the same SQLite file:
//!
//! - a multi-connection **read pool** opened with `SQLITE_OPEN_READONLY`, so
//!   the engine itself rejects any write that slips onto the read lane;
//! - a **single write connection** (a 1-connection sqlx pool), so all writes
//!   from one process serialize at pool checkout instead of contending for
//!   SQLite's writer lock.
//!
//! `DbConnection` implements [`sea_orm::ConnectionTrait`] over the read lane only, so
//! existing query builders (`Entity::find().all(&db)` etc.) keep working for
//! reads. Writes run directly on the write connection via [`DbConnection::inner`]
//! (`stmt.exec(db.inner()?)`), and multi-statement atomic work goes through
//! [`DbConnection::transaction`].
//!
//! Cross-process contention with other writers (e.g. the in-VM runtime)
//! still exists and is absorbed by the `busy_timeout` PRAGMA plus the
//! retry-on-busy helpers in [`crate::retry`].

use std::{future::Future, path::Path, time::Duration};

use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseTransaction, DbBackend, DbErr, ExecResult,
    QueryResult, Statement, TransactionTrait,
};

use crate::{pool, retry, retry::IsSqliteBusy};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One handle to the database: a read-only pool for queries plus an
/// optional single write connection.
///
/// Open with [`DbConnection::open`] (full read/write handle; creates the file) or
/// [`DbConnection::open_observer`] (read-only pool only; [`DbConnection::inner`] and
/// [`DbConnection::transaction`] fail with a clear error).
///
/// `Clone` is cheap: connections hold `Arc`s over the underlying sqlx pools,
/// so cloned handles share the same connections.
#[derive(Debug, Clone)]
pub struct DbConnection {
    /// Multi-connection pool opened read-only; the engine rejects writes here.
    read: DatabaseConnection,

    /// Single-connection write pool (`None` for observer handles); concurrent
    /// statements and transactions serialize at pool checkout.
    write: Option<DatabaseConnection>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DbConnection {
    /// Open a full read/write handle for the SQLite file at `db_path`.
    ///
    /// The write connection opens first (creating the file and establishing
    /// WAL mode, which persists in the database header) so the read-only pool
    /// always opens an existing WAL database. `max_read_connections` sizes
    /// only the read pool; the write side is always a single connection.
    ///
    /// Does not run migrations — callers own schema management (via
    /// [`DbConnection::inner`]).
    pub async fn open(
        db_path: &Path,
        max_read_connections: u32,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> Result<Self, sqlx::Error> {
        let write = pool::build_write_pool(db_path, connect_timeout, busy_timeout).await?;
        let read =
            pool::build_read_pool(db_path, max_read_connections, connect_timeout, busy_timeout)
                .await?;

        Ok(Self {
            read,
            write: Some(write),
        })
    }

    /// Open a read-only observer handle: a read pool and no write connection.
    ///
    /// Fails if the database file does not exist (a read-only open never
    /// creates or pre-empts the database owned by `msb`); callers that expect
    /// the file to appear later retry lazily. [`DbConnection::inner`] and
    /// [`DbConnection::transaction`] on an observer return a clear [`DbErr`] instead of
    /// touching the database.
    pub async fn open_observer(
        db_path: &Path,
        max_read_connections: u32,
        connect_timeout: Duration,
        busy_timeout: Duration,
    ) -> Result<Self, sqlx::Error> {
        let read =
            pool::build_read_pool(db_path, max_read_connections, connect_timeout, busy_timeout)
                .await?;

        Ok(Self { read, write: None })
    }

    /// Borrow the raw single write connection, or fail with a clear error on
    /// observer handles.
    pub fn inner(&self) -> Result<&DatabaseConnection, DbErr> {
        self.write.as_ref().ok_or_else(|| {
            DbErr::Custom("read-only database handle: opened as observer".to_string())
        })
    }

    /// Run a multi-statement atomic write inside a transaction on the write
    /// connection with automatic retry on `SQLITE_BUSY` /
    /// `SQLITE_BUSY_SNAPSHOT`. Use this when you need several writes to
    /// commit (or roll back) as a unit.
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
        let write = self.inner().map_err(E::from)?;

        retry::retry_on_busy(|| async {
            let txn = write.begin().await?;
            let (txn, value) = f(txn).await?;
            txn.commit().await?;
            Ok(value)
        })
        .await
    }

    /// Close both lanes, waiting for the underlying pools to shut down.
    ///
    /// Useful when a caller must observe SQLite's on-close behavior
    /// deterministically (e.g. WAL sidecar removal) instead of relying on
    /// drop-time cleanup.
    pub async fn close(self) -> Result<(), DbErr> {
        if let Some(write) = self.write {
            write.close().await?;
        }
        self.read.close().await
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

// The `ConnectionTrait` impl delegates to the read lane ONLY. The read pool
// is opened with `SQLITE_OPEN_READONLY`, so a write routed through this impl
// fails in the engine rather than silently landing on the wrong lane.
#[async_trait::async_trait]
impl ConnectionTrait for DbConnection {
    fn get_database_backend(&self) -> DbBackend {
        self.read.get_database_backend()
    }

    async fn execute(&self, stmt: Statement) -> Result<ExecResult, DbErr> {
        self.read.execute(stmt).await
    }

    async fn execute_unprepared(&self, sql: &str) -> Result<ExecResult, DbErr> {
        self.read.execute_unprepared(sql).await
    }

    async fn query_one(&self, stmt: Statement) -> Result<Option<QueryResult>, DbErr> {
        self.read.query_one(stmt).await
    }

    async fn query_all(&self, stmt: Statement) -> Result<Vec<QueryResult>, DbErr> {
        self.read.query_all(stmt).await
    }

    fn support_returning(&self) -> bool {
        self.read.support_returning()
    }

    fn is_mock_connection(&self) -> bool {
        self.read.is_mock_connection()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm::DatabaseBackend;

    use super::*;

    const TIMEOUT: Duration = Duration::from_secs(5);

    async fn open_db(db_path: &Path) -> DbConnection {
        DbConnection::open(db_path, 2, TIMEOUT, TIMEOUT)
            .await
            .unwrap()
    }

    fn select_count() -> Statement {
        Statement::from_string(DatabaseBackend::Sqlite, "SELECT COUNT(*) FROM t")
    }

    async fn count_rows(db: &DbConnection) -> i64 {
        db.query_one(select_count())
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<i64>(0)
            .unwrap()
    }

    #[tokio::test]
    async fn read_open_does_not_create_db() {
        // Existing directory, missing DB file.
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");

        let result = DbConnection::open_observer(&db_path, 1, TIMEOUT, TIMEOUT).await;

        assert!(result.is_err(), "observer open should fail on a missing db");
        assert!(
            !db_path.exists(),
            "observer open must not create the db file"
        );
    }

    #[tokio::test]
    async fn write_open_creates_db() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");

        let db = DbConnection::open(&db_path, 1, TIMEOUT, TIMEOUT).await;

        assert!(db.is_ok(), "open should succeed");
        assert!(db_path.exists(), "open should create the db file");
    }

    #[tokio::test]
    async fn read_lane_rejects_writes_in_the_engine() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(&dir.path().join("msb.db")).await;
        db.inner()
            .unwrap()
            .execute_unprepared("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
            .await
            .unwrap();

        // An INSERT routed through the ConnectionTrait impl hits the
        // read-only pool and must be rejected by SQLite itself.
        let err = ConnectionTrait::execute(
            &db,
            Statement::from_string(DatabaseBackend::Sqlite, "INSERT INTO t (v) VALUES ('x')"),
        )
        .await
        .unwrap_err();

        assert!(
            err.to_string().contains("readonly"),
            "expected a SQLITE_READONLY error, got: {err}"
        );
        assert_eq!(count_rows(&db).await, 0, "the write must not land");
    }

    #[tokio::test]
    async fn observer_reads_work_and_write_paths_fail_clearly() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");
        let owner = open_db(&db_path).await;
        let owner_conn = owner.inner().unwrap();
        owner_conn
            .execute_unprepared("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
            .await
            .unwrap();
        owner_conn
            .execute_unprepared("INSERT INTO t (v) VALUES ('seeded')")
            .await
            .unwrap();

        let observer = DbConnection::open_observer(&db_path, 1, TIMEOUT, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(count_rows(&observer).await, 1, "observer reads must work");

        let inner_err = observer.inner().unwrap_err();
        let txn_err = observer
            .transaction::<_, _, (), DbErr>(|txn| async move { Ok((txn, ())) })
            .await
            .unwrap_err();

        for err in [inner_err, txn_err] {
            assert!(
                err.to_string().contains("opened as observer"),
                "expected the observer capability error, got: {err}"
            );
        }
    }

    #[tokio::test]
    async fn write_waits_for_in_flight_transaction() {
        let dir = tempfile::tempdir().unwrap();
        let db = open_db(&dir.path().join("msb.db")).await;
        db.inner()
            .unwrap()
            .execute_unprepared("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
            .await
            .unwrap();

        // Channels let the test hold a transaction open at a known point.
        // They live in Option cells because the transaction closure is `Fn`
        // (retriable); the single successful attempt takes them out.
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel::<()>();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel::<()>();
        let entered_tx = std::sync::Mutex::new(Some(entered_tx));
        let release_rx = std::sync::Mutex::new(Some(release_rx));

        let txn_db = db.clone();
        let txn_task = tokio::spawn(async move {
            txn_db
                .transaction::<_, _, (), DbErr>(|txn| {
                    let entered_tx = entered_tx.lock().unwrap().take().unwrap();
                    let release_rx = release_rx.lock().unwrap().take().unwrap();
                    async move {
                        txn.execute_unprepared("INSERT INTO t (v) VALUES ('txn')")
                            .await?;
                        entered_tx.send(()).unwrap();
                        release_rx.await.unwrap();
                        Ok((txn, ()))
                    }
                })
                .await
        });

        // Wait until the transaction is provably in flight, then race a
        // single-statement write against it.
        entered_rx.await.unwrap();
        let write_db = db.clone();
        let mut write_task = tokio::spawn(async move {
            write_db
                .inner()?
                .execute(Statement::from_string(
                    DatabaseBackend::Sqlite,
                    "INSERT INTO t (v) VALUES ('write')",
                ))
                .await
        });

        // The transaction owns the single pooled write connection, so the
        // statement must park at pool checkout until the transaction commits.
        let parked = tokio::time::timeout(Duration::from_millis(200), &mut write_task).await;
        assert!(
            parked.is_err(),
            "the write must wait for the in-flight transaction, not interleave"
        );

        release_tx.send(()).unwrap();
        txn_task.await.unwrap().unwrap();
        write_task.await.unwrap().unwrap();
        assert_eq!(count_rows(&db).await, 2, "both writes must land in order");
    }

    #[tokio::test]
    async fn observer_reads_while_owner_holds_the_file_open() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");
        let owner = open_db(&db_path).await;
        let owner_conn = owner.inner().unwrap();
        owner_conn
            .execute_unprepared("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
            .await
            .unwrap();
        owner_conn
            .execute_unprepared("INSERT INTO t (v) VALUES ('live')")
            .await
            .unwrap();

        // WAL sidecars exist while the owner is open; a read-only open must
        // still attach and see committed data.
        let observer = DbConnection::open_observer(&db_path, 1, TIMEOUT, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(count_rows(&observer).await, 1);
    }

    #[tokio::test]
    async fn observer_reopens_after_wal_sidecars_are_removed() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("msb.db");
        let owner = open_db(&db_path).await;
        let owner_conn = owner.inner().unwrap();
        owner_conn
            .execute_unprepared("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
            .await
            .unwrap();
        owner_conn
            .execute_unprepared("INSERT INTO t (v) VALUES ('persisted')")
            .await
            .unwrap();

        // Closing the last connection makes SQLite checkpoint and delete the
        // `-wal` / `-shm` sidecars.
        owner.close().await.unwrap();
        assert!(
            !db_path.with_extension("db-wal").exists(),
            "closing the owner should remove the WAL sidecar"
        );

        // A read-only reopen in a writable directory recreates the sidecars
        // and reads the checkpointed data.
        let observer = DbConnection::open_observer(&db_path, 1, TIMEOUT, TIMEOUT)
            .await
            .unwrap();
        assert_eq!(count_rows(&observer).await, 1);
    }
}
