//! sea-orm proxy backends over a remote libSQL server connection.

use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use sea_orm::{
    ConnAcquireErr, DbErr, ProxyDatabaseTrait, ProxyExecResult, ProxyRow, RuntimeErr, Statement,
};
use tokio::sync::{Mutex, OwnedSemaphorePermit, Semaphore};
use tokio::time::timeout;

use crate::convert::{self, ColumnKind};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Prefix marking a server-reported SQLite busy condition; the retry layer
/// classifies on it (see `microsandbox_db::retry::is_sqlite_busy`).
pub const BUSY_SENTINEL: &str = "SQLITE_BUSY";

/// Server messages meaning a request was rejected because its hrana stream
/// no longer exists — typically after a server restart.
const STREAM_DEAD_MARKERS: &[&str] = &[
    "invalid baton",
    "stream closed",
    "stream not found",
    "stream expired",
];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Write-side proxy: one server connection, self-managed admission.
///
/// Acquires the single-writer permit when a `BEGIN`/`BEGIN IMMEDIATE`
/// statement passes through `execute`, and releases it on `COMMIT`/
/// `ROLLBACK`. Mid-transaction statements pass through without re-acquiring,
/// eliminating the need for a `WriteControl` handle passed to callers.
pub(crate) struct WriteProxy {
    database: libsql::Database,
    conn: Mutex<libsql::Connection>,
    admission: Arc<Semaphore>,
    acquire_timeout: Duration,
    request_timeout: Duration,
    stale: AtomicBool,
    /// Whether a transaction is currently open (permit held).
    in_transaction: AtomicBool,
    /// The held admission permit while a transaction is in progress.
    ///
    /// Uses a std mutex (not tokio) so it can be locked synchronously
    /// from `start_rollback`, which sea-orm calls from `Drop`.
    permit: std::sync::Mutex<Option<OwnedSemaphorePermit>>,
    /// Dirty flag: an abandoned transaction needs a defensive ROLLBACK on
    /// the next checkout.
    dirty: Arc<AtomicBool>,
    column_kinds: Arc<HashMap<String, ColumnKind>>,
}

/// Read-side proxy: a fixed set of server connections handed out under a
/// semaphore sized to match.
pub(crate) struct ReadProxy {
    database: libsql::Database,
    conns: Mutex<Vec<libsql::Connection>>,
    admission: Arc<Semaphore>,
    acquire_timeout: Duration,
    request_timeout: Duration,
    column_kinds: Arc<HashMap<String, ColumnKind>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WriteProxy {
    /// Build a write proxy over one server connection.
    pub(crate) fn new(
        database: libsql::Database,
        conn: libsql::Connection,
        acquire_timeout: Duration,
        request_timeout: Duration,
        column_kinds: Arc<HashMap<String, ColumnKind>>,
    ) -> Self {
        Self {
            database,
            conn: Mutex::new(conn),
            admission: Arc::new(Semaphore::new(1)),
            acquire_timeout,
            request_timeout,
            stale: AtomicBool::new(false),
            in_transaction: AtomicBool::new(false),
            permit: std::sync::Mutex::new(None),
            dirty: Arc::new(AtomicBool::new(false)),
            column_kinds,
        }
    }

    /// Run `op` on the write connection.
    ///
    /// Inside a transaction the permit is already held; outside, no admission
    /// is checked for individual statements (only BEGIN acquires). A connection
    /// whose server stream died is replaced with a fresh one on the next checkout.
    async fn with_conn<T, F, Fut>(&self, op_name: &'static str, op: F) -> Result<T, DbErr>
    where
        F: Fn(libsql::Connection) -> Fut,
        Fut: Future<Output = Result<T, libsql::Error>>,
    {
        let conn = {
            let mut guard = self.conn.lock().await;

            if self.stale.swap(false, Ordering::AcqRel) {
                *guard = self.database.connect().map_err(reconnect_err)?;
            }

            if self.dirty.swap(false, Ordering::AcqRel) {
                let _ = guard.execute("ROLLBACK", ()).await;
            }

            guard.clone()
        };

        let result = bounded(op_name, self.request_timeout, op(conn)).await;

        let Err(err) = &result else { return result };
        if !is_stream_dead_db(err) {
            return result;
        }

        if self.in_transaction.load(Ordering::Acquire) {
            // Stream died mid-transaction — poison: mark stale + dirty so
            // the next checkout reconnects and rolls back. Tag as busy so
            // the retry layer retries the whole transaction on a fresh conn.
            self.stale.store(true, Ordering::Release);
            self.dirty.store(true, Ordering::Release);
            self.in_transaction.store(false, Ordering::Release);
            // Release the permit so the retry attempt can re-acquire.
            *self.permit.lock().expect("permit mutex poisoned") = None;
            return Err(DbErr::Exec(RuntimeErr::Internal(format!(
                "{BUSY_SENTINEL}: db stream reset mid-transaction \
                 (server restarted); transaction rolled back"
            ))));
        }

        let fresh = self.database.connect().map_err(reconnect_err)?;
        *self.conn.lock().await = fresh.clone();
        bounded(op_name, self.request_timeout, op(fresh)).await
    }

    /// Whether `sql` starts a transaction (needs admission acquisition).
    fn is_begin(sql: &str) -> bool {
        let s = sql.trim().to_ascii_uppercase();
        s == "BEGIN" || s == "BEGIN IMMEDIATE" || s.starts_with("BEGIN ")
    }

    /// Whether `sql` ends a transaction (releases admission permit).
    fn is_end(sql: &str) -> bool {
        let s = sql.trim().to_ascii_uppercase();
        s == "COMMIT" || s == "ROLLBACK" || s.starts_with("COMMIT ") || s.starts_with("ROLLBACK ")
    }
}

impl ReadProxy {
    /// Build a read proxy over a fixed set of server connections.
    pub(crate) fn new(
        database: libsql::Database,
        conns: Vec<libsql::Connection>,
        acquire_timeout: Duration,
        request_timeout: Duration,
        column_kinds: Arc<HashMap<String, ColumnKind>>,
    ) -> Self {
        let admission = Arc::new(Semaphore::new(conns.len()));
        Self {
            database,
            conns: Mutex::new(conns),
            admission,
            acquire_timeout,
            request_timeout,
            column_kinds,
        }
    }

    /// Run `op` on a checked-out read connection.
    async fn with_conn<T, F, Fut>(&self, op_name: &'static str, op: F) -> Result<T, DbErr>
    where
        F: Fn(libsql::Connection) -> Fut,
        Fut: Future<Output = Result<T, libsql::Error>>,
    {
        let _permit = acquire(&self.admission, self.acquire_timeout).await?;

        let mut conn = {
            let mut conns = self.conns.lock().await;
            conns.pop().expect("read connection available per permit")
        };

        let mut result = bounded(op_name, self.request_timeout, op(conn.clone())).await;

        if result.as_ref().is_err_and(is_stream_dead_db) {
            match self.database.connect().map_err(reconnect_err) {
                Ok(fresh) => {
                    conn = fresh;
                    result = bounded(op_name, self.request_timeout, op(conn.clone())).await;
                }
                Err(err) => result = Err(err),
            }
        }

        self.conns.lock().await.push(conn);
        result
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for WriteProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WriteProxy").finish_non_exhaustive()
    }
}

impl fmt::Debug for ReadProxy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadProxy").finish_non_exhaustive()
    }
}

#[async_trait::async_trait]
impl ProxyDatabaseTrait for WriteProxy {
    async fn query(&self, statement: Statement) -> Result<Vec<ProxyRow>, DbErr> {
        let kinds = self.column_kinds.clone();
        self.with_conn("query", |conn| {
            run_query(conn, statement.clone(), kinds.clone())
        })
        .await
    }

    async fn execute(&self, statement: Statement) -> Result<ProxyExecResult, DbErr> {
        let sql = statement.sql.trim();

        if Self::is_begin(sql) {
            // Acquire the single-writer permit before issuing BEGIN.
            let permit = acquire(&self.admission, self.acquire_timeout).await?;
            {
                *self.permit.lock().expect("permit mutex poisoned") = Some(permit);
            }
            self.in_transaction.store(true, Ordering::Release);
        }

        let result = self
            .with_conn("execute", |conn| run_execute(conn, statement.clone()))
            .await;

        if Self::is_end(sql) || result.is_err() {
            // Release permit on COMMIT/ROLLBACK or on any error (so a
            // failed BEGIN doesn't leave the semaphore permanently held).
            if Self::is_end(sql) {
                self.in_transaction.store(false, Ordering::Release);
            }
            *self.permit.lock().expect("permit mutex poisoned") = None;
        }

        result
    }

    async fn ping(&self) -> Result<(), DbErr> {
        self.with_conn("ping", |conn| async move {
            conn.query("SELECT 1", ()).await.map(|_| ())
        })
        .await
    }

    fn start_rollback(&self) {
        // A `DatabaseTransaction` is being dropped. If we still hold the write
        // permit, no COMMIT/ROLLBACK ran (the transaction was cancelled or
        // panicked mid-flight): release the permit synchronously and mark
        // dirty so the next checkout issues a defensive server-side ROLLBACK.
        let mut permit = self.permit.lock().expect("permit mutex poisoned");
        if permit.take().is_some() {
            self.in_transaction.store(false, Ordering::Release);
            self.dirty.store(true, Ordering::Release);
        }
    }
}

#[async_trait::async_trait]
impl ProxyDatabaseTrait for ReadProxy {
    async fn query(&self, statement: Statement) -> Result<Vec<ProxyRow>, DbErr> {
        let kinds = self.column_kinds.clone();
        self.with_conn("query", |conn| {
            run_query(conn, statement.clone(), kinds.clone())
        })
        .await
    }

    async fn execute(&self, statement: Statement) -> Result<ProxyExecResult, DbErr> {
        self.with_conn("execute", |conn| run_execute(conn, statement.clone()))
            .await
    }

    async fn ping(&self) -> Result<(), DbErr> {
        self.with_conn("ping", |conn| async move {
            conn.query("SELECT 1", ()).await.map(|_| ())
        })
        .await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Acquire an admission permit within `acquire_timeout`.
async fn acquire(
    semaphore: &Arc<Semaphore>,
    acquire_timeout: Duration,
) -> Result<OwnedSemaphorePermit, DbErr> {
    match timeout(acquire_timeout, semaphore.clone().acquire_owned()).await {
        Ok(Ok(permit)) => Ok(permit),
        Ok(Err(_)) => Err(DbErr::ConnectionAcquire(ConnAcquireErr::ConnectionClosed)),
        Err(_) => Err(DbErr::ConnectionAcquire(ConnAcquireErr::Timeout)),
    }
}

/// Bound a server call to `request_timeout`.
async fn bounded<T>(
    op_name: &'static str,
    request_timeout: Duration,
    fut: impl Future<Output = Result<T, libsql::Error>>,
) -> Result<T, DbErr> {
    match timeout(request_timeout, fut).await {
        Ok(result) => result.map_err(|e| map_libsql_err(op_name, e)),
        Err(_) => Err(DbErr::Custom(format!(
            "db {op_name} timed out after {}s",
            request_timeout.as_secs()
        ))),
    }
}

/// Execute a statement and report affected rows + last insert id.
async fn run_execute(
    conn: libsql::Connection,
    statement: Statement,
) -> Result<ProxyExecResult, libsql::Error> {
    let params = bind_params(&statement)?;
    let rows_affected = conn.execute(&statement.sql, params).await?;

    Ok(ProxyExecResult {
        last_insert_id: conn.last_insert_rowid() as u64,
        rows_affected,
    })
}

/// Run a query and convert every row through the schema-derived kinds.
async fn run_query(
    conn: libsql::Connection,
    statement: Statement,
    column_kinds: Arc<HashMap<String, ColumnKind>>,
) -> Result<Vec<ProxyRow>, libsql::Error> {
    let params = bind_params(&statement)?;
    let mut rows = conn.query(&statement.sql, params).await?;

    let names: Vec<String> = (0..rows.column_count())
        .map(|i| rows.column_name(i).unwrap_or_default().to_owned())
        .collect();

    let mut out = Vec::new();
    while let Some(row) = rows.next().await? {
        let mut values = std::collections::BTreeMap::new();
        for (i, name) in names.iter().enumerate() {
            let value = row.get_value(i as i32)?;
            values.insert(
                name.clone(),
                convert::to_sea_value(name, value, &column_kinds),
            );
        }
        out.push(ProxyRow { values });
    }

    Ok(out)
}

/// Translate a statement's bind values into libsql positional params.
fn bind_params(statement: &Statement) -> Result<libsql::params::Params, libsql::Error> {
    let Some(values) = &statement.values else {
        return Ok(libsql::params::Params::None);
    };

    let converted: Result<Vec<libsql::Value>, DbErr> =
        values.0.iter().map(convert::to_libsql_value).collect();
    let converted =
        converted.map_err(|e| libsql::Error::ToSqlConversionFailure(e.to_string().into()))?;

    Ok(libsql::params::Params::Positional(converted))
}

/// Whether a mapped error reports a dead server stream.
fn is_stream_dead_db(err: &DbErr) -> bool {
    let DbErr::Custom(message) = err else {
        return false;
    };

    let lower = message.to_ascii_lowercase();
    STREAM_DEAD_MARKERS.iter().any(|m| lower.contains(m))
}

/// Contextual error for a failed replacement of a dead server connection.
fn reconnect_err(err: libsql::Error) -> DbErr {
    DbErr::Custom(format!("db reconnect: {err}"))
}

/// Map a libsql error into `DbErr`, tagging server-side busy conditions
/// with [`BUSY_SENTINEL`] so the retry layer treats them as transient.
fn map_libsql_err(op_name: &'static str, err: libsql::Error) -> DbErr {
    let busy = match &err {
        libsql::Error::RemoteSqliteFailure(code, _, _) => *code == 5 || *code == 517,
        libsql::Error::Hrana(inner) => {
            let text = inner.to_string();
            text.contains("SQLITE_BUSY") || text.contains("database is locked")
        }
        _ => false,
    };

    if busy {
        return DbErr::Exec(RuntimeErr::Internal(format!("{BUSY_SENTINEL}: {err}")));
    }

    DbErr::Custom(format!("db {op_name}: {err}"))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stream_dead_classification_matches_rejected_stream_errors() {
        let baton = DbErr::Custom("db execute: Hrana: `api error: `Invalid baton``".into());
        let closed = DbErr::Custom("db query: Hrana: `stream closed: `gone``".into());

        assert!(is_stream_dead_db(&baton));
        assert!(is_stream_dead_db(&closed));
    }

    #[test]
    fn stream_dead_classification_ignores_statement_and_busy_errors() {
        let sql = DbErr::Custom("db execute: Hrana: `api error: `no such table: runs``".into());
        let busy = DbErr::Exec(RuntimeErr::Internal(format!(
            "{BUSY_SENTINEL}: database is locked"
        )));

        assert!(!is_stream_dead_db(&sql));
        assert!(!is_stream_dead_db(&busy));
    }
}
