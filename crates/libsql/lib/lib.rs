//! libSQL server proxy backend for microsandbox-db.
//!
//! Provides a sea-orm [`DatabaseConnection`] that routes statements to a
//! self-hosted libSQL server (`sqld`) over the remote protocol. Admission is
//! bounded by internal semaphores so overload surfaces as a pool-acquisition
//! timeout instead of an unbounded wait.
//!
//! The [`ColumnKind`] map that drives result-cell conversion is injected at
//! open time so this crate stays free of any dependency on `microsandbox-db`
//! (no cycle: `microsandbox-db` depends on this crate, not the reverse).

#![warn(missing_docs)]

//--------------------------------------------------------------------------------------------------
// Modules
//--------------------------------------------------------------------------------------------------

mod backend;
mod convert;

//--------------------------------------------------------------------------------------------------
// Exports
//--------------------------------------------------------------------------------------------------

pub use backend::BUSY_SENTINEL;
pub use convert::ColumnKind;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use sea_orm::{
    ConnectionTrait, Database, DatabaseConnection, DbBackend, DbErr, ProxyDatabaseTrait, Statement,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a read-side proxy connection: `max_connections` server connections
/// behind bounded admission. Verifies the server answers a real query.
pub async fn open_read(
    url: &str,
    max_connections: u32,
    acquire_timeout: Duration,
    request_timeout: Duration,
    column_kinds: Arc<HashMap<String, ColumnKind>>,
) -> Result<DatabaseConnection, DbErr> {
    let database = connect_database(url).await?;

    let mut conns = Vec::new();
    for _ in 0..max_connections.max(1) {
        conns.push(database.connect().map_err(connect_err)?);
    }

    let proxy = backend::ReadProxy::new(
        database,
        conns,
        acquire_timeout,
        request_timeout,
        column_kinds,
    );
    let conn = into_proxy_connection(Box::new(proxy)).await?;

    // A read consumer must find an existing database, mirroring the file
    // backend's refusal to create one: probe the schema, not just the port.
    let probe = Statement::from_string(
        DbBackend::Sqlite,
        "SELECT count(*) FROM sqlite_master".to_owned(),
    );
    conn.query_one(probe).await?;
    Ok(conn)
}

/// Open the write-side proxy connection (single server connection).
///
/// The write proxy self-manages its single-writer admission permit: it
/// acquires on `BEGIN`/`BEGIN IMMEDIATE` statements and releases on
/// `COMMIT`/`ROLLBACK`, removing the need for a separate `WriteControl`
/// handle.
pub async fn open_write(
    url: &str,
    acquire_timeout: Duration,
    request_timeout: Duration,
    column_kinds: Arc<HashMap<String, ColumnKind>>,
) -> Result<DatabaseConnection, DbErr> {
    let database = connect_database(url).await?;
    let server_conn = database.connect().map_err(connect_err)?;

    let proxy = backend::WriteProxy::new(
        database,
        server_conn,
        acquire_timeout,
        request_timeout,
        column_kinds,
    );
    let conn = into_proxy_connection(Box::new(proxy)).await?;

    conn.ping().await?;
    Ok(conn)
}

/// Build the libsql database handle for a server URL.
async fn connect_database(url: &str) -> Result<libsql::Database, DbErr> {
    libsql::Builder::new_remote(url.to_owned(), String::new())
        .build()
        .await
        .map_err(connect_err)
}

/// Wrap a proxy backend into a sea-orm `DatabaseConnection`.
async fn into_proxy_connection(
    proxy: Box<dyn ProxyDatabaseTrait>,
) -> Result<DatabaseConnection, DbErr> {
    Database::connect_proxy(DbBackend::Sqlite, Arc::new(proxy)).await
}

/// Contextual error for connection establishment failures.
fn connect_err(err: libsql::Error) -> DbErr {
    DbErr::Conn(sea_orm::RuntimeErr::Internal(format!(
        "connect to database server: {err}"
    )))
}
