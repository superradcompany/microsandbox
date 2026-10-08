//! Retain a database inode without closing descriptors outside SQLite's VFS.

use std::path::Path;

use sqlx::{Connection, SqliteConnection, sqlite::SqliteConnectOptions};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A dedicated SQLite connection that keeps the original database file alive.
///
/// Unlike an idle pool connection, this connection is retained until the pin is
/// dropped. SQLite coordinates its close with other connections' file locks.
pub struct DbFilePin {
    _connection: SqliteConnection,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DbFilePin {
    /// Open an existing database read-only without changing its journal mode.
    pub async fn open(path: &Path) -> Result<Self, sqlx::Error> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .read_only(true)
            .create_if_missing(false);
        Ok(Self {
            _connection: SqliteConnection::connect_with(&options).await?,
        })
    }
}
