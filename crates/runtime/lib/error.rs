//! Error types for the microsandbox-runtime crate.

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The result type for runtime operations.
pub type RuntimeResult<T> = Result<T, RuntimeError>;

/// Errors that can occur during runtime operations.
#[derive(Debug, Error)]
pub enum RuntimeError {
    /// An I/O error.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// A database error.
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),

    /// A JSON serialization/deserialization error.
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    /// An errno-based system error.
    #[error("system error: {0}")]
    Nix(#[from] nix::errno::Errno),

    /// A custom error message.
    #[error("{0}")]
    Custom(String),
}

impl microsandbox_db::retry::IsSqliteBusy for RuntimeError {
    fn is_sqlite_busy(&self) -> bool {
        matches!(self, RuntimeError::Database(db_err) if microsandbox_db::retry::is_sqlite_busy(db_err))
    }
}
