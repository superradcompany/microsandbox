//! Error types for microsandbox.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The result type for microsandbox operations.
pub type MicrosandboxResult<T> = Result<T, MicrosandboxError>;

/// Errors that can occur in microsandbox operations.
#[derive(Debug, thiserror::Error)]
pub enum MicrosandboxError {
    /// An I/O error occurred.
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// An HTTP request error occurred.
    #[error("http error: {0}")]
    Http(#[from] reqwest::Error),

    /// The libkrunfw library was not found at the expected location.
    #[error("libkrunfw not found: {0}")]
    LibkrunfwNotFound(String),

    /// A database error occurred.
    #[error("database error: {0}")]
    Database(#[from] sea_orm::DbErr),

    /// A custom error message.
    #[error("{0}")]
    Custom(String),
}
