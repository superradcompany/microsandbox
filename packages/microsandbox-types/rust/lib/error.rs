//! Error types for shared microsandbox contracts.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The result type for shared microsandbox contract operations.
pub type TypesResult<T> = Result<T, TypesError>;

/// Errors returned by shared microsandbox contract helpers.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TypesError {
    /// A supplied configuration value is invalid.
    #[error("invalid config: {0}")]
    InvalidConfig(String),
}

/// The result type for snapshot descriptor operations.
pub type SnapshotManifestResult<T> = Result<T, SnapshotManifestError>;

/// Errors returned by snapshot descriptor parsing, validation, and canonical
/// serialization.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SnapshotManifestError {
    /// Snapshot descriptor bytes or fields violate the schema contract.
    #[error("manifest parse error: {0}")]
    ManifestParse(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TypesError {
    pub(crate) fn invalid_config(message: impl Into<String>) -> Self {
        Self::InvalidConfig(message.into())
    }
}
