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

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TypesError {
    pub(crate) fn invalid_config(message: impl Into<String>) -> Self {
        Self::InvalidConfig(message.into())
    }
}
