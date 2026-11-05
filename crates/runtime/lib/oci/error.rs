//! Error types for OCI runtime compatibility.

use std::path::PathBuf;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result type used by OCI compatibility components.
pub type OciResult<T> = Result<T, OciRuntimeError>;

/// Errors returned by OCI compatibility components.
#[derive(Debug, thiserror::Error)]
pub enum OciRuntimeError {
    /// The supplied container ID is empty or contains path separators.
    #[error("invalid container ID `{id}`")]
    InvalidContainerId {
        /// Invalid container ID.
        id: String,
    },

    /// The OCI bundle does not contain a valid `config.json`.
    #[error("invalid OCI bundle `{bundle}`: {reason}")]
    InvalidBundle {
        /// Bundle path.
        bundle: PathBuf,

        /// Human-readable validation failure.
        reason: String,
    },

    /// The requested container state was not found.
    #[error("container `{id}` does not exist")]
    NotFound {
        /// Container ID.
        id: String,
    },

    /// The requested container ID is already in use.
    #[error("container `{id}` already exists")]
    AlreadyExists {
        /// Container ID.
        id: String,
    },

    /// The requested operation is not valid for the current OCI status.
    #[error("cannot {operation} container `{id}` while it is {status}")]
    InvalidTransition {
        /// Container ID.
        id: String,

        /// Requested operation.
        operation: &'static str,

        /// Current status.
        status: String,
    },

    /// A required OCI process was not provided.
    #[error("container `{id}` has no OCI process to start")]
    MissingProcess {
        /// Container ID.
        id: String,
    },

    /// A filesystem operation failed.
    #[error("{operation} `{path}`: {source}")]
    Io {
        /// Operation that failed.
        operation: &'static str,

        /// Path involved in the failure.
        path: PathBuf,

        /// Source I/O error.
        #[source]
        source: std::io::Error,
    },

    /// JSON serialization or parsing failed.
    #[error("{operation} JSON `{path}`: {source}")]
    Json {
        /// Operation that failed.
        operation: &'static str,

        /// Path involved in the failure.
        path: PathBuf,

        /// Source JSON error.
        #[source]
        source: serde_json::Error,
    },
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn io_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: std::io::Error,
) -> OciRuntimeError {
    OciRuntimeError::Io {
        operation,
        path: path.into(),
        source,
    }
}

pub(crate) fn json_error(
    operation: &'static str,
    path: impl Into<PathBuf>,
    source: serde_json::Error,
) -> OciRuntimeError {
    OciRuntimeError::Json {
        operation,
        path: path.into(),
        source,
    }
}
