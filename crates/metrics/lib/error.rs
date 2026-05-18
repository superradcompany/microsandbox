//! Error type used by the metrics registry.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result alias for metrics operations.
pub type MetricsResult<T> = Result<T, MetricsError>;

/// Errors produced by the metrics registry.
#[derive(Debug, thiserror::Error)]
pub enum MetricsError {
    /// Underlying I/O failure (typically from `shm_open`/`mmap`).
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    /// The registry already exists. Used internally for the create-or-open
    /// race; callers rarely see this directly.
    #[error("registry already exists")]
    AlreadyExists,

    /// No free slots are available.
    #[error("metrics registry full")]
    Full,

    /// A slot's generation does not match the caller's expectation.
    #[error("generation mismatch: expected {expected}, observed {actual}")]
    GenerationMismatch {
        /// Generation the caller believed it owned.
        expected: u64,
        /// Generation currently stored in the slot.
        actual: u64,
    },

    /// Anything else worth surfacing as a string.
    #[error("{0}")]
    Custom(String),
}
