//! Error type for the metrics collector orchestrator.

use thiserror::Error;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result alias for collector operations.
pub type MetricsCollectorResult<T> = Result<T, MetricsCollectorError>;

/// Errors raised by the metrics collector.
///
/// Decoupled from `microsandbox::MicrosandboxError` so this crate doesn't
/// drag in the umbrella's dependency closure. Shm registry errors flow
/// through the `Registry` variant via `#[from]`.
#[derive(Debug, Error)]
pub enum MetricsCollectorError {
    /// A shared-memory registry operation failed.
    #[error("metrics registry: {0}")]
    Registry(#[from] microsandbox_metrics::MetricsError),

    /// Builder validation failed.
    #[error("invalid collector configuration: {0}")]
    InvalidConfig(String),

    /// Anything else worth surfacing as a string (e.g., timeouts,
    /// worker/driver task panics, exporter-supplied errors).
    #[error("{0}")]
    Custom(String),
}
