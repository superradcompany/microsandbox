//! Structured failures while observing an accepted resize; never mutation retry advice.

use std::fmt;

use microsandbox_types::modify::ResourceResizeStatus;
use serde::Serialize;

use super::MicrosandboxError;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Why an operation-specific wait could not establish completion.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResizeWaitFailure {
    /// A later accepted request replaced the pending operation.
    Superseded,
    /// Sandbox or runtime continuity was lost; the original outcome is not inferred.
    Interrupted,
    /// The requested identity is unknown or no longer retained by this runtime.
    HistoryUnavailable,
    /// A response failed the operation's identity or evidence contract.
    InvalidResponse,
    /// A transport failure prevented observation; this does not prove the VM stopped.
    ObservationUnavailable,
}

/// Structured wait failure, with original cause and only validated status observations.
///
/// This is not a failed-resize receipt. The request may have applied; neither this error nor
/// cancellation undoes it. Unknown future peer codes retain the ordinary control-client error.
#[derive(Debug, Serialize)]
pub struct ResizeWaitError {
    /// Machine-readable wait outcome, separate from per-resource convergence.
    pub reason: ResizeWaitFailure,
    /// Sandbox being awaited, when the failure has wait context.
    pub sandbox: Option<String>,
    /// Exact operation identified by the failure, when available.
    pub operation_id: Option<String>,
    /// Validated last observations; supplied caller records are never copied here as evidence.
    pub status: Vec<ResourceResizeStatus>,
    /// Human-readable original diagnostic, not a code to parse.
    pub message: String,
    /// Original SDK/control error, including delivery information and peer response.
    /// It is kept in Rust's source chain but never serialized into binding payloads.
    #[serde(skip)]
    pub cause: Option<Box<MicrosandboxError>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ResizeWaitError {
    #[cfg(feature = "local")]
    pub(crate) fn new(reason: ResizeWaitFailure, cause: MicrosandboxError) -> Self {
        Self {
            reason,
            sandbox: None,
            operation_id: None,
            status: Vec::new(),
            message: cause.to_string(),
            cause: Some(Box::new(cause)),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Display for ResizeWaitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ResizeWaitError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.cause.as_deref().map(|cause| cause as _)
    }
}
