//! API error types and response mapping.

use axum::{Json, http::StatusCode, response::IntoResponse};
use serde::Serialize;
use serde_json::{Value, json};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// JSON error response.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorResponse {
    /// Error payload.
    pub error: ErrorBody,
}

/// JSON error body.
#[derive(Debug, Clone, Serialize)]
pub struct ErrorBody {
    /// Stable error code.
    pub code: String,

    /// Human-readable error message.
    pub message: String,

    /// Structured extra details.
    pub details: Value,
}

/// API error with HTTP status.
#[derive(Debug, Clone)]
pub struct ApiError {
    status: StatusCode,
    code: String,
    message: String,
    details: Value,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ApiError {
    /// Build a not-found error.
    pub fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }

    /// Build a bad-request error.
    pub fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }

    /// Build an internal error.
    pub fn internal(message: impl Into<String>) -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal_error", message)
    }

    /// Build a local unsupported endpoint error.
    pub fn unsupported_locally(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_IMPLEMENTED, "unsupported_locally", message)
    }

    /// Build an error with status and code.
    pub fn new(status: StatusCode, code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            status,
            code: code.into(),
            message: message.into(),
            details: json!({}),
        }
    }

    /// Add JSON details.
    pub fn with_details(mut self, details: Value) -> Self {
        self.details = details;
        self
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<ApiError> for ErrorResponse {
    fn from(error: ApiError) -> Self {
        Self {
            error: ErrorBody {
                code: error.code,
                message: error.message,
                details: error.details,
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let status = self.status;
        (status, Json(ErrorResponse::from(self))).into_response()
    }
}
