//! API route assembly.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    http::{Method, Uri},
    routing::{get, post},
};
use serde_json::json;

use crate::{auth::optional_auth, error::ApiError, state::ApiState};

pub mod devboxes;
pub mod executions;
pub mod snapshots;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build the API router.
pub fn router(state: ApiState) -> Router {
    Router::new()
        .route("/v1/devboxes", post(devboxes::create).get(devboxes::list))
        .route("/v1/devboxes/{id}", get(devboxes::get))
        .route("/v1/devboxes/{id}/execute", post(executions::execute))
        .route("/v1/devboxes/{id}/execute_sync", post(executions::execute))
        .route(
            "/v1/devboxes/{id}/execute_async",
            post(executions::execute_async),
        )
        .route("/v1/devboxes/{id}/shutdown", post(devboxes::shutdown))
        .route(
            "/v1/devboxes/{id}/wait_for_status",
            post(devboxes::wait_for_status),
        )
        .route(
            "/v1/devboxes/{devbox_id}/executions/{execution_id}",
            get(executions::get),
        )
        .route(
            "/v1/devboxes/{devbox_id}/executions/{execution_id}/kill",
            post(executions::kill),
        )
        .route(
            "/v1/devboxes/{devbox_id}/executions/{execution_id}/send_std_in",
            post(executions::send_std_in),
        )
        .route(
            "/v1/devboxes/{devbox_id}/executions/{execution_id}/wait_for_status",
            post(executions::wait_for_status),
        )
        .route(
            "/v1/devboxes/{id}/keep_alive",
            post(|| async { axum::Json(crate::dto::EmptyRecord {}) }),
        )
        .route(
            "/v1/devboxes/{id}/read_file_contents",
            post(devboxes::read_file_contents)
                .layer(DefaultBodyLimit::max(devboxes::TEXT_FILE_LIMIT + 1024)),
        )
        .route(
            "/v1/devboxes/{id}/write_file_contents",
            post(devboxes::write_file_contents)
                .layer(DefaultBodyLimit::max(devboxes::TEXT_FILE_LIMIT + 1024)),
        )
        .route(
            "/v1/devboxes/{id}/download_file",
            post(devboxes::download_file),
        )
        .route(
            "/v1/devboxes/{id}/upload_file",
            post(devboxes::upload_file)
                .layer(DefaultBodyLimit::max(devboxes::BINARY_FILE_LIMIT + 1024)),
        )
        .route("/v1/devboxes/{id}/logs", get(devboxes::logs))
        .route("/v1/devboxes/{id}/logs/tail", get(devboxes::logs_tail))
        .route("/v1/devboxes/{id}/usage", get(devboxes::usage))
        .route(
            "/v1/devboxes/{id}/snapshot_disk",
            post(snapshots::snapshot_disk),
        )
        .route(
            "/v1/devboxes/disk_snapshots",
            get(snapshots::list_disk_snapshots),
        )
        .route(
            "/v1/devboxes/disk_snapshots/{id}/status",
            get(snapshots::disk_snapshot_status),
        )
        .route(
            "/v1/devboxes/disk_snapshots/{id}/delete",
            post(snapshots::delete_disk_snapshot),
        )
        .fallback(unsupported_local)
        .with_state(state)
        .layer(axum::middleware::from_fn(optional_auth))
}

/// Return a visible local unsupported response for unmatched RunLoop API routes.
pub async fn unsupported_local(method: Method, uri: Uri) -> ApiError {
    ApiError::unsupported_locally(format!(
        "{method} {} is not implemented by the local Microsandbox API POC",
        uri.path()
    ))
    .with_details(json!({
        "method": method.as_str(),
        "path": uri.path(),
    }))
}
