//! Snapshot routes.

use std::collections::HashMap;

use axum::{
    Json,
    extract::{Path, State},
};
use chrono::DateTime;
use microsandbox::{MicrosandboxError, Sandbox, Snapshot, SnapshotHandle};

use crate::{
    dto::{DiskSnapshotListView, DiskSnapshotStatusView, DiskSnapshotView, EmptyRecord},
    error::ApiError,
    ids::new_execution_id,
    state::ApiState,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create a disk snapshot.
pub async fn snapshot_disk(
    State(_state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<DiskSnapshotView>, ApiError> {
    let snapshot_name = format!("snap_{}", new_execution_id().trim_start_matches("exec_"));
    let snapshot = Sandbox::get(&id)
        .await
        .map_err(|_| ApiError::not_found(format!("Devbox '{id}' was not found.")))?
        .snapshot(&snapshot_name)
        .await
        .map_err(snapshot_error)?;
    Ok(Json(snapshot_view_from_snapshot(
        &snapshot,
        Some(snapshot_name),
        id,
    )?))
}

/// List disk snapshots.
pub async fn list_disk_snapshots() -> Result<Json<DiskSnapshotListView>, ApiError> {
    let snapshots = Snapshot::list().await.map_err(snapshot_error)?;
    let total_count = snapshots.len();
    let snapshots = snapshots
        .into_iter()
        .map(|snapshot| snapshot_view_from_handle(&snapshot, ""))
        .collect();
    Ok(Json(DiskSnapshotListView {
        snapshots,
        has_more: false,
        total_count: Some(total_count as i32),
    }))
}

/// Get disk snapshot status.
pub async fn disk_snapshot_status(
    Path(id): Path<String>,
) -> Result<Json<DiskSnapshotStatusView>, ApiError> {
    let snapshot = Snapshot::get(&id).await.map_err(snapshot_error)?;
    Ok(Json(DiskSnapshotStatusView {
        status: "complete".into(),
        snapshot: snapshot_view_from_handle(&snapshot, ""),
    }))
}

/// Delete a disk snapshot.
pub async fn delete_disk_snapshot(Path(id): Path<String>) -> Result<Json<EmptyRecord>, ApiError> {
    Snapshot::remove(&id, false).await.map_err(snapshot_error)?;
    Ok(Json(EmptyRecord {}))
}

fn snapshot_view_from_snapshot(
    snapshot: &Snapshot,
    name: Option<String>,
    source_devbox_id: String,
) -> Result<DiskSnapshotView, ApiError> {
    Ok(DiskSnapshotView {
        id: snapshot.digest().to_string(),
        name,
        metadata: HashMap::new(),
        source_devbox_id,
        create_time_ms: snapshot_create_time_ms(snapshot)?,
        size_bytes: Some(snapshot.size_bytes()),
    })
}

fn snapshot_view_from_handle(
    snapshot: &SnapshotHandle,
    source_devbox_id: impl Into<String>,
) -> DiskSnapshotView {
    DiskSnapshotView {
        id: snapshot.digest().to_string(),
        name: snapshot.name().map(str::to_string),
        metadata: HashMap::new(),
        source_devbox_id: source_devbox_id.into(),
        create_time_ms: snapshot.created_at().and_utc().timestamp_millis(),
        size_bytes: snapshot.size_bytes(),
    }
}

fn snapshot_create_time_ms(snapshot: &Snapshot) -> Result<i64, ApiError> {
    DateTime::parse_from_rfc3339(&snapshot.manifest().created_at)
        .map(|created_at| created_at.timestamp_millis())
        .map_err(|err| ApiError::internal(err.to_string()))
}

fn snapshot_error(err: MicrosandboxError) -> ApiError {
    match err {
        MicrosandboxError::SnapshotNotFound(snapshot) => {
            ApiError::not_found(format!("Snapshot '{snapshot}' was not found."))
        }
        err => ApiError::internal(err.to_string()),
    }
}
