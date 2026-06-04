//! Devbox routes.

use std::{convert::Infallible, time::Duration};

use axum::{
    Json,
    extract::{Multipart, Path, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{
        IntoResponse,
        sse::{Event, Sse},
    },
};
use chrono::SecondsFormat;
use futures::{Stream, StreamExt};
use microsandbox::{
    Sandbox,
    logs::{LogOptions, LogSource, LogStreamOptions},
    sandbox::SandboxMetrics,
};

use crate::{
    adapter,
    dto::{
        DevboxCreateRequest, DevboxListView, DevboxView, DownloadFileRequest, EmptyRecord,
        LogEntryView, ReadFileRequest, UsageView, WaitForStatusRequest, WriteFileRequest,
    },
    error::ApiError,
    state::ApiState,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum UTF-8 file payload size.
pub const TEXT_FILE_LIMIT: usize = 10 * 1024 * 1024;

/// Maximum binary file payload size.
pub const BINARY_FILE_LIMIT: usize = 100 * 1024 * 1024;

const DEFAULT_WAIT_TIMEOUT_SECONDS: u64 = 10;
const MAX_WAIT_TIMEOUT_SECONDS: u64 = 30;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create a devbox.
pub async fn create(
    State(_state): State<ApiState>,
    Json(request): Json<DevboxCreateRequest>,
) -> Result<Json<DevboxView>, ApiError> {
    Ok(Json(adapter::create_devbox(request).await?))
}

/// List devboxes.
pub async fn list(State(_state): State<ApiState>) -> Result<Json<DevboxListView>, ApiError> {
    let devboxes = adapter::list_devboxes().await?;
    Ok(Json(DevboxListView {
        total_count: Some(devboxes.len() as i32),
        has_more: false,
        devboxes,
    }))
}

/// Get devbox details.
pub async fn get(
    State(_state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<DevboxView>, ApiError> {
    Ok(Json(adapter::get_devbox(&id).await?))
}

/// Shutdown a devbox.
pub async fn shutdown(
    State(_state): State<ApiState>,
    Path(id): Path<String>,
) -> Result<Json<EmptyRecord>, ApiError> {
    let handle = Sandbox::get(&id)
        .await
        .map_err(|_| ApiError::not_found(format!("Devbox '{id}' was not found.")))?;
    handle
        .stop()
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(Json(EmptyRecord {}))
}

/// Wait for a devbox status.
pub async fn wait_for_status(
    State(_state): State<ApiState>,
    Path(id): Path<String>,
    Json(request): Json<WaitForStatusRequest>,
) -> Result<Json<DevboxView>, ApiError> {
    if request.statuses.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_request",
            "statuses must not be empty",
        ));
    }

    let timeout = Duration::from_secs(
        request
            .timeout_seconds
            .unwrap_or(DEFAULT_WAIT_TIMEOUT_SECONDS)
            .min(MAX_WAIT_TIMEOUT_SECONDS),
    );
    let deadline = tokio::time::Instant::now() + timeout;

    loop {
        let devbox = adapter::get_devbox(&id).await?;
        if request
            .statuses
            .iter()
            .any(|status| status == &devbox.status)
        {
            return Ok(Json(devbox));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ApiError::new(
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                "timed out waiting for devbox status",
            ));
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Read text file contents.
pub async fn read_file_contents(
    Path(id): Path<String>,
    Json(request): Json<ReadFileRequest>,
) -> Result<String, ApiError> {
    let sandbox = Sandbox::get(&id)
        .await
        .map_err(|_| ApiError::not_found(format!("Devbox '{id}' was not found.")))?
        .connect()
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    let contents = sandbox
        .fs()
        .read_to_string(&request.file_path)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    if contents.len() > TEXT_FILE_LIMIT {
        return Err(size_limit_exceeded("file exceeds text response size limit"));
    }
    Ok(contents)
}

/// Write text file contents.
pub async fn write_file_contents(
    Path(id): Path<String>,
    Json(request): Json<WriteFileRequest>,
) -> Result<Json<EmptyRecord>, ApiError> {
    if request.contents.len() > TEXT_FILE_LIMIT {
        return Err(size_limit_exceeded(
            "contents exceeds text request size limit",
        ));
    }

    let sandbox = Sandbox::get(&id)
        .await
        .map_err(|_| ApiError::not_found(format!("Devbox '{id}' was not found.")))?
        .connect()
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    sandbox
        .fs()
        .write(&request.file_path, request.contents)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(Json(EmptyRecord {}))
}

/// Download binary file.
pub async fn download_file(
    Path(id): Path<String>,
    Json(request): Json<DownloadFileRequest>,
) -> Result<impl IntoResponse, ApiError> {
    let sandbox = Sandbox::get(&id)
        .await
        .map_err(|_| ApiError::not_found(format!("Devbox '{id}' was not found.")))?
        .connect()
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    let data = sandbox
        .fs()
        .read(&request.path)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    if data.len() > BINARY_FILE_LIMIT {
        return Err(size_limit_exceeded(
            "file exceeds binary response size limit",
        ));
    }

    let mut headers = HeaderMap::new();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/octet-stream"),
    );
    headers.insert(
        header::CONTENT_DISPOSITION,
        content_disposition(&request.path)?,
    );
    Ok((headers, data))
}

/// Upload binary file.
pub async fn upload_file(
    Path(id): Path<String>,
    mut multipart: Multipart,
) -> Result<Json<EmptyRecord>, ApiError> {
    let mut path = None;
    let mut file = None;

    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|err| ApiError::bad_request("invalid_multipart", err.to_string()))?
    {
        match field.name() {
            Some("path") => {
                path =
                    Some(field.text().await.map_err(|err| {
                        ApiError::bad_request("invalid_multipart", err.to_string())
                    })?);
            }
            Some("file") => {
                let data = field
                    .bytes()
                    .await
                    .map_err(|err| ApiError::bad_request("invalid_multipart", err.to_string()))?;
                if data.len() > BINARY_FILE_LIMIT {
                    return Err(size_limit_exceeded(
                        "file exceeds binary request size limit",
                    ));
                }
                file = Some(data);
            }
            _ => {}
        }
    }

    let path = path.ok_or_else(|| ApiError::bad_request("invalid_request", "path is required"))?;
    let file = file.ok_or_else(|| ApiError::bad_request("invalid_request", "file is required"))?;
    let sandbox = Sandbox::get(&id)
        .await
        .map_err(|_| ApiError::not_found(format!("Devbox '{id}' was not found.")))?
        .connect()
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    sandbox
        .fs()
        .write(&path, file)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(Json(EmptyRecord {}))
}

/// Get devbox logs.
pub async fn logs(Path(id): Path<String>) -> Result<Json<Vec<LogEntryView>>, ApiError> {
    let logs = microsandbox::logs::read_logs(&id, &LogOptions::default())
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?
        .into_iter()
        .map(log_entry_view)
        .collect();
    Ok(Json(logs))
}

/// Tail devbox logs.
pub async fn logs_tail(
    Path(id): Path<String>,
) -> Result<Sse<impl Stream<Item = Result<Event, Infallible>>>, ApiError> {
    let stream = microsandbox::logs::log_stream(
        &id,
        &LogStreamOptions {
            follow: true,
            ..Default::default()
        },
    )
    .await
    .map_err(|err| ApiError::internal(err.to_string()))?
    .map(|item| {
        let data = match item {
            Ok(entry) => {
                serde_json::to_string(&log_entry_view(entry)).unwrap_or_else(|_| "{}".into())
            }
            Err(err) => serde_json::json!({ "error": err.to_string() }).to_string(),
        };
        Ok(Event::default().data(data))
    });
    Ok(Sse::new(stream))
}

/// Get usage metrics.
pub async fn usage(Path(id): Path<String>) -> Result<Json<UsageView>, ApiError> {
    let metrics = Sandbox::get(&id)
        .await
        .map_err(|_| ApiError::not_found(format!("Devbox '{id}' was not found.")))?
        .metrics()
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(Json(usage_view(metrics)))
}

fn size_limit_exceeded(message: &'static str) -> ApiError {
    ApiError::new(
        StatusCode::PAYLOAD_TOO_LARGE,
        "size_limit_exceeded",
        message,
    )
}

fn content_disposition(path: &str) -> Result<HeaderValue, ApiError> {
    let filename = path
        .rsplit('/')
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or("download");
    let sanitized = filename.replace(['\\', '"', '\r', '\n'], "_");
    HeaderValue::from_str(&format!("attachment; filename=\"{sanitized}\""))
        .map_err(|err| ApiError::internal(err.to_string()))
}

fn log_entry_view(entry: microsandbox::logs::LogEntry) -> LogEntryView {
    LogEntryView {
        timestamp: entry.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true),
        source: log_source(entry.source).into(),
        session_id: entry.session_id,
        data: String::from_utf8_lossy(&entry.data).into_owned(),
    }
}

fn log_source(source: LogSource) -> &'static str {
    match source {
        LogSource::Stdout => "stdout",
        LogSource::Stderr => "stderr",
        LogSource::Output => "output",
        LogSource::System => "system",
    }
}

fn usage_view(metrics: SandboxMetrics) -> UsageView {
    UsageView {
        cpu_percent: metrics.cpu_percent,
        memory_bytes: metrics.memory_bytes,
        memory_limit_bytes: metrics.memory_limit_bytes,
        disk_read_bytes: metrics.disk_read_bytes,
        disk_write_bytes: metrics.disk_write_bytes,
        net_rx_bytes: metrics.net_rx_bytes,
        net_tx_bytes: metrics.net_tx_bytes,
        uptime_ms: metrics.uptime.as_millis(),
        timestamp: metrics
            .timestamp
            .to_rfc3339_opts(SecondsFormat::Millis, true),
    }
}
