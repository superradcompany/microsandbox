//! Execution routes.

use std::time::Duration;

use axum::{
    Json,
    extract::{Path, State},
    http::StatusCode,
};
use microsandbox::{ExecEvent, Sandbox};

use crate::{
    dto::{
        EmptyRecord, ExecuteAsyncRequest, ExecuteRequest, ExecutionView, SendStdinRequest,
        WaitForExecutionStatusRequest,
    },
    error::ApiError,
    ids::new_execution_id,
    state::ApiState,
    store::{ExecutionInsert, StoredExecution},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEFAULT_EXECUTION_WAIT_SECONDS: u64 = 25;
const MAX_EXECUTION_WAIT_SECONDS: u64 = 25;
const POLL_INTERVAL: Duration = Duration::from_millis(100);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute with optimistic wait.
pub async fn execute(
    State(state): State<ApiState>,
    Path(devbox_id): Path<String>,
    Json(request): Json<ExecuteRequest>,
) -> Result<Json<ExecutionView>, ApiError> {
    reject_shell_name(request.shell_name.as_ref())?;
    let execution_id = request.command_id.unwrap_or_else(new_execution_id);
    start_execution(
        state.clone(),
        devbox_id.clone(),
        execution_id.clone(),
        request.command,
        false,
    )
    .await?;

    let timeout = execution_wait_timeout(request.optimistic_timeout);
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let row = get_required(&state, &devbox_id, &execution_id).await?;
        if is_terminal(&row) || tokio::time::Instant::now() >= deadline {
            return Ok(Json(row.into()));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

/// Execute asynchronously.
pub async fn execute_async(
    State(state): State<ApiState>,
    Path(devbox_id): Path<String>,
    Json(request): Json<ExecuteAsyncRequest>,
) -> Result<Json<ExecutionView>, ApiError> {
    reject_shell_name(request.shell_name.as_ref())?;
    let execution_id = new_execution_id();
    start_execution(
        state.clone(),
        devbox_id.clone(),
        execution_id.clone(),
        request.command,
        request.attach_stdin.unwrap_or(false),
    )
    .await?;
    Ok(Json(
        get_required(&state, &devbox_id, &execution_id)
            .await?
            .into(),
    ))
}

/// Get execution status.
pub async fn get(
    State(state): State<ApiState>,
    Path((devbox_id, execution_id)): Path<(String, String)>,
) -> Result<Json<ExecutionView>, ApiError> {
    Ok(Json(
        get_required(&state, &devbox_id, &execution_id)
            .await?
            .into(),
    ))
}

/// Kill a live execution.
pub async fn kill(
    State(state): State<ApiState>,
    Path((devbox_id, execution_id)): Path<(String, String)>,
) -> Result<Json<EmptyRecord>, ApiError> {
    let control = state
        .live
        .read()
        .await
        .control(&devbox_id, &execution_id)
        .ok_or_else(|| ApiError::not_found(format!("Execution '{execution_id}' is not live.")))?;
    control
        .kill()
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(Json(EmptyRecord {}))
}

/// Send stdin to a live execution.
pub async fn send_std_in(
    State(state): State<ApiState>,
    Path((devbox_id, execution_id)): Path<(String, String)>,
    Json(request): Json<SendStdinRequest>,
) -> Result<Json<EmptyRecord>, ApiError> {
    let stdin = state
        .live
        .read()
        .await
        .stdin(&devbox_id, &execution_id)
        .ok_or_else(|| {
            ApiError::bad_request(
                "stdin_unavailable",
                "execution stdin is not attached or is no longer live",
            )
        })?;
    stdin
        .write(request.content.as_bytes())
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;
    Ok(Json(EmptyRecord {}))
}

/// Wait for execution status.
pub async fn wait_for_status(
    State(state): State<ApiState>,
    Path((devbox_id, execution_id)): Path<(String, String)>,
    Json(request): Json<WaitForExecutionStatusRequest>,
) -> Result<Json<ExecutionView>, ApiError> {
    if request.statuses.is_empty() {
        return Err(ApiError::bad_request(
            "invalid_request",
            "statuses must not be empty",
        ));
    }

    let timeout = execution_wait_timeout(request.timeout_seconds);
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let row = get_required(&state, &devbox_id, &execution_id).await?;
        if request
            .statuses
            .iter()
            .any(|status| status == row.status.as_str())
        {
            return Ok(Json(row.into()));
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ApiError::new(
                StatusCode::REQUEST_TIMEOUT,
                "timeout",
                "timed out waiting for execution status",
            ));
        }
        tokio::time::sleep(POLL_INTERVAL).await;
    }
}

async fn start_execution(
    state: ApiState,
    devbox_id: String,
    execution_id: String,
    command: String,
    attach_stdin: bool,
) -> Result<(), ApiError> {
    let sandbox = Sandbox::get(&devbox_id)
        .await
        .map_err(|_| ApiError::not_found(format!("Devbox '{devbox_id}' was not found.")))?
        .connect()
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;

    state
        .store
        .insert(ExecutionInsert {
            devbox_id: devbox_id.clone(),
            execution_id: execution_id.clone(),
            command: command.clone(),
            stdin_attached: attach_stdin,
        })
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;

    let mut handle = match sandbox
        .shell_stream_with(command, |exec| {
            if attach_stdin {
                exec.stdin_pipe()
            } else {
                exec
            }
        })
        .await
    {
        Ok(handle) => handle,
        Err(err) => {
            let message = err.to_string();
            let _ = state
                .store
                .mark_failed(&devbox_id, &execution_id, &message)
                .await;
            return Err(ApiError::internal(message));
        }
    };

    state
        .store
        .mark_running(&devbox_id, &execution_id)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?;

    let store = state.store.clone();
    let live = state.live.clone();
    let control = handle.control();
    let stdin = handle.take_stdin();
    {
        let mut live = live.write().await;
        live.insert_control(devbox_id.clone(), execution_id.clone(), control);
        if let Some(stdin) = stdin {
            live.insert_stdin(devbox_id.clone(), execution_id.clone(), stdin);
        }
    }

    tokio::spawn(async move {
        let mut terminal_event = false;
        while let Some(event) = handle.recv().await {
            match event {
                ExecEvent::Started { .. } => {}
                ExecEvent::Stdout(bytes) => {
                    let _ = store
                        .append_output(&devbox_id, &execution_id, &bytes, b"")
                        .await;
                }
                ExecEvent::Stderr(bytes) => {
                    let _ = store
                        .append_output(&devbox_id, &execution_id, b"", &bytes)
                        .await;
                }
                ExecEvent::Exited { code } => {
                    terminal_event = true;
                    let _ = store.mark_completed(&devbox_id, &execution_id, code).await;
                    break;
                }
                ExecEvent::Failed(failed) => {
                    terminal_event = true;
                    let _ = store
                        .mark_failed(&devbox_id, &execution_id, &failed.message)
                        .await;
                    break;
                }
                ExecEvent::StdinError(_) => {}
            }
        }
        if !terminal_event {
            let _ = store
                .mark_failed(
                    &devbox_id,
                    &execution_id,
                    "execution event stream ended before completion",
                )
                .await;
        }
        live.write().await.remove(&devbox_id, &execution_id);
    });

    Ok(())
}

fn reject_shell_name(shell_name: Option<&String>) -> Result<(), ApiError> {
    if shell_name.is_some() {
        return Err(ApiError::bad_request(
            "unsupported_field",
            "shell_name is not supported by the local Microsandbox API POC.",
        ));
    }
    Ok(())
}

fn execution_wait_timeout(timeout_seconds: Option<u64>) -> Duration {
    Duration::from_secs(
        timeout_seconds
            .unwrap_or(DEFAULT_EXECUTION_WAIT_SECONDS)
            .min(MAX_EXECUTION_WAIT_SECONDS),
    )
}

fn is_terminal(row: &StoredExecution) -> bool {
    matches!(
        row.status,
        crate::store::ExecutionStatus::Completed | crate::store::ExecutionStatus::Failed
    )
}

async fn get_required(
    state: &ApiState,
    devbox_id: &str,
    execution_id: &str,
) -> Result<StoredExecution, ApiError> {
    state
        .store
        .get(devbox_id, execution_id)
        .await
        .map_err(|err| ApiError::internal(err.to_string()))?
        .ok_or_else(|| ApiError::not_found(format!("Execution '{execution_id}' was not found.")))
}
