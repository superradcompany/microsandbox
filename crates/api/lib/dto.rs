//! RunLoop-shaped request and response DTOs.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types: Devboxes
//--------------------------------------------------------------------------------------------------

/// Create Devbox request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DevboxCreateRequest {
    /// Optional display name.
    pub name: Option<String>,

    /// Public OCI image reference for the local POC.
    pub image: Option<String>,

    /// RunLoop blueprint ID. Unsupported locally.
    pub blueprint_id: Option<String>,

    /// RunLoop blueprint name. Unsupported locally.
    pub blueprint_name: Option<String>,

    /// User metadata.
    pub metadata: Option<HashMap<String, String>>,

    /// Environment variables.
    pub environment_variables: Option<HashMap<String, String>>,
}

/// Devbox response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DevboxView {
    /// Devbox ID.
    pub id: String,

    /// Optional display name.
    pub name: Option<String>,

    /// Devbox status.
    pub status: String,

    /// Metadata.
    pub metadata: HashMap<String, String>,
}

/// List response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DevboxListView {
    /// Devboxes.
    pub devboxes: Vec<DevboxView>,

    /// Whether another page exists.
    pub has_more: bool,

    /// Optional total count.
    pub total_count: Option<i32>,
}

/// Read text file request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ReadFileRequest {
    /// Path to read.
    pub file_path: String,
}

/// Write text file request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WriteFileRequest {
    /// Path to write.
    pub file_path: String,

    /// UTF-8 contents.
    pub contents: String,
}

/// Download file request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DownloadFileRequest {
    /// Path to read.
    pub path: String,
}

/// Wait for devbox status request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WaitForStatusRequest {
    /// Statuses to wait for.
    pub statuses: Vec<String>,

    /// Timeout in seconds, capped at 30.
    pub timeout_seconds: Option<u64>,
}

/// Log entry response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct LogEntryView {
    /// RFC 3339 timestamp.
    pub timestamp: String,

    /// Source tag.
    pub source: String,

    /// Optional session ID.
    pub session_id: Option<u64>,

    /// Log data decoded as UTF-8 lossily.
    pub data: String,
}

/// Usage metrics response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct UsageView {
    /// CPU usage as a percentage across all host CPUs.
    pub cpu_percent: f32,

    /// Resident memory usage in bytes.
    pub memory_bytes: u64,

    /// Configured guest memory limit in bytes.
    pub memory_limit_bytes: u64,

    /// Cumulative disk bytes read by the sandbox process.
    pub disk_read_bytes: u64,

    /// Cumulative disk bytes written by the sandbox process.
    pub disk_write_bytes: u64,

    /// Cumulative network bytes delivered from the runtime to the guest.
    pub net_rx_bytes: u64,

    /// Cumulative network bytes transmitted from the guest into the runtime.
    pub net_tx_bytes: u64,

    /// Sandbox uptime in milliseconds.
    pub uptime_ms: u128,

    /// RFC 3339 timestamp of the sample.
    pub timestamp: String,
}

//--------------------------------------------------------------------------------------------------
// Types: Disk Snapshots
//--------------------------------------------------------------------------------------------------

/// Disk snapshot response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiskSnapshotView {
    /// Snapshot ID.
    pub id: String,

    /// Optional snapshot display name.
    pub name: Option<String>,

    /// Metadata.
    pub metadata: HashMap<String, String>,

    /// Source Devbox ID, when known.
    pub source_devbox_id: String,

    /// Creation time in milliseconds since the Unix epoch.
    pub create_time_ms: i64,

    /// Snapshot size in bytes.
    pub size_bytes: Option<u64>,
}

/// List disk snapshots response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiskSnapshotListView {
    /// Disk snapshots.
    pub snapshots: Vec<DiskSnapshotView>,

    /// Whether another page exists.
    pub has_more: bool,

    /// Optional total count.
    pub total_count: Option<i32>,
}

/// Disk snapshot status response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DiskSnapshotStatusView {
    /// Snapshot status.
    pub status: String,

    /// Snapshot details.
    pub snapshot: DiskSnapshotView,
}

//--------------------------------------------------------------------------------------------------
// Types: Executions
//--------------------------------------------------------------------------------------------------

/// Execute request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExecuteRequest {
    /// Idempotency and tracking ID.
    pub command_id: Option<String>,

    /// Shell command.
    pub command: String,

    /// Persistent shell name. Unsupported locally.
    pub shell_name: Option<String>,

    /// Optimistic wait timeout in seconds.
    pub optimistic_timeout: Option<u64>,
}

/// Async execute request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExecuteAsyncRequest {
    /// Shell command.
    pub command: String,

    /// Persistent shell name. Unsupported locally.
    pub shell_name: Option<String>,

    /// Whether stdin is attached.
    pub attach_stdin: Option<bool>,
}

/// Execution detail response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ExecutionView {
    /// Execution ID.
    pub id: String,

    /// Devbox ID.
    pub devbox_id: String,

    /// Execution status.
    pub status: String,

    /// Exit code.
    pub exit_code: Option<i32>,

    /// Captured stdout.
    pub stdout: String,

    /// Captured stderr.
    pub stderr: String,

    /// Error message.
    pub error: Option<String>,
}

/// Send stdin request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SendStdinRequest {
    /// Content to write to stdin.
    pub content: String,
}

/// Wait for execution status request.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct WaitForExecutionStatusRequest {
    /// Statuses to wait for.
    pub statuses: Vec<String>,

    /// Timeout in seconds, capped at 25.
    pub timeout_seconds: Option<u64>,
}

/// Empty object response.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct EmptyRecord {}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<crate::store::StoredExecution> for ExecutionView {
    fn from(row: crate::store::StoredExecution) -> Self {
        Self {
            id: row.execution_id,
            devbox_id: row.devbox_id,
            status: row.status.as_str().into(),
            exit_code: row.exit_code,
            stdout: row.stdout,
            stderr: row.stderr,
            error: row.error,
        }
    }
}
