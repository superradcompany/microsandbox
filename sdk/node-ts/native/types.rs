use std::collections::HashMap;

use napi_derive::napi;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Process exit status.
#[napi(object)]
pub struct ExitStatus {
    pub code: i32,
    pub success: bool,
}

/// One captured log entry from `exec.log`.
#[napi(object)]
pub struct LogEntry {
    /// Wall-clock timestamp when the chunk was captured (ms since epoch).
    pub timestamp_ms: f64,

    /// `"stdout"`, `"stderr"`, `"output"`, or `"system"`.
    pub source: String,

    /// Relay-monotonic session id. `null` for `system` entries
    /// (lifecycle markers aren't tied to a specific session).
    /// Exposed as `f64` so it survives JS's number type without
    /// requiring BigInt; session ids stay small in practice
    /// (start at 1, +1 per session opened).
    pub session_id: Option<f64>,

    /// Body bytes. UTF-8 lossy decoded by default; raw mode (future)
    /// preserves bytes via base64 round-trip on the host side.
    pub data: napi::bindgen_prelude::Buffer,
}

/// Filters applied by `Sandbox.logs()`.
///
/// All fields optional. Defaults: tail = unset (return everything),
/// since/until = unset (no time filter), sources = `["stdout", "stderr", "output"]`.
#[napi(object)]
pub struct LogOptions {
    /// Show only the last N entries.
    pub tail: Option<u32>,

    /// Inclusive lower bound (ms since epoch).
    pub since_ms: Option<f64>,

    /// Exclusive upper bound (ms since epoch).
    pub until_ms: Option<f64>,

    /// Sources to include. Each element is `"stdout"`, `"stderr"`,
    /// `"output"`, `"system"`, or `"all"`. Defaults to
    /// `["stdout", "stderr", "output"]` when omitted.
    pub sources: Option<Vec<String>>,
}

/// Filesystem entry metadata returned by `fs.list()`.
#[napi(object)]
pub struct FsEntry {
    pub path: String,
    /// "file", "directory", "symlink", or "other".
    pub kind: String,
    pub size: f64,
    pub mode: u32,
    pub modified: Option<f64>,
}

/// Filesystem metadata returned by `fs.stat()`.
#[napi(object)]
pub struct FsMetadata {
    /// "file", "directory", "symlink", or "other".
    pub kind: String,
    pub size: f64,
    pub mode: u32,
    pub readonly: bool,
    pub modified: Option<f64>,
    pub created: Option<f64>,
}

/// Point-in-time resource metrics for a sandbox.
#[napi(object)]
pub struct SandboxMetrics {
    pub cpu_percent: f64,
    pub memory_bytes: f64,
    pub memory_limit_bytes: f64,
    pub disk_read_bytes: f64,
    pub disk_write_bytes: f64,
    pub net_rx_bytes: f64,
    pub net_tx_bytes: f64,
    /// Uptime in milliseconds.
    pub uptime_ms: f64,
    /// Timestamp as milliseconds since Unix epoch.
    pub timestamp_ms: f64,
}

/// Execution event emitted by `ExecHandle.recv()`.
#[napi(object)]
pub struct ExecEvent {
    /// "started", "stdout", "stderr", or "exited".
    pub event_type: String,
    /// Process ID (only for "started" events).
    pub pid: Option<u32>,
    /// Output data (only for "stdout" and "stderr" events).
    pub data: Option<napi::bindgen_prelude::Buffer>,
    /// Exit code (only for "exited" events).
    pub code: Option<i32>,
}

/// Lightweight handle info for a sandbox from the database.
#[napi(object)]
pub struct SandboxInfo {
    pub name: String,
    /// "running", "stopped", "crashed", or "draining".
    pub status: String,
    pub config_json: String,
    pub created_at: Option<f64>,
    pub updated_at: Option<f64>,
}

/// Volume handle info from the database.
#[napi(object)]
pub struct VolumeInfo {
    pub name: String,
    pub quota_mib: Option<u32>,
    pub used_bytes: f64,
    pub labels: HashMap<String, String>,
    pub created_at: Option<f64>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub fn datetime_to_ms(dt: &chrono::DateTime<chrono::Utc>) -> f64 {
    dt.timestamp_millis() as f64
}

pub fn opt_datetime_to_ms(dt: &Option<chrono::DateTime<chrono::Utc>>) -> Option<f64> {
    dt.as_ref().map(datetime_to_ms)
}
