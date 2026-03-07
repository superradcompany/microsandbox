//! Exec-related protocol message payloads.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Request to execute a command in the guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRequest {
    /// The command to execute (program path).
    pub cmd: String,

    /// Arguments to the command.
    #[serde(default)]
    pub args: Vec<String>,

    /// Environment variables as key=value pairs.
    #[serde(default)]
    pub env: Vec<String>,

    /// Working directory for the command.
    #[serde(default)]
    pub cwd: Option<String>,

    /// Whether to allocate a PTY for the command.
    #[serde(default)]
    pub tty: bool,

    /// Initial terminal rows (only used when `tty` is true).
    #[serde(default = "default_rows")]
    pub rows: u16,

    /// Initial terminal columns (only used when `tty` is true).
    #[serde(default = "default_cols")]
    pub cols: u16,

    /// POSIX resource limits to apply to the spawned process via `setrlimit()`.
    #[serde(default)]
    pub rlimits: Vec<ExecRlimit>,
}

/// A POSIX resource limit to apply to a spawned process.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecRlimit {
    /// Resource name (lowercase): "nofile", "nproc", "as", "cpu", etc.
    pub resource: String,

    /// Soft limit (can be raised up to hard limit by the process).
    pub soft: u64,

    /// Hard limit (ceiling, requires privileges to raise).
    pub hard: u64,
}

/// Confirmation that a command has been started.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecStarted {
    /// The PID of the spawned process.
    pub pid: u32,
}

/// Stdin data sent to a running command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecStdin {
    /// The raw input data.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Stdout data from a running command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecStdout {
    /// The raw output data.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Stderr data from a running command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecStderr {
    /// The raw error output data.
    #[serde(with = "serde_bytes")]
    pub data: Vec<u8>,
}

/// Notification that a command has exited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecExited {
    /// The exit code of the process.
    pub code: i32,
}

/// Request to resize the PTY of a running command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecResize {
    /// New number of rows.
    pub rows: u16,

    /// New number of columns.
    pub cols: u16,
}

/// Request to send a signal to a running command.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecSignal {
    /// The signal number to send (e.g. 15 for SIGTERM).
    pub signal: i32,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_rows() -> u16 {
    24
}

fn default_cols() -> u16 {
    80
}
