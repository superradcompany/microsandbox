//! Exec-related protocol message payloads.

use std::str::FromStr;

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

    /// Optional guest user override for the command.
    #[serde(default)]
    pub user: Option<String>,

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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FromStr for ExecRlimit {
    type Err = String;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let (resource, limit) = spec
            .split_once('=')
            .ok_or_else(|| "rlimit must be in format RESOURCE=LIMIT".to_string())?;

        let mut parts = limit.split(':');
        let soft = parts
            .next()
            .ok_or_else(|| "missing soft limit".to_string())?
            .parse::<u64>()
            .map_err(|err| format!("invalid soft limit: {err}"))?;
        let hard = match parts.next() {
            Some(value) => value
                .parse::<u64>()
                .map_err(|err| format!("invalid hard limit: {err}"))?,
            None => soft,
        };

        if parts.next().is_some() {
            return Err("too many ':' separators".into());
        }

        if soft > hard {
            return Err("soft limit cannot exceed hard limit".into());
        }

        Ok(Self {
            resource: resource.to_ascii_lowercase(),
            soft,
            hard,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::ExecRlimit;

    #[test]
    fn test_exec_rlimit_from_str_uses_soft_for_hard_when_omitted() {
        assert_eq!(
            "NOFILE=65535".parse::<ExecRlimit>().unwrap(),
            ExecRlimit {
                resource: "nofile".to_string(),
                soft: 65_535,
                hard: 65_535,
            }
        );
    }

    #[test]
    fn test_exec_rlimit_from_str_parses_soft_and_hard() {
        assert_eq!(
            "nofile=4096:65535".parse::<ExecRlimit>().unwrap(),
            ExecRlimit {
                resource: "nofile".to_string(),
                soft: 4_096,
                hard: 65_535,
            }
        );
    }

    #[test]
    fn test_exec_rlimit_from_str_rejects_soft_above_hard() {
        let err = "nofile=65535:4096".parse::<ExecRlimit>().unwrap_err();
        assert_eq!(err, "soft limit cannot exceed hard limit");
    }
}
