//! Log file management with rotation for capturing VM console output.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use crate::RuntimeResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// CLI-selectable tracing verbosity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    /// Emit only error logs.
    Error,

    /// Emit warning and error logs.
    Warn,

    /// Emit info, warning, and error logs.
    Info,

    /// Emit debug and higher-severity logs.
    Debug,

    /// Emit trace and higher-severity logs.
    Trace,
}

/// Error returned when parsing an invalid log level string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseLogLevelError {
    value: String,
}

/// A simple rotating log writer.
///
/// Writes to a log file and rotates when the file exceeds `max_bytes`.
/// Rotated files are renamed with a numeric suffix (e.g., `vm.log.1`).
pub struct RotatingLog {
    /// Path to the current log file.
    path: PathBuf,

    /// Open file handle for writing.
    file: File,

    /// Maximum file size in bytes before rotation.
    max_bytes: u64,

    /// Bytes written to the current file.
    written: u64,
}

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum number of rotated log files to keep.
const MAX_ROTATED_FILES: u32 = 3;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LogLevel {
    /// Return the canonical string representation for this level.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }

    /// Return the CLI flag corresponding to this level.
    pub const fn as_cli_flag(self) -> &'static str {
        match self {
            Self::Error => "--error",
            Self::Warn => "--warn",
            Self::Info => "--info",
            Self::Debug => "--debug",
            Self::Trace => "--trace",
        }
    }

    /// Return the tracing level corresponding to this selection.
    pub const fn as_tracing_level(self) -> tracing::Level {
        match self {
            Self::Error => tracing::Level::ERROR,
            Self::Warn => tracing::Level::WARN,
            Self::Info => tracing::Level::INFO,
            Self::Debug => tracing::Level::DEBUG,
            Self::Trace => tracing::Level::TRACE,
        }
    }
}

impl RotatingLog {
    /// Create a new rotating log writer.
    ///
    /// The log file is created at `<log_dir>/<prefix>.log`.
    pub fn new(log_dir: &Path, prefix: &str, max_bytes: u64) -> RuntimeResult<Self> {
        fs::create_dir_all(log_dir)?;

        let path = log_dir.join(format!("{prefix}.log"));
        let written = path.metadata().map(|m| m.len()).unwrap_or(0);
        let file = OpenOptions::new().create(true).append(true).open(&path)?;

        Ok(Self {
            path,
            file,
            max_bytes,
            written,
        })
    }

    /// Write data to the log file, rotating if necessary.
    pub fn write(&mut self, data: &[u8]) -> RuntimeResult<()> {
        if self.written + data.len() as u64 > self.max_bytes {
            self.rotate()?;
        }

        self.file.write_all(data)?;
        self.written += data.len() as u64;
        Ok(())
    }

    /// Flush the log file.
    pub fn flush(&mut self) -> RuntimeResult<()> {
        self.file.flush()?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Helpers
//--------------------------------------------------------------------------------------------------

impl RotatingLog {
    fn rotate(&mut self) -> RuntimeResult<()> {
        self.file.flush()?;

        // Shift existing rotated files: .log.2 → .log.3, .log.1 → .log.2, etc.
        for i in (1..=MAX_ROTATED_FILES).rev() {
            let from = format!("{}.{i}", self.path.display());
            let to = format!("{}.{}", self.path.display(), i + 1);
            if Path::new(&from).exists() {
                fs::rename(&from, &to)?;
            }
        }

        // Rename current log to .log.1
        let rotated = format!("{}.1", self.path.display());
        fs::rename(&self.path, &rotated)?;

        // Open a fresh log file
        self.file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.path)?;
        self.written = 0;

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for LogLevel {
    type Err = ParseLogLevelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(ParseLogLevelError {
                value: s.to_owned(),
            }),
        }
    }
}

impl std::fmt::Display for ParseLogLevelError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "invalid log level: {} (expected: error, warn, info, debug, trace)",
            self.value
        )
    }
}

impl std::error::Error for ParseLogLevelError {}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::LogLevel;

    #[test]
    fn test_log_level_cli_flags() {
        assert_eq!(LogLevel::Error.as_cli_flag(), "--error");
        assert_eq!(LogLevel::Warn.as_cli_flag(), "--warn");
        assert_eq!(LogLevel::Info.as_cli_flag(), "--info");
        assert_eq!(LogLevel::Debug.as_cli_flag(), "--debug");
        assert_eq!(LogLevel::Trace.as_cli_flag(), "--trace");
    }

    #[test]
    fn test_log_level_display() {
        assert_eq!(LogLevel::Error.to_string(), "error");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Debug.to_string(), "debug");
        assert_eq!(LogLevel::Trace.to_string(), "trace");
    }

    #[test]
    fn test_log_level_from_str() {
        assert_eq!("error".parse::<LogLevel>().unwrap(), LogLevel::Error);
        assert_eq!("warn".parse::<LogLevel>().unwrap(), LogLevel::Warn);
        assert_eq!("info".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("debug".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("trace".parse::<LogLevel>().unwrap(), LogLevel::Trace);
        assert!("verbose".parse::<LogLevel>().is_err());
    }
}
