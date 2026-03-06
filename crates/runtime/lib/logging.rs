//! Log file management with rotation for capturing VM console output.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::RuntimeResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

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

impl RotatingLog {
    /// Create a new rotating log writer.
    ///
    /// The log file is created at `<log_dir>/<prefix>.log`.
    pub fn new(log_dir: &Path, prefix: &str, max_bytes: u64) -> RuntimeResult<Self> {
        fs::create_dir_all(log_dir)?;

        let path = log_dir.join(format!("{prefix}.log"));
        let written = path.metadata().map(|m| m.len()).unwrap_or(0);
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)?;

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
