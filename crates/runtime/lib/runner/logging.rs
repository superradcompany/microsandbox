//! Log file management with rotation for capturing VM console output.

use std::{
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

use crate::RuntimeResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum number of rotated log files to keep.
const MAX_ROTATED_FILES: u32 = 3;

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
// Methods
//--------------------------------------------------------------------------------------------------

impl RotatingLog {
    /// Create a new rotating log writer.
    ///
    /// The log file is created at `<log_dir>/<prefix>.log`.
    pub fn new(log_dir: &Path, prefix: &str, max_bytes: u64) -> RuntimeResult<Self> {
        microsandbox_utils::private_file::create_private_dir_all(log_dir)?;

        let path = log_dir.join(format!("{prefix}.log"));
        let written = path.metadata().map(|m| m.len()).unwrap_or(0);
        let file = open_log(&path)?;

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
        self.file = open_log(&self.path)?;
        self.written = 0;

        Ok(())
    }
}

fn open_log(path: &Path) -> std::io::Result<File> {
    match microsandbox_utils::private_file::create_new_append(path) {
        Ok(file) => Ok(file),
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let mut options = OpenOptions::new();
            options.append(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
            }
            let file = options.open(path)?;
            if !file.metadata()?.is_file() {
                return Err(std::io::Error::other("runtime log is not a regular file"));
            }
            Ok(file)
        }
        Err(error) => Err(error),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[test]
    fn new_and_rotated_logs_are_owner_private() {
        for host_umask in [0o000, 0o022, 0o077] {
            let output = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("log_umask_child")
                .arg("--nocapture")
                .env("MSB_TEST_LOG_UMASK", format!("{host_umask:o}"))
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "host umask {host_umask:03o}:\n{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
    }

    #[test]
    fn log_umask_child() {
        let Ok(value) = std::env::var("MSB_TEST_LOG_UMASK") else {
            return;
        };
        let host_umask = u32::from_str_radix(&value, 8).unwrap();
        let previous_umask = unsafe { libc::umask(host_umask as libc::mode_t) };
        use std::os::unix::fs::PermissionsExt;

        let temporary_root = tempfile::tempdir().unwrap();
        let directory = temporary_root.path().join("logs");
        let mut log = RotatingLog::new(&directory, "vm", 1).unwrap();
        log.write(b"a").unwrap();
        log.write(b"b").unwrap();

        for name in ["vm.log", "vm.log.1"] {
            let metadata = fs::metadata(directory.join(name)).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600, "{name}");
        }
        assert_eq!(
            fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
        unsafe { libc::umask(previous_umask) };
    }
}
