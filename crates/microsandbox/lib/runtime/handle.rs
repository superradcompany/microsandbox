//! Handle to a running sandbox process.
//!
//! [`ProcessHandle`] holds the PID of the sandbox process and provides
//! methods for lifecycle management (signals, wait).

use std::os::fd::{AsRawFd, OwnedFd};
use std::process::ExitStatus;

use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
use tempfile::TempDir;
use tokio::process::Child;

use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Handle to a running sandbox process.
pub struct ProcessHandle {
    /// PID of the sandbox process.
    pid: u32,

    /// Name of the sandbox this process manages.
    sandbox_name: String,

    /// The sandbox child process handle.
    child: Child,

    /// When true, the Drop impl will NOT send SIGTERM.
    detached: bool,

    /// Writer side of the attached-parent watchdog pipe. Keeping this open
    /// lets the child detect when the owner process disappears.
    parent_watchdog: Option<OwnedFd>,

    /// Ephemeral staging directory for file mounts. Dropped when the
    /// process handle is dropped, which auto-removes all staged files.
    _file_mounts_staging: Option<TempDir>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProcessHandle {
    /// Create a new handle.
    pub(crate) fn new(
        pid: u32,
        sandbox_name: String,
        child: Child,
        file_mounts_staging: Option<TempDir>,
        parent_watchdog: Option<OwnedFd>,
    ) -> Self {
        Self {
            pid,
            sandbox_name,
            child,
            detached: false,
            _file_mounts_staging: file_mounts_staging,
            parent_watchdog,
        }
    }

    /// Get the sandbox process PID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Get the sandbox name. Names are limited to 128 UTF-8 bytes.
    pub fn sandbox_name(&self) -> &str {
        &self.sandbox_name
    }

    /// Send SIGKILL to the sandbox process for immediate termination.
    pub fn kill(&self) -> MicrosandboxResult<()> {
        tracing::debug!(pid = self.pid, sandbox = %self.sandbox_name, "sending SIGKILL");
        signal::kill(Pid::from_raw(self.pid as i32), Signal::SIGKILL)?;
        Ok(())
    }

    /// Send SIGUSR1 to the sandbox process to trigger a graceful drain.
    ///
    /// The libkrun signal handler catches SIGUSR1, writes to the exit event
    /// fd, exit observers run, and the process terminates.
    pub fn drain(&self) -> MicrosandboxResult<()> {
        tracing::debug!(pid = self.pid, sandbox = %self.sandbox_name, "sending SIGUSR1 (drain)");
        signal::kill(Pid::from_raw(self.pid as i32), Signal::SIGUSR1)?;
        Ok(())
    }

    /// Wait for the sandbox process to exit.
    pub async fn wait(&mut self) -> MicrosandboxResult<ExitStatus> {
        tracing::debug!(pid = self.pid, sandbox = %self.sandbox_name, "waiting for exit");
        let status = self.child.wait().await?;
        tracing::debug!(pid = self.pid, ?status, "process exited");
        Ok(status)
    }

    /// Check if the process has exited without blocking.
    pub fn try_wait(&mut self) -> MicrosandboxResult<Option<ExitStatus>> {
        Ok(self.child.try_wait()?)
    }

    /// Disarm the SIGTERM safety net so the sandbox keeps running after
    /// this handle is dropped. Used by detached sandbox flows.
    ///
    /// Also prevents the file-mounts staging directory from being deleted,
    /// since the detached VM process still needs the backing files.
    pub fn disarm(&mut self) {
        self.detached = true;

        if let Some(parent_watchdog) = &self.parent_watchdog
            && let Err(err) = send_parent_watchdog_detach(parent_watchdog)
        {
            tracing::debug!(
                error = %err,
                sandbox = %self.sandbox_name,
                "failed to send parent-watch detach"
            );
        }

        // Consume the TempDir without deleting its contents — the detached
        // VM process still reads from it via virtiofs.
        if let Some(td) = self._file_mounts_staging.take() {
            let _ = td.keep();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        if self.detached {
            return;
        }

        // Attached sandboxes are coupled to the owner through the parent
        // watchdog pipe. Dropping the last writer is enough to trigger guest
        // shutdown and lets the runtime distinguish owner-exit cleanup from a
        // normal explicit stop. Keep SIGTERM only for legacy/non-watchdog
        // cases.
        if self.parent_watchdog.is_some() {
            tracing::debug!(
                sandbox = %self.sandbox_name,
                "drop: closing parent watchdog writer for attached sandbox cleanup"
            );
            return;
        }

        if let Ok(None) = self.child.try_wait()
            && let Some(pid) = self.child.id()
        {
            tracing::debug!(pid, sandbox = %self.sandbox_name, "drop: sending SIGTERM safety net");
            let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn send_parent_watchdog_detach(fd: &OwnedFd) -> std::io::Result<()> {
    let byte = [microsandbox_runtime::vm::PARENT_WATCH_DETACH];

    loop {
        let written = unsafe {
            libc::write(
                fd.as_raw_fd(),
                byte.as_ptr().cast::<libc::c_void>(),
                byte.len(),
            )
        };
        if written == byte.len() as isize {
            return Ok(());
        }
        if written < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err);
        }
        return Err(std::io::Error::new(
            std::io::ErrorKind::WriteZero,
            "failed to write parent-watch detach byte",
        ));
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::os::fd::FromRawFd;

    use super::*;

    #[test]
    fn test_send_parent_watchdog_detach_writes_detach_byte() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let read_fd = unsafe { OwnedFd::from_raw_fd(fds[0]) };
        let write_fd = unsafe { OwnedFd::from_raw_fd(fds[1]) };

        send_parent_watchdog_detach(&write_fd).unwrap();

        let mut reader = std::fs::File::from(read_fd);
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte).unwrap();
        assert_eq!(byte[0], microsandbox_runtime::vm::PARENT_WATCH_DETACH);
    }
}
