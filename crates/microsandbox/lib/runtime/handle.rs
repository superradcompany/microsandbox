//! Handle to a running sandbox process.
//!
//! [`ProcessHandle`] holds the PID of the sandbox process and provides
//! methods for lifecycle management (signals, wait).

use std::process::ExitStatus;

use nix::{
    sys::signal::{self, Signal},
    unistd::Pid,
};
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
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProcessHandle {
    /// Create a new handle.
    pub(crate) fn new(pid: u32, sandbox_name: String, child: Child) -> Self {
        Self {
            pid,
            sandbox_name,
            child,
            detached: false,
        }
    }

    /// Get the sandbox process PID.
    pub fn pid(&self) -> u32 {
        self.pid
    }

    /// Get the sandbox name.
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
    pub fn disarm(&mut self) {
        self.detached = true;
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

        // Safety net: send SIGTERM so the sandbox process is cleaned up
        // if the handle is dropped without an explicit stop.
        if let Ok(None) = self.child.try_wait()
            && let Some(pid) = self.child.id()
        {
            tracing::debug!(pid, sandbox = %self.sandbox_name, "drop: sending SIGTERM safety net");
            let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
        }
    }
}
