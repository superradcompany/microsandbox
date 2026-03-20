//! Handle to a running supervisor process.
//!
//! [`SupervisorHandle`] holds the PIDs of the supervisor, VM, and msbnet
//! processes and provides methods for lifecycle management (signals, wait).

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

/// Handle to a running supervisor process and its children.
pub struct SupervisorHandle {
    /// PID of the supervisor process (`msb supervisor`).
    supervisor_pid: u32,

    /// PID of the VM process (`msb microvm`).
    vm_pid: u32,

    /// PID of the msbnet process (if spawned).
    msbnet_pid: Option<u32>,

    /// Name of the sandbox this supervisor manages.
    sandbox_name: String,

    /// The supervisor child process handle.
    child: Child,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SupervisorHandle {
    /// Create a new supervisor handle.
    pub(crate) fn new(
        supervisor_pid: u32,
        vm_pid: u32,
        msbnet_pid: Option<u32>,
        sandbox_name: String,
        child: Child,
    ) -> Self {
        Self {
            supervisor_pid,
            vm_pid,
            msbnet_pid,
            sandbox_name,
            child,
        }
    }

    /// Get the supervisor PID.
    pub fn supervisor_pid(&self) -> u32 {
        self.supervisor_pid
    }

    /// Get the VM PID.
    pub fn vm_pid(&self) -> u32 {
        self.vm_pid
    }

    /// Get the msbnet PID, if running.
    pub fn msbnet_pid(&self) -> Option<u32> {
        self.msbnet_pid
    }

    /// Get the sandbox name.
    pub fn sandbox_name(&self) -> &str {
        &self.sandbox_name
    }

    /// Send SIGKILL to the VM process for immediate termination.
    pub fn kill_vm(&self) -> MicrosandboxResult<()> {
        signal::kill(Pid::from_raw(self.vm_pid as i32), Signal::SIGKILL)?;
        Ok(())
    }

    /// Send SIGUSR1 to the supervisor to trigger a graceful drain.
    pub fn drain_supervisor(&self) -> MicrosandboxResult<()> {
        signal::kill(Pid::from_raw(self.supervisor_pid as i32), Signal::SIGUSR1)?;
        Ok(())
    }

    /// Wait for the supervisor process to exit.
    pub async fn wait(&mut self) -> MicrosandboxResult<ExitStatus> {
        let status = self.child.wait().await?;
        Ok(status)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for SupervisorHandle {
    fn drop(&mut self) {
        // Safety net: send SIGTERM to the supervisor so child processes
        // are cleaned up if the handle is dropped without an explicit stop.
        if let Ok(None) = self.child.try_wait()
            && let Some(pid) = self.child.id()
        {
            let _ = signal::kill(Pid::from_raw(pid as i32), Signal::SIGTERM);
        }
    }
}
