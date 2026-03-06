//! Child process monitoring with restart tracking.
//!
//! Each child (VM, msbnet) is tracked as a `ChildProcess` with its lifecycle
//! policy and restart state. The supervisor polls children and applies policies
//! on exit.

use nix::sys::signal::Signal;
use nix::unistd::Pid;

use crate::policy::ChildPolicy;
use crate::RuntimeResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Tracks a child process with its policy and restart state.
pub struct ChildProcess {
    /// Display name (e.g., "vm", "msbnet").
    name: String,

    /// Process ID, if currently running.
    pid: Option<u32>,

    /// The lifecycle policy for this child.
    policy: ChildPolicy,

    /// Whether this child has exited.
    exited: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ChildProcess {
    /// Create a new child process monitor.
    pub fn new(pid: u32, name: String, policy: ChildPolicy) -> Self {
        Self {
            name,
            pid: Some(pid),
            policy,
            exited: false,
        }
    }

    /// Returns the display name of this child.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the PID of this child, if running.
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// Returns the policy for this child.
    pub fn policy(&self) -> &ChildPolicy {
        &self.policy
    }

    /// Returns whether the child has exited.
    pub fn has_exited(&self) -> bool {
        self.exited
    }

    /// Mark this child as exited.
    pub fn mark_exited(&mut self) {
        self.exited = true;
        self.pid = None;
    }

    /// Send a signal to the process group of this child.
    ///
    /// Uses negative PID to target the entire process group, ensuring
    /// grandchildren are also signaled.
    pub fn signal_group(&self, signal: Signal) -> RuntimeResult<()> {
        if let Some(pid) = self.pid {
            tracing::debug!(
                child = %self.name,
                pid,
                ?signal,
                "sending signal to process group",
            );
            let pid_i32 = i32::try_from(pid).map_err(|_| {
                crate::RuntimeError::Custom(format!("PID {pid} exceeds i32 range"))
            })?;
            nix::sys::signal::kill(Pid::from_raw(-pid_i32), signal)?;
        }
        Ok(())
    }
}
