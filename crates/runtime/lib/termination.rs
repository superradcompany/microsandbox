//! Termination reason tracking for sandbox lifecycle.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The reason a sandbox terminated.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TerminationReason {
    /// VM exited with code 0 (guest shutdown cleanly).
    VmCompleted,

    /// VM exited with non-zero code or was killed by signal.
    VmFailed,

    /// msbnet restart limit exhausted, triggered ShutdownAll.
    MsbnetRestartsExhausted,

    /// Sandbox exceeded `max_duration_secs`.
    MaxDurationExceeded,

    /// agentd reported no activity for `idle_timeout_secs`.
    IdleTimeout,

    /// SIGUSR1 received (explicit drain request).
    DrainRequested,

    /// SIGTERM/SIGINT received from external source.
    SupervisorSignal,

    /// Supervisor internal error.
    InternalError,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TerminationReason {
    /// Returns the string representation for database storage.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::VmCompleted => "vm_completed",
            Self::VmFailed => "vm_failed",
            Self::MsbnetRestartsExhausted => "msbnet_restarts_exhausted",
            Self::MaxDurationExceeded => "max_duration_exceeded",
            Self::IdleTimeout => "idle_timeout",
            Self::DrainRequested => "drain_requested",
            Self::SupervisorSignal => "supervisor_signal",
            Self::InternalError => "internal_error",
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Display for TerminationReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
