//! Child process and supervisor lifecycle policies.
//!
//! These types are serialized as JSON and passed to the supervisor via CLI args.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Action taken when a child process exits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ExitAction {
    /// Kill all other children and shut down the supervisor.
    ShutdownAll,

    /// Restart the child (up to `max_restarts` within `restart_window_secs`).
    Restart,

    /// Log the exit and keep running.
    Ignore,
}

/// Policy for a single child process (VM or msbnet).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildPolicy {
    /// Action to take when the child exits.
    pub on_exit: ExitAction,

    /// Maximum restart attempts before falling back to `ShutdownAll`.
    pub max_restarts: u32,

    /// Delay in milliseconds between restart attempts.
    pub restart_delay_ms: u64,

    /// Window in seconds for counting restart attempts (counter resets after).
    pub restart_window_secs: u64,

    /// Grace period in milliseconds before SIGKILL on shutdown.
    pub shutdown_timeout_ms: u64,
}

/// Shutdown mode for the supervisor drain sequence.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ShutdownMode {
    /// Wait for voluntary exit, then SIGTERM, then SIGKILL.
    Graceful,

    /// Send SIGTERM immediately, then SIGKILL after grace period.
    Terminate,

    /// Send SIGKILL immediately.
    Kill,
}

/// Supervisor-level lifecycle policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SupervisorPolicy {
    /// How to shut down children when drain is triggered.
    pub shutdown_mode: ShutdownMode,

    /// Grace period in seconds between escalation steps during drain.
    pub grace_secs: u64,

    /// Hard cap on total sandbox lifetime in seconds. `None` = run forever.
    pub max_duration_secs: Option<u64>,

    /// Idle timeout in seconds. `None` = no idle detection.
    pub idle_timeout_secs: Option<u64>,
}

/// Combined child policies for all managed processes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChildPolicies {
    /// Policy for the VM process.
    pub vm: ChildPolicy,

    /// Policy for the msbnet process.
    pub msbnet: ChildPolicy,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ChildPolicy {
    /// Default policy for the VM process.
    ///
    /// VM exit triggers `ShutdownAll` — there's nothing to supervise without the VM.
    pub fn vm_default() -> Self {
        Self {
            on_exit: ExitAction::ShutdownAll,
            max_restarts: 0,
            restart_delay_ms: 0,
            restart_window_secs: 0,
            shutdown_timeout_ms: 5000,
        }
    }

    /// Default policy for the msbnet process.
    ///
    /// msbnet is restarted up to 3 times within a 60-second window.
    pub fn msbnet_default() -> Self {
        Self {
            on_exit: ExitAction::Restart,
            max_restarts: 3,
            restart_delay_ms: 1000,
            restart_window_secs: 60,
            shutdown_timeout_ms: 2000,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ChildPolicies {
    fn default() -> Self {
        Self {
            vm: ChildPolicy::vm_default(),
            msbnet: ChildPolicy::msbnet_default(),
        }
    }
}

impl Default for SupervisorPolicy {
    fn default() -> Self {
        Self {
            shutdown_mode: ShutdownMode::Graceful,
            grace_secs: 15,
            max_duration_secs: None,
            idle_timeout_secs: None,
        }
    }
}
