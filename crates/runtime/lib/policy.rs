//! Child process and supervisor lifecycle policies.

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Action taken when a child process exits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
pub enum ExitAction {
    /// Kill all other children and shut down the supervisor.
    ShutdownAll,

    /// Restart the child (up to `max_restarts` within `restart_window_secs`).
    Restart,

    /// Log the exit and keep running.
    Ignore,
}

/// Policy for a single child process.
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
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
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ChildPolicy {
    /// Default policy for the VM process.
    ///
    /// VM exit triggers `ShutdownAll` — there's nothing to supervise without the VM.
    /// No grace period before SIGKILL: libkrun VMs have no persistent state to flush.
    pub fn vm_default() -> Self {
        Self {
            on_exit: ExitAction::ShutdownAll,
            max_restarts: 0,
            restart_delay_ms: 0,
            restart_window_secs: 0,
            shutdown_timeout_ms: 0,
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
        }
    }
}

impl Default for SupervisorPolicy {
    fn default() -> Self {
        Self {
            shutdown_mode: ShutdownMode::Graceful,
            grace_secs: 3,
            max_duration_secs: None,
            idle_timeout_secs: None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_supervisor_policy_serde_roundtrip() {
        let policy = SupervisorPolicy {
            shutdown_mode: ShutdownMode::Terminate,
            grace_secs: 30,
            max_duration_secs: Some(3600),
            idle_timeout_secs: Some(120),
        };

        let json = serde_json::to_string(&policy).unwrap();
        let decoded: SupervisorPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.shutdown_mode, ShutdownMode::Terminate);
        assert_eq!(decoded.grace_secs, 30);
        assert_eq!(decoded.max_duration_secs, Some(3600));
        assert_eq!(decoded.idle_timeout_secs, Some(120));
    }

    #[test]
    fn test_child_policies_serde_roundtrip() {
        let policies = ChildPolicies::default();

        let json = serde_json::to_string(&policies).unwrap();
        let decoded: ChildPolicies = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.vm.on_exit, ExitAction::ShutdownAll);
        assert_eq!(decoded.vm.shutdown_timeout_ms, 0);
    }

    #[test]
    fn test_default_supervisor_policy() {
        let policy = SupervisorPolicy::default();
        assert_eq!(policy.shutdown_mode, ShutdownMode::Graceful);
        assert_eq!(policy.grace_secs, 3);
        assert!(policy.max_duration_secs.is_none());
        assert!(policy.idle_timeout_secs.is_none());
    }

    #[test]
    fn test_default_child_policies() {
        let policies = ChildPolicies::default();

        // VM default: ShutdownAll, no restarts.
        assert_eq!(policies.vm.on_exit, ExitAction::ShutdownAll);
        assert_eq!(policies.vm.max_restarts, 0);
    }
}
