//! OCI lifecycle command validation.

use super::{OciResult, OciRuntimeError, OciState, OciStatus};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// OCI lifecycle operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciOperation {
    /// Create the container environment.
    Create,

    /// Start the configured init process.
    Start,

    /// Execute an additional process in the running container.
    Exec,

    /// Send a signal to the container init process.
    Kill,

    /// Delete resources created by `create`.
    Delete,

    /// Return current container state.
    State,

    /// Suspend the container.
    Pause,

    /// Resume the container.
    Resume,
}

/// State transition requested by an OCI operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OciTransition {
    /// Operation being performed.
    pub operation: OciOperation,

    /// Status before the operation.
    pub from: OciStatus,

    /// Status after the operation.
    pub to: OciStatus,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OciOperation {
    /// Operation name used in diagnostics.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Create => "create",
            Self::Start => "start",
            Self::Exec => "exec",
            Self::Kill => "kill",
            Self::Delete => "delete",
            Self::State => "state",
            Self::Pause => "pause",
            Self::Resume => "resume",
        }
    }

    /// Validate that this operation can run against the supplied state.
    pub fn validate(self, state: &OciState) -> OciResult<()> {
        let valid = match self {
            Self::Create => false,
            Self::Start => matches!(state.status, OciStatus::Created),
            Self::Exec => matches!(state.status, OciStatus::Running),
            Self::Kill => state.status.can_receive_signal(),
            Self::Delete => matches!(state.status, OciStatus::Stopped),
            Self::State => true,
            Self::Pause => matches!(state.status, OciStatus::Running),
            Self::Resume => matches!(state.status, OciStatus::Paused),
        };

        if valid {
            Ok(())
        } else {
            Err(OciRuntimeError::InvalidTransition {
                id: state.id.clone(),
                operation: self.as_str(),
                status: state.status.as_str().to_string(),
            })
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate and compute the next state for an OCI operation that has a direct status transition.
pub fn next_status(operation: OciOperation, state: &OciState) -> OciResult<OciStatus> {
    operation.validate(state)?;
    let next = match operation {
        OciOperation::Start => OciStatus::Running,
        OciOperation::Kill => OciStatus::Stopped,
        OciOperation::Pause => OciStatus::Paused,
        OciOperation::Resume => OciStatus::Running,
        OciOperation::State | OciOperation::Exec => state.status,
        OciOperation::Delete => state.status,
        OciOperation::Create => OciStatus::Created,
    };
    Ok(next)
}

/// Validate and return a transition descriptor for a direct status-changing operation.
pub fn transition(operation: OciOperation, state: &OciState) -> OciResult<OciTransition> {
    Ok(OciTransition {
        operation,
        from: state.status,
        to: next_status(operation, state)?,
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use chrono::Utc;

    use super::super::MicrosandboxState;
    use super::*;

    fn state(status: OciStatus) -> OciState {
        let mut state = OciState::created(
            "demo",
            "1.2.0",
            "/bundle",
            BTreeMap::new(),
            MicrosandboxState::new("oci-demo", "/state/demo", "/bundle/rootfs", Utc::now()),
        );
        state.status = status;
        state
    }

    #[test]
    fn start_only_accepts_created() {
        assert_eq!(
            next_status(OciOperation::Start, &state(OciStatus::Created)).expect("start"),
            OciStatus::Running
        );
        assert!(next_status(OciOperation::Start, &state(OciStatus::Running)).is_err());
        assert!(next_status(OciOperation::Start, &state(OciStatus::Stopped)).is_err());
    }

    #[test]
    fn docker_exec_requires_running_container() {
        assert_eq!(
            next_status(OciOperation::Exec, &state(OciStatus::Running)).expect("exec"),
            OciStatus::Running
        );
        assert!(next_status(OciOperation::Exec, &state(OciStatus::Created)).is_err());
        assert!(next_status(OciOperation::Exec, &state(OciStatus::Paused)).is_err());
    }

    #[test]
    fn pause_resume_cycle_matches_de_facto_runtime_behavior() {
        assert_eq!(
            next_status(OciOperation::Pause, &state(OciStatus::Running)).expect("pause"),
            OciStatus::Paused
        );
        assert_eq!(
            next_status(OciOperation::Resume, &state(OciStatus::Paused)).expect("resume"),
            OciStatus::Running
        );
        assert!(next_status(OciOperation::Pause, &state(OciStatus::Created)).is_err());
    }

    #[test]
    fn delete_only_accepts_stopped() {
        assert!(next_status(OciOperation::Delete, &state(OciStatus::Stopped)).is_ok());
        assert!(next_status(OciOperation::Delete, &state(OciStatus::Running)).is_err());
    }
}
