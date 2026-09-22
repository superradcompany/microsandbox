//! Live resize status readback and convergence waiting.

use std::{sync::Arc, time::Duration};

use microsandbox_control_client::{CpuState, GetCpuState, GetMemoryState, MemoryState};
use microsandbox_types::modify::{ResourceConvergenceState, ResourceKind, ResourceResizeStatus};
use tokio::time::Instant;

use crate::backend::{Backend, ControlSession};
use crate::error::Operation;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::modify::{format_mib, running_status};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const RESIZE_POLL_INTERVAL: Duration = Duration::from_millis(100);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read live resize status. Empty when the sandbox is not running or has no resize control.
pub(crate) async fn resize_status(
    backend: &Arc<dyn Backend>,
    name: &str,
) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
    match open_session(backend, name).await? {
        Some(session) => read_resize_status(&session).await,
        None => Ok(Vec::new()),
    }
}

/// Poll until every resource is terminal. `None` waits without a deadline.
pub(crate) async fn wait_until_resized(
    backend: &Arc<dyn Backend>,
    name: &str,
    timeout: Option<Duration>,
) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
    let started = Instant::now();
    let Some(session) = open_session(backend, name).await? else {
        return Ok(Vec::new());
    };
    loop {
        let status = read_resize_status(&session).await?;
        if resize_settled(&status) {
            return Ok(status);
        }
        let delay = match timeout {
            Some(timeout) => {
                let remaining = timeout.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    return Err(MicrosandboxError::ResizeTimeout {
                        name: name.to_string(),
                        timeout,
                        status,
                    });
                }
                remaining.min(RESIZE_POLL_INTERVAL)
            }
            None => RESIZE_POLL_INTERVAL,
        };
        tokio::time::sleep(delay).await;
    }
}

/// Applied once the guest and host enforcement both reach the accepted CPU target.
pub(crate) fn cpu_resize_status(requested: u32, state: CpuState) -> ResourceResizeStatus {
    let applied =
        state.actual_online == state.requested_online && state.enforced == state.requested_online;
    ResourceResizeStatus {
        resource: ResourceKind::Cpus,
        requested: requested.to_string(),
        actual: state.actual_online.to_string(),
        enforced: state.enforced.to_string(),
        state: converged(applied),
    }
}

/// Applied once plugged memory equals the accepted target, so shrinks wait for the guest.
pub(crate) fn memory_resize_status(requested_mib: u32, state: MemoryState) -> ResourceResizeStatus {
    ResourceResizeStatus {
        resource: ResourceKind::Memory,
        requested: format_mib(requested_mib),
        actual: format_mib(saturating_mib(state.current_mib)),
        enforced: format_mib(saturating_mib(state.target_mib)),
        state: converged(state.current_mib == state.target_mib),
    }
}

/// True when every resource is applied, refused, or failed.
pub(crate) fn resize_settled(status: &[ResourceResizeStatus]) -> bool {
    status.iter().all(|entry| entry.state.is_terminal())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

async fn open_session(
    backend: &Arc<dyn Backend>,
    name: &str,
) -> MicrosandboxResult<Option<ControlSession>> {
    let handle = backend.sandboxes().get(backend.clone(), name).await?;
    if !running_status(handle.status_snapshot()) {
        return Ok(None);
    }
    let local = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxModify))?;
    local.control_session(name).await
}

async fn read_resize_status(
    session: &ControlSession,
) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
    let caps = session.capabilities();
    let mut status = Vec::with_capacity(2);
    if caps.cpu_resize {
        let state = session
            .request(&GetCpuState)
            .await
            .map_err(MicrosandboxError::ControlClient)?;
        status.push(cpu_resize_status(state.requested_online, state));
    }
    if caps.memory_resize {
        let state = session
            .request(&GetMemoryState)
            .await
            .map_err(MicrosandboxError::ControlClient)?;
        status.push(memory_resize_status(
            saturating_mib(state.target_mib),
            state,
        ));
    }
    Ok(status)
}

fn converged(applied: bool) -> ResourceConvergenceState {
    if applied {
        ResourceConvergenceState::Applied
    } else {
        ResourceConvergenceState::Converging
    }
}

fn saturating_mib(mib: u64) -> u32 {
    u32::try_from(mib).unwrap_or(u32::MAX)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn cpu(requested_online: u32, actual_online: u32, enforced: u32) -> CpuState {
        CpuState {
            possible: 8,
            requested_online,
            actual_online,
            enforced,
        }
    }

    fn memory(target_mib: u64, current_mib: u64) -> MemoryState {
        MemoryState {
            boot_mib: 4096,
            target_mib,
            current_mib,
            max_mib: 32768,
        }
    }

    #[test]
    fn cpu_grow_is_converging_until_guest_onlines() {
        let status = cpu_resize_status(4, cpu(4, 2, 4));
        assert_eq!(status.state, ResourceConvergenceState::Converging);
        assert_eq!(status.requested, "4");
        assert_eq!(status.actual, "2");
        assert_eq!(status.enforced, "4");
    }

    #[test]
    fn cpu_shrink_is_converging_until_guest_offlines() {
        let status = cpu_resize_status(2, cpu(2, 4, 2));
        assert_eq!(status.state, ResourceConvergenceState::Converging);
        let status = cpu_resize_status(2, cpu(2, 2, 4));
        assert_eq!(status.state, ResourceConvergenceState::Converging);
    }

    #[test]
    fn cpu_applied_when_actual_and_enforced_match() {
        let status = cpu_resize_status(3, cpu(3, 3, 3));
        assert_eq!(status.state, ResourceConvergenceState::Applied);
        assert_eq!(status.resource, ResourceKind::Cpus);
    }

    #[test]
    fn cpu_applied_when_target_is_clamped() {
        let status = cpu_resize_status(8, cpu(6, 6, 6));
        assert_eq!(status.state, ResourceConvergenceState::Applied);
        assert_eq!(status.requested, "8");
        assert_eq!(status.actual, "6");
        let status = cpu_resize_status(8, cpu(6, 4, 6));
        assert_eq!(status.state, ResourceConvergenceState::Converging);
    }

    #[test]
    fn memory_grow_is_converging_until_plugged() {
        let status = memory_resize_status(16384, memory(16384, 8192));
        assert_eq!(status.state, ResourceConvergenceState::Converging);
        assert_eq!(status.requested, "16 GiB");
        assert_eq!(status.actual, "8 GiB");
        assert_eq!(status.enforced, "16 GiB");
    }

    #[test]
    fn memory_shrink_is_converging_until_released() {
        let status = memory_resize_status(8192, memory(8192, 16384));
        assert_eq!(status.state, ResourceConvergenceState::Converging);
    }

    #[test]
    fn memory_applied_only_when_equal() {
        let status = memory_resize_status(8000, memory(8192, 8192));
        assert_eq!(status.state, ResourceConvergenceState::Applied);
        assert_eq!(status.resource, ResourceKind::Memory);
        assert_eq!(status.requested, "8000 MiB");
        assert_eq!(status.enforced, "8 GiB");
    }

    #[test]
    fn settled_requires_every_resource_terminal() {
        assert!(resize_settled(&[]));
        let applied = cpu_resize_status(2, cpu(2, 2, 2));
        let converging = memory_resize_status(8192, memory(8192, 4096));
        assert!(resize_settled(std::slice::from_ref(&applied)));
        assert!(!resize_settled(&[applied.clone(), converging]));
        let refused = ResourceResizeStatus {
            state: ResourceConvergenceState::GuestRefused,
            ..applied.clone()
        };
        let failed = ResourceResizeStatus {
            state: ResourceConvergenceState::Failed,
            ..applied
        };
        assert!(resize_settled(&[refused, failed]));
    }
}
