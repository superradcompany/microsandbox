//! Live resize status readback and convergence waiting.

use std::{sync::Arc, time::Duration};

use microsandbox_control_client::{
    CpuState, DEFAULT_REQUEST_TIMEOUT, GetCpuState, GetMemoryState, MemoryState,
};
use microsandbox_types::modify::{ResourceConvergenceState, ResourceKind, ResourceResizeStatus};
use tokio::time::Instant;

use crate::backend::{Backend, ControlSession, sandbox::SandboxIdentity};
use crate::error::Operation;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::SandboxId;
use super::status::running_status;

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
    identity: &SandboxIdentity,
) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
    match open_session(backend, name, identity).await? {
        Some(session) => read_checked(backend, name, identity, &session).await,
        None => Ok(Vec::new()),
    }
}

/// Poll until every resource is terminal. `None` waits without a deadline.
///
/// A zero timeout performs one check, bounded by the control request deadline.
/// A timeout carries the last completed read, or an empty list if none completed.
pub(crate) async fn wait_until_resized(
    backend: &Arc<dyn Backend>,
    name: &str,
    identity: &SandboxIdentity,
    timeout: Option<Duration>,
) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
    let started = Instant::now();
    let mut last = Vec::new();
    let wait = async {
        let Some(session) = open_session(backend, name, identity).await? else {
            return Ok(Vec::new());
        };
        loop {
            let status = read_checked(backend, name, identity, &session).await?;
            if resize_settled(&status) {
                return Ok(status);
            }
            last.clone_from(&status);
            let Some(delay) = next_poll_delay(timeout, started.elapsed()) else {
                return Err(resize_timeout(name, timeout, status));
            };
            tokio::time::sleep(delay).await;
        }
    };
    let Some(budget) = timeout.map(wait_budget) else {
        return wait.await;
    };
    let result = tokio::time::timeout(budget, wait).await;
    result.unwrap_or_else(|_| Err(resize_timeout(name, timeout, last)))
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

/// Format a MiB count, using GiB when it divides evenly.
pub(super) fn format_mib(mib: u32) -> String {
    if mib >= 1024 && mib.is_multiple_of(1024) {
        format!("{} GiB", mib / 1024)
    } else {
        format!("{mib} MiB")
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

async fn open_session(
    backend: &Arc<dyn Backend>,
    name: &str,
    identity: &SandboxIdentity,
) -> MicrosandboxResult<Option<ControlSession>> {
    let handle = backend.sandboxes().get(backend.clone(), name).await?;
    ensure_same_identity(name, identity, &handle.identity())?;
    if !running_status(handle.status_snapshot()) {
        return Ok(None);
    }
    let local = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxModify))?;
    local.control_session(name).await
}

async fn read_checked(
    backend: &Arc<dyn Backend>,
    name: &str,
    identity: &SandboxIdentity,
    session: &ControlSession,
) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
    let handle = backend.sandboxes().get(backend.clone(), name).await?;
    ensure_same_identity(name, identity, &handle.identity())?;
    read_resize_status(session).await
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

fn ensure_same_identity(
    name: &str,
    expected: &SandboxIdentity,
    actual: &SandboxIdentity,
) -> MicrosandboxResult<()> {
    if expected == actual {
        return Ok(());
    }
    Err(MicrosandboxError::SandboxReplaced {
        name: name.to_string(),
        expected: sandbox_id(expected).to_string(),
        actual: sandbox_id(actual).to_string(),
    })
}

fn sandbox_id(identity: &SandboxIdentity) -> SandboxId {
    match identity {
        SandboxIdentity::Local(id) => SandboxId::local(*id),
        SandboxIdentity::Cloud(id) => SandboxId::cloud(id),
    }
}

fn wait_budget(timeout: Duration) -> Duration {
    if timeout.is_zero() {
        DEFAULT_REQUEST_TIMEOUT
    } else {
        timeout
    }
}

fn next_poll_delay(timeout: Option<Duration>, elapsed: Duration) -> Option<Duration> {
    let Some(timeout) = timeout else {
        return Some(RESIZE_POLL_INTERVAL);
    };
    let remaining = timeout.saturating_sub(elapsed);
    (!remaining.is_zero()).then(|| remaining.min(RESIZE_POLL_INTERVAL))
}

fn resize_timeout(
    name: &str,
    timeout: Option<Duration>,
    status: Vec<ResourceResizeStatus>,
) -> MicrosandboxError {
    MicrosandboxError::ResizeTimeout {
        name: name.to_string(),
        timeout: timeout.unwrap_or_default(),
        status,
    }
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

    #[test]
    fn identity_check_rejects_a_reused_name() {
        let old = SandboxIdentity::Local(1);
        assert!(ensure_same_identity("reused", &old, &SandboxIdentity::Local(1)).is_ok());
        let error = ensure_same_identity("reused", &old, &SandboxIdentity::Local(2)).unwrap_err();
        assert!(matches!(
            error,
            MicrosandboxError::SandboxReplaced { name, expected, actual }
                if name == "reused" && expected == "local:1" && actual == "local:2"
        ));
    }

    #[test]
    fn zero_budget_still_allows_one_bounded_read() {
        assert_eq!(wait_budget(Duration::ZERO), DEFAULT_REQUEST_TIMEOUT);
        let budget = Duration::from_millis(5);
        assert_eq!(wait_budget(budget), budget);
    }

    #[test]
    fn poll_delay_respects_remaining_budget() {
        let second = Duration::from_secs(1);
        assert_eq!(
            next_poll_delay(None, Duration::from_secs(3600)),
            Some(RESIZE_POLL_INTERVAL)
        );
        assert_eq!(next_poll_delay(Some(Duration::ZERO), Duration::ZERO), None);
        assert_eq!(next_poll_delay(Some(second), second), None);
        assert_eq!(
            next_poll_delay(Some(second), Duration::from_millis(950)),
            Some(Duration::from_millis(50))
        );
        assert_eq!(
            next_poll_delay(Some(second), Duration::ZERO),
            Some(RESIZE_POLL_INTERVAL)
        );
    }

    #[test]
    fn timeout_error_carries_last_status() {
        let status = vec![cpu_resize_status(4, cpu(4, 2, 4))];
        let error = resize_timeout("api", Some(Duration::from_secs(2)), status.clone());
        assert!(matches!(
            error,
            MicrosandboxError::ResizeTimeout { name, timeout, status: last }
                if name == "api" && timeout == Duration::from_secs(2) && last == status
        ));
    }
}
