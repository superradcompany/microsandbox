//! Live resize status readback and convergence waiting.

use std::{sync::Arc, time::Duration};

use microsandbox_control_client::{ControlClientError, DEFAULT_REQUEST_TIMEOUT, ManageResize};
use microsandbox_protocol::resize::{
    ResizeObservation, ResizeOperation, ResizeOutcome, ResizeRequest, ResizeResponse, ResizeTarget,
    ResizeTracking,
};
use microsandbox_types::modify::{ResourceConvergenceState, ResourceKind, ResourceResizeStatus};
use tokio::time::Instant;

use crate::backend::{Backend, ControlSession, sandbox::SandboxIdentity};
use crate::error::{Operation, ResizeWaitError, ResizeWaitFailure, UnsupportedReason};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Sandbox, SandboxId, SandboxStatus};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Total setup/read budget for a zero-timeout resize check, including binding lookup.
pub const DEFAULT_RESIZE_READ_TIMEOUT: Duration = DEFAULT_REQUEST_TIMEOUT;

const RESIZE_POLL_INTERVAL: Duration = Duration::from_millis(100);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Read the current live CPU and memory resize status.
    ///
    /// Returns an error when the sandbox is not running, and
    /// `Unsupported` when its runtime cannot report resize status.
    #[cfg(feature = "local")]
    pub async fn resize_status(&self) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        self::resize_status(&self.backend, &self.name, &self.identity()).await
    }

    /// Read the latest retained operation for each resource, including identity and evidence.
    ///
    /// Empty means no recorded request. These records can be passed to
    /// [`Self::wait_for_resize_operations`] without rebinding to later requests.
    #[cfg(feature = "local")]
    pub async fn resize_operations(&self) -> MicrosandboxResult<Vec<ResizeOperation>> {
        self::resize_operations(&self.backend, &self.name, &self.identity()).await
    }

    /// Wait for exact operations returned by `apply_with_resize_tracking`.
    ///
    /// May reconnect to the same runtime. Missing history or replacement is an error;
    /// a later request is never substituted. `None` waits without a deadline.
    #[cfg(feature = "local")]
    pub async fn wait_for_resize_operations(
        &self,
        operations: &[ResizeOperation],
        timeout: Option<Duration>,
    ) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        wait_for_operations(
            &self.backend,
            &self.name,
            &self.identity(),
            Some(operations),
            timeout,
        )
        .await
    }

    /// Wait for the operations selected at the first read to be guest-confirmed.
    ///
    /// Returns an error when the sandbox is not running, and
    /// `Unsupported` when its runtime cannot report resize status. Keeps polling
    /// while a guest never converges; use `wait_until_resized_with_timeout` to
    /// bound the wait.
    #[cfg(feature = "local")]
    pub async fn wait_until_resized(&self) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        self::wait_until_resized(&self.backend, &self.name, &self.identity(), None).await
    }

    /// Wait for the initially selected operations to be guest-confirmed within `timeout`.
    ///
    /// Returns an error when the sandbox is not running, and
    /// `Unsupported` when its runtime cannot report resize status. Expiry returns
    /// [`crate::MicrosandboxError::ResizeTimeout`] with the last observed status, which is empty when no read
    /// completed before the deadline.
    #[cfg(feature = "local")]
    pub async fn wait_until_resized_with_timeout(
        &self,
        timeout: std::time::Duration,
    ) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        self::wait_until_resized(&self.backend, &self.name, &self.identity(), Some(timeout)).await
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read the latest retained resize status; empty means no recorded request.
pub(crate) async fn resize_status(
    backend: &Arc<dyn Backend>,
    name: &str,
    identity: &SandboxIdentity,
) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
    Ok(resize_operations(backend, name, identity)
        .await?
        .into_iter()
        .map(|operation| operation.status)
        .collect())
}

/// Read identities and status together without selecting or applying a new target.
pub(crate) async fn resize_operations(
    backend: &Arc<dyn Backend>,
    name: &str,
    identity: &SandboxIdentity,
) -> MicrosandboxResult<Vec<ResizeOperation>> {
    let session = open_session(backend, name, identity).await?;
    let operations = current_operations(&session).await?;
    ensure_same_sandbox(backend, name, identity).await?;
    Ok(operations)
}

/// Poll until every resource is terminal. `None` waits without a deadline.
///
/// A zero timeout performs one check, bounded by the control request deadline.
/// A timeout carries the latest completed read per resource, or an empty list if none completed.
pub(crate) async fn wait_until_resized(
    backend: &Arc<dyn Backend>,
    name: &str,
    identity: &SandboxIdentity,
    timeout: Option<Duration>,
) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
    wait_for_operations(backend, name, identity, None, timeout).await
}

pub(crate) async fn wait_for_operations(
    backend: &Arc<dyn Backend>,
    name: &str,
    identity: &SandboxIdentity,
    selected: Option<&[ResizeOperation]>,
    timeout: Option<Duration>,
) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
    wait_for_operations_with_budget(
        backend,
        name,
        identity,
        selected,
        timeout,
        timeout.map(wait_budget),
    )
    .await
}

/// Keep the single-check/polling policy separate from its remaining transport budget.
/// Bindings can charge lookup time without placing a competing timer around partial replies.
pub(crate) async fn wait_for_operations_with_budget(
    backend: &Arc<dyn Backend>,
    name: &str,
    identity: &SandboxIdentity,
    selected: Option<&[ResizeOperation]>,
    timeout: Option<Duration>,
    budget: Option<Duration>,
) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
    let started = Instant::now();
    let mut last = Vec::new();
    let mut reading_id = None;
    let wait = async {
        let session = open_session(backend, name, identity).await?;
        // Bind once. A later request, including an identical target, must not
        // become the operation this wait was supposed to observe.
        let mut operations = match selected {
            Some(operations) => {
                // Re-read even a retained Applied record: callers may reconnect with an
                // expired ID or a replaced runtime, so supplied result bytes are not proof.
                let mut current = Vec::with_capacity(operations.len());
                if operations.is_empty() || operations.len() > 2 {
                    return Err(invalid_resize_response());
                }
                for operation in operations {
                    reading_id = Some(operation.id.clone());
                    let response = session
                        .request(&ManageResize(ResizeRequest::Read {
                            runtime_boot_id: operation.runtime_boot_id.clone(),
                            id: operation.id.clone(),
                        }))
                        .await
                        .map_err(MicrosandboxError::ControlClient)?;
                    let operation = checked_operation(operation, response)?;
                    // A subsequent resource read can exhaust the deadline. Retain this
                    // validated reply now, without inventing progress for unread resources.
                    last.push(operation.status.clone());
                    current.push(operation);
                    reading_id = None;
                }
                current
            }
            None => {
                let current = current_operations(&session).await?;
                last = current
                    .iter()
                    .map(|operation| operation.status.clone())
                    .collect();
                current
            }
        };
        loop {
            ensure_same_sandbox(backend, name, identity).await?;
            if operations_settled(&operations)? {
                return Ok(last.clone());
            }
            let Some(delay) = next_poll_delay(timeout, started.elapsed()) else {
                return Err(resize_timeout(name, timeout, last.clone()));
            };
            tokio::time::sleep(delay).await;
            for (index, operation) in operations.iter_mut().enumerate() {
                reading_id = Some(operation.id.clone());
                let response = session
                    .request(&ManageResize(ResizeRequest::Read {
                        runtime_boot_id: operation.runtime_boot_id.clone(),
                        id: operation.id.clone(),
                    }))
                    .await
                    .map_err(MicrosandboxError::ControlClient)?;
                *operation = checked_operation(operation, response)?;
                // Preserve the previous reply for resources not yet read on this pass.
                last[index] = operation.status.clone();
                reading_id = None;
            }
        }
    };
    let result = match budget {
        Some(budget) => tokio::time::timeout(budget, wait)
            .await
            .unwrap_or_else(|_| Err(resize_timeout(name, timeout, last.clone()))),
        None => wait.await,
    };
    result.map_err(|error| contextualize_wait_error(name, reading_id, last, error))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

pub(super) async fn begin_tracking(
    session: &ControlSession,
) -> MicrosandboxResult<Option<ResizeTracking>> {
    if !session.capabilities().resize_operations {
        return Ok(None);
    }
    let response = session
        .request(&ManageResize(ResizeRequest::Hello))
        .await
        .map_err(MicrosandboxError::ControlClient)?;
    if !response.operations.is_empty()
        || response.tracking.runtime_boot_id.is_empty()
        || response.tracking.max_retained < 2
    {
        return Err(invalid_resize_response());
    }
    Ok(Some(response.tracking))
}

pub(super) async fn apply_target(
    session: &ControlSession,
    tracking: &ResizeTracking,
    target: ResizeTarget,
) -> MicrosandboxResult<ResizeOperation> {
    let response = session
        .request(&ManageResize(ResizeRequest::Apply {
            runtime_boot_id: tracking.runtime_boot_id.clone(),
            target: target.clone(),
        }))
        .await
        .map_err(MicrosandboxError::ControlClient)?;
    accepted_operation(tracking, target, response)
}

fn accepted_operation(
    tracking: &ResizeTracking,
    target: ResizeTarget,
    response: ResizeResponse,
) -> MicrosandboxResult<ResizeOperation> {
    let invalid = || {
        MicrosandboxError::Runtime(
        "resize may have been applied, but its operation identity was not valid; the request was not retried".into())
    };
    if response.tracking != *tracking || response.operations.len() != 1 {
        return Err(invalid());
    }
    let operation = response.operations.into_iter().next().unwrap();
    let same_resource = matches!(
        (&target, &operation.accepted_target),
        (ResizeTarget::Cpus { .. }, ResizeTarget::Cpus { .. })
            | (ResizeTarget::Memory { .. }, ResizeTarget::Memory { .. })
    );
    let matching_status = matches!(
        (&target, operation.status.resource),
        (ResizeTarget::Cpus { .. }, ResourceKind::Cpus)
            | (ResizeTarget::Memory { .. }, ResourceKind::Memory)
    );
    if !matching_status
        || operation.id.is_empty()
        || operation.id.len() > 128
        || !operation.id.bytes().all(|byte| byte.is_ascii_graphic())
        || operation.generation == 0
        || operation.runtime_boot_id != tracking.runtime_boot_id
        || operation.requested_target != target
        || !same_resource
        || operation.outcome != ResizeOutcome::Pending
        || operation.status.state != ResourceConvergenceState::Accepted
    {
        return Err(invalid());
    }
    Ok(operation)
}

async fn open_session(
    backend: &Arc<dyn Backend>,
    name: &str,
    identity: &SandboxIdentity,
) -> MicrosandboxResult<ControlSession> {
    let handle = backend.sandboxes().get(backend.clone(), name).await?;
    ensure_same_identity(name, identity, &handle.identity())?;
    if !matches!(
        handle.status_snapshot(),
        SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused
    ) {
        return Err(MicrosandboxError::SandboxNotRunning(name.into()));
    }
    let local = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::local_only(Operation::SandboxModify))?;
    let session = local
        .control_session(name)
        .await?
        .ok_or_else(resize_status_unsupported)?;
    let caps = session.capabilities();
    if !caps.resize_operations {
        return Err(resize_status_unsupported());
    }
    Ok(session)
}

fn resize_status_unsupported() -> MicrosandboxError {
    MicrosandboxError::unsupported(
        Operation::SandboxModify,
        UnsupportedReason::NotAvailable(
            "this runtime and guest combination cannot confirm live resize completion".into(),
        ),
    )
}

async fn ensure_same_sandbox(
    backend: &Arc<dyn Backend>,
    name: &str,
    identity: &SandboxIdentity,
) -> MicrosandboxResult<()> {
    let handle = backend.sandboxes().get(backend.clone(), name).await?;
    ensure_same_identity(name, identity, &handle.identity())
}

async fn current_operations(session: &ControlSession) -> MicrosandboxResult<Vec<ResizeOperation>> {
    let hello = session
        .request(&ManageResize(ResizeRequest::Hello))
        .await
        .map_err(MicrosandboxError::ControlClient)?;
    let response = session
        .request(&ManageResize(ResizeRequest::Current {
            runtime_boot_id: hello.tracking.runtime_boot_id.clone(),
        }))
        .await
        .map_err(MicrosandboxError::ControlClient)?;
    if response.tracking != hello.tracking
        || response.operations.len() > 2
        || response
            .operations
            .iter()
            .any(|operation| operation.runtime_boot_id != hello.tracking.runtime_boot_id)
    {
        return Err(invalid_resize_response());
    }
    for operation in &response.operations {
        validate_completion_observation(operation)?;
    }
    Ok(response.operations)
}

fn checked_operation(
    expected: &ResizeOperation,
    response: ResizeResponse,
) -> MicrosandboxResult<ResizeOperation> {
    let mut operations = response.operations;
    if response.tracking.runtime_boot_id != expected.runtime_boot_id || operations.len() != 1 {
        return Err(invalid_resize_response());
    }
    let operation = operations.pop().unwrap();
    if operation.id != expected.id
        || operation.runtime_boot_id != expected.runtime_boot_id
        || operation.generation != expected.generation
        || operation.requested_target != expected.requested_target
        || operation.accepted_target != expected.accepted_target
        || operation.status.resource != expected.status.resource
        || operation.status.requested != expected.status.requested
    {
        return Err(invalid_resize_response());
    }
    // Reject contradictory completion before callers retain this reply as last-known progress.
    validate_completion_observation(&operation)?;
    Ok(operation)
}

fn invalid_resize_response() -> MicrosandboxError {
    MicrosandboxError::ResizeWait(Box::new(ResizeWaitError::new(
        ResizeWaitFailure::InvalidResponse,
        MicrosandboxError::Runtime("resize response did not match the selected operation".into()),
    )))
}

/// Completion is meaningful only with an available observation and matching resource state.
fn validate_completion_observation(operation: &ResizeOperation) -> MicrosandboxResult<()> {
    if operation.outcome == ResizeOutcome::Applied
        && (operation.observation != ResizeObservation::Available
            || operation.status.state != ResourceConvergenceState::Applied)
    {
        return Err(invalid_resize_response());
    }
    Ok(())
}

fn operations_settled(operations: &[ResizeOperation]) -> MicrosandboxResult<bool> {
    if operations.is_empty() {
        return Err(MicrosandboxError::unsupported(
            Operation::SandboxModify,
            UnsupportedReason::NotAvailable(
                "no retained resize operation is available to wait for".into(),
            ),
        ));
    }
    for operation in operations {
        if operation.outcome == ResizeOutcome::Superseded {
            let mut error = ResizeWaitError::new(
                ResizeWaitFailure::Superseded,
                MicrosandboxError::Runtime(format!(
                    "resize operation {} was superseded by a later request",
                    operation.id
                )),
            );
            error.operation_id = Some(operation.id.clone());
            return Err(MicrosandboxError::ResizeWait(Box::new(error)));
        }
        validate_completion_observation(operation)?;
        if operation.outcome != ResizeOutcome::Applied
            && operation.observation == ResizeObservation::Unsupported
        {
            return Err(resize_status_unsupported());
        }
    }
    Ok(operations
        .iter()
        .all(|operation| operation.outcome == ResizeOutcome::Applied))
}

/// Enrich errors only at the wait boundary. Apply failures retain their delivery semantics,
/// and an unrecognized peer code must not become a guessed terminal operation outcome.
fn contextualize_wait_error(
    name: &str,
    reading_id: Option<String>,
    status: Vec<ResourceResizeStatus>,
    error: MicrosandboxError,
) -> MicrosandboxError {
    let mut failure = match error {
        MicrosandboxError::ResizeWait(failure) => failure,
        error => {
            let reason = match &error {
                MicrosandboxError::SandboxNotRunning(_)
                | MicrosandboxError::SandboxNotFound(_)
                | MicrosandboxError::SandboxReplaced { .. } => ResizeWaitFailure::Interrupted,
                MicrosandboxError::ControlClient(cause) => match cause.as_ref() {
                    ControlClientError::RuntimeChanged => ResizeWaitFailure::Interrupted,
                    ControlClientError::Peer { error: peer, .. } => match peer.code.as_str() {
                        "runtime_changed" => ResizeWaitFailure::Interrupted,
                        "resize_history_unavailable" => ResizeWaitFailure::HistoryUnavailable,
                        _ => return error,
                    },
                    ControlClientError::Client(_) => ResizeWaitFailure::ObservationUnavailable,
                    ControlClientError::InvalidResponse { .. }
                    | ControlClientError::InvalidJsonResponse { .. } => {
                        ResizeWaitFailure::InvalidResponse
                    }
                    _ => return error,
                },
                _ => return error,
            };
            Box::new(ResizeWaitError::new(reason, error))
        }
    };
    failure.sandbox = Some(name.into());
    if failure.operation_id.is_none() {
        failure.operation_id = reading_id;
    }
    failure.status = status;
    MicrosandboxError::ResizeWait(failure)
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
        DEFAULT_RESIZE_READ_TIMEOUT
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn operation(outcome: ResizeOutcome, observation: ResizeObservation) -> ResizeOperation {
        ResizeOperation {
            id: "first".into(),
            runtime_boot_id: "boot".into(),
            generation: 1,
            requested_target: ResizeTarget::Cpus { online: 4 },
            accepted_target: ResizeTarget::Cpus { online: 4 },
            status: ResourceResizeStatus {
                resource: ResourceKind::Cpus,
                requested: "4".into(),
                actual: "4".into(),
                enforced: "4".into(),
                state: if outcome == ResizeOutcome::Applied {
                    ResourceConvergenceState::Applied
                } else {
                    ResourceConvergenceState::Accepted
                },
            },
            outcome,
            observation,
        }
    }

    #[test]
    fn apply_reply_requires_the_dispatched_target_and_a_fresh_pending_identity() {
        let tracking = ResizeTracking {
            runtime_boot_id: "boot".into(),
            max_retained: 256,
        };
        let accepted = operation(ResizeOutcome::Pending, ResizeObservation::Unavailable);
        let response = |operation| ResizeResponse {
            tracking: tracking.clone(),
            operations: vec![operation],
        };
        assert_eq!(
            accepted_operation(
                &tracking,
                accepted.requested_target.clone(),
                response(accepted.clone())
            )
            .unwrap(),
            accepted
        );
        assert!(
            accepted_operation(
                &tracking,
                ResizeTarget::Cpus { online: 8 },
                response(accepted.clone())
            )
            .is_err()
        );
        for case in 0..5 {
            let mut invalid = accepted.clone();
            match case {
                0 => invalid.runtime_boot_id = "replacement".into(),
                1 => invalid.id.clear(),
                2 => invalid.generation = 0,
                3 => invalid.outcome = ResizeOutcome::Applied,
                _ => invalid.status.resource = ResourceKind::Memory,
            }
            let error = accepted_operation(
                &tracking,
                accepted.requested_target.clone(),
                response(invalid),
            )
            .unwrap_err();
            assert!(error.to_string().contains("may have been applied"));
        }
    }

    #[test]
    fn absent_unsupported_paused_and_superseded_are_never_completion() {
        assert!(operations_settled(&[]).is_err());
        for observation in [ResizeObservation::Unavailable, ResizeObservation::Paused] {
            assert!(
                !operations_settled(&[operation(ResizeOutcome::Pending, observation)]).unwrap()
            );
            assert!(operations_settled(&[operation(ResizeOutcome::Applied, observation)]).is_err());
        }
        assert!(
            operations_settled(&[operation(
                ResizeOutcome::Pending,
                ResizeObservation::Unsupported
            )])
            .is_err()
        );
        assert!(
            operations_settled(&[operation(
                ResizeOutcome::Superseded,
                ResizeObservation::Available
            )])
            .is_err()
        );
        assert!(
            operations_settled(&[operation(
                ResizeOutcome::Applied,
                ResizeObservation::Available
            )])
            .unwrap()
        );
    }

    #[test]
    fn readback_rejects_same_target_aba_runtime_replacement_and_missing_history() {
        let expected = operation(ResizeOutcome::Pending, ResizeObservation::Available);
        let reply = |records| ResizeResponse {
            tracking: ResizeTracking {
                runtime_boot_id: "boot".into(),
                max_retained: 256,
            },
            operations: records,
        };
        assert!(checked_operation(&expected, reply(vec![])).is_err());
        let mut replacement = expected.clone();
        replacement.id = "second".into();
        assert!(checked_operation(&expected, reply(vec![replacement])).is_err());
        let mut replacement = expected.clone();
        replacement.generation += 1;
        assert!(checked_operation(&expected, reply(vec![replacement])).is_err());
        let mut response = reply(vec![expected.clone()]);
        response.tracking.runtime_boot_id = "new-boot".into();
        assert!(checked_operation(&expected, response).is_err());
        let applied = operation(ResizeOutcome::Applied, ResizeObservation::Available);
        assert_eq!(
            checked_operation(&expected, reply(vec![applied.clone()])).unwrap(),
            applied
        );
    }

    #[test]
    fn contradictory_completion_is_rejected_before_retaining_progress() {
        let expected = operation(ResizeOutcome::Pending, ResizeObservation::Available);
        for observation in [
            ResizeObservation::Unavailable,
            ResizeObservation::Paused,
            ResizeObservation::Unsupported,
        ] {
            let response = ResizeResponse {
                tracking: ResizeTracking {
                    runtime_boot_id: "boot".into(),
                    max_retained: 256,
                },
                operations: vec![operation(ResizeOutcome::Applied, observation)],
            };
            assert!(matches!(
                checked_operation(&expected, response),
                Err(MicrosandboxError::ResizeWait(_))
            ));
        }
        let mut inconsistent = operation(ResizeOutcome::Applied, ResizeObservation::Available);
        inconsistent.status.state = ResourceConvergenceState::Accepted;
        assert!(validate_completion_observation(&inconsistent).is_err());
    }

    #[test]
    fn structured_peer_codes_preserve_unknown_codes_and_original_frames() {
        use microsandbox_protocol::{
            codec::RawFrame,
            control::{ControlError, ErrorEffect},
            wire::Envelope,
        };
        use microsandbox_protocol_client::Message;

        for (code, expected) in [
            ("runtime_changed", Some(ResizeWaitFailure::Interrupted)),
            (
                "resize_history_unavailable",
                Some(ResizeWaitFailure::HistoryUnavailable),
            ),
            ("future_peer_code", None),
        ] {
            let source = Arc::new(ControlClientError::Peer {
                error: ControlError {
                    code: code.into(),
                    message: "peer detail".into(),
                    effect: ErrorEffect::None,
                },
                response: Box::new(Message::new(
                    RawFrame {
                        id: 7,
                        flags: 0,
                        body: vec![9, 8, 7],
                    },
                    Envelope {
                        v: 2,
                        t: "control.error".into(),
                        p: vec![],
                    },
                )),
            });
            let error = contextualize_wait_error(
                "box",
                Some("selected".into()),
                vec![],
                MicrosandboxError::ControlClient(source.clone()),
            );
            match (expected, error) {
                (Some(reason), MicrosandboxError::ResizeWait(details)) => {
                    assert_eq!(details.reason, reason);
                    let Some(cause) = details.cause else {
                        panic!("lost cause")
                    };
                    let MicrosandboxError::ControlClient(actual) = *cause else {
                        panic!("changed cause")
                    };
                    assert!(Arc::ptr_eq(&actual, &source));
                }
                (None, MicrosandboxError::ControlClient(actual)) => {
                    assert!(Arc::ptr_eq(&actual, &source))
                }
                _ => panic!("misclassified peer code"),
            }
        }
    }

    #[test]
    fn wait_errors_preserve_cause_identity_and_only_verified_status() {
        use std::error::Error;

        let confirmed = operation(ResizeOutcome::Applied, ResizeObservation::Available).status;
        let original =
            MicrosandboxError::ControlClient(Arc::new(ControlClientError::RuntimeChanged));
        let diagnostic = original.to_string();
        let wrapped = contextualize_wait_error(
            "box",
            Some("selected".into()),
            vec![confirmed.clone()],
            original,
        );
        let MicrosandboxError::ResizeWait(details) = wrapped else {
            panic!("missing details")
        };
        assert_eq!(details.reason, ResizeWaitFailure::Interrupted);
        assert_eq!(details.sandbox.as_deref(), Some("box"));
        assert_eq!(details.operation_id.as_deref(), Some("selected"));
        assert_eq!(details.status, vec![confirmed]);
        assert_eq!(details.to_string(), diagnostic);
        assert!(details.source().is_some());
        let payload = serde_json::to_value(details).unwrap();
        assert_eq!(payload["reason"], "interrupted");
        assert!(payload.get("cause").is_none());

        let superseded = operation(ResizeOutcome::Superseded, ResizeObservation::Available);
        let error = operations_settled(&[superseded]).unwrap_err();
        let MicrosandboxError::ResizeWait(details) =
            contextualize_wait_error("box", None, vec![], error)
        else {
            panic!("missing supersession")
        };
        assert_eq!(details.reason, ResizeWaitFailure::Superseded);
        assert_eq!(details.operation_id.as_deref(), Some("first"));
        assert!(details.status.is_empty());
        assert!(matches!(
            contextualize_wait_error("box", None, vec![], resize_status_unsupported()),
            MicrosandboxError::Unsupported { .. }
        ));
        let timeout = resize_timeout("box", Some(Duration::ZERO), vec![]);
        assert!(matches!(
            contextualize_wait_error("box", None, vec![], timeout),
            MicrosandboxError::ResizeTimeout { .. }
        ));
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
        let status = vec![operation(ResizeOutcome::Pending, ResizeObservation::Available).status];
        let error = resize_timeout("api", Some(Duration::from_secs(2)), status.clone());
        assert!(matches!(
            error,
            MicrosandboxError::ResizeTimeout { name, timeout, status: last }
                if name == "api" && timeout == Duration::from_secs(2) && last == status
        ));
    }
}

#[cfg(all(test, unix))]
#[path = "resize_wait_tests.rs"]
mod wait_tests;
