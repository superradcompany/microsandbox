//! Local-only capabilities remain fallible in a remote-only build.

use std::time::Duration;

use microsandbox_protocol::resize::ResizeOperation;
use microsandbox_types::modify::ResourceResizeStatus;

use super::{Sandbox, SandboxMetrics, SandboxPingResult, SandboxRecord, SandboxTouchResult};
use crate::{MicrosandboxError, MicrosandboxResult, Operation};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Total setup/read budget for a zero-timeout resize check, including binding lookup.
pub const DEFAULT_RESIZE_READ_TIMEOUT: Duration =
    microsandbox_control_client::DEFAULT_REQUEST_TIMEOUT;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl crate::Sandboxes {
    /// Internal CLI lookup on this destination.
    #[doc(hidden)]
    pub async fn get_for_control(&self, name: &str) -> MicrosandboxResult<SandboxRecord> {
        self.context
            .sandbox_ops()
            .get(self.context.clone(), name)
            .await
    }
}

impl Sandbox {
    /// Live resize observation requires the local provider.
    pub async fn resize_status(&self) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        Err(MicrosandboxError::local_only(Operation::SandboxModify))
    }

    /// Retained resize operation identities require the local provider.
    pub async fn resize_operations(&self) -> MicrosandboxResult<Vec<ResizeOperation>> {
        Err(MicrosandboxError::local_only(Operation::SandboxModify))
    }

    /// Waiting for retained resize operations requires the local provider.
    pub async fn wait_for_resize_operations(
        &self,
        _operations: &[ResizeOperation],
        _timeout: Option<Duration>,
    ) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        Err(MicrosandboxError::local_only(Operation::SandboxModify))
    }

    /// Live resize convergence requires the local provider.
    pub async fn wait_until_resized(&self) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        Err(MicrosandboxError::local_only(Operation::SandboxModify))
    }

    /// Live resize convergence requires the local provider, including a zero-timeout check.
    pub async fn wait_until_resized_with_timeout(
        &self,
        _timeout: Duration,
    ) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        Err(MicrosandboxError::local_only(Operation::SandboxModify))
    }

    #[doc(hidden)]
    pub async fn get_for_control(name: &str) -> MicrosandboxResult<SandboxRecord> {
        Self::get_record(name).await
    }

    /// Host process removal requires the local provider.
    pub async fn remove_persisted(&self) -> MicrosandboxResult<()> {
        Err(MicrosandboxError::local_only(
            Operation::SandboxRemovePersisted,
        ))
    }
    /// Host liveness probing requires the local provider.
    pub async fn ping(&self) -> MicrosandboxResult<SandboxPingResult> {
        Err(MicrosandboxError::local_only(Operation::SandboxPing))
    }
    /// Host activity notification requires the local provider.
    pub async fn touch(&self) -> MicrosandboxResult<SandboxTouchResult> {
        Err(MicrosandboxError::local_only(Operation::SandboxTouch))
    }
    /// Resident VM pause requires the local provider.
    pub async fn pause(&self) -> MicrosandboxResult<()> {
        Err(MicrosandboxError::local_only(Operation::SandboxPause))
    }
    /// Resident VM pause requires the local provider.
    pub async fn pause_with_guest_flush(
        &self,
        _policy: microsandbox_types::GuestFlush,
    ) -> MicrosandboxResult<()> {
        self.pause().await
    }
    /// Resident VM resume requires the local provider.
    pub async fn resume(&self) -> MicrosandboxResult<()> {
        Err(MicrosandboxError::local_only(Operation::SandboxResume))
    }
    /// Host process exit status requires the local provider; use wait_until_stopped remotely.
    pub async fn wait(&self) -> MicrosandboxResult<std::process::ExitStatus> {
        Err(MicrosandboxError::local_only(Operation::SandboxWait))
    }
    /// Host process exit status requires the local provider.
    pub async fn stop_and_wait(&self) -> MicrosandboxResult<std::process::ExitStatus> {
        Err(MicrosandboxError::local_only(Operation::SandboxStopAndWait))
    }
}

impl SandboxRecord {
    /// Live resize observation requires the local provider regardless of the read budget.
    #[doc(hidden)]
    pub async fn check_resize_operations_with_budget(
        &self,
        _operations: Option<&[ResizeOperation]>,
        _budget: Duration,
    ) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        Err(MicrosandboxError::local_only(Operation::SandboxModify))
    }

    /// Live resize observation requires the local provider.
    pub async fn resize_status(&self) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        Err(MicrosandboxError::local_only(Operation::SandboxModify))
    }

    /// Retained resize operation identities require the local provider.
    pub async fn resize_operations(&self) -> MicrosandboxResult<Vec<ResizeOperation>> {
        Err(MicrosandboxError::local_only(Operation::SandboxModify))
    }

    /// Waiting for retained resize operations requires the local provider.
    pub async fn wait_for_resize_operations(
        &self,
        _operations: &[ResizeOperation],
        _timeout: Option<Duration>,
    ) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        Err(MicrosandboxError::local_only(Operation::SandboxModify))
    }

    /// Live resize convergence requires the local provider.
    pub async fn wait_until_resized(&self) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        Err(MicrosandboxError::local_only(Operation::SandboxModify))
    }

    /// Live resize convergence requires the local provider, including a zero-timeout check.
    pub async fn wait_until_resized_with_timeout(
        &self,
        _timeout: Duration,
    ) -> MicrosandboxResult<Vec<ResourceResizeStatus>> {
        Err(MicrosandboxError::local_only(Operation::SandboxModify))
    }

    /// Host liveness probing requires the local provider.
    pub async fn ping(&self) -> MicrosandboxResult<SandboxPingResult> {
        Err(MicrosandboxError::local_only(Operation::SandboxPing))
    }
    /// Host activity notification requires the local provider.
    pub async fn touch(&self) -> MicrosandboxResult<SandboxTouchResult> {
        Err(MicrosandboxError::local_only(Operation::SandboxTouch))
    }
    /// Resident VM pause requires the local provider.
    pub async fn pause(&self) -> MicrosandboxResult<()> {
        Err(MicrosandboxError::local_only(Operation::SandboxPause))
    }
    /// Resident VM pause requires the local provider.
    pub async fn pause_with_guest_flush(
        &self,
        _policy: microsandbox_types::GuestFlush,
    ) -> MicrosandboxResult<()> {
        self.pause().await
    }
    /// Resident VM resume requires the local provider.
    pub async fn resume(&self) -> MicrosandboxResult<()> {
        Err(MicrosandboxError::local_only(Operation::SandboxResume))
    }

    /// Provider observation metrics are available through the unified resource.
    pub async fn metrics(&self) -> MicrosandboxResult<SandboxMetrics> {
        Err(MicrosandboxError::local_only(Operation::SandboxMetrics))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, feature = "cloud"))]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::CloudSandboxStatus;
    use crate::context::{CloudCreateSandboxResponse, SandboxRemoteState};
    use crate::error::UnsupportedReason;
    use crate::sandbox::SandboxConfig;

    fn assert_local_only<T>(result: MicrosandboxResult<T>) {
        assert!(matches!(
            result,
            Err(MicrosandboxError::Unsupported {
                op: Operation::SandboxModify,
                reason: UnsupportedReason::LocalOnly,
            })
        ));
    }

    #[tokio::test]
    async fn remote_resize_refuses_without_provider_io_or_successful_empty_results() {
        // An unreachable endpoint catches accidental fallback to a cloud modification
        // or a live lookup. Unsupported operations must fail before either happens.
        let backend =
            Arc::new(crate::test_support::cloud_backend("http://127.0.0.1:1", "test-key").unwrap());
        let sandbox = Sandbox::from_cloud_state(
            backend.clone(),
            SandboxRemoteState {
                id: "sandbox-id".into(),
                org_id: "org-id".into(),
                created_at: chrono::Utc::now(),
            },
            "remote-resize".into(),
            SandboxConfig::default(),
        );
        let record = SandboxRecord::from_cloud(
            backend,
            CloudCreateSandboxResponse {
                id: "sandbox-id".into(),
                org_id: "org-id".into(),
                name: "remote-resize".into(),
                slug: "remote-resize".into(),
                status: CloudSandboxStatus::Running,
                status_reason: None,
                spec: None,
                ephemeral: false,
                created_at: chrono::Utc::now(),
                started_at: None,
                stopped_at: None,
                last_failure_message: None,
            },
        )
        .unwrap();

        assert_local_only(sandbox.resize_status().await);
        assert_local_only(sandbox.resize_operations().await);
        assert_local_only(sandbox.wait_until_resized().await);
        assert_local_only(record.resize_status().await);
        assert_local_only(record.resize_operations().await);
        assert_local_only(record.wait_until_resized().await);
        for timeout in [Duration::ZERO, Duration::from_secs(1)] {
            assert_local_only(sandbox.wait_until_resized_with_timeout(timeout).await);
            assert_local_only(record.wait_until_resized_with_timeout(timeout).await);
            assert_local_only(
                record
                    .check_resize_operations_with_budget(None, timeout)
                    .await,
            );
        }
        for timeout in [None, Some(Duration::ZERO), Some(Duration::from_secs(1))] {
            assert_local_only(sandbox.wait_for_resize_operations(&[], timeout).await);
            assert_local_only(record.wait_for_resize_operations(&[], timeout).await);
        }
        assert_local_only(sandbox.modify().cpus(2).apply_with_resize_tracking().await);
        assert_local_only(record.modify().cpus(2).apply_with_resize_tracking().await);
    }
}
