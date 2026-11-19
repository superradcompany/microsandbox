//! Local-only capabilities remain fallible in a remote-only build.

use super::{Sandbox, SandboxMetrics, SandboxPingResult, SandboxRecord, SandboxTouchResult};
use crate::{MicrosandboxError, MicrosandboxResult, Operation};

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
