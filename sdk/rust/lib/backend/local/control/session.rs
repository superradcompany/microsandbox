//! A prepared SDK operation keeps one runtime session through its whole apply.

use std::sync::Arc;

use microsandbox_control_client::{
    CompatibleControlRequest, ControlClientError, ControlConnection, ErrorKind,
};

use super::registry::{Entry, SharedError};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct ControlSession {
    pub(super) entry: Arc<Entry>,
    connection: ControlConnection,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ControlSession {
    pub(super) fn new(entry: Arc<Entry>, connection: ControlConnection) -> Self {
        Self { entry, connection }
    }

    pub fn capabilities(&self) -> microsandbox_control_client::RuntimeCapabilities {
        *self.connection.runtime_capabilities()
    }

    /// Bound job polling and input across all handles sharing this runtime connection.
    pub async fn job_request(
        &self,
        request: &microsandbox_control_client::ManageJob,
    ) -> Result<microsandbox_protocol::jobs::JobResponse, SharedError> {
        let permit = self
            .entry
            .job_requests
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Arc::new(ControlClientError::RuntimeChanged))?;
        let session = self.clone();
        let request = request.clone();
        // Keep the reservation until the actual response, even when a terminal select branch
        // cancels its local waiter. Cancellation neither replays nor terminates remote work.
        tokio::spawn(async move {
            let _permit = permit;
            session.request(&request).await
        })
        .await
        .map_err(|_| Arc::new(ControlClientError::RuntimeChanged))?
    }

    /// Whether this retained session belongs to the caller's already selected run generation.
    pub(crate) fn matches_run(&self, run: crate::sandbox::identity::SandboxRunIdentity) -> bool {
        self.entry.key.sandbox_id == run.sandbox_id
            && self.entry.key.run_id == run.run_id
            && self.entry.key.pid == run.pid
    }

    #[cfg(test)]
    pub(super) fn mode(&self) -> microsandbox_control_client::ControlMode {
        self.connection.mode()
    }

    pub async fn request<R: CompatibleControlRequest>(
        &self,
        request: &R,
    ) -> Result<R::Response, SharedError> {
        if self.entry.invalidated.is_cancelled() {
            return Err(Arc::new(ControlClientError::RuntimeChanged));
        }
        match self.connection.request_typed(request).await {
            Ok(response) => Ok(response),
            Err(error) => {
                let invalidate = match &error {
                    ControlClientError::Client(error) => matches!(
                        error.kind,
                        ErrorKind::Closed
                            | ErrorKind::PeerClosed
                            | ErrorKind::TruncatedFrame
                            | ErrorKind::Io(_)
                            | ErrorKind::Timeout
                            | ErrorKind::InvalidData
                    ),
                    ControlClientError::RuntimeChanged
                    | ControlClientError::InvalidJsonResponse { .. }
                    | ControlClientError::InvalidResponse { .. } => true,
                    _ => false,
                };
                let error = Arc::new(error);
                if invalidate {
                    self.entry.invalidate(error.clone());
                    self.connection.close().await;
                }
                Err(error)
            }
        }
    }
}
