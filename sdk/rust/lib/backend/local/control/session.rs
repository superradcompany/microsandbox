//! A prepared SDK operation keeps one runtime session through its whole apply.

use std::collections::BTreeMap;
use std::sync::Arc;

use microsandbox_protocol::labels::{LabelsRequest, LabelsResponse};
use sha2::{Digest, Sha256};

use microsandbox_control_client::{
    CompatibleControlRequest, ControlClientError, ControlConnection, ControlMode, ErrorKind,
    ManageLabels,
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

    /// Read-only capability selection; never treat a mutation failure as a fallback signal.
    pub(crate) async fn label_update_owner(&self) -> Result<Option<(String, bool)>, SharedError> {
        if self.connection.mode() == ControlMode::Json {
            return Ok(None);
        }
        match self.request(&ManageLabels(LabelsRequest::Hello)).await {
            Ok(LabelsResponse::Supported {
                runtime_boot_id,
                config_delta,
            }) if !runtime_boot_id.is_empty() && runtime_boot_id.len() <= 128 => {
                Ok(Some((runtime_boot_id, config_delta)))
            }
            Ok(_) => Err(Arc::new(ControlClientError::RuntimeChanged)),
            Err(error) => match error.as_ref() {
                ControlClientError::UnsupportedMode => Ok(None),
                ControlClientError::Client(error)
                    if error.kind == ErrorKind::UnsupportedOperation =>
                {
                    Ok(None)
                }
                ControlClientError::Peer { error, .. } if error.code == "unsupported_operation" => {
                    Ok(None)
                }
                _ => Err(error),
            },
        }
    }

    pub(crate) async fn update_labels(
        &self,
        owner: (String, bool),
        expected_active: &str,
        expected_desired: &str,
        desired_config_json: String,
        set: BTreeMap<String, String>,
        remove: Vec<String>,
    ) -> Result<(), SharedError> {
        let (runtime_boot_id, config_delta) = owner;
        let expected_active_sha256 = hex::encode(Sha256::digest(expected_active.as_bytes()));
        let request = if config_delta {
            let desired_delta_json = microsandbox_protocol::labels_delta::between(
                expected_desired,
                &desired_config_json,
            )
            .map_err(|_| {
                Arc::new(ControlClientError::Wire(
                    microsandbox_protocol::wire::WireError::InvalidRecord,
                ))
            })?;
            LabelsRequest::UpdateDelta {
                runtime_boot_id: runtime_boot_id.clone(),
                expected_active_sha256,
                expected_desired_sha256: hex::encode(Sha256::digest(expected_desired.as_bytes())),
                desired_delta_json,
                set,
                remove,
            }
        } else {
            LabelsRequest::Update {
                runtime_boot_id: runtime_boot_id.clone(),
                expected_active_sha256,
                desired_config_json,
                set,
                remove,
            }
        };
        match self.request(&ManageLabels(request)).await? {
            LabelsResponse::Updated {
                runtime_boot_id: actual,
                generation,
            } if actual == runtime_boot_id && generation > 0 => Ok(()),
            _ => Err(Arc::new(ControlClientError::RuntimeChanged)),
        }
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

    /// Identity selected before dispatch, independent of values in a capture response.
    pub(crate) fn run_identity(&self) -> crate::sandbox::identity::SandboxRunIdentity {
        crate::sandbox::identity::SandboxRunIdentity {
            sandbox_id: self.entry.key.sandbox_id,
            run_id: self.entry.key.run_id,
            pid: self.entry.key.pid,
        }
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
