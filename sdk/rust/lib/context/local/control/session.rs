//! A prepared SDK operation keeps one runtime session through its whole apply.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use microsandbox_protocol::labels::{LabelsRequest, LabelsResponse};
use sha2::{Digest, Sha256};

use microsandbox_control_client::{
    CompatibleControlRequest, ControlClientError, ControlConnection, ControlMode, ErrorKind,
    ManageLabels, RequestOptions,
};

use super::registry::{Entry, SharedError};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

// Capture copies and syncs RAM/disks and can exceed the short control deadline under load.
// Match the bounded cloud snapshot wait without retrying an ambiguously delivered mutation.
const CAPTURE_REQUEST_TIMEOUT: Duration = Duration::from_secs(30 * 60);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone)]
pub(crate) struct ControlSession {
    pub(super) entry: Arc<Entry>,
    connection: ControlConnection,
}

pub(crate) struct LabelUpdateOwner {
    boot_id: String,
    config_delta: bool,
    caller_overrides_delta: bool,
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
    pub(crate) async fn label_update_owner(&self) -> Result<Option<LabelUpdateOwner>, SharedError> {
        if self.connection.mode() == ControlMode::Json {
            return Ok(None);
        }
        match self.request(&ManageLabels(LabelsRequest::Hello)).await {
            Ok(LabelsResponse::Supported {
                runtime_boot_id,
                config_delta,
                caller_overrides_delta,
            }) if !runtime_boot_id.is_empty() && runtime_boot_id.len() <= 128 => {
                Ok(Some(LabelUpdateOwner {
                    boot_id: runtime_boot_id,
                    config_delta,
                    caller_overrides_delta,
                }))
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
        owner: LabelUpdateOwner,
        expected_active: &str,
        stored: &crate::context::SandboxRecordLocalState,
        config: &crate::SandboxConfig,
        set: BTreeMap<String, String>,
        remove: Vec<String>,
    ) -> Result<(), SharedError> {
        let runtime_boot_id = owner.boot_id;
        let invalid = || {
            Arc::new(ControlClientError::Wire(
                microsandbox_protocol::wire::WireError::InvalidRecord,
            ))
        };
        let expected_desired = &stored.config_json;
        let desired_config_json = serde_json::to_string(config).map_err(|_| invalid())?;
        let expected_active_sha256 = hex::encode(Sha256::digest(expected_active.as_bytes()));
        let request = if owner.config_delta {
            let desired_delta_json = microsandbox_protocol::labels_delta::between(
                expected_desired,
                &desired_config_json,
            )
            .map_err(|_| {
                Arc::new(ControlClientError::Wire(
                    microsandbox_protocol::wire::WireError::InvalidRecord,
                ))
            })?;
            let caller_overrides = if owner.caller_overrides_delta {
                // The runtime stores the reconstructed JSON. Bind the evidence to those
                // exact bytes, including object order, rather than SDK serialization.
                let reconstructed = microsandbox_protocol::labels_delta::apply(
                    expected_desired,
                    &desired_delta_json,
                )
                .map_err(|_| invalid())?;
                let next = config
                    .caller_config_overrides_json(&reconstructed)
                    .map_err(|_| invalid())?
                    .ok_or_else(invalid)?;
                let prior = stored.caller_config_overrides_json.as_deref();
                Some(microsandbox_protocol::labels::CallerOverridesDelta {
                    expected_sha256: prior.map(|json| hex::encode(Sha256::digest(json.as_bytes()))),
                    delta_json: microsandbox_protocol::labels_delta::between(
                        prior.unwrap_or("{}"),
                        &next,
                    )
                    .map_err(|_| invalid())?,
                })
            } else {
                None
            };
            LabelsRequest::UpdateDelta {
                caller_overrides,
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
        self.request_with_options(request, RequestOptions::default())
            .await
    }

    /// Wait for a snapshot or fork capture, including publication and source recovery.
    pub(crate) async fn capture<R: CompatibleControlRequest>(
        &self,
        request: &R,
    ) -> Result<R::Response, SharedError> {
        self.request_with_options(
            request,
            RequestOptions::default().request_timeout(CAPTURE_REQUEST_TIMEOUT),
        )
        .await
    }

    async fn request_with_options<R: CompatibleControlRequest>(
        &self,
        request: &R,
        options: RequestOptions,
    ) -> Result<R::Response, SharedError> {
        if self.entry.invalidated.is_cancelled() {
            return Err(Arc::new(ControlClientError::RuntimeChanged));
        }
        match self
            .connection
            .request_typed_with(request, |_| options)
            .await
        {
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
