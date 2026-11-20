//! Native error envelopes, preserving established kinds and optional structured details.

use microsandbox::MicrosandboxError;

use super::{FfiError, Handle, UnsupportedReason, error_kind, service};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FfiError {
    pub(super) fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            service: None,
            changed: None,
            recovery: None,
            import: None,
            removal: None,
            group_removal: None,
            verification: None,
            resize_status: None,
            resize_wait: None,
            os_error: None,
        }
    }

    pub(super) fn invalid_argument(message: impl Into<String>) -> Self {
        Self::new(error_kind::INVALID_ARGUMENT, message)
    }

    pub(super) fn invalid_handle(handle: Handle) -> Self {
        Self::new(
            error_kind::INVALID_HANDLE,
            format!("unknown sandbox handle: {handle}"),
        )
    }

    pub(super) fn internal(message: impl Into<String>) -> Self {
        Self::new(error_kind::INTERNAL, message)
    }

    pub(super) fn with_change(mut self, changed: microsandbox::ChangeState) -> Self {
        self.changed = Some(changed);
        self
    }

    /// Serialize to the JSON payload returned by the error C string.
    pub(super) fn to_json(&self) -> String {
        let mut payload = serde_json::json!({ "kind": self.kind, "message": self.message });
        if let Some(changed) = self.changed {
            payload["changed"] = match changed {
                microsandbox::ChangeState::Unchanged => "unchanged",
                microsandbox::ChangeState::Unknown => "unknown",
            }
            .into();
        }
        if let Some(service) = &self.service {
            payload["service"] = serde_json::json!(service);
        }
        if let Some(os_error) = self.os_error {
            payload["os_error"] = os_error.into();
        }
        if let Some(recovery) = &self.recovery
            && let Ok(recovery) = serde_json::to_value(recovery)
        {
            payload["recovery"] = recovery;
        }
        if let Some(details) = &self.import {
            payload["import"] = serde_json::json!(details);
        }
        if let Some(report) = &self.verification {
            payload["report"] = serde_json::json!(report);
        }
        if let Some((result, detail)) = self.removal.as_deref() {
            payload["removal"] = serde_json::json!(result);
            payload["detail"] = serde_json::json!(detail);
        }
        if let Some((result, detail)) = self.group_removal.as_deref() {
            payload["removal"] = serde_json::json!(result);
            payload["detail"] = serde_json::json!(detail);
        }
        if let Some(status) = &self.resize_status
            && let Ok(status) = serde_json::to_value(status)
        {
            payload["resize_status"] = status;
        }
        if let Some(details) = &self.resize_wait
            && let Ok(details) = serde_json::to_value(details)
        {
            payload["resize_wait"] = details;
        }
        payload.to_string()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<MicrosandboxError> for FfiError {
    fn from(e: MicrosandboxError) -> Self {
        let kind = match &e {
            MicrosandboxError::SandboxNotFound(_) => error_kind::SANDBOX_NOT_FOUND,
            MicrosandboxError::SandboxStillRunning(_) => error_kind::SANDBOX_STILL_RUNNING,
            MicrosandboxError::SandboxNotRunning(_) => error_kind::SANDBOX_NOT_RUNNING,
            MicrosandboxError::SandboxAlreadyExists(_) => error_kind::SANDBOX_ALREADY_EXISTS,
            MicrosandboxError::SandboxReplaced { .. } => error_kind::SANDBOX_REPLACED,
            MicrosandboxError::SandboxStopTimedOut { .. } => error_kind::SANDBOX_STOP_TIMED_OUT,
            MicrosandboxError::VolumeNotFound(_) => error_kind::VOLUME_NOT_FOUND,
            MicrosandboxError::VolumeAlreadyExists(_) => error_kind::VOLUME_ALREADY_EXISTS,
            MicrosandboxError::ServiceNotFound(_) => error_kind::SERVICE_NOT_FOUND,
            MicrosandboxError::ServiceAlreadyExists(_) => error_kind::SERVICE_ALREADY_EXISTS,
            MicrosandboxError::Service { .. } => error_kind::SERVICE,
            MicrosandboxError::ExecTimeout(_) => error_kind::EXEC_TIMEOUT,
            MicrosandboxError::StopTimeout { .. } => error_kind::STOP_TIMEOUT,
            MicrosandboxError::ResizeTimeout { .. } => error_kind::RESIZE_TIMEOUT,
            MicrosandboxError::ResizeWait(_) => "resize_wait",
            MicrosandboxError::NoDefaultCommand => error_kind::NO_DEFAULT_COMMAND,
            MicrosandboxError::InvalidConfig(_)
            | MicrosandboxError::InvalidWorkdir { .. }
            | MicrosandboxError::MissingRestoreBindings { .. } => error_kind::INVALID_CONFIG,
            MicrosandboxError::SandboxFsOps(_) => error_kind::FILESYSTEM,
            MicrosandboxError::ImageNotFound(_) => error_kind::IMAGE_NOT_FOUND,
            MicrosandboxError::ImageInUse(_) => error_kind::IMAGE_IN_USE,
            MicrosandboxError::SnapshotNotFound(_) => error_kind::SNAPSHOT_NOT_FOUND,
            MicrosandboxError::SnapshotAlreadyExists(_) => error_kind::SNAPSHOT_ALREADY_EXISTS,
            MicrosandboxError::SnapshotSandboxRunning(_) => error_kind::SNAPSHOT_SANDBOX_RUNNING,
            MicrosandboxError::SnapshotImageMissing(_) => error_kind::SNAPSHOT_IMAGE_MISSING,
            MicrosandboxError::SnapshotIntegrity(_) => error_kind::SNAPSHOT_INTEGRITY,
            MicrosandboxError::SnapshotMigration { .. } => error_kind::SNAPSHOT_MIGRATION,
            MicrosandboxError::SnapshotSourceRecovery(_) => error_kind::SNAPSHOT_SOURCE_RECOVERY,
            MicrosandboxError::SnapshotImport(_) => error_kind::SNAPSHOT_IMPORT,
            MicrosandboxError::SnapshotVerification(_) => error_kind::SNAPSHOT_VERIFICATION,
            MicrosandboxError::SnapshotGroupRemovalRecovery { .. } => {
                error_kind::SNAPSHOT_GROUP_REMOVAL_RECOVERY
            }
            MicrosandboxError::SnapshotRemovalRecovery { .. } => {
                error_kind::SNAPSHOT_REMOVAL_RECOVERY
            }
            MicrosandboxError::PatchFailed(_) => error_kind::PATCH_FAILED,
            MicrosandboxError::MetricsDisabled(_) => error_kind::METRICS_DISABLED,
            MicrosandboxError::MetricsUnavailable(_) => error_kind::METRICS_UNAVAILABLE,
            MicrosandboxError::Unsupported {
                op,
                reason: UnsupportedReason::CloudOnly,
            } if service::is_service_operation(*op) => error_kind::CLOUD_ONLY,
            MicrosandboxError::Unsupported { .. } => error_kind::UNSUPPORTED_OPERATION,
            MicrosandboxError::ModificationNotConfirmed { .. } => {
                error_kind::MODIFICATION_NOT_CONFIRMED
            }
            MicrosandboxError::RuntimeNotInstalled(_) => "runtime_not_installed",
            MicrosandboxError::RuntimeIncomplete(_) => "runtime_incomplete",
            MicrosandboxError::Io(_) => error_kind::IO,
            _ => error_kind::INTERNAL,
        };
        let mut error = Self::new(kind, e.to_string());
        error.service = service::error_details(&e);
        match e {
            MicrosandboxError::SnapshotSourceRecovery(details) => error.recovery = Some(details),
            MicrosandboxError::SnapshotImport(details) => error.import = Some(details),
            MicrosandboxError::SnapshotVerification(details) => error.verification = Some(details),
            MicrosandboxError::SnapshotRemovalRecovery { result, source } => {
                error.removal = Some(Box::new((*result, source.to_string())));
            }
            MicrosandboxError::SnapshotGroupRemovalRecovery { result, source } => {
                error.group_removal = Some(Box::new((*result, source.to_string())));
            }
            MicrosandboxError::ResizeTimeout { status, .. } => {
                error.resize_status = Some(Box::new(status))
            }
            MicrosandboxError::ResizeWait(details) => error.resize_wait = Some(details),
            _ => {}
        }
        error
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_removal_error_preserves_committed_result_and_detail() {
        let id = format!("snap_{:032x}", 1);
        let error = MicrosandboxError::SnapshotRemovalRecovery {
            result: Box::new(microsandbox::CheckpointRemoveResult {
                id: microsandbox::snapshot::SnapshotId::new(id.clone()).unwrap(),
                head_update: None,
                warnings: vec!["cleanup pending".into()],
            }),
            source: Box::new(MicrosandboxError::Runtime("catalog offline".into())),
        };
        let message = error.to_string();
        let payload: serde_json::Value =
            serde_json::from_str(&FfiError::from(error).to_json()).unwrap();
        assert_eq!(
            payload,
            serde_json::json!({
                "kind": "snapshot_removal_recovery",
                "message": message,
                "detail": "runtime error: catalog offline",
                "removal": {"id": id, "head_update": null, "warnings": ["cleanup pending"]},
            })
        );
    }

    #[test]
    fn resize_wait_payload_keeps_reason_and_omits_internal_cause() {
        let error = MicrosandboxError::ResizeWait(Box::new(microsandbox::ResizeWaitError {
            reason: microsandbox::ResizeWaitFailure::HistoryUnavailable,
            sandbox: Some("box".into()),
            operation_id: Some("selected".into()),
            status: vec![],
            message: "missing history".into(),
            cause: Some(Box::new(MicrosandboxError::Runtime("raw cause".into()))),
        }));
        let value: serde_json::Value =
            serde_json::from_str(&FfiError::from(error).to_json()).unwrap();
        let details = &value["resize_wait"];
        assert_eq!(details["reason"], "history_unavailable");
        assert_eq!(details["operation_id"], "selected");
        assert_eq!(details["status"], serde_json::json!([]));
        assert!(details.get("cause").is_none());
    }
}
