//! Native error envelopes, preserving established kinds and optional structured details.

use microsandbox::MicrosandboxError;

use super::{FfiError, Handle, error_kind};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FfiError {
    pub(super) fn new(kind: &'static str, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
            recovery: None,
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

    /// Serialize to the JSON payload returned by the error C string.
    pub(super) fn to_json(&self) -> String {
        let mut payload = serde_json::json!({ "kind": self.kind, "message": self.message });
        if let Some(os_error) = self.os_error {
            payload["os_error"] = os_error.into();
        }
        if let Some(recovery) = &self.recovery
            && let Ok(recovery) = serde_json::to_value(recovery)
        {
            payload["recovery"] = recovery;
        }
        if let Some(status) = &self.resize_status
            && let Ok(status) = serde_json::to_value(status)
        {
            payload["resize_status"] = status;
        }
        if let Some(details) = &self.resize_wait {
            payload["resize_wait"] = details.clone();
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
            MicrosandboxError::ExecTimeout(_) => error_kind::EXEC_TIMEOUT,
            MicrosandboxError::StopTimeout { .. } => error_kind::STOP_TIMEOUT,
            MicrosandboxError::ResizeTimeout { .. } => error_kind::RESIZE_TIMEOUT,
            MicrosandboxError::ResizeWait(_) => "resize_wait",
            MicrosandboxError::NoDefaultCommand => error_kind::NO_DEFAULT_COMMAND,
            MicrosandboxError::InvalidConfig(_)
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
            MicrosandboxError::PatchFailed(_) => error_kind::PATCH_FAILED,
            MicrosandboxError::MetricsDisabled(_) => error_kind::METRICS_DISABLED,
            MicrosandboxError::MetricsUnavailable(_) => error_kind::METRICS_UNAVAILABLE,
            MicrosandboxError::Unsupported { .. } => error_kind::UNSUPPORTED_OPERATION,
            MicrosandboxError::RuntimeNotInstalled(_) => "runtime_not_installed",
            MicrosandboxError::RuntimeIncomplete(_) => "runtime_incomplete",
            MicrosandboxError::Io(_) => error_kind::IO,
            _ => error_kind::INTERNAL,
        };
        let message = e.to_string();
        let resize_wait = match &e {
            MicrosandboxError::ResizeWait(details) => serde_json::to_value(details).ok(),
            _ => None,
        };
        let (recovery, resize_status) = match e {
            MicrosandboxError::SnapshotSourceRecovery(recovery) => (Some(recovery), None),
            MicrosandboxError::ResizeTimeout { status, .. } => (None, Some(status)),
            _ => (None, None),
        };
        Self {
            kind,
            message,
            recovery,
            resize_status,
            resize_wait,
            os_error: None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
