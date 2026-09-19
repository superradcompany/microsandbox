use microsandbox::MicrosandboxError;
use napi::Status;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert a `MicrosandboxError` into a `napi::Error` with a typed code string.
pub fn to_napi_error(err: MicrosandboxError) -> napi::Error {
    let code = error_type_str(&err);
    if let Some(payload) = source_recovery_payload(&err) {
        return napi::Error::new(Status::GenericFailure, format!("[{code}] {payload}"));
    }
    napi::Error::new(Status::GenericFailure, format!("[{code}] {err}"))
}

fn source_recovery_payload(err: &MicrosandboxError) -> Option<String> {
    let MicrosandboxError::SnapshotSourceRecovery(recovery) = err else {
        return None;
    };
    // Only this error carries recovery metadata; ordinary errors retain their existing wire form.
    let recovery = serde_json::to_value(recovery).ok()?;
    Some(serde_json::json!({ "message": err.to_string(), "recovery": recovery }).to_string())
}

/// Return a string tag for the error variant, used as the JS error `code` field.
fn error_type_str(err: &MicrosandboxError) -> &'static str {
    match err {
        MicrosandboxError::Io(_) => "Io",
        MicrosandboxError::Http(_) => "Http",
        MicrosandboxError::CloudHttp { .. } => "CloudHttp",
        MicrosandboxError::LibkrunfwNotFound(_) => "LibkrunfwNotFound",
        MicrosandboxError::RuntimeNotInstalled(_) => "RuntimeNotInstalled",
        MicrosandboxError::RuntimeIncomplete(_) => "RuntimeIncomplete",
        MicrosandboxError::Database(_) => "Database",
        MicrosandboxError::InvalidConfig(_) => "InvalidConfig",
        MicrosandboxError::NoDefaultCommand => "NoDefaultCommand",
        MicrosandboxError::SandboxNotFound(_) => "SandboxNotFound",
        MicrosandboxError::SandboxAlreadyExists(_) => "SandboxAlreadyExists",
        MicrosandboxError::SandboxReplaced { .. } => "SandboxReplaced",
        MicrosandboxError::SandboxStillRunning(_) => "SandboxStillRunning",
        MicrosandboxError::SandboxNotRunning(_) => "SandboxNotRunning",
        MicrosandboxError::SandboxStopTimedOut { .. } => "SandboxStopTimedOut",
        MicrosandboxError::Runtime(_) => "Runtime",
        MicrosandboxError::BootStart { .. } => "BootStart",
        MicrosandboxError::Json(_) => "Json",
        MicrosandboxError::Protocol(_) => "Protocol",
        MicrosandboxError::AgentClient(microsandbox::AgentClientError::UnsupportedOperation {
            ..
        }) => "UnsupportedOperation",
        MicrosandboxError::AgentClient(_) => "AgentClient",
        MicrosandboxError::ControlClient(_) => "Runtime",
        MicrosandboxError::ControlStateChanged => "Runtime",
        MicrosandboxError::ControlSecretBatch { .. } => "Runtime",
        #[cfg(unix)]
        MicrosandboxError::Nix(_) => "Nix",
        #[cfg(windows)]
        MicrosandboxError::WindowsHostSetup(_) => "WindowsHostSetup",
        MicrosandboxError::ExecTimeout(_) => "ExecTimeout",
        MicrosandboxError::StopTimeout { .. } => "StopTimeout",
        MicrosandboxError::ExecFailed(_) => "ExecFailed",
        MicrosandboxError::Terminal(_) => "Terminal",
        MicrosandboxError::SandboxFsOps(_) => "SandboxFsOps",
        MicrosandboxError::ImageNotFound(_) => "ImageNotFound",
        MicrosandboxError::ImageInUse(_) => "ImageInUse",
        MicrosandboxError::VolumeNotFound(_) => "VolumeNotFound",
        MicrosandboxError::VolumeAlreadyExists(_) => "VolumeAlreadyExists",
        MicrosandboxError::Image(_) => "Image",
        MicrosandboxError::NetworkBuilder(_) => "NetworkBuilder",
        MicrosandboxError::PatchFailed(_) => "PatchFailed",
        MicrosandboxError::SnapshotNotFound(_) => "SnapshotNotFound",
        MicrosandboxError::SnapshotAlreadyExists(_) => "SnapshotAlreadyExists",
        MicrosandboxError::SnapshotSandboxRunning(_) => "SnapshotSandboxRunning",
        MicrosandboxError::SnapshotImageMissing(_) => "SnapshotImageMissing",
        MicrosandboxError::SnapshotIntegrity(_) => "SnapshotIntegrity",
        MicrosandboxError::SnapshotSourceRecovery(_) => "SnapshotSourceRecovery",
        MicrosandboxError::SnapshotMigration { .. } => "SnapshotMigration",
        MicrosandboxError::MetricsDisabled(_) => "MetricsDisabled",
        MicrosandboxError::MetricsUnavailable(_) => "MetricsUnavailable",
        MicrosandboxError::MissedRotation { .. } => "MissedRotation",
        MicrosandboxError::InvalidCursor(_) => "InvalidCursor",
        MicrosandboxError::Unsupported { .. } => "Unsupported",
        MicrosandboxError::Custom(_) => "Custom",
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_recovery_error_preserves_structured_native_payload() {
        let error = MicrosandboxError::SnapshotSourceRecovery(Box::new(
            microsandbox::SnapshotSourceRecoveryError {
                source_sandbox: "team/source".into(),
                checkpoint_id: "checkpoint-1".into(),
                checkpoint_root: "sha256:root".into(),
                checkpoint_path: "/runtime/checkpoint".into(),
                artifact: None,
                detail: "thaw acknowledgement lost".into(),
                publication_error: Some("disk full".into()),
            },
        ));
        let message = error.to_string();
        assert_eq!(error_type_str(&error), "SnapshotSourceRecovery");
        let payload: serde_json::Value =
            serde_json::from_str(&source_recovery_payload(&error).unwrap()).unwrap();
        assert_eq!(payload["message"], message);
        assert_eq!(payload["recovery"]["checkpoint_id"], "checkpoint-1");
        assert_eq!(
            payload["recovery"]["checkpoint_path"],
            "/runtime/checkpoint"
        );
        assert!(payload["recovery"]["artifact"].is_null());
        assert_eq!(payload["recovery"]["publication_error"], "disk full");
    }
}
