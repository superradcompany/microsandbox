use std::time::Duration;

use microsandbox::{ChangeState, MicrosandboxError, ServiceError};
use napi::Status;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Convert a `MicrosandboxError` into a `napi::Error` with a typed code string.
pub fn to_napi_error(err: MicrosandboxError) -> napi::Error {
    let code = error_type_str(&err);
    if let Some(payload) = source_recovery_payload(&err).or_else(|| service_payload(&err)) {
        return napi::Error::new(Status::GenericFailure, format!("[{code}] {payload}"));
    }
    napi::Error::new(Status::GenericFailure, format!("[{code}] {err}"))
}

/// Convert an error from a Service change while preserving whether the change may have applied.
pub fn to_napi_service_change_error(err: MicrosandboxError) -> napi::Error {
    let code = error_type_str(&err);
    let payload = service_payload(&err).unwrap_or_else(|| {
        serde_json::json!({
            "message": err.to_string(),
            "changed": change_state_str(err.changed()),
        })
        .to_string()
    });

    napi::Error::new(Status::GenericFailure, format!("[{code}] {payload}"))
}

fn source_recovery_payload(err: &MicrosandboxError) -> Option<String> {
    let MicrosandboxError::SnapshotSourceRecovery(recovery) = err else {
        return None;
    };
    // Only this error carries recovery metadata; ordinary errors retain their existing wire form.
    let recovery = serde_json::to_value(recovery).ok()?;
    Some(serde_json::json!({ "message": err.to_string(), "recovery": recovery }).to_string())
}

/// Carry a Service change failure's reason, wait and change state as JSON after the tag.
fn service_payload(err: &MicrosandboxError) -> Option<String> {
    let MicrosandboxError::Service { slug, error } = err else {
        return None;
    };
    let (reason, retry_after, raw_code, raw_status, raw_message) = service_reason(error);
    let changed = change_state_str(err.changed());
    let retry_after_ms = retry_after.map(|wait| wait.as_millis() as f64);
    Some(
        serde_json::json!({
            "message": err.to_string(),
            "slug": slug,
            "reason": reason,
            "retryAfterMs": retry_after_ms,
            "changed": changed,
            "rawCode": raw_code,
            "rawStatus": raw_status,
            "rawMessage": raw_message,
        })
        .to_string(),
    )
}

fn service_reason(
    error: &ServiceError,
) -> (
    &'static str,
    Option<Duration>,
    Option<&str>,
    Option<u16>,
    Option<&str>,
) {
    match error {
        ServiceError::QuotaExceeded => ("serviceQuotaExceeded", None, None, None, None),
        ServiceError::SandboxLimitExceeded => {
            ("sandboxServiceLimitExceeded", None, None, None, None)
        }
        ServiceError::Conflict => ("serviceConflict", None, None, None, None),
        ServiceError::Detached => ("serviceDetached", None, None, None, None),
        ServiceError::TargetUnreachable { retry_after } => {
            ("targetUnreachable", *retry_after, None, None, None)
        }
        ServiceError::TargetNotRunning => ("sandboxNotRunning", None, None, None, None),
        ServiceError::ChangesPaused { retry_after } => {
            ("serviceChangesPaused", *retry_after, None, None, None)
        }
        ServiceError::OutcomeUnknown => ("outcomeUnknown", None, None, None, None),
        ServiceError::Other {
            code,
            status,
            message,
        } => (
            "other",
            None,
            Some(code.as_str()),
            Some(*status),
            Some(message.as_str()),
        ),
        // `ServiceError` is non-exhaustive; `changed` still reports a newer reason correctly.
        _ => ("other", None, None, None, None),
    }
}

fn change_state_str(changed: ChangeState) -> &'static str {
    match changed {
        ChangeState::Unchanged => "unchanged",
        ChangeState::Unknown => "unknown",
    }
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
        MicrosandboxError::InvalidConfig(_) | MicrosandboxError::MissingRestoreBindings { .. } => {
            "InvalidConfig"
        }
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
        MicrosandboxError::ServiceNotFound(_) => "ServiceNotFound",
        MicrosandboxError::ServiceAlreadyExists(_) => "ServiceAlreadyExists",
        MicrosandboxError::Service { .. } => "Service",
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
        MicrosandboxError::ModificationNotConfirmed { .. } => "ModificationNotConfirmed",
        MicrosandboxError::Custom(_) => "Custom",
        _ => "Unknown",
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox::RestoreKind;

    use super::*;

    #[test]
    fn missing_restore_bindings_keep_the_invalid_config_code() {
        let error = MicrosandboxError::MissingRestoreBindings {
            missing: vec!["mount /data".into()],
            restore: RestoreKind::Disk,
        };

        assert_eq!(error_type_str(&error), "InvalidConfig");
    }

    #[test]
    fn service_errors_carry_reason_wait_and_change_state() {
        let sandbox_limit = MicrosandboxError::Service {
            slug: "my-app".into(),
            error: ServiceError::SandboxLimitExceeded,
        };
        let refused = MicrosandboxError::Service {
            slug: "my-app".into(),
            error: ServiceError::TargetUnreachable {
                retry_after: Some(Duration::from_secs(5)),
            },
        };
        let unknown = MicrosandboxError::Service {
            slug: "my-app".into(),
            error: ServiceError::OutcomeUnknown,
        };

        let sandbox_limit_payload: serde_json::Value =
            serde_json::from_str(&service_payload(&sandbox_limit).unwrap()).unwrap();
        let refused_payload: serde_json::Value =
            serde_json::from_str(&service_payload(&refused).unwrap()).unwrap();
        let unknown_payload: serde_json::Value =
            serde_json::from_str(&service_payload(&unknown).unwrap()).unwrap();

        assert_eq!(error_type_str(&refused), "Service");
        assert_eq!(
            sandbox_limit_payload["reason"],
            "sandboxServiceLimitExceeded"
        );
        assert_eq!(sandbox_limit_payload["changed"], "unchanged");
        assert_eq!(refused_payload["message"], refused.to_string());
        assert_eq!(refused_payload["slug"], "my-app");
        assert_eq!(refused_payload["reason"], "targetUnreachable");
        assert_eq!(refused_payload["retryAfterMs"], 5000.0);
        assert_eq!(refused_payload["changed"], "unchanged");
        assert!(refused_payload["rawCode"].is_null());
        assert!(refused_payload["rawStatus"].is_null());
        assert!(refused_payload["rawMessage"].is_null());
        assert_eq!(unknown_payload["reason"], "outcomeUnknown");
        assert!(unknown_payload["retryAfterMs"].is_null());
        assert_eq!(unknown_payload["changed"], "unknown");
        assert!(service_payload(&MicrosandboxError::ServiceNotFound("my-app".into())).is_none());
    }

    #[test]
    fn other_service_errors_keep_the_raw_refusal() {
        let error = MicrosandboxError::Service {
            slug: "my-app".into(),
            error: ServiceError::Other {
                code: "new_service_refusal".into(),
                status: 409,
                message: "a newer refusal".into(),
            },
        };

        let payload: serde_json::Value =
            serde_json::from_str(&service_payload(&error).unwrap()).unwrap();

        assert_eq!(payload["reason"], "other");
        assert_eq!(payload["rawCode"], "new_service_refusal");
        assert_eq!(payload["rawStatus"], 409);
        assert_eq!(payload["rawMessage"], "a newer refusal");
        assert_eq!(payload["changed"], "unchanged");
    }

    #[test]
    fn non_service_change_errors_carry_change_state() {
        let error = MicrosandboxError::ServiceNotFound("my-app".into());
        let napi_error = to_napi_service_change_error(error);
        let payload = napi_error
            .reason
            .strip_prefix("[ServiceNotFound] ")
            .unwrap();
        let payload: serde_json::Value = serde_json::from_str(payload).unwrap();

        assert_eq!(payload["message"], "service not found: my-app");
        assert_eq!(payload["changed"], "unchanged");
    }

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

    #[test]
    fn modification_not_confirmed_preserves_code_and_message() {
        let error = MicrosandboxError::ModificationNotConfirmed {
            cause: "the running sandbox does not hold the secret".into(),
        };

        assert_eq!(error_type_str(&error), "ModificationNotConfirmed");
        assert_eq!(
            error.to_string(),
            "the change did not complete as asked: the running sandbox does not hold the secret"
        );
    }
}
