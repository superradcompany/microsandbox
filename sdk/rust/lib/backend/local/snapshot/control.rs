//! Checkpoint capture through a running local sandbox's control endpoint.

use microsandbox_control_client::{CreateCheckpoint, CreateDiskCheckpoint};

use crate::error::{Operation, UnsupportedReason};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A published runtime checkpoint and the independent outcome of source recovery.
pub(super) struct CheckpointCaptureOutcome {
    pub(super) checkpoint: microsandbox_protocol::control::CheckpointState,
    pub(super) recovery_error: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Capture one full checkpoint through the running sandbox's existing control endpoint.
///
/// A published checkpoint may coexist with failed source recovery. Preserve both facts so the
/// snapshot caller can publish the artifact before reporting a typed partial failure.
pub(super) async fn control_checkpoint_create(
    local: &crate::backend::LocalBackend,
    name: &str,
    checkpoint_id: String,
    record_integrity: bool,
    guest_flush: microsandbox_types::GuestFlush,
) -> MicrosandboxResult<CheckpointCaptureOutcome> {
    let session = local.control_session(name).await?.ok_or_else(|| {
        MicrosandboxError::Runtime("runtime control endpoint is unavailable".into())
    })?;
    let capabilities = session.capabilities();
    if !capabilities.checkpoint_create {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(
                "this running sandbox does not support full checkpoint capture".into(),
            ),
        ));
    }
    let request = microsandbox_protocol::control::CheckpointCreate {
        guest_flush: capture_flush_policy(Some(capabilities), guest_flush, false)?,
        record_integrity,
        checkpoint_id,
        intent: microsandbox_protocol::control::CheckpointCaptureIntent::FullSnapshot,
    };
    if !capabilities.optional_disk_integrity {
        return Err(MicrosandboxError::Runtime(
            "source runtime lacks optional disk integrity; restart with the matching runtime"
                .into(),
        ));
    }
    let response = session
        .request(&CreateCheckpoint(request))
        .await
        .map_err(crate::MicrosandboxError::ControlClient)?;
    checkpoint_response(response)
}

fn checkpoint_response(
    response: microsandbox_protocol::control::CheckpointResult,
) -> MicrosandboxResult<CheckpointCaptureOutcome> {
    let checkpoint = response.checkpoint.ok_or_else(|| {
        MicrosandboxError::Runtime("control response omitted checkpoint state".into())
    })?;
    Ok(CheckpointCaptureOutcome {
        checkpoint,
        recovery_error: response.recovery_error,
    })
}

/// Request disk-only capture without falling back to full-state capture or a stopped copy.
pub(super) async fn control_disk_checkpoint_create(
    local: &crate::backend::LocalBackend,
    name: &str,
    checkpoint_id: String,
    guest_flush: microsandbox_types::GuestFlush,
) -> MicrosandboxResult<microsandbox_runtime::control::DiskCheckpointControlState> {
    let session = local.control_session(name).await?.ok_or_else(|| {
        MicrosandboxError::Runtime("runtime control endpoint is unavailable".into())
    })?;
    let capabilities = session.capabilities();
    if !capabilities.disk_checkpoint_create {
        return Err(MicrosandboxError::unsupported(Operation::SnapshotOps,
            UnsupportedReason::NotAvailable("this runtime does not support live disk-only snapshots; recreate the sandbox with the updated runtime".into())));
    }
    let request = microsandbox_protocol::control::DiskCheckpointCreate {
        checkpoint_id,
        guest_flush: capture_flush_policy(Some(capabilities), guest_flush, true)?,
    };
    let response = session
        .request(&CreateDiskCheckpoint(request))
        .await
        .map_err(crate::MicrosandboxError::ControlClient)?;
    Ok(microsandbox_runtime::control::DiskCheckpointControlState {
        checkpoint_id: response.checkpoint_id,
        path: response.path,
        disk: response.disk,
        owned_volumes: response.owned_volumes,
    })
}

/// Never let an older runtime silently discard an explicit policy. Full Auto is the
/// released behavior and can retain the old request shape; disk Auto is a new guarantee.
pub(crate) fn capture_flush_policy(
    capabilities: Option<microsandbox_protocol::control::RuntimeCapabilities>,
    policy: microsandbox_types::GuestFlush,
    disk_only: bool,
) -> MicrosandboxResult<Option<microsandbox_types::GuestFlush>> {
    if capabilities.is_some_and(|capabilities| capabilities.guest_flush_policy) {
        return Ok(Some(policy));
    }
    if !disk_only && policy == microsandbox_types::GuestFlush::Auto {
        return Ok(None);
    }
    Err(MicrosandboxError::unsupported(Operation::SnapshotOps,
        UnsupportedReason::NotAvailable("source runtime does not support guest-flush policy; restart the sandbox with an updated runtime".into())))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guest_flush_capability_never_silently_weakens_capture() {
        use microsandbox_types::GuestFlush::{Auto, Required, Skip};
        let old = microsandbox_protocol::control::RuntimeCapabilities::default();
        let new = microsandbox_protocol::control::RuntimeCapabilities {
            guest_flush_policy: true,
            ..old
        };
        for capabilities in [None, Some(old)] {
            assert_eq!(
                capture_flush_policy(capabilities, Auto, false).unwrap(),
                None
            );
            for policy in [Auto, Required, Skip] {
                assert!(capture_flush_policy(capabilities, policy, true).is_err());
                if policy != Auto {
                    assert!(capture_flush_policy(capabilities, policy, false).is_err());
                }
            }
        }
        for disk in [true, false] {
            for policy in [Auto, Required, Skip] {
                assert_eq!(
                    capture_flush_policy(Some(new), policy, disk).unwrap(),
                    Some(policy)
                );
            }
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn full_checkpoint_uses_selected_backend_and_retains_post_publish_failure() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let first_home = tempfile::tempdir_in("/tmp").unwrap();
        let second_home = tempfile::tempdir_in("/tmp").unwrap();
        let first = crate::test_support::local_backend_builder(first_home.path())
            .build()
            .await
            .unwrap();
        let second = crate::test_support::local_backend_builder(second_home.path())
            .build()
            .await
            .unwrap();
        crate::test_support::seed_control_run(&first, "worker").await;
        crate::test_support::seed_control_run(&second, "worker").await;
        let mut servers = Vec::new();
        for (local, label, resume_ok) in [(&first, "first", true), (&second, "second", false)] {
            let agent =
                crate::runtime::sandbox_agent_socket_path_candidates_for(local, "worker").remove(0);
            let path = microsandbox_runtime::control::control_socket_path_for(&agent);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let listener = tokio::net::UnixListener::bind(path).unwrap();
            servers.push(tokio::spawn(async move {
                for request_index in 0..2 {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut stream = BufReader::new(stream);
                    let mut line = String::new();
                    stream.read_line(&mut line).await.unwrap();
                    let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                    let response = if request_index == 0 {
                        assert_eq!(request["op"], "capabilities");
                        serde_json::json!({"ok":true,"capabilities":{"optional_disk_integrity":true,"checkpoint_create":true,"cpu_resize":false,"memory_resize":false,"secrets_update":false}})
                    } else {
                        assert_eq!(request["op"], "checkpoint_create");
                        assert_eq!(request["record_integrity"], label == "second");
                        serde_json::json!({"ok":resume_ok,"error":"source resume failed","checkpoint":{
                            "checkpoint_id":request["checkpoint_id"], "checkpoint_root":format!("sha256:{}", "a".repeat(64)),
                            "path":format!("/capture/{label}"), "memory_mode":"full", "memory_logical_bytes":4096, "memory_emitted_bytes":4096
                        }})
                    };
                    stream.get_mut().write_all(format!("{response}\n").as_bytes()).await.unwrap();
                }
            }));
        }
        let first_capture = control_checkpoint_create(
            &first,
            "worker",
            "first-checkpoint".into(),
            false,
            microsandbox_types::GuestFlush::Auto,
        )
        .await
        .unwrap();
        let second_capture = control_checkpoint_create(
            &second,
            "worker",
            "second-checkpoint".into(),
            true,
            microsandbox_types::GuestFlush::Auto,
        )
        .await
        .unwrap();
        assert_eq!(
            first_capture.checkpoint.path,
            std::path::Path::new("/capture/first")
        );
        assert!(first_capture.recovery_error.is_none());
        assert_eq!(
            second_capture.checkpoint.path,
            std::path::Path::new("/capture/second")
        );
        assert_eq!(
            second_capture.recovery_error.as_deref(),
            Some("source resume failed")
        );
        for server in servers {
            server.await.unwrap();
        }
    }

    fn checkpoint_reply(ok: bool) -> microsandbox_protocol::control::CheckpointResult {
        microsandbox_protocol::control::CheckpointResult {
            checkpoint: Some(microsandbox_protocol::control::CheckpointState {
                checkpoint_id: "checkpoint_test".into(),
                checkpoint_root: format!("sha256:{}", "a".repeat(64)),
                path: "/runtime/checkpoint_test".into(),
                memory_mode: "full".into(),
                memory_logical_bytes: 4096,
                memory_emitted_bytes: 4096,
            }),
            recovery_error: (!ok)
                .then(|| "source recovery failed without a runtime diagnostic".into()),
        }
    }

    #[test]
    fn checkpoint_reply_preserves_publication_and_failed_source_recovery() {
        for detail in ["resume failed", "thaw timed out; re-pause failed"] {
            let mut response = checkpoint_reply(false);
            response.recovery_error = Some(detail.into());
            let outcome = checkpoint_response(response).unwrap();
            assert_eq!(outcome.checkpoint.checkpoint_id, "checkpoint_test");
            assert_eq!(outcome.recovery_error.as_deref(), Some(detail));
        }
    }

    #[test]
    fn checkpoint_reply_preserves_success_without_requesting_another_resume() {
        // The runtime alone restores the prior execution state. This also covers its successful
        // capture of an intentionally paused source; the SDK must not initiate another resume.
        let outcome = checkpoint_response(checkpoint_reply(true)).unwrap();
        assert!(outcome.recovery_error.is_none());
    }

    #[test]
    fn checkpoint_reply_never_invents_a_published_artifact() {
        for ok in [false, true] {
            let mut response = checkpoint_reply(ok);
            response.checkpoint = None;
            assert!(matches!(
                checkpoint_response(response),
                Err(crate::MicrosandboxError::Runtime(_))
            ));
        }
        let outcome = checkpoint_response(checkpoint_reply(false)).unwrap();
        assert_eq!(
            outcome.recovery_error.as_deref(),
            Some("source recovery failed without a runtime diagnostic")
        );
    }
}
