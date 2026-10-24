//! Runtime maintenance and snapshot operations over retained control sessions.

use std::sync::Arc;

use microsandbox_control_client::{
    CompactDisks, CreateCheckpoint, CreateDiskCheckpoint, GetCpuState, GetMemoryState,
};

use crate::backend::LocalBackend;
use crate::error::{Operation, UnsupportedReason};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::ControlSession;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A published runtime checkpoint and the independent outcome of source recovery.
pub(crate) struct CheckpointCaptureOutcome {
    pub(crate) checkpoint: microsandbox_protocol::control::CheckpointState,
    pub(crate) recovery_error: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    /// Open a control session, returning an error when the runtime has no endpoint.
    pub(crate) async fn require_control_session(
        &self,
        name: &str,
    ) -> MicrosandboxResult<ControlSession> {
        self.control_session(name).await?.ok_or_else(|| {
            MicrosandboxError::Runtime("runtime control endpoint is unavailable".into())
        })
    }

    /// Retain the protocol session only when it matches an earlier identity-bearing selection.
    pub(crate) async fn control_session_for_run(
        &self,
        name: &str,
        run: crate::sandbox::identity::SandboxRunIdentity,
    ) -> MicrosandboxResult<ControlSession> {
        let session = self.require_control_session(name).await?;
        if !session.matches_run(run) {
            return Err(MicrosandboxError::ControlClient(Arc::new(
                microsandbox_control_client::ControlClientError::RuntimeChanged,
            )));
        }
        Ok(session)
    }

    /// Project restored live targets into configuration after construction used original geometry.
    pub(crate) async fn restore_requested_resources(
        &self,
        config: &mut crate::sandbox::SandboxConfig,
    ) -> MicrosandboxResult<()> {
        let resources = &config.spec.resources;
        let session = if resources.max_cpus > resources.cpus
            || resources.max_memory_mib > resources.memory_mib
        {
            // The restored sandbox is still `Starting` here: readiness is published after this.
            self.control_session_while_starting(&config.spec.name)
                .await?
        } else {
            None
        };
        let mut cpus = resources.cpus;
        let mut memory_mib = resources.memory_mib;
        // libkrun creates the CPU controller only when capacity exceeds boot CPUs.
        // A fixed multi-CPU VM has no controller; its captured boot count is already final.
        if resources.max_cpus > resources.cpus {
            let state = session
                .as_ref()
                .ok_or_else(|| {
                    MicrosandboxError::ControlClient(Arc::new(
                        microsandbox_control_client::ControlClientError::RuntimeChanged,
                    ))
                })?
                .request(&GetCpuState)
                .await
                .map_err(MicrosandboxError::ControlClient)?;
            if state.possible != u32::from(resources.max_cpus)
                || state.requested_online == 0
                || state.requested_online > state.possible
            {
                return Err(crate::MicrosandboxError::Runtime(
                    "restored CPU target is outside captured capacity".into(),
                ));
            }
            cpus = state.requested_online as u8;
        }
        if resources.max_memory_mib > resources.memory_mib {
            let state = session
                .as_ref()
                .ok_or_else(|| {
                    MicrosandboxError::ControlClient(Arc::new(
                        microsandbox_control_client::ControlClientError::RuntimeChanged,
                    ))
                })?
                .request(&GetMemoryState)
                .await
                .map_err(MicrosandboxError::ControlClient)?;
            if state.boot_mib != u64::from(resources.memory_mib)
                || state.max_mib != u64::from(resources.max_memory_mib)
                || state.target_mib < state.boot_mib
                || state.target_mib > state.max_mib
            {
                return Err(crate::MicrosandboxError::Runtime(
                    "restored memory target is outside captured capacity".into(),
                ));
            }
            memory_mib = state.target_mib as u32;
        }
        // Persist requested targets, not the boot values or possibly still-converging actual values,
        // so subsequent modify calls neither silently skip changes nor claim false convergence.
        config.spec.resources.cpus = cpus;
        config.spec.resources.memory_mib = memory_mib;
        Ok(())
    }
}

impl ControlSession {
    /// Capability-gated disk maintenance over the existing control endpoint.
    pub(crate) async fn compact_disks(
        &self,
        target: microsandbox_types::DiskCompactionTarget,
        layers: Option<usize>,
        dry_run: bool,
    ) -> MicrosandboxResult<crate::sandbox::DiskCompactionResult> {
        let capabilities = self.capabilities();
        if !capabilities.disk_compact_owned {
            return Err(crate::MicrosandboxError::Runtime(
                "this running sandbox does not support disk compaction; restart with the updated runtime".into(),
            ));
        }
        self.request(&CompactDisks(microsandbox_protocol::control::DiskCompact {
            target,
            layers: layers.map(|value| value as u64),
            dry_run,
        }))
        .await
        .map_err(crate::MicrosandboxError::ControlClient)
    }

    /// Capture one full checkpoint through the running sandbox's existing control endpoint.
    ///
    /// A published checkpoint may coexist with failed source recovery. Preserve both facts so the
    /// snapshot caller can publish the artifact before reporting a typed partial failure.
    pub(crate) async fn create_checkpoint(
        &self,
        checkpoint_id: String,
        record_integrity: bool,
        guest_flush: microsandbox_types::GuestFlush,
    ) -> MicrosandboxResult<CheckpointCaptureOutcome> {
        let capabilities = self.capabilities();
        if !capabilities.checkpoint_create {
            return Err(MicrosandboxError::unsupported(
                Operation::SnapshotOps,
                UnsupportedReason::NotAvailable(
                    "this running sandbox does not support full checkpoint capture".into(),
                ),
            ));
        }
        let request = microsandbox_protocol::control::CheckpointCreate {
            guest_flush: Self::capture_flush_policy(Some(capabilities), guest_flush, false)?,
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
        let response = self
            .request(&CreateCheckpoint(request))
            .await
            .map_err(crate::MicrosandboxError::ControlClient)?;
        CheckpointCaptureOutcome::from_response(response)
    }

    /// Request disk-only capture without falling back to full-state capture or a stopped copy.
    pub(crate) async fn create_disk_checkpoint(
        &self,
        checkpoint_id: String,
        guest_flush: microsandbox_types::GuestFlush,
    ) -> MicrosandboxResult<microsandbox_runtime::control::DiskCheckpointControlState> {
        let capabilities = self.capabilities();
        if !capabilities.disk_checkpoint_create {
            return Err(MicrosandboxError::unsupported(Operation::SnapshotOps,
                UnsupportedReason::NotAvailable("this runtime does not support live disk-only snapshots; recreate the sandbox with the updated runtime".into())));
        }
        let request = microsandbox_protocol::control::DiskCheckpointCreate {
            checkpoint_id,
            guest_flush: Self::capture_flush_policy(Some(capabilities), guest_flush, true)?,
        };
        let response = self
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
}

impl CheckpointCaptureOutcome {
    fn from_response(
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
}
//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
            let outcome = CheckpointCaptureOutcome::from_response(response).unwrap();
            assert_eq!(outcome.checkpoint.checkpoint_id, "checkpoint_test");
            assert_eq!(outcome.recovery_error.as_deref(), Some(detail));
        }
    }

    #[test]
    fn checkpoint_reply_preserves_success_without_requesting_another_resume() {
        // The runtime alone restores the prior execution state. This also covers its successful
        // capture of an intentionally paused source; the SDK must not initiate another resume.
        let outcome = CheckpointCaptureOutcome::from_response(checkpoint_reply(true)).unwrap();
        assert!(outcome.recovery_error.is_none());
    }

    #[test]
    fn checkpoint_reply_never_invents_a_published_artifact() {
        for ok in [false, true] {
            let mut response = checkpoint_reply(ok);
            response.checkpoint = None;
            assert!(matches!(
                CheckpointCaptureOutcome::from_response(response),
                Err(crate::MicrosandboxError::Runtime(_))
            ));
        }
        let outcome = CheckpointCaptureOutcome::from_response(checkpoint_reply(false)).unwrap();
        assert_eq!(
            outcome.recovery_error.as_deref(),
            Some("source recovery failed without a runtime diagnostic")
        );
    }
}
