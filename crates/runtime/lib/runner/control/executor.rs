//! Runtime-owned serialization and fencing for host control mutations.

use std::collections::{BTreeMap, VecDeque};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rand::Rng as _;
use sha2::{Digest as _, Sha256};

use crate::checkpoint::{CheckpointCoordinator, CheckpointResult, UserPause};
use crate::control::*;
use crate::vm::VmConfig;
use microsandbox_protocol::bootstrap::GuestBootstrap;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_DEDUP_RESPONSES: usize = 256;
const MAX_CONTROL_ID_BYTES: usize = 128;
const RUNTIME_BOOT_ID_FILE: &str = "runtime-boot-id";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One in-process authority for all host-owned runtime mutations.
pub struct RuntimeControlExecutor {
    pause_observation: std::sync::RwLock<ControlResponse>,
    resident_paused: std::sync::Arc<std::sync::atomic::AtomicBool>,
    vm: msb_krun::VmControl,
    #[cfg(feature = "net")]
    secrets: Option<microsandbox_network::secrets::handle::SecretsHandle>,
    state: Mutex<ExecutorState>,
}

struct ExecutorState {
    runtime_boot_id: String,
    revision: u64,
    lifecycle: RuntimeLifecycle,
    dedup: BTreeMap<String, DedupEntry>,
    dedup_order: VecDeque<String>,
    checkpoint: CheckpointCoordinator,
    user_pause: Option<UserPause>,
}

#[derive(Clone)]
struct DedupEntry {
    fingerprint: [u8; 32],
    response: ControlEnvelopeResponse,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RuntimeControlExecutor {
    /// Construct an executor and atomically publish a fresh runtime boot identity.
    // Construction binds the VM, guest channel, and host lifecycle resources once.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        vm: msb_krun::VmControl,
        #[cfg(feature = "net")] secrets: Option<
            microsandbox_network::secrets::handle::SecretsHandle,
        >,
        runtime_dir: &Path,
        vm_config: &VmConfig,
        guest_bootstrap: &GuestBootstrap,
        runtime: tokio::runtime::Handle,
        agent_sock: &Path,
        workload_control: std::sync::Arc<crate::runner::workload_control::WorkloadControl>,
        resident_paused: std::sync::Arc<std::sync::atomic::AtomicBool>,
        inherited_memory: Option<crate::checkpoint::LocalMemoryPin>,
        owned_directory_checkpoints: BTreeMap<
            String,
            microsandbox_filesystem::OwnedDirectoryCheckpoint,
        >,
    ) -> Result<Self, String> {
        let runtime_boot_id = new_runtime_boot_id();
        persist_runtime_boot_id(runtime_dir, &runtime_boot_id)
            .map_err(|error| error.to_string())?;
        let mut checkpoint = CheckpointCoordinator::open(
            runtime_dir,
            vm_config,
            guest_bootstrap,
            runtime,
            agent_sock,
            workload_control,
            owned_directory_checkpoints,
        )?;
        checkpoint.inherit_local_memory(inherited_memory);
        Ok(Self {
            pause_observation: std::sync::RwLock::new(ControlResponse {
                ok: true,
                pause: Some(crate::control::PauseControlState {
                    paused: false,
                    recovery_required: false,
                    capture_unavailable: None,
                }),
                ..Default::default()
            }),
            resident_paused,
            vm,
            #[cfg(feature = "net")]
            secrets,
            state: Mutex::new(ExecutorState {
                runtime_boot_id,
                revision: 0,
                lifecycle: RuntimeLifecycle::Running,
                dedup: BTreeMap::new(),
                dedup_order: VecDeque::new(),
                checkpoint,
                user_pause: None,
            }),
        })
    }

    /// Execute a legacy command through the same exclusive mutation path.
    pub fn execute_legacy(&self, command: ControlRequest) -> ControlResponse {
        // Observation remains available during a long capture. It describes the last completed
        // lifecycle transition; it neither borrows nor releases mutation/pause authority.
        if matches!(command, ControlRequest::PauseState) {
            return self.pause_observation.read().unwrap().clone();
        }
        let mut state = self.state.lock().unwrap();
        let response = self.execute_locked(&mut state, command);
        *self.pause_observation.write().unwrap() = pause_response(&state);
        response
    }

    /// Execute a fenced, idempotent control request.
    pub fn execute(&self, envelope: ControlEnvelope) -> ControlEnvelopeResponse {
        let fingerprint = fingerprint(&envelope);
        let mut state = self.state.lock().unwrap();
        if let Some(cached) = state.dedup.get(&envelope.request_id) {
            if cached.fingerprint == fingerprint {
                return cached.response.clone();
            }
            return envelope_error(
                &state,
                envelope.request_id,
                "request_id_conflict",
                "request id was already used for different command bytes",
            );
        }
        if envelope.protocol_version != CONTROL_PROTOCOL_VERSION {
            return envelope_error(
                &state,
                envelope.request_id,
                "unsupported_protocol",
                format!(
                    "unsupported control protocol {} (expected {CONTROL_PROTOCOL_VERSION})",
                    envelope.protocol_version
                ),
            );
        }
        if !valid_control_id(&envelope.request_id)
            || envelope
                .operation_id
                .as_deref()
                .is_some_and(|id| !valid_control_id(id))
        {
            return envelope_error(
                &state,
                envelope.request_id,
                "invalid_identifier",
                "control identifiers must be non-empty printable ASCII and at most 128 bytes",
            );
        }
        if envelope.runtime_boot_id != state.runtime_boot_id {
            return envelope_error(
                &state,
                envelope.request_id,
                "stale_runtime_boot",
                "request targets a different runtime boot",
            );
        }
        if envelope
            .expected_revision
            .is_some_and(|expected| expected != state.revision)
        {
            return envelope_error(
                &state,
                envelope.request_id,
                "revision_conflict",
                "runtime revision changed before the request was applied",
            );
        }

        let request_id = envelope.request_id;
        let response = self.execute_locked(&mut state, envelope.command);
        *self.pause_observation.write().unwrap() = pause_response(&state);
        let response = ControlEnvelopeResponse {
            request_id: request_id.clone(),
            runtime: snapshot_state(&state),
            response,
        };
        remember_response(&mut state, request_id, fingerprint, response.clone());
        response
    }

    /// Return the current immutable boot identity and mutation revision.
    pub fn state(&self) -> RuntimeControlState {
        snapshot_state(&self.state.lock().unwrap())
    }

    fn execute_locked(
        &self,
        state: &mut ExecutorState,
        request: ControlRequest,
    ) -> ControlResponse {
        let memory_backing = match &request {
            ControlRequest::BranchCreateMemfd {
                backing: Some(file),
                ..
            } if cfg!(target_os = "linux") => Some(file.clone()),
            ControlRequest::BranchCreateMemfd { .. } => {
                return control_error(
                    "missing_memory_handoff",
                    "branch requires a Linux memory descriptor",
                );
            }
            _ => None,
        };
        // Gate the authoritative operation, including idempotent Resume on a running VM.
        // Clients need no separate capability exchange, and refusal never changes ownership.
        if matches!(
            request,
            ControlRequest::Pause
                | ControlRequest::PauseWithGuestFlush { .. }
                | ControlRequest::Resume
        ) && let Some(response) =
            unsupported_lifecycle_request(&request, self.vm.clock_sync_supported())
        {
            return response;
        }
        let mutation = matches!(
            request,
            ControlRequest::MemoryTarget { .. }
                | ControlRequest::RootDiskGrow { .. }
                | ControlRequest::CpuTarget { .. }
                | ControlRequest::SecretsUpdate { .. }
                | ControlRequest::CheckpointCreate { .. }
                | ControlRequest::DiskCheckpointCreate { .. }
                | ControlRequest::BranchCreate { .. }
                | ControlRequest::BranchCreateMemfd { .. }
                | ControlRequest::DiskCompact { dry_run: false, .. }
                | ControlRequest::Pause
                | ControlRequest::PauseWithGuestFlush { .. }
                | ControlRequest::Resume
        );
        let resident_operation = state.user_pause.is_some()
            && matches!(
                request,
                ControlRequest::Pause
                    | ControlRequest::PauseWithGuestFlush { .. }
                    | ControlRequest::Resume
                    | ControlRequest::CheckpointCreate { .. }
                    | ControlRequest::DiskCheckpointCreate { .. }
                    | ControlRequest::BranchCreate { .. }
                    | ControlRequest::BranchCreateMemfd { .. }
            );
        if mutation && state.lifecycle != RuntimeLifecycle::Running && !resident_operation {
            return control_error(
                "runtime_busy",
                "runtime lifecycle does not currently admit mutations",
            );
        }

        let pause_policy = match &request {
            ControlRequest::PauseWithGuestFlush { guest_flush } => Some(*guest_flush),
            _ => None,
        };
        let response = match request {
            ControlRequest::DiskCheckpointCreate {
                checkpoint_id,
                guest_flush,
            } => {
                state.lifecycle = RuntimeLifecycle::Quiescing;
                match state.checkpoint.capture_disk(
                    &self.vm,
                    &checkpoint_id,
                    state.user_pause.as_ref(),
                    guest_flush,
                ) {
                    Ok(result) => {
                        state.lifecycle = if state.user_pause.is_some() {
                            RuntimeLifecycle::Quiesced
                        } else {
                            RuntimeLifecycle::Running
                        };
                        ControlResponse {
                            ok: true,
                            disk_checkpoint: Some(result),
                            ..Default::default()
                        }
                    }
                    Err(error) => {
                        if error.keep_paused {
                            state.user_pause = None;
                        }
                        state.lifecycle = if error.keep_paused || state.user_pause.is_some() {
                            RuntimeLifecycle::Quiesced
                        } else {
                            RuntimeLifecycle::Running
                        };
                        control_error("disk_checkpoint_failed", error.to_string())
                    }
                }
            }
            ControlRequest::Pause | ControlRequest::PauseWithGuestFlush { .. } => {
                if let (Some(paused), Some(policy)) = (state.user_pause.as_ref(), pause_policy)
                    && let Err(error) = state
                        .checkpoint
                        .validate_paused_flush(&self.vm, paused, policy)
                {
                    return control_error("guest_flush_required", error);
                }
                if state.user_pause.is_none() {
                    self.resident_paused
                        .store(true, std::sync::atomic::Ordering::Release);
                    let attempt = format!("pause-{}-{}", state.runtime_boot_id, state.revision);
                    state.lifecycle = RuntimeLifecycle::Quiescing;
                    match state
                        .checkpoint
                        .pause_user(&self.vm, &attempt, pause_policy)
                    {
                        Ok(paused) => {
                            state.user_pause = Some(paused);
                            state.lifecycle = RuntimeLifecycle::Quiesced;
                        }
                        Err(error) => {
                            state.lifecycle = if error.keep_paused {
                                RuntimeLifecycle::Quiesced
                            } else {
                                RuntimeLifecycle::Running
                            };
                            self.resident_paused
                                .store(error.keep_paused, std::sync::atomic::Ordering::Release);
                            return control_error("pause_failed", error.to_string());
                        }
                    }
                }
                pause_response(state)
            }
            ControlRequest::Resume => {
                if let Some(paused) = state.user_pause.take() {
                    if let Err(error) = state.checkpoint.resume_user(&self.vm, &paused) {
                        // A failed resume becomes recovery-owned, never a public resume token.
                        state.lifecycle = RuntimeLifecycle::Quiesced;
                        return control_error("resume_recovery_required", error.to_string());
                    }
                    state.lifecycle = RuntimeLifecycle::Running;
                    self.resident_paused
                        .store(false, std::sync::atomic::Ordering::Release);
                }
                pause_response(state)
            }
            ControlRequest::PauseState => pause_response(state),
            ControlRequest::RootDiskGrow { size_bytes } => {
                match state.checkpoint.grow_root(&self.vm, size_bytes) {
                    Ok(root_disk) => ControlResponse {
                        ok: true,
                        root_disk: Some(root_disk),
                        ..Default::default()
                    },
                    Err(error) => {
                        if error.keep_paused {
                            state.lifecycle = RuntimeLifecycle::Quiesced;
                        }
                        control_error("root_disk_growth_incomplete", error.to_string())
                    }
                }
            }
            ControlRequest::DiskCompact {
                target,
                layers,
                dry_run,
            } => match state.checkpoint.compact(&self.vm, target, layers, dry_run) {
                Ok(result) => ControlResponse {
                    ok: true,
                    compaction: Some(result),
                    ..Default::default()
                },
                Err(error) => {
                    if error.keep_paused {
                        state.lifecycle = RuntimeLifecycle::Quiesced;
                    }
                    control_error(
                        if error.keep_paused {
                            "compaction_recovery_required"
                        } else {
                            "compaction_failed"
                        },
                        error.to_string(),
                    )
                }
            },
            ControlRequest::BranchCreate {
                guest_flush,
                record_integrity,
                branch_id,
                child_name,
                memory_cache_dir,
            }
            | ControlRequest::BranchCreateMemfd {
                guest_flush,
                record_integrity,
                branch_id,
                child_name,
                memory_cache_dir,
                ..
            } => {
                state.lifecycle = RuntimeLifecycle::Quiescing;
                match state.checkpoint.branch(
                    &self.vm,
                    &branch_id,
                    &child_name,
                    &memory_cache_dir,
                    state.user_pause.as_ref(),
                    memory_backing.as_deref(),
                    record_integrity,
                    guest_flush,
                ) {
                    Ok(result) => {
                        state.lifecycle = if state.user_pause.is_some() {
                            RuntimeLifecycle::Quiesced
                        } else {
                            RuntimeLifecycle::Running
                        };
                        ControlResponse {
                            ok: true,
                            branch: Some(result.path),
                            ..Default::default()
                        }
                    }
                    Err(error) => {
                        if error.keep_paused {
                            state.user_pause = None;
                        }
                        state.lifecycle = if error.keep_paused || state.user_pause.is_some() {
                            RuntimeLifecycle::Quiesced
                        } else {
                            RuntimeLifecycle::Running
                        };
                        control_error("branch_failed", error.to_string())
                    }
                }
            }
            ControlRequest::CheckpointCreate {
                guest_flush,
                checkpoint_id,
                intent,
                record_integrity,
            } => {
                state.lifecycle = RuntimeLifecycle::Quiescing;
                match state.checkpoint.capture(
                    &self.vm,
                    &checkpoint_id,
                    match intent {
                        CheckpointCaptureIntent::FullSnapshot => {
                            microsandbox_image::checkpoint::CaptureIntent::FullSnapshot
                        }
                        CheckpointCaptureIntent::Park => {
                            microsandbox_image::checkpoint::CaptureIntent::Park
                        }
                        CheckpointCaptureIntent::TransparentTransfer => {
                            microsandbox_image::checkpoint::CaptureIntent::TransparentTransfer
                        }
                    },
                    state.user_pause.as_ref(),
                    record_integrity,
                    guest_flush,
                ) {
                    Ok(result) => {
                        state.lifecycle = if state.user_pause.is_some() {
                            RuntimeLifecycle::Quiesced
                        } else {
                            RuntimeLifecycle::Running
                        };
                        checkpoint_response(Some(result), true, None, None)
                    }
                    Err(error) => {
                        // A failed rebind can invalidate the user's original pause authority.
                        // Recovery-owned suspension must never be released by ordinary resume.
                        if error.keep_paused {
                            state.user_pause = None;
                        }
                        state.lifecycle = if error.keep_paused || state.user_pause.is_some() {
                            RuntimeLifecycle::Quiesced
                        } else {
                            RuntimeLifecycle::Running
                        };
                        checkpoint_response(
                            error.published.as_deref().cloned(),
                            false,
                            Some("checkpoint_failed".into()),
                            Some(error.to_string()),
                        )
                    }
                }
            }
            request => self.handle_request(request),
        };
        self.resident_paused.store(
            state.lifecycle != RuntimeLifecycle::Running,
            std::sync::atomic::Ordering::Release,
        );
        // A partially applied secret batch changes authoritative state too.
        let partial = matches!(
            response.secret_result,
            Some(microsandbox_protocol::control::SecretsResult::Failed {
                applied_count: 1..,
                ..
            })
        );
        if mutation && (response.ok || partial) {
            match state.revision.checked_add(1) {
                Some(revision) => state.revision = revision,
                None => {
                    state.lifecycle = RuntimeLifecycle::Retiring;
                    return control_error(
                        "revision_exhausted",
                        "runtime mutation revision is exhausted",
                    );
                }
            }
        }
        response
    }

    fn handle_request(&self, request: ControlRequest) -> ControlResponse {
        let memory = |state: Option<msb_krun::VmMemoryState>| match state {
            Some(state) => ControlResponse {
                ok: true,
                memory: Some(MemoryControlState {
                    boot_mib: state.boot_mib,
                    target_mib: state.target_mib,
                    current_mib: state.current_mib,
                    max_mib: state.max_mib,
                }),
                ..Default::default()
            },
            None => control_error(
                "memory_resize_unavailable",
                "this VM booted without memory hotplug capacity",
            ),
        };
        let cpu = |state: Option<msb_krun::VmCpuState>| match state {
            Some(state) => ControlResponse {
                ok: true,
                cpu: Some(CpuControlState {
                    possible: state.possible,
                    requested_online: state.requested_online,
                    actual_online: state.actual_online,
                    enforced: state.enforced,
                }),
                ..Default::default()
            },
            None => control_error(
                "cpu_resize_unavailable",
                "this VM booted without CPU capacity",
            ),
        };

        match request {
            ControlRequest::Capabilities => ControlResponse {
                control_protocols: Some(vec!["json".into(), "cbor".into()]),
                ok: true,
                capabilities: Some(ControlCapabilities {
                    cpu_resize: self.vm.cpu_resize_supported(),
                    memory_resize: self.vm.memory_resize_supported(),
                    secrets_update: self.secrets_update_supported(),
                    checkpoint_create: true,
                    disk_checkpoint_create: true,
                    branch_create: cfg!(any(unix, windows)),
                    optional_disk_integrity: true,
                    guest_flush_policy: true,
                    branch_memfd: cfg!(target_os = "linux"),
                    disk_compact: true,
                    disk_compact_owned: true,
                    root_disk_grow: true,
                    pause_resume: self.vm.clock_sync_supported(),
                }),
                ..Default::default()
            },
            ControlRequest::MemoryTarget { total_mib } => {
                if self.vm.set_memory_target_mib(total_mib).is_none() {
                    return memory(None);
                }
                memory(self.vm.memory_state())
            }
            ControlRequest::MemoryState => memory(self.vm.memory_state()),
            ControlRequest::CpuTarget { online } => {
                if self.vm.set_cpu_target(online).is_none() {
                    return cpu(None);
                }
                cpu(self.vm.cpu_state())
            }
            ControlRequest::CpuState => cpu(self.vm.cpu_state()),
            ControlRequest::SecretsUpdate { changes } => self.handle_secrets_update(changes),
            ControlRequest::CheckpointCreate { .. }
            | ControlRequest::DiskCheckpointCreate { .. }
            | ControlRequest::BranchCreate { .. }
            | ControlRequest::BranchCreateMemfd { .. }
            | ControlRequest::Pause
            | ControlRequest::PauseWithGuestFlush { .. }
            | ControlRequest::Resume
            | ControlRequest::PauseState
            | ControlRequest::DiskCompact { .. }
            | ControlRequest::RootDiskGrow { .. } => {
                unreachable!("checkpoint requests are handled by the executor lifecycle path")
            }
        }
    }

    fn secrets_update_supported(&self) -> bool {
        #[cfg(feature = "net")]
        {
            self.secrets.is_some()
        }
        #[cfg(not(feature = "net"))]
        {
            false
        }
    }

    #[cfg(feature = "net")]
    fn handle_secrets_update(&self, changes: Vec<SecretLiveChange>) -> ControlResponse {
        let changes = serde_json::from_value(
            serde_json::to_value(changes).expect("secret changes serialize"),
        )
        .expect("shared secret change schema");
        let response = super::handler::apply_secret_changes(self.secrets.as_ref(), changes);
        ControlResponse {
            ok: response.json.ok,
            error: response.json.error,
            error_code: (!response.json.ok).then(|| {
                if self.secrets.is_some() {
                    "secrets_update_failed"
                } else {
                    "secrets_update_unavailable"
                }
                .into()
            }),
            secret_result: match response.framed {
                super::handler::Reply::Secrets(result) => Some(result),
                _ => None,
            },
            ..Default::default()
        }
    }

    #[cfg(not(feature = "net"))]
    fn handle_secrets_update(&self, _changes: Vec<SecretLiveChange>) -> ControlResponse {
        control_error(
            "network_support_unavailable",
            "this runtime was built without network support",
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn unsupported_lifecycle_request(
    request: &ControlRequest,
    clock_sync: bool,
) -> Option<ControlResponse> {
    (!clock_sync && matches!(request, ControlRequest::Pause | ControlRequest::PauseWithGuestFlush { .. } | ControlRequest::Resume)).then(|| {
        control_error(
            "pause_resume_unavailable",
            "resident pause/resume requires a runtime and guest kernel with clock-only resume support",
        )
    })
}

fn new_runtime_boot_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    format!("boot_{}", hex::encode(bytes))
}

fn pause_response(state: &ExecutorState) -> ControlResponse {
    ControlResponse {
        ok: true,
        pause: Some(crate::control::PauseControlState {
            paused: state.user_pause.is_some(),
            recovery_required: state.lifecycle == RuntimeLifecycle::Quiesced
                && state.user_pause.is_none(),
            capture_unavailable: state
                .user_pause
                .as_ref()
                .and_then(|paused| paused.capture_unavailable.clone()),
        }),
        ..Default::default()
    }
}

fn checkpoint_response(
    result: Option<CheckpointResult>,
    ok: bool,
    error_code: Option<String>,
    error: Option<String>,
) -> ControlResponse {
    let checkpoint = result.map(|result| CheckpointControlState {
        checkpoint_id: result.checkpoint_id,
        checkpoint_root: result.checkpoint_root,
        path: result.path,
        memory_mode: match result.memory_mode {
            microsandbox_image::checkpoint::MemoryCaptureMode::Full => "full",
            microsandbox_image::checkpoint::MemoryCaptureMode::Incremental => "incremental",
        }
        .into(),
        memory_logical_bytes: result.memory_logical_bytes,
        memory_emitted_bytes: result.memory_emitted_bytes,
    });
    ControlResponse {
        ok,
        error,
        error_code,
        checkpoint,
        ..Default::default()
    }
}

fn persist_runtime_boot_id(runtime_dir: &Path, boot_id: &str) -> std::io::Result<()> {
    std::fs::create_dir_all(runtime_dir)?;
    let target = runtime_dir.join(RUNTIME_BOOT_ID_FILE);
    let temporary = unique_temporary_path(runtime_dir, RUNTIME_BOOT_ID_FILE);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(boot_id.as_bytes())?;
    file.write_all(b"\n")?;
    // This file is diagnostic/live discovery, not a restart journal. Fencing uses the new
    // in-memory identity on every boot; atomic visibility is sufficient here.
    drop(file);
    crate::checkpoint::replace_file(&temporary, &target)?;
    Ok(())
}

fn unique_temporary_path(directory: &Path, stem: &str) -> PathBuf {
    directory.join(format!(
        ".{stem}.{}.{}.tmp",
        std::process::id(),
        rand::random::<u64>()
    ))
}

fn valid_control_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_CONTROL_ID_BYTES
        && id.bytes().all(|byte| byte.is_ascii_graphic())
}

fn fingerprint(envelope: &ControlEnvelope) -> [u8; 32] {
    let bytes = serde_json::to_vec(envelope).unwrap_or_default();
    Sha256::digest(bytes).into()
}

fn snapshot_state(state: &ExecutorState) -> RuntimeControlState {
    RuntimeControlState {
        runtime_boot_id: state.runtime_boot_id.clone(),
        revision: state.revision,
        lifecycle: state.lifecycle,
    }
}

fn remember_response(
    state: &mut ExecutorState,
    request_id: String,
    fingerprint: [u8; 32],
    response: ControlEnvelopeResponse,
) {
    while state.dedup.len() >= MAX_DEDUP_RESPONSES {
        if let Some(oldest) = state.dedup_order.pop_front() {
            state.dedup.remove(&oldest);
        }
    }
    state.dedup_order.push_back(request_id.clone());
    state.dedup.insert(
        request_id,
        DedupEntry {
            fingerprint,
            response,
        },
    );
}

fn envelope_error(
    state: &ExecutorState,
    request_id: String,
    code: &str,
    message: impl Into<String>,
) -> ControlEnvelopeResponse {
    ControlEnvelopeResponse {
        request_id,
        runtime: snapshot_state(state),
        response: control_error(code, message),
    }
}

fn control_error(code: &str, message: impl Into<String>) -> ControlResponse {
    ControlResponse {
        ok: false,
        error_code: Some(code.to_string()),
        error: Some(message.into()),
        ..Default::default()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_pause_and_resume_refuse_before_idempotent_mutation() {
        for request in [ControlRequest::Pause, ControlRequest::Resume] {
            let refused = unsupported_lifecycle_request(&request, false).unwrap();
            assert!(!refused.ok);
            assert_eq!(
                refused.error_code.as_deref(),
                Some("pause_resume_unavailable")
            );
            assert!(refused.pause.is_none());
            assert!(unsupported_lifecycle_request(&request, true).is_none());
        }
        // Observation remains safe without a kernel clock callback.
        assert!(unsupported_lifecycle_request(&ControlRequest::PauseState, false).is_none());
        assert!(unsupported_lifecycle_request(&ControlRequest::Capabilities, false).is_none());
    }

    #[test]
    fn control_ids_are_bounded_and_printable() {
        assert!(valid_control_id("request_42"));
        assert!(!valid_control_id(""));
        assert!(!valid_control_id("contains space"));
        assert!(!valid_control_id(&"x".repeat(MAX_CONTROL_ID_BYTES + 1)));
    }

    #[test]
    fn runtime_boot_identity_is_published_atomically() {
        let directory = tempfile::tempdir().unwrap();
        let first = new_runtime_boot_id();
        persist_runtime_boot_id(directory.path(), &first).unwrap();
        assert_eq!(
            std::fs::read_to_string(directory.path().join(RUNTIME_BOOT_ID_FILE)).unwrap(),
            format!("{first}\n")
        );

        let second = new_runtime_boot_id();
        persist_runtime_boot_id(directory.path(), &second).unwrap();
        assert_ne!(first, second);
        assert_eq!(
            std::fs::read_to_string(directory.path().join(RUNTIME_BOOT_ID_FILE)).unwrap(),
            format!("{second}\n")
        );
    }
}
