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

#[path = "executor/labels.rs"]
mod labels;

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
    signal_runtime: tokio::runtime::Handle,
    signal_workload: std::sync::Arc<crate::runner::workload_control::WorkloadControl>,
    jobs: std::sync::Arc<crate::runner::jobs::JobManager>,
    pause_observation: std::sync::RwLock<ControlResponse>,
    resident_paused: std::sync::Arc<std::sync::atomic::AtomicBool>,
    vm: msb_krun::VmControl,
    #[cfg(feature = "net")]
    secrets: Option<microsandbox_network::secrets::handle::SecretsHandle>,
    state: Mutex<ExecutorState>,
    retention_db: microsandbox_db::DbWriteConnection,
    runtime_script_root: Option<std::fs::File>,
    mounted_filesystems: crate::retention::MountedStorageEvidence,
}

struct ExecutorState {
    runtime_boot_id: String,
    revision: u64,
    lifecycle: RuntimeLifecycle,
    dedup: BTreeMap<String, DedupEntry>,
    dedup_order: VecDeque<String>,
    checkpoint: CheckpointCoordinator,
    user_pause: Option<UserPause>,
    retention: crate::retention::RetentionJournal,
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
        runtime_script_root: Option<std::fs::File>,
        mounted_filesystems: crate::runner::storage_observation::MountedFilesystemInventory,
        retention: crate::retention::RetentionJournal,
        retention_db: microsandbox_db::DbWriteConnection,
    ) -> Result<Self, String> {
        let runtime_boot_id = retention.record().owner.runtime_boot_id.clone();
        let jobs = crate::runner::jobs::JobManager::open(
            runtime_boot_id.clone(),
            runtime_dir
                .parent()
                .ok_or("runtime directory has no sandbox parent")?,
            agent_sock,
            runtime.clone(),
        )?;
        persist_runtime_boot_id(runtime_dir, &runtime_boot_id)
            .map_err(|error| error.to_string())?;
        let mut checkpoint = CheckpointCoordinator::open(
            runtime_dir,
            vm_config,
            guest_bootstrap,
            runtime.clone(),
            agent_sock,
            workload_control.clone(),
            owned_directory_checkpoints,
        )?;
        checkpoint.inherit_local_memory(inherited_memory);
        Ok(Self {
            mounted_filesystems: mounted_filesystems.guest_evidence(guest_bootstrap),
            runtime_script_root,
            retention_db,
            signal_runtime: runtime.clone(),
            signal_workload: std::sync::Arc::clone(&workload_control),
            jobs,
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
                retention,
            }),
        })
    }

    /// Confirm activation under the same authority used by both legacy and framed mutations.
    pub(crate) fn confirm_activation(
        &self,
        source: Option<crate::retention::RetentionSource>,
    ) -> Result<(), String> {
        let mut state = self.state.lock().unwrap();
        state
            .retention
            .confirm_start(
                source.map(|source| source.configuration),
                self.signal_workload.boot_init(),
            )
            .map_err(|error| {
                format!(
                    "active configuration confirmation failed after guest activation; \
                     outcome uncertain and runtime termination requested: {error}"
                )
            })
    }

    /// Generate the shared startup/control identity before any guest activation.
    pub(crate) fn new_boot_identity() -> String {
        new_runtime_boot_id()
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

    /// Admit a bounded job operation under the same lifecycle lock as full capture and pause.
    pub(crate) fn job_request(
        &self,
        request: microsandbox_protocol::jobs::JobRequest,
    ) -> microsandbox_protocol::jobs::JobResponse {
        let state = self.state.lock().unwrap();
        if matches!(
            request.operation,
            microsandbox_protocol::jobs::JobOperation::Hello
                | microsandbox_protocol::jobs::JobOperation::Start { .. }
        ) && !self
            .signal_workload
            .ordinary_writer()
            .ok()
            .flatten()
            .is_some_and(|writer| {
                writer
                    .exec_controls
                    .enabled
                    .load(std::sync::atomic::Ordering::Acquire)
            })
        {
            return microsandbox_protocol::jobs::JobResponse::error(
                "unsupported_feature",
                "managed jobs require a guest with bounded stdin and execution control support",
            );
        }
        if self
            .signal_workload
            .ordinary_writer()
            .ok()
            .flatten()
            .is_some_and(|writer| {
                writer
                    .exec_controls
                    .stopping
                    .load(std::sync::atomic::Ordering::Acquire)
            })
            && matches!(
                request.operation,
                microsandbox_protocol::jobs::JobOperation::Start { .. }
                    | microsandbox_protocol::jobs::JobOperation::Write { .. }
                    | microsandbox_protocol::jobs::JobOperation::Eof { .. }
            )
        {
            return microsandbox_protocol::jobs::JobResponse::error(
                "runtime_stopping",
                "sandbox is stopping; new job input is closed",
            );
        }
        self.jobs.request(
            request,
            state.lifecycle == RuntimeLifecycle::Running && state.user_pause.is_none(),
        )
    }

    pub(crate) fn exec_signal(
        &self,
        request: microsandbox_protocol::exec_control::ExecControlRequest,
    ) -> microsandbox_protocol::exec_control::ExecControlResponse {
        let writer = match self.signal_workload.ordinary_writer() {
            Ok(Some(writer)) => writer,
            _ => {
                return microsandbox_protocol::exec_control::ExecControlResponse::error(
                    "runtime_closed",
                    "execution transport is unavailable",
                );
            }
        };
        // The dispatch worker is blocking, while guest I/O runs on the independent runtime.
        // No lifecycle lock crosses this wait: snapshot gates still apply inside relay admission.
        self.signal_runtime
            .block_on(writer.exec_controls.signal(&writer, request))
    }

    fn execute_locked(
        &self,
        state: &mut ExecutorState,
        request: ControlRequest,
    ) -> ControlResponse {
        // Capturing an active job without its host ownership would restore an unattachable
        // process. Gate every full-capture entry point, including legacy and descriptor forms.
        if matches!(
            request,
            ControlRequest::CheckpointCreate { .. }
                | ControlRequest::BranchCreate { .. }
                | ControlRequest::BranchCreateMemfd { .. }
        ) && self.jobs.active()
        {
            return control_error(
                "active_jobs",
                "full capture and fork are unavailable while managed jobs are active; wait for or terminate those jobs first",
            );
        }
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
        if mutation
            && state.retention.record().pending
                == Some(crate::retention::RetentionTransition::Start)
        {
            return control_error(
                "runtime_busy",
                "runtime activation has not confirmed its configuration",
            );
        }
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
        let configuration_change = matches!(
            request,
            ControlRequest::CpuTarget { .. }
                | ControlRequest::MemoryTarget { .. }
                | ControlRequest::RootDiskGrow { .. }
                | ControlRequest::SecretsUpdate { .. }
        );
        let mut next_source = if configuration_change {
            let source = state
                .retention
                .record()
                .confirmed
                .as_ref()
                .filter(|confirmed| confirmed.owner == state.retention.record().owner)
                .and_then(|confirmed| confirmed.source.clone());
            let next_source = source.and_then(|source| retained_source_after(source, &request));
            if let Err(error) = state.retention.begin_modify() {
                return control_error(
                    "configuration_not_applied",
                    format!(
                        "change refused before application: cannot record configuration transition: {error}"
                    ),
                );
            }
            next_source
        } else {
            None
        };
        let response = match request {
            ControlRequest::DiskCheckpointCreate {
                retain_configuration,
                retain_configuration_exec_limits,
                retain_configuration_storage,
                checkpoint_id,
                guest_flush,
            } => {
                if (retain_configuration_storage == Some(true)
                    || retain_configuration_exec_limits == Some(true))
                    && retain_configuration != Some(true)
                {
                    return control_error(
                        "invalid_request",
                        "optional evidence requires configuration capture",
                    );
                }
                state.lifecycle = RuntimeLifecycle::Quiescing;
                let configuration = retain_configuration.unwrap_or(false).then(|| {
                    crate::retention::ConfigurationCaptureContext::new(
                        &state.retention,
                        &self.retention_db,
                        self.runtime_script_root.as_ref(),
                        (retain_configuration_storage == Some(true))
                            .then_some(&self.mounted_filesystems),
                        // Ready belongs to this executor's guest and the policy is immutable.
                        // Older guests omit it; never manufacture current defaults as evidence.
                        (retain_configuration_exec_limits == Some(true))
                            .then(|| {
                                self.signal_workload
                                    .ready()
                                    .ok()
                                    .and_then(|(_, ready)| ready.ready.exec_limits)
                            })
                            .flatten(),
                    )
                });
                match state.checkpoint.capture_disk(
                    &self.vm,
                    &checkpoint_id,
                    state.user_pause.as_ref(),
                    guest_flush,
                    configuration.as_ref(),
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
                retain_configuration,
                retain_configuration_exec_limits,
                retain_configuration_storage,
                guest_flush,
                checkpoint_id,
                intent,
                record_integrity,
            } => {
                if (retain_configuration_storage == Some(true)
                    || retain_configuration_exec_limits == Some(true))
                    && retain_configuration != Some(true)
                {
                    return control_error(
                        "invalid_request",
                        "optional evidence requires configuration capture",
                    );
                }
                state.lifecycle = RuntimeLifecycle::Quiescing;
                let configuration = retain_configuration.unwrap_or(false).then(|| {
                    crate::retention::ConfigurationCaptureContext::new(
                        &state.retention,
                        &self.retention_db,
                        self.runtime_script_root.as_ref(),
                        (retain_configuration_storage == Some(true))
                            .then_some(&self.mounted_filesystems),
                        // Ready belongs to this executor's guest and the policy is immutable.
                        // Older guests omit it; never manufacture current defaults as evidence.
                        (retain_configuration_exec_limits == Some(true))
                            .then(|| {
                                self.signal_workload
                                    .ready()
                                    .ok()
                                    .and_then(|(_, ready)| ready.ready.exec_limits)
                            })
                            .flatten(),
                    )
                });
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
                    configuration.as_ref(),
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
        if configuration_change && response.ok {
            // Native setters clamp/round requests. Persist their accepted target, not the
            // caller's unbounded number and not guest convergence/plugged capacity.
            if let Some(source) = next_source.as_mut() {
                if let Some(memory) = response.memory {
                    source["resources"]["memory_mib"] = memory.target_mib.into();
                }
                if let Some(cpu) = response.cpu {
                    source["resources"]["cpus"] = cpu.enforced.into();
                }
            }
            if let Err(error) = state.retention.confirm(next_source) {
                // The revision already advanced because the effect happened. Preserve the pending
                // fence and report through the existing envelope, including to legacy JSON callers.
                return ControlResponse {
                    ok: false,
                    error_code: Some("configuration_outcome_unknown".into()),
                    error: Some(format!(
                        "change may have applied but configuration confirmation failed; \
                         outcome uncertain; the runtime remains running: {error}"
                    )),
                    // A Complete secret result otherwise takes precedence over ok=false in
                    // framed projection and would hide the failed durable confirmation.
                    secret_result: None,
                    ..response
                };
            }
        }
        // Failed operations retain the pending fence. In particular, a partial secret batch
        // cannot turn the previous confirmed configuration back into current evidence.
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
                    configuration_capture: true,
                    configuration_exec_limits: true,
                    configuration_storage: true,
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
        let changes = changes
            .into_iter()
            .map(|change| match change {
                SecretLiveChange::Rotate { name, value } => {
                    microsandbox_protocol::control::SecretChange::Rotate {
                        name,
                        value: microsandbox_protocol::control::SecretValue(value.0.clone()),
                    }
                }
                SecretLiveChange::Remove { name } => {
                    microsandbox_protocol::control::SecretChange::Remove { name }
                }
                SecretLiveChange::SetAllowedHosts { name, hosts } => {
                    microsandbox_protocol::control::SecretChange::SetAllowedHosts { name, hosts }
                }
            })
            .collect();
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

fn retained_source_after(
    mut source: serde_json::Value,
    request: &ControlRequest,
) -> Option<serde_json::Value> {
    match request {
        ControlRequest::CpuTarget { online } => {
            *source.get_mut("resources")?.get_mut("cpus")? = (*online).into();
        }
        ControlRequest::MemoryTarget { total_mib } => {
            *source.get_mut("resources")?.get_mut("memory_mib")? = (*total_mib).into();
        }
        ControlRequest::RootDiskGrow { size_bytes } => {
            let image = source.get_mut("image")?.get_mut("Oci")?;
            if image
                .get("root_disk")
                .is_none_or(serde_json::Value::is_null)
            {
                image["root_disk"] = serde_json::json!({"kind": "managed"});
            }
            let root = image.get_mut("root_disk")?;
            if !matches!(root.get("kind")?.as_str()?, "managed" | "flat") {
                return None;
            }
            if size_bytes % (1024 * 1024) != 0 {
                return None;
            }
            root["size_mib"] = (size_bytes / (1024 * 1024)).into();
        }
        ControlRequest::SecretsUpdate { changes } => {
            if changes.is_empty() {
                return Some(source);
            }
            let secrets = source.get_mut("network")?.get_mut("secrets")?;
            let mut config: microsandbox_types::SecretsConfig =
                serde_json::from_value(secrets.clone()).ok()?;
            for change in changes {
                match change {
                    SecretLiveChange::Remove { name } => {
                        config.secrets.retain(|entry| entry.env_var != *name);
                    }
                    SecretLiveChange::SetAllowedHosts { name, hosts } => {
                        let entry = config
                            .secrets
                            .iter_mut()
                            .find(|entry| entry.env_var == *name)?;
                        entry.allowed_hosts = hosts
                            .iter()
                            .map(|host| microsandbox_types::HostPattern::parse(host))
                            .collect();
                    }
                    SecretLiveChange::Rotate { .. } => {
                        // Legacy control carries resolved values, not source-reference provenance.
                        // Never persist that plaintext as user-declared source or keep a stale
                        // reference. The source-aware mutation handoff must supply this evidence.
                        return None;
                    }
                }
            }
            *secrets = serde_json::to_value(config).ok()?;
        }
        _ => {}
    }
    Some(source)
}

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
        configuration: result.configuration,
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
    fn retained_projection_preserves_ceilings_and_does_not_invent_secret_provenance() {
        let source = serde_json::json!({
            "resources": {"cpus": 1, "memory_mib": 256, "max_cpus": 4, "max_memory_mib": 1024},
            "image": {"Oci": {"reference": "alpine"}}
        });
        let cpu = retained_source_after(source.clone(), &ControlRequest::CpuTarget { online: 2 })
            .unwrap();
        assert_eq!(cpu["resources"]["cpus"], 2);
        assert_eq!(cpu["resources"]["max_cpus"], 4);
        let memory = retained_source_after(
            source.clone(),
            &ControlRequest::MemoryTarget { total_mib: 512 },
        )
        .unwrap();
        assert_eq!(memory["resources"]["memory_mib"], 512);
        assert_eq!(memory["resources"]["max_memory_mib"], 1024);
        let disk = retained_source_after(
            source.clone(),
            &ControlRequest::RootDiskGrow {
                size_bytes: 8192 * 1024 * 1024,
            },
        )
        .unwrap();
        assert_eq!(disk["image"]["Oci"]["root_disk"]["kind"], "managed");
        assert_eq!(disk["image"]["Oci"]["root_disk"]["size_mib"], 8192);
        assert!(
            retained_source_after(source, &ControlRequest::SecretsUpdate { changes: vec![] })
                .is_some()
        );
    }

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
