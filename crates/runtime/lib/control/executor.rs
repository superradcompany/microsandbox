//! Runtime-owned serialization and fencing for host control mutations.

use std::collections::{BTreeMap, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rand::Rng as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::{
    CheckpointCaptureIntent, CheckpointControlState, ControlCapabilities, ControlRequest,
    ControlResponse, CpuControlState, MemoryControlState, SecretLiveChange,
};
use crate::checkpoint::{CheckpointCoordinator, CheckpointResult};
use crate::vm::VmConfig;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Initial version of the fenced runtime-control envelope.
pub const CONTROL_PROTOCOL_VERSION: u16 = 1;
const MAX_DEDUP_RESPONSES: usize = 256;
const MAX_CONTROL_ID_BYTES: usize = 128;
const RUNTIME_BOOT_ID_FILE: &str = "runtime-boot-id";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fenced control request carried by the versioned host-control protocol.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEnvelope {
    /// Runtime-control protocol version.
    pub protocol_version: u16,
    /// Caller-generated idempotency key.
    pub request_id: String,
    /// Immutable identity of the intended runtime process boot.
    pub runtime_boot_id: String,
    /// Optional compare-and-swap revision.
    pub expected_revision: Option<u64>,
    /// Stable operation identity when this request belongs to longer work.
    pub operation_id: Option<String>,
    /// Typed control command.
    pub command: ControlRequest,
}

/// Runtime lifecycle projected through control responses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeLifecycle {
    /// Guest vCPUs and admitted workers may run.
    Running,
    /// One executor-owned operation is establishing a quiesced boundary.
    Quiescing,
    /// Execution is paused and externally visible writers remain fenced.
    Quiesced,
    /// Runtime is permanently fenced from further work.
    Retiring,
}

/// Identity and concurrency state returned with fenced responses.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeControlState {
    /// Immutable identity of this process boot.
    pub runtime_boot_id: String,
    /// Monotonic successful-mutation revision.
    pub revision: u64,
    /// Current lifecycle projection.
    pub lifecycle: RuntimeLifecycle,
}

/// Reply to a [`ControlEnvelope`].
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControlEnvelopeResponse {
    /// Correlated request id.
    pub request_id: String,
    /// Runtime identity/revision observed after executing the command.
    pub runtime: RuntimeControlState,
    /// Existing command response payload.
    pub response: ControlResponse,
}

/// One in-process authority for all host-owned runtime mutations.
pub struct RuntimeControlExecutor {
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
    /// Construct an executor and durably publish a fresh runtime boot identity.
    pub fn new(
        vm: msb_krun::VmControl,
        #[cfg(feature = "net")] secrets: Option<
            microsandbox_network::secrets::handle::SecretsHandle,
        >,
        runtime_dir: &Path,
        vm_config: &VmConfig,
        runtime: tokio::runtime::Handle,
    ) -> Result<Self, String> {
        let runtime_boot_id = new_runtime_boot_id();
        persist_runtime_boot_id(runtime_dir, &runtime_boot_id)
            .map_err(|error| error.to_string())?;
        let checkpoint = CheckpointCoordinator::open(runtime_dir, vm_config, runtime)?;
        Ok(Self {
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
            }),
        })
    }

    /// Execute a legacy command through the same exclusive mutation path.
    pub fn execute_legacy(&self, command: ControlRequest) -> ControlResponse {
        let mut state = self.state.lock().unwrap();
        self.execute_locked(&mut state, command)
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
        let mutation = matches!(
            request,
            ControlRequest::MemoryTarget { .. }
                | ControlRequest::CpuTarget { .. }
                | ControlRequest::SecretsUpdate { .. }
                | ControlRequest::CheckpointCreate { .. }
        );
        if mutation && state.lifecycle != RuntimeLifecycle::Running {
            return control_error(
                "runtime_busy",
                "runtime lifecycle does not currently admit mutations",
            );
        }

        let response = match request {
            ControlRequest::CheckpointCreate {
                checkpoint_id,
                intent,
            } => {
                state.lifecycle = RuntimeLifecycle::Quiescing;
                match state.checkpoint.capture(
                    &self.vm,
                    &checkpoint_id,
                    match intent {
                        CheckpointCaptureIntent::ResumableSnapshot => {
                            microsandbox_image::checkpoint::CaptureIntent::ResumableSnapshot
                        }
                        CheckpointCaptureIntent::Park => {
                            microsandbox_image::checkpoint::CaptureIntent::Park
                        }
                        CheckpointCaptureIntent::TransparentTransfer => {
                            microsandbox_image::checkpoint::CaptureIntent::TransparentTransfer
                        }
                    },
                ) {
                    Ok(result) => {
                        state.lifecycle = RuntimeLifecycle::Running;
                        checkpoint_response(Some(result), true, None, None)
                    }
                    Err(error) => {
                        state.lifecycle = if error.keep_paused {
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
        if mutation && response.ok {
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
                ok: true,
                capabilities: Some(ControlCapabilities {
                    cpu_resize: self.vm.cpu_resize_supported(),
                    memory_resize: self.vm.memory_resize_supported(),
                    secrets_update: self.secrets_update_supported(),
                    checkpoint_create: true,
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
            ControlRequest::CheckpointCreate { .. } => {
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
        let Some(secrets) = &self.secrets else {
            return control_error(
                "secrets_update_unavailable",
                "live secret reconfiguration is not available for this sandbox",
            );
        };
        for change in changes {
            let result = match change {
                SecretLiveChange::Rotate { name, value } => {
                    secrets.rotate_value(&name, value.0.clone())
                }
                SecretLiveChange::Remove { name } => {
                    secrets.remove(&name);
                    Ok(())
                }
                SecretLiveChange::SetAllowedHosts { name, hosts } => {
                    secrets.set_allowed_hosts(&name, &hosts)
                }
            };
            if let Err(error) = result {
                return control_error("secrets_update_failed", error.to_string());
            }
        }
        ControlResponse {
            ok: true,
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

fn new_runtime_boot_id() -> String {
    let mut bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut bytes);
    format!("boot_{}", hex::encode(bytes))
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
    file.sync_all()?;
    drop(file);
    crate::checkpoint::replace_file(&temporary, &target)?;
    #[cfg(unix)]
    File::open(runtime_dir)?.sync_all()?;
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
