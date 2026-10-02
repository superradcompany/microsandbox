//! Existing host operations, with both legacy JSON and framed observations.

use microsandbox_protocol::{
    control::*,
    wire::{Envelope, WireError},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-only VM control and secret state; never exposed to the guest agent.
#[derive(Clone)]
pub struct ControlContext {
    /// Shared authority for lifecycle, revision fencing, and host mutations.
    pub executor: std::sync::Arc<super::executor::RuntimeControlExecutor>,
}

pub(crate) trait Handler: Send + Sync + 'static {
    fn handle(&self, request: ControlOperation, generation: u8) -> Response;

    fn handle_json_with_memory(
        &self,
        value: serde_json::Value,
        memory: Option<std::fs::File>,
    ) -> Vec<u8> {
        if memory.is_some() {
            return b"{\"ok\":false,\"error\":\"unexpected control descriptor\"}\n".to_vec();
        }
        self.handle_json(value)
    }

    fn handle_json(&self, value: serde_json::Value) -> Vec<u8> {
        let response = match serde_json::from_value(value) {
            Ok(request) => {
                self.handle(ControlOperation::GenerationOne(request), 1)
                    .json
            }
            Err(_) => JsonControlResponse {
                ok: false,
                error: Some("invalid control request".into()),
                ..Default::default()
            },
        };
        let mut bytes = serde_json::to_vec(&response).unwrap_or_default();
        bytes.push(b'\n');
        bytes
    }
}

pub(crate) struct Response {
    pub json: JsonControlResponse,
    pub framed: Reply,
}

pub(crate) enum Reply {
    Capabilities(Capabilities),
    RuntimeCapabilities(RuntimeCapabilities),
    Memory(MemoryState),
    Cpu(CpuState),
    Secrets(SecretsResult),
    Checkpoint(CheckpointResult),
    DiskCheckpoint(DiskCheckpointState),
    Branch(BranchResult),
    Pause(PauseState),
    RootDisk(RootDiskState),
    DiskCompact(DiskCompactionResult),
    Error(ControlError),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Response {
    pub(crate) fn error(error: ControlError, legacy: impl Into<String>) -> Self {
        Self {
            json: JsonControlResponse {
                ok: false,
                error: Some(legacy.into()),
                ..Default::default()
            },
            framed: Reply::Error(error),
        }
    }
}

impl Reply {
    pub(crate) fn envelope(&self, generation: u8) -> Result<Envelope, WireError> {
        match self {
            Self::Capabilities(value) => {
                Envelope::new(generation, "control.capabilities.result", value)
            }
            Self::RuntimeCapabilities(value) => {
                Envelope::new(generation, "control.capabilities.result", value)
            }
            Self::Memory(value) => Envelope::new(generation, "control.memory.state", value),
            Self::Cpu(value) => Envelope::new(generation, "control.cpu.state", value),
            Self::Secrets(value) => Envelope::new(generation, "control.secrets.result", value),
            Self::Checkpoint(value) => {
                Envelope::new(generation, "control.checkpoint.result", value)
            }
            Self::DiskCheckpoint(value) => {
                Envelope::new(generation, "control.disk.checkpoint.result", value)
            }
            Self::Branch(value) => Envelope::new(generation, "control.branch.result", value),
            Self::Pause(value) => Envelope::new(generation, "control.pause.state", value),
            Self::RootDisk(value) => Envelope::new(generation, "control.root-disk.state", value),
            Self::DiskCompact(value) => {
                Envelope::new(generation, "control.disk.compact.result", value)
            }
            Self::Error(value) => Envelope::new(generation, "control.error", value),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Handler for ControlContext {
    fn handle_json_with_memory(
        &self,
        value: serde_json::Value,
        memory: Option<std::fs::File>,
    ) -> Vec<u8> {
        super::legacy::respond_with_memory(&value.to_string(), self, memory)
    }

    fn handle_json(&self, value: serde_json::Value) -> Vec<u8> {
        super::legacy::respond_to_line(&value.to_string(), self)
    }

    fn handle(&self, request: ControlOperation, generation: u8) -> Response {
        // Both transports enter the release's executor. Framed traffic cannot
        // bypass a checkpoint, resident pause, or revision ownership fence.
        let mutation = !matches!(
            request,
            ControlOperation::GenerationOne(
                ControlRequest::Capabilities
                    | ControlRequest::MemoryState
                    | ControlRequest::CpuState
            ) | ControlOperation::PauseState
        );
        let command = match operation_to_legacy(request) {
            Ok(command) => command,
            Err(error) => return Response::error(error, "invalid control request payload"),
        };
        let result = self.executor.execute_legacy(command);
        let error = || ControlError {
            code: result
                .error_code
                .clone()
                .unwrap_or_else(|| "operation_failed".into()),
            message: result
                .error
                .clone()
                .unwrap_or_else(|| "control operation failed".into()),
            effect: if mutation {
                ErrorEffect::Unknown
            } else {
                ErrorEffect::None
            },
        };
        let framed = if let Some(secrets) = result.secret_result.clone() {
            Reply::Secrets(secrets)
        } else if let Some(checkpoint) = result.checkpoint.clone() {
            Reply::Checkpoint(CheckpointResult {
                checkpoint: Some(CheckpointState {
                    checkpoint_id: checkpoint.checkpoint_id,
                    checkpoint_root: checkpoint.checkpoint_root,
                    path: checkpoint.path,
                    memory_mode: checkpoint.memory_mode,
                    memory_logical_bytes: checkpoint.memory_logical_bytes,
                    memory_emitted_bytes: checkpoint.memory_emitted_bytes,
                }),
                recovery_error: (!result.ok).then(|| result.error.clone()).flatten(),
            })
        } else if !result.ok {
            Reply::Error(error())
        } else if let Some(caps) = result.capabilities {
            let capabilities = RuntimeCapabilities {
                root_disk_grow: caps.root_disk_grow,
                guest_flush_policy: caps.guest_flush_policy,
                optional_disk_integrity: caps.optional_disk_integrity,
                branch_create: caps.branch_create,
                branch_memfd: caps.branch_memfd,
                pause_resume: caps.pause_resume,
                disk_compact: caps.disk_compact,
                disk_compact_owned: caps.disk_compact_owned,
                cpu_resize: caps.cpu_resize,
                memory_resize: caps.memory_resize,
                secrets_update: caps.secrets_update,
                checkpoint_create: caps.checkpoint_create,
                disk_checkpoint_create: caps.disk_checkpoint_create,
            };
            if generation >= 2 {
                Reply::RuntimeCapabilities(capabilities)
            } else {
                Reply::Capabilities(capabilities.generation_one())
            }
        } else if let Some(state) = result.memory {
            Reply::Memory(MemoryState {
                boot_mib: state.boot_mib,
                target_mib: state.target_mib,
                current_mib: state.current_mib,
                max_mib: state.max_mib,
            })
        } else if let Some(state) = result.cpu {
            Reply::Cpu(CpuState {
                possible: state.possible,
                requested_online: state.requested_online,
                actual_online: state.actual_online,
                enforced: state.enforced,
            })
        } else if let Some(state) = result.disk_checkpoint {
            Reply::DiskCheckpoint(DiskCheckpointState {
                checkpoint_id: state.checkpoint_id,
                path: state.path,
                disk: state.disk,
                owned_volumes: state.owned_volumes,
            })
        } else if let Some(path) = result.branch {
            Reply::Branch(BranchResult { path })
        } else if let Some(state) = result.pause {
            Reply::Pause(PauseState {
                paused: state.paused,
                recovery_required: state.recovery_required,
                capture_unavailable: state.capture_unavailable,
            })
        } else if let Some(state) = result.root_disk {
            Reply::RootDisk(RootDiskState {
                filesystem_bytes: state.filesystem_bytes,
                device_bytes: state.device_bytes,
                total_us: state.total_us,
                pause_us: state.pause_us,
                guest_us: state.guest_us,
            })
        } else if let Some(result) = result.compaction {
            Reply::DiskCompact(result)
        } else {
            Reply::Error(ControlError::rejected(
                "invalid_response",
                "runtime omitted control result",
            ))
        };
        Response {
            json: JsonControlResponse::default(),
            framed,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn operation_to_legacy(
    operation: ControlOperation,
) -> Result<crate::control::ControlRequest, ControlError> {
    use crate::control::{
        CheckpointCaptureIntent as LegacyIntent, ControlRequest as Legacy,
        SecretLiveChange as LegacySecret, SecretValue as LegacyValue,
    };

    Ok(match operation {
        ControlOperation::GenerationOne(request) => match request {
            ControlRequest::Capabilities => Legacy::Capabilities,
            ControlRequest::MemoryTarget { total_mib } => Legacy::MemoryTarget { total_mib },
            ControlRequest::MemoryState => Legacy::MemoryState,
            ControlRequest::CpuTarget { online } => Legacy::CpuTarget { online },
            ControlRequest::CpuState => Legacy::CpuState,
            ControlRequest::SecretsUpdate { changes } => Legacy::SecretsUpdate {
                changes: changes
                    .into_iter()
                    .map(|change| match change {
                        SecretChange::Rotate { name, value } => LegacySecret::Rotate {
                            name,
                            value: LegacyValue(value.0.clone()),
                        },
                        SecretChange::Remove { name } => LegacySecret::Remove { name },
                        SecretChange::SetAllowedHosts { name, hosts } => {
                            LegacySecret::SetAllowedHosts { name, hosts }
                        }
                    })
                    .collect(),
            },
        },
        ControlOperation::CheckpointCreate(request) => Legacy::CheckpointCreate {
            guest_flush: request.guest_flush,
            record_integrity: request.record_integrity,
            checkpoint_id: request.checkpoint_id,
            intent: match request.intent {
                CheckpointCaptureIntent::FullSnapshot => LegacyIntent::FullSnapshot,
                CheckpointCaptureIntent::Park => LegacyIntent::Park,
                CheckpointCaptureIntent::TransparentTransfer => LegacyIntent::TransparentTransfer,
            },
        },
        ControlOperation::DiskCheckpointCreate(request) => Legacy::DiskCheckpointCreate {
            guest_flush: request.guest_flush,
            checkpoint_id: request.checkpoint_id,
        },
        ControlOperation::BranchCreate(request) => Legacy::BranchCreate {
            guest_flush: request.guest_flush,
            record_integrity: request.record_integrity,
            branch_id: request.branch_id,
            child_name: request.child_name,
            memory_cache_dir: request.memory_cache_dir,
        },
        ControlOperation::Pause(request) => match request.guest_flush {
            Some(guest_flush) => Legacy::PauseWithGuestFlush { guest_flush },
            None => Legacy::Pause,
        },
        ControlOperation::Resume => Legacy::Resume,
        ControlOperation::PauseState => Legacy::PauseState,
        ControlOperation::RootDiskGrow(request) => Legacy::RootDiskGrow {
            size_bytes: request.size_bytes,
        },
        ControlOperation::DiskCompact(request) => Legacy::DiskCompact {
            target: request.target,
            layers: request
                .layers
                .map(usize::try_from)
                .transpose()
                .map_err(|_| {
                    ControlError::rejected("invalid_request", "layer count exceeds the host range")
                })?,
            dry_run: request.dry_run,
        },
    })
}

/// Shared execution path, also exercised against the actual host secret store.
#[cfg(feature = "net")]
pub(super) fn apply_secret_changes(
    secrets: Option<&microsandbox_network::secrets::handle::SecretsHandle>,
    changes: Vec<SecretChange>,
) -> Response {
    use microsandbox_network::secrets::handle::SecretsUpdateError;

    let Some(secrets) = secrets else {
        return Response::error(
            ControlError::rejected("unsupported_operation", "secret updates are unavailable"),
            "live secret reconfiguration is not available for this sandbox",
        );
    };
    let mut applied_count = 0u32;
    for change in changes {
        let result = match change {
            SecretChange::Rotate { name, value } => secrets.rotate_value(&name, value.0.clone()),
            SecretChange::Remove { name } => {
                secrets.remove(&name);
                Ok(())
            }
            SecretChange::SetAllowedHosts { name, hosts } => {
                secrets.set_allowed_hosts(&name, &hosts)
            }
        };
        if let Err(error) = result {
            let structured = match &error {
                SecretsUpdateError::UnknownSecret { .. } => {
                    ControlError::rejected("unknown_secret", "the secret does not exist")
                }
                SecretsUpdateError::MissingAllowedHosts { .. } => ControlError::rejected(
                    "invalid_secret_hosts",
                    "at least one allowed host is required",
                ),
            };
            // These existing failures precede mutation of the failed entry.
            // Earlier entries remain applied; JSON retains its old error text.
            return Response {
                json: JsonControlResponse {
                    ok: false,
                    error: Some(error.to_string()),
                    ..Default::default()
                },
                framed: Reply::Secrets(SecretsResult::Failed {
                    applied_count,
                    failed_index: applied_count,
                    error: structured,
                }),
            };
        }
        // A bounded framed request cannot approach u32::MAX entries. Legacy
        // JSON has no line cap and does not expose this new progress field.
        applied_count = applied_count.saturating_add(1);
    }
    Response {
        json: JsonControlResponse {
            ok: true,
            ..Default::default()
        },
        framed: Reply::Secrets(SecretsResult::Complete { applied_count }),
    }
}
