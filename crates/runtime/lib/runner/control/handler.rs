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
    fn handle(&self, request: ControlRequest) -> Response;

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
            Ok(request) => self.handle(request).json,
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
    Memory(MemoryState),
    Cpu(CpuState),
    Secrets(SecretsResult),
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
            Self::Memory(value) => Envelope::new(generation, "control.memory.state", value),
            Self::Cpu(value) => Envelope::new(generation, "control.cpu.state", value),
            Self::Secrets(value) => Envelope::new(generation, "control.secrets.result", value),
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

    fn handle(&self, request: ControlRequest) -> Response {
        // Both transports enter the release's executor. Framed traffic cannot
        // bypass a checkpoint, resident pause, or revision ownership fence.
        let wire = serde_json::to_value(&request).expect("control request serializes");
        let command = serde_json::from_value(wire).expect("shared control operation");
        let result = self.executor.execute_legacy(command);
        let json = serde_json::from_value(
            serde_json::to_value(&result).expect("control response serializes"),
        )
        .expect("shared control response");
        let error = || ControlError {
            code: result
                .error_code
                .clone()
                .unwrap_or_else(|| "operation_failed".into()),
            message: result
                .error
                .clone()
                .unwrap_or_else(|| "control operation failed".into()),
            effect: if matches!(
                request,
                ControlRequest::MemoryTarget { .. } | ControlRequest::CpuTarget { .. }
            ) {
                ErrorEffect::Unknown
            } else {
                ErrorEffect::None
            },
        };
        let framed = if let Some(secrets) = result.secret_result {
            Reply::Secrets(secrets)
        } else if !result.ok {
            Reply::Error(error())
        } else if let Some(caps) = result.capabilities {
            Reply::Capabilities(Capabilities {
                root_disk_grow: caps.root_disk_grow,
                cpu_resize: caps.cpu_resize,
                memory_resize: caps.memory_resize,
                secrets_update: caps.secrets_update,
            })
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
        } else {
            Reply::Error(ControlError::rejected(
                "invalid_response",
                "runtime omitted control result",
            ))
        };
        Response { json, framed }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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
