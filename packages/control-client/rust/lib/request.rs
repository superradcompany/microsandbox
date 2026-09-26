//! Prepared checked operations. No SDK resource convergence policy lives here.

use microsandbox_protocol::{
    control::{
        BranchCreate, BranchResult, Capabilities, CheckpointCreate, CheckpointResult, ControlError,
        CpuState, CpuTarget, DiskCheckpointCreate, DiskCheckpointState, DiskCompact, Empty,
        MemoryState, MemoryTarget, Pause, PauseState, RootDiskGrow, RootDiskState,
        RuntimeCapabilities, SecretChange, SecretsResult,
    },
    wire,
};
use microsandbox_protocol_client::{EncodedMessage, Message, Request};
use microsandbox_utils::size::Mebibytes;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    CompatibleControlRequest, ControlClientError, ControlClientResult, ControlProtocol, JsonReply,
};
use zeroize::Zeroizing;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Query available host operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetCapabilities;
/// Query the complete generation-two runtime facility inventory.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetRuntimeCapabilities;
/// Read accepted and observed memory quantities.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetMemoryState;
/// Set a memory target without waiting for guest convergence.
#[derive(Debug, Clone, Copy)]
pub struct SetMemoryTarget {
    /// Full-width wire quantity; direct construction avoids SDK input narrowing.
    pub total_mib: u64,
}
/// Read CPU capacity, target, observation, and enforcement.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetCpuState;
/// Set a CPU target without waiting for guest convergence.
#[derive(Debug, Clone, Copy)]
pub struct SetCpuTarget {
    /// Requested online CPUs.
    pub online: u32,
}
/// Apply ordered secret changes, preserving partial completion in the result.
#[derive(Debug, Clone)]
pub struct UpdateSecrets {
    /// Entries execute sequentially, stopping at the first operation failure.
    pub changes: Vec<SecretChange>,
}
/// Create one full checkpoint.
#[derive(Debug, Clone)]
pub struct CreateCheckpoint(pub CheckpointCreate);
/// Create one disk-only checkpoint.
#[derive(Debug, Clone)]
pub struct CreateDiskCheckpoint(pub DiskCheckpointCreate);
/// Create one direct local branch without descriptor transfer.
#[derive(Debug, Clone)]
pub struct CreateBranch(pub BranchCreate);
/// Pause the runtime, optionally requiring guest writeback.
#[derive(Debug, Clone, Copy, Default)]
pub struct PauseRuntime(pub Pause);
/// Resume a resident pause.
#[derive(Debug, Clone, Copy, Default)]
pub struct ResumeRuntime;
/// Inspect resident pause state.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetPauseState;
/// Grow the owned root disk and filesystem.
#[derive(Debug, Clone, Copy)]
pub struct GrowRootDisk(pub RootDiskGrow);
/// Compact selected owned disk chains.
#[derive(Debug, Clone)]
pub struct CompactDisks(pub DiskCompact);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SetMemoryTarget {
    /// Accept the SDK's existing integer/MiB helpers and their conversion rules.
    ///
    /// `SetMemoryTarget::new(2048.mib())` uses the shared `SizeExt` owner. This
    /// does not change its existing sub-MiB truncation or overflow semantics.
    /// For full-width MiB input construct the public `total_mib` field directly.
    pub fn new(size: impl Into<Mebibytes>) -> Self {
        Self {
            total_mib: u64::from(size.into().as_u32()),
        }
    }
}

impl SetCpuTarget {
    /// Prepare an online CPU target without performing I/O.
    pub fn new(online: u32) -> Self {
        Self { online }
    }
}

impl UpdateSecrets {
    /// Prepare a caller-ordered batch without performing I/O.
    pub fn new(changes: Vec<SecretChange>) -> Self {
        Self { changes }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Request<ControlProtocol> for GetCapabilities {
    type Response = Capabilities;
    type Error = ControlClientError;
    fn message(&self) -> ControlClientResult<EncodedMessage> {
        prepared("control.capabilities", &Empty {})
    }
    fn decode(&self, response: Message) -> ControlClientResult<Self::Response> {
        checked(response, 1, "control.capabilities.result")
    }
}

impl Request<ControlProtocol> for GetRuntimeCapabilities {
    type Response = RuntimeCapabilities;
    type Error = ControlClientError;
    fn message(&self) -> ControlClientResult<EncodedMessage> {
        prepared("control.capabilities", &Empty {})
    }
    fn decode(&self, response: Message) -> ControlClientResult<Self::Response> {
        checked(response, 2, "control.capabilities.result")
    }
}

impl Request<ControlProtocol> for GetMemoryState {
    type Response = MemoryState;
    type Error = ControlClientError;
    fn message(&self) -> ControlClientResult<EncodedMessage> {
        prepared("control.memory.state", &Empty {})
    }
    fn decode(&self, response: Message) -> ControlClientResult<Self::Response> {
        checked(response, 1, "control.memory.state")
    }
}

impl Request<ControlProtocol> for SetMemoryTarget {
    type Response = MemoryState;
    type Error = ControlClientError;
    fn message(&self) -> ControlClientResult<EncodedMessage> {
        prepared(
            "control.memory.target",
            &MemoryTarget {
                total_mib: self.total_mib,
            },
        )
    }
    fn decode(&self, response: Message) -> ControlClientResult<Self::Response> {
        checked(response, 1, "control.memory.state")
    }
}

impl Request<ControlProtocol> for GetCpuState {
    type Response = CpuState;
    type Error = ControlClientError;
    fn message(&self) -> ControlClientResult<EncodedMessage> {
        prepared("control.cpu.state", &Empty {})
    }
    fn decode(&self, response: Message) -> ControlClientResult<Self::Response> {
        checked(response, 1, "control.cpu.state")
    }
}

impl Request<ControlProtocol> for SetCpuTarget {
    type Response = CpuState;
    type Error = ControlClientError;
    fn message(&self) -> ControlClientResult<EncodedMessage> {
        prepared(
            "control.cpu.target",
            &CpuTarget {
                online: self.online,
            },
        )
    }
    fn decode(&self, response: Message) -> ControlClientResult<Self::Response> {
        checked(response, 1, "control.cpu.state")
    }
}

impl Request<ControlProtocol> for UpdateSecrets {
    type Response = SecretsResult;
    type Error = ControlClientError;
    fn message(&self) -> ControlClientResult<EncodedMessage> {
        #[derive(Serialize)]
        struct Payload<'a> {
            changes: &'a [SecretChange],
        }
        prepared(
            "control.secrets.update",
            &Payload {
                changes: &self.changes,
            },
        )
    }
    fn decode(&self, response: Message) -> ControlClientResult<Self::Response> {
        checked_with(response, 1, "control.secrets.result", |bytes| {
            let result = SecretsResult::decode(bytes)?;
            // Completion cannot include entries the caller never sent. Preserve
            // partial failure as an ordinary typed result, not a rollback claim.
            let valid = match &result {
                SecretsResult::Complete { applied_count } => {
                    *applied_count as usize == self.changes.len()
                }
                SecretsResult::Failed { failed_index, .. } => {
                    (*failed_index as usize) < self.changes.len()
                }
            };
            if !valid {
                return Err(wire::WireError::InvalidRecord);
            }
            Ok(result)
        })
    }
}

macro_rules! v2_request {
    ($request:ty, $response:ty, $request_name:literal, $response_name:literal) => {
        impl Request<ControlProtocol> for $request {
            type Response = $response;
            type Error = ControlClientError;

            fn message(&self) -> ControlClientResult<EncodedMessage> {
                prepared($request_name, &self.0)
            }

            fn decode(&self, response: Message) -> ControlClientResult<Self::Response> {
                checked(response, 2, $response_name)
            }
        }
    };
}

v2_request!(
    CreateCheckpoint,
    CheckpointResult,
    "control.checkpoint.create",
    "control.checkpoint.result"
);
v2_request!(
    CreateDiskCheckpoint,
    DiskCheckpointState,
    "control.disk.checkpoint.create",
    "control.disk.checkpoint.result"
);
v2_request!(
    CreateBranch,
    BranchResult,
    "control.branch.create",
    "control.branch.result"
);
v2_request!(
    PauseRuntime,
    PauseState,
    "control.pause",
    "control.pause.state"
);
v2_request!(
    GrowRootDisk,
    RootDiskState,
    "control.root-disk.grow",
    "control.root-disk.state"
);
v2_request!(
    CompactDisks,
    microsandbox_protocol::control::DiskCompactionResult,
    "control.disk.compact",
    "control.disk.compact.result"
);

impl Request<ControlProtocol> for ResumeRuntime {
    type Response = PauseState;
    type Error = ControlClientError;

    fn message(&self) -> ControlClientResult<EncodedMessage> {
        prepared("control.resume", &Empty {})
    }

    fn decode(&self, response: Message) -> ControlClientResult<Self::Response> {
        checked(response, 2, "control.pause.state")
    }
}

impl Request<ControlProtocol> for GetPauseState {
    type Response = PauseState;
    type Error = ControlClientError;

    fn message(&self) -> ControlClientResult<EncodedMessage> {
        prepared("control.pause.state", &Empty {})
    }

    fn decode(&self, response: Message) -> ControlClientResult<Self::Response> {
        checked(response, 2, "control.pause.state")
    }
}

macro_rules! compatible_v2 {
    ($request:ty, $json:expr, $decode:expr) => {
        impl CompatibleControlRequest for $request {
            fn min_generation(&self) -> u8 {
                2
            }

            fn compatibility_json_bytes(&self) -> ControlClientResult<Zeroizing<Vec<u8>>> {
                let value = ($json)(self);
                Ok(Zeroizing::new(serde_json::to_vec(&value).map_err(
                    |_| {
                        microsandbox_protocol_client::ClientError::new(
                            microsandbox_protocol_client::ErrorKind::Encode,
                        )
                    },
                )?))
            }

            fn decode_compatibility_json(
                &self,
                reply: JsonReply,
            ) -> ControlClientResult<Self::Response> {
                ($decode)(reply)
            }
        }
    };
}

compatible_v2!(
    GetRuntimeCapabilities,
    |_: &GetRuntimeCapabilities| serde_json::json!({
        "op": "capabilities",
    }),
    |reply| decode_json_field(reply, "capabilities")
);

compatible_v2!(
    CreateCheckpoint,
    |request: &CreateCheckpoint| serde_json::json!({
        "op": "checkpoint_create",
        "guest_flush": request.0.guest_flush,
        "record_integrity": request.0.record_integrity,
        "checkpoint_id": request.0.checkpoint_id,
        "intent": request.0.intent,
    }),
    decode_checkpoint_json
);
compatible_v2!(
    CreateDiskCheckpoint,
    |request: &CreateDiskCheckpoint| serde_json::json!({
        "op": "disk_checkpoint_create",
        "guest_flush": request.0.guest_flush,
        "checkpoint_id": request.0.checkpoint_id,
    }),
    |reply| decode_json_field(reply, "disk_checkpoint")
);
compatible_v2!(
    CreateBranch,
    |request: &CreateBranch| serde_json::json!({
        "op": "branch_create",
        "guest_flush": request.0.guest_flush,
        "record_integrity": request.0.record_integrity,
        "branch_id": request.0.branch_id,
        "child_name": request.0.child_name,
        "memory_cache_dir": request.0.memory_cache_dir,
    }),
    decode_branch_json
);
compatible_v2!(
    PauseRuntime,
    |request: &PauseRuntime| match request.0.guest_flush {
        Some(policy) => serde_json::json!({"op": "pause_with_guest_flush", "guest_flush": policy}),
        None => serde_json::json!({"op": "pause"}),
    },
    |reply| decode_json_field(reply, "pause")
);
compatible_v2!(
    GrowRootDisk,
    |request: &GrowRootDisk| serde_json::json!({
        "op": "root_disk_grow", "size_bytes": request.0.size_bytes,
    }),
    |reply| decode_json_field(reply, "root_disk")
);
compatible_v2!(
    CompactDisks,
    |request: &CompactDisks| serde_json::json!({
        "op": "disk_compact",
        "target": request.0.target,
        "layers": request.0.layers,
        "dry_run": request.0.dry_run,
    }),
    |reply| decode_json_field(reply, "compaction")
);

impl CompatibleControlRequest for ResumeRuntime {
    fn min_generation(&self) -> u8 {
        2
    }
    fn compatibility_json_bytes(&self) -> ControlClientResult<Zeroizing<Vec<u8>>> {
        json_operation("resume")
    }
    fn decode_compatibility_json(&self, reply: JsonReply) -> ControlClientResult<Self::Response> {
        decode_json_field(reply, "pause")
    }
}

impl CompatibleControlRequest for GetPauseState {
    fn min_generation(&self) -> u8 {
        2
    }
    fn compatibility_json_bytes(&self) -> ControlClientResult<Zeroizing<Vec<u8>>> {
        json_operation("pause_state")
    }
    fn decode_compatibility_json(&self, reply: JsonReply) -> ControlClientResult<Self::Response> {
        decode_json_field(reply, "pause")
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn prepared(name: &str, payload: &impl Serialize) -> ControlClientResult<EncodedMessage> {
    Ok(EncodedMessage::new(name, wire::encode(payload)?))
}

fn checked<T: DeserializeOwned>(
    response: Message,
    minimum: u8,
    expected: &str,
) -> ControlClientResult<T> {
    checked_with(response, minimum, expected, wire::decode_record)
}

fn checked_with<T>(
    response: Message,
    minimum: u8,
    expected: &str,
    decode: impl FnOnce(&[u8]) -> Result<T, wire::WireError>,
) -> ControlClientResult<T> {
    if !(minimum..=microsandbox_protocol::control::CONTROL_GENERATION).contains(&response.v)
        || response.id == 0
        || response.flags != 1
    {
        return Err(ControlClientError::InvalidResponse {
            response: Box::new(response),
        });
    }
    if response.t == "control.error" {
        let Ok(error) = wire::decode_record::<ControlError>(&response.p) else {
            return Err(ControlClientError::InvalidResponse {
                response: Box::new(response),
            });
        };
        return Err(ControlClientError::Peer {
            error,
            response: Box::new(response),
        });
    }
    if response.t != expected {
        return Err(ControlClientError::InvalidResponse {
            response: Box::new(response),
        });
    }
    decode(&response.p).map_err(|_| ControlClientError::InvalidResponse {
        response: Box::new(response),
    })
}

fn json_operation(operation: &str) -> ControlClientResult<Zeroizing<Vec<u8>>> {
    Ok(Zeroizing::new(
        serde_json::to_vec(&serde_json::json!({"op": operation})).map_err(|_| {
            microsandbox_protocol_client::ClientError::new(
                microsandbox_protocol_client::ErrorKind::Encode,
            )
        })?,
    ))
}

fn decode_json_field<T: DeserializeOwned>(reply: JsonReply, field: &str) -> ControlClientResult<T> {
    let decoded = serde_json::from_slice::<serde_json::Value>(reply.raw())
        .ok()
        .and_then(|value| value.get(field).cloned())
        .and_then(|value| serde_json::from_value(value).ok());
    reply.checked(|_| decoded)
}

fn decode_branch_json(reply: JsonReply) -> ControlClientResult<BranchResult> {
    let path = serde_json::from_slice::<serde_json::Value>(reply.raw())
        .ok()
        .and_then(|value| value.get("branch").cloned())
        .and_then(|value| serde_json::from_value(value).ok());
    reply.checked(|_| path.map(|path| BranchResult { path }))
}

fn decode_checkpoint_json(reply: JsonReply) -> ControlClientResult<CheckpointResult> {
    #[derive(serde::Deserialize)]
    struct Response {
        ok: bool,
        #[serde(default)]
        error: Option<String>,
        #[serde(default)]
        checkpoint: Option<microsandbox_protocol::control::CheckpointState>,
    }

    let decoded = serde_json::from_slice::<Response>(reply.raw()).ok();
    if let Some(response) = decoded
        && let Some(checkpoint) = response.checkpoint
    {
        return Ok(CheckpointResult {
            checkpoint: Some(checkpoint),
            recovery_error: (!response.ok).then_some(response.error).flatten(),
        });
    }
    reply.checked(|_| None)
}
