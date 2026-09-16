//! Prepared checked operations. No SDK resource convergence policy lives here.

use microsandbox_protocol::{
    control::{
        CONTROL_GENERATION, Capabilities, ControlError, CpuState, CpuTarget, Empty, MemoryState,
        MemoryTarget, SecretChange, SecretsResult,
    },
    wire,
};
use microsandbox_protocol_client::{EncodedMessage, Message, Request};
use microsandbox_utils::size::Mebibytes;
use serde::{Serialize, de::DeserializeOwned};

use crate::{ControlClientError, ControlClientResult, ControlProtocol};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Query available host operations.
#[derive(Debug, Clone, Copy, Default)]
pub struct GetCapabilities;
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
        checked(response, "control.capabilities.result")
    }
}

impl Request<ControlProtocol> for GetMemoryState {
    type Response = MemoryState;
    type Error = ControlClientError;
    fn message(&self) -> ControlClientResult<EncodedMessage> {
        prepared("control.memory.state", &Empty {})
    }
    fn decode(&self, response: Message) -> ControlClientResult<Self::Response> {
        checked(response, "control.memory.state")
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
        checked(response, "control.memory.state")
    }
}

impl Request<ControlProtocol> for GetCpuState {
    type Response = CpuState;
    type Error = ControlClientError;
    fn message(&self) -> ControlClientResult<EncodedMessage> {
        prepared("control.cpu.state", &Empty {})
    }
    fn decode(&self, response: Message) -> ControlClientResult<Self::Response> {
        checked(response, "control.cpu.state")
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
        checked(response, "control.cpu.state")
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
        checked_with(response, "control.secrets.result", |bytes| {
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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn prepared(name: &str, payload: &impl Serialize) -> ControlClientResult<EncodedMessage> {
    Ok(EncodedMessage::new(name, wire::encode(payload)?))
}

fn checked<T: DeserializeOwned>(response: Message, expected: &str) -> ControlClientResult<T> {
    checked_with(response, expected, wire::decode_record)
}

fn checked_with<T>(
    response: Message,
    expected: &str,
    decode: impl FnOnce(&[u8]) -> Result<T, wire::WireError>,
) -> ControlClientResult<T> {
    if response.v != CONTROL_GENERATION || response.id == 0 || response.flags != 1 {
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
