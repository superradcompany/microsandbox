//! Explicit native translation and optional checked JSON normalization.

use microsandbox_protocol::control::{ControlRequest, SecretChange, SecretValue, SecretsResult};
use microsandbox_protocol_client::{
    ClientError, EncodedMessage, ErrorKind, IntoOutboundMessage, Request, TypedMessage,
};
use serde::Serialize;
use zeroize::Zeroizing;

use crate::{
    ControlClientError, ControlClientResult, ControlProtocol, GetCapabilities, GetCpuState,
    GetMemoryState, JsonReply, JsonValue, SetCpuTarget, SetMemoryTarget, UpdateSecrets, json_reply,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Named messages that can choose a real framed or legacy representation.
pub trait IntoControlMessage: IntoOutboundMessage<ControlProtocol> {
    /// Translate a known native request. Encoded payloads fail locally because
    /// parsing them into a JSON substitute would discard the caller's wire form.
    fn into_json(self) -> ControlClientResult<ControlRequest>;
}

/// Checked control requests sharing operation records across both formats.
pub trait CheckedControlRequest: Request<ControlProtocol, Error = ControlClientError> {
    /// Prepare the actual legacy operation, before any connection or write.
    fn json_request(&self) -> ControlClientResult<ControlRequest>;
    /// Normalize a real JSON response, preserving its original bytes on failure.
    fn decode_json(&self, reply: JsonReply) -> ControlClientResult<Self::Response>;
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<T: Serialize> IntoControlMessage for TypedMessage<T> {
    fn into_json(self) -> ControlClientResult<ControlRequest> {
        // Do not apply the framed four-MiB ceiling to a native legacy request.
        // Parsing its actual JSON tokens also catches duplicate keys emitted by
        // a custom Serialize implementation before a map could erase them.
        let bytes = Zeroizing::new(
            serde_json::to_vec(&self.payload).map_err(|_| ClientError::new(ErrorKind::Encode))?,
        );
        let value =
            JsonValue::parse(&bytes).map_err(|_| ClientError::new(ErrorKind::InvalidData))?;
        if value.as_object().is_none() {
            return invalid();
        }
        Ok(match self.message_type.as_str() {
            "control.capabilities" => ControlRequest::Capabilities,
            "control.memory.state" => ControlRequest::MemoryState,
            "control.cpu.state" => ControlRequest::CpuState,
            "control.memory.target" => ControlRequest::MemoryTarget {
                total_mib: value
                    .get("total_mib")
                    .and_then(JsonValue::as_u64)
                    .ok_or_else(invalid_error)?,
            },
            "control.cpu.target" => ControlRequest::CpuTarget {
                online: value
                    .get("online")
                    .and_then(JsonValue::as_u64)
                    .and_then(|number| number.try_into().ok())
                    .ok_or_else(invalid_error)?,
            },
            "control.secrets.update" => ControlRequest::SecretsUpdate {
                changes: value
                    .get("changes")
                    .and_then(JsonValue::as_array)
                    .ok_or_else(invalid_error)?
                    .iter()
                    .map(secret_change)
                    .collect::<ControlClientResult<_>>()?,
            },
            _ => return Err(ControlClientError::UnsupportedMode),
        })
    }
}

impl IntoControlMessage for EncodedMessage {
    fn into_json(self) -> ControlClientResult<ControlRequest> {
        Err(ControlClientError::UnsupportedMode)
    }
}

impl CheckedControlRequest for GetCapabilities {
    fn json_request(&self) -> ControlClientResult<ControlRequest> {
        Ok(ControlRequest::Capabilities)
    }
    fn decode_json(&self, reply: JsonReply) -> ControlClientResult<Self::Response> {
        reply.checked(|value| json_reply::capabilities(value.get("capabilities")?))
    }
}

impl CheckedControlRequest for GetMemoryState {
    fn json_request(&self) -> ControlClientResult<ControlRequest> {
        Ok(ControlRequest::MemoryState)
    }
    fn decode_json(&self, reply: JsonReply) -> ControlClientResult<Self::Response> {
        reply.checked(|value| json_reply::memory(value.get("memory")?))
    }
}

impl CheckedControlRequest for SetMemoryTarget {
    fn json_request(&self) -> ControlClientResult<ControlRequest> {
        Ok(ControlRequest::MemoryTarget {
            total_mib: self.total_mib,
        })
    }
    fn decode_json(&self, reply: JsonReply) -> ControlClientResult<Self::Response> {
        GetMemoryState.decode_json(reply)
    }
}

impl CheckedControlRequest for GetCpuState {
    fn json_request(&self) -> ControlClientResult<ControlRequest> {
        Ok(ControlRequest::CpuState)
    }
    fn decode_json(&self, reply: JsonReply) -> ControlClientResult<Self::Response> {
        reply.checked(|value| json_reply::cpu(value.get("cpu")?))
    }
}

impl CheckedControlRequest for SetCpuTarget {
    fn json_request(&self) -> ControlClientResult<ControlRequest> {
        Ok(ControlRequest::CpuTarget {
            online: self.online,
        })
    }
    fn decode_json(&self, reply: JsonReply) -> ControlClientResult<Self::Response> {
        GetCpuState.decode_json(reply)
    }
}

impl CheckedControlRequest for UpdateSecrets {
    fn json_request(&self) -> ControlClientResult<ControlRequest> {
        Ok(ControlRequest::SecretsUpdate {
            changes: self.changes.clone(),
        })
    }
    fn decode_json(&self, reply: JsonReply) -> ControlClientResult<Self::Response> {
        reply.checked(|_| {
            Some(SecretsResult::Complete {
                applied_count: self.changes.len().try_into().ok()?,
            })
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn invalid_error() -> ControlClientError {
    ClientError::new(ErrorKind::InvalidData).into()
}

fn invalid<T>() -> ControlClientResult<T> {
    Err(invalid_error())
}

fn secret_change(value: &JsonValue) -> ControlClientResult<SecretChange> {
    let name = value
        .get("name")
        .and_then(JsonValue::as_str)
        .ok_or_else(invalid_error)?
        .to_owned();
    Ok(match value.get("change").and_then(JsonValue::as_str) {
        Some("rotate") => SecretChange::Rotate {
            name,
            value: SecretValue(
                value
                    .get("value")
                    .and_then(JsonValue::as_str)
                    .ok_or_else(invalid_error)?
                    .to_owned(),
            ),
        },
        Some("remove") => SecretChange::Remove { name },
        Some("set_allowed_hosts") => SecretChange::SetAllowedHosts {
            name,
            hosts: value
                .get("hosts")
                .and_then(JsonValue::as_array)
                .ok_or_else(invalid_error)?
                .iter()
                .map(|host| host.as_str().map(str::to_owned).ok_or_else(invalid_error))
                .collect::<ControlClientResult<_>>()?,
        },
        _ => return invalid(),
    })
}
