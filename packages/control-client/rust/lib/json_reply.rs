//! Original JSON replies and checked field access, without fabricated frames.

use std::fmt;

use microsandbox_protocol::control::{Capabilities, CpuState, MemoryState};
use microsandbox_protocol_client::{ClientError, ErrorKind};
use zeroize::Zeroizing;

use crate::{ControlClientError, ControlClientResult, ControlMode, JsonValue};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One actual response line, retaining unknown fields and lossless numbers.
pub struct JsonReply {
    raw: Zeroizing<Vec<u8>>,
    value: JsonValue,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl JsonReply {
    /// Decode a complete original line (or a nonempty EOF-delimited reply).
    pub fn parse(raw: Vec<u8>) -> ControlClientResult<Self> {
        let raw = Zeroizing::new(raw);
        let text =
            std::str::from_utf8(&raw).map_err(|_| ClientError::new(ErrorKind::InvalidData))?;
        let value = JsonValue::parse(text.trim().as_bytes())
            .map_err(|_| ClientError::new(ErrorKind::InvalidData))?;
        if value.as_object().is_none() {
            return Err(ClientError::new(ErrorKind::InvalidData).into());
        }
        Ok(Self { raw, value })
    }

    /// Exact original line, including received whitespace and delimiter.
    pub fn raw(&self) -> &[u8] {
        &self.raw
    }

    /// Inspect unknown fields without losing numeric precision.
    pub fn value(&self) -> &JsonValue {
        &self.value
    }

    /// Validate an affirmative capabilities reply and select a supported format.
    /// No error strings or unexpected EOFs are interpreted as legacy support.
    pub fn discovery_mode(&self) -> ControlClientResult<ControlMode> {
        if self.value.get("ok").and_then(JsonValue::as_bool) != Some(true)
            || self
                .value
                .get("error")
                .is_some_and(|value| !matches!(value, JsonValue::Null))
            || self
                .value
                .get("capabilities")
                .and_then(capabilities)
                .is_none()
        {
            return Err(ClientError::new(ErrorKind::InvalidData).into());
        }
        let Some(advertisement) = self.value.get("control_protocols") else {
            return Ok(ControlMode::Json);
        };
        let protocols = advertisement
            .as_array()
            .ok_or_else(|| ClientError::new(ErrorKind::InvalidData))?;
        let names = protocols
            .iter()
            .map(JsonValue::as_str)
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| ClientError::new(ErrorKind::InvalidData))?;
        if names.contains(&"cbor") {
            Ok(ControlMode::Framed)
        } else if names.contains(&"json") {
            Ok(ControlMode::Json)
        } else {
            Err(ClientError::new(ErrorKind::UnsupportedOperation).into())
        }
    }

    pub(crate) fn checked<T>(
        self,
        decode: impl FnOnce(&JsonValue) -> Option<T>,
    ) -> ControlClientResult<T> {
        match self.value.get("ok").and_then(JsonValue::as_bool) {
            Some(false) => Err(ControlClientError::LegacyRemote {
                reply: Box::new(self),
            }),
            Some(true) => match decode(&self.value) {
                Some(value) => Ok(value),
                None => Err(ControlClientError::InvalidJsonResponse {
                    reply: Box::new(self),
                }),
            },
            None => Err(ControlClientError::InvalidJsonResponse {
                reply: Box::new(self),
            }),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for JsonReply {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JsonReply")
            .field("bytes", &self.raw.len())
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn capabilities(value: &JsonValue) -> Option<Capabilities> {
    Some(Capabilities {
        root_disk_grow: value
            .get("root_disk_grow")
            .map(|v| v.as_bool())
            .unwrap_or(Some(false))?,
        cpu_resize: value.get("cpu_resize")?.as_bool()?,
        memory_resize: value.get("memory_resize")?.as_bool()?,
        secrets_update: value.get("secrets_update")?.as_bool()?,
    })
}

pub(crate) fn memory(value: &JsonValue) -> Option<MemoryState> {
    Some(MemoryState {
        boot_mib: value.get("boot_mib")?.as_u64()?,
        target_mib: value.get("target_mib")?.as_u64()?,
        current_mib: value.get("current_mib")?.as_u64()?,
        max_mib: value.get("max_mib")?.as_u64()?,
    })
}

pub(crate) fn cpu(value: &JsonValue) -> Option<CpuState> {
    Some(CpuState {
        possible: value.get("possible")?.as_u64()?.try_into().ok()?,
        requested_online: value.get("requested_online")?.as_u64()?.try_into().ok()?,
        actual_online: value.get("actual_online")?.as_u64()?.try_into().ok()?,
        enforced: value.get("enforced")?.as_u64()?.try_into().ok()?,
    })
}
