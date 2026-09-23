//! Control message inventory and checked dispatch decoding.

use ciborium::Value;
use serde::{Deserialize, Serialize};

use super::{ControlRequest, CpuTarget, Empty, MemoryTarget, SecretsResult, SecretsUpdate};
use crate::wire::{Envelope, WireError, decode_value, validate_record};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Known control wire names. The strum spelling is the authoritative mapping.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    strum::IntoStaticStr,
    strum::EnumString,
    strum::EnumIter,
)]
pub enum ControlMessageType {
    /// Initial generation offer.
    #[strum(serialize = "control.hello")]
    Hello,
    /// Selected generation and limits.
    #[strum(serialize = "control.welcome")]
    Welcome,
    /// Facility query.
    #[strum(serialize = "control.capabilities")]
    Capabilities,
    /// Facility response.
    #[strum(serialize = "control.capabilities.result")]
    CapabilitiesResult,
    /// Memory query or terminal memory observation.
    #[strum(serialize = "control.memory.state")]
    MemoryState,
    /// Set a memory target.
    #[strum(serialize = "control.memory.target")]
    MemoryTarget,
    /// CPU query or terminal CPU observation.
    #[strum(serialize = "control.cpu.state")]
    CpuState,
    /// Set a CPU target.
    #[strum(serialize = "control.cpu.target")]
    CpuTarget,
    /// Ordered host secret modifications.
    #[strum(serialize = "control.secrets.update")]
    SecretsUpdate,
    /// Complete or partial secret progress.
    #[strum(serialize = "control.secrets.result")]
    SecretsResult,
    /// Recoverable operation or handshake error.
    #[strum(serialize = "control.error")]
    Error,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ControlMessageType {
    /// Stable wire spelling.
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    /// Resolve a known spelling, retaining unknown names in the envelope layer.
    pub fn from_wire_str(name: &str) -> Option<Self> {
        name.parse().ok()
    }

    /// Whether this is an application request permitted after the handshake.
    pub fn is_request(self) -> bool {
        matches!(
            self,
            Self::Capabilities
                | Self::MemoryState
                | Self::MemoryTarget
                | Self::CpuState
                | Self::CpuTarget
                | Self::SecretsUpdate
        )
    }
}

impl ControlRequest {
    /// Decode a known application request after the server validates its frame.
    pub fn from_envelope(envelope: &Envelope) -> Result<Self, WireError> {
        Ok(match ControlMessageType::from_wire_str(&envelope.t) {
            Some(ControlMessageType::Capabilities) => {
                envelope.payload::<Empty>()?;
                Self::Capabilities
            }
            Some(ControlMessageType::MemoryState) => {
                envelope.payload::<Empty>()?;
                Self::MemoryState
            }
            Some(ControlMessageType::CpuState) => {
                envelope.payload::<Empty>()?;
                Self::CpuState
            }
            Some(ControlMessageType::MemoryTarget) => {
                let payload: MemoryTarget = envelope.payload()?;
                Self::MemoryTarget {
                    total_mib: payload.total_mib,
                }
            }
            Some(ControlMessageType::CpuTarget) => {
                let payload: CpuTarget = envelope.payload()?;
                Self::CpuTarget {
                    online: payload.online,
                }
            }
            Some(ControlMessageType::SecretsUpdate) => {
                // Serde's tagged-enum buffering alone does not reject every
                // duplicate. Check each entry before any host operation runs.
                let value = decode_value(&envelope.p)?;
                validate_record(&value)?;
                let Value::Map(fields) = &value else {
                    unreachable!()
                };
                if let Some((_, Value::Array(changes))) = fields
                    .iter()
                    .find(|(key, _)| key.as_text() == Some("changes"))
                {
                    for change in changes {
                        validate_record(change)?;
                    }
                }
                let payload: SecretsUpdate =
                    value.deserialized().map_err(|_| WireError::InvalidRecord)?;
                Self::SecretsUpdate {
                    changes: payload.changes,
                }
            }
            _ => return Err(WireError::InvalidRecord),
        })
    }

    /// Encode the CBOR operation corresponding to this legacy-compatible value.
    pub fn envelope(&self, generation: u8) -> Result<Envelope, WireError> {
        match self {
            Self::Capabilities => Envelope::new(
                generation,
                ControlMessageType::Capabilities.as_str(),
                &Empty {},
            ),
            Self::MemoryState => Envelope::new(
                generation,
                ControlMessageType::MemoryState.as_str(),
                &Empty {},
            ),
            Self::CpuState => {
                Envelope::new(generation, ControlMessageType::CpuState.as_str(), &Empty {})
            }
            Self::MemoryTarget { total_mib } => Envelope::new(
                generation,
                ControlMessageType::MemoryTarget.as_str(),
                &MemoryTarget {
                    total_mib: *total_mib,
                },
            ),
            Self::CpuTarget { online } => Envelope::new(
                generation,
                ControlMessageType::CpuTarget.as_str(),
                &CpuTarget { online: *online },
            ),
            Self::SecretsUpdate { changes } => {
                // Borrow secret entries instead of cloning their plaintext.
                #[derive(Serialize)]
                struct Payload<'a> {
                    changes: &'a [super::SecretChange],
                }
                Envelope::new(
                    generation,
                    ControlMessageType::SecretsUpdate.as_str(),
                    &Payload { changes },
                )
            }
        }
    }
}

impl SecretsResult {
    /// Decode sequential progress, checking nested error keys and index equality.
    pub fn decode(payload: &[u8]) -> Result<Self, WireError> {
        let value = decode_value(payload)?;
        validate_record(&value)?;
        if let Value::Map(fields) = &value
            && let Some((_, error)) = fields
                .iter()
                .find(|(key, _)| key.as_text() == Some("error"))
        {
            validate_record(error)?;
        }
        let result: Self = value.deserialized().map_err(|_| WireError::InvalidRecord)?;
        if matches!(&result, Self::Failed { applied_count, failed_index, .. } if applied_count != failed_index)
        {
            return Err(WireError::InvalidRecord);
        }
        Ok(result)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl AsRef<str> for ControlMessageType {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl Serialize for ControlMessageType {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for ControlMessageType {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let name = String::deserialize(deserializer)?;
        Self::from_wire_str(&name)
            .ok_or_else(|| serde::de::Error::custom("unknown control message type"))
    }
}
