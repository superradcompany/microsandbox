//! Protocol-independent envelopes. Raw routing does not need to decode these.

use std::collections::HashSet;
use std::io::Cursor;

use ciborium::Value;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::codec::{MAX_FRAME_SIZE, RawFrame};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A decoded envelope without a closed application-message enum.
///
/// Keep the original frame when forwarding: re-encoding this view would discard
/// unknown envelope fields. Debug output deliberately omits the payload.
#[derive(Clone, Serialize, Deserialize)]
pub struct Envelope {
    /// Protocol generation.
    pub v: u8,
    /// Application-defined wire name, including unknown future names.
    pub t: String,
    /// Independently CBOR-encoded payload bytes.
    #[serde(with = "serde_bytes")]
    pub p: Vec<u8>,
}

/// Errors from checked envelope/payload decoding, with no untrusted values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum WireError {
    /// The input is not exactly one complete CBOR value.
    #[error("invalid or trailing CBOR data")]
    InvalidCbor,
    /// Input exceeds the outer frame's byte limit.
    #[error("CBOR data exceeds the frame limit")]
    TooLarge,
    /// A checked record does not match its field contract.
    #[error("invalid protocol record")]
    InvalidRecord,
    /// Duplicate keys make a checked record ambiguous.
    #[error("duplicate protocol record key")]
    DuplicateKey,
    /// A native payload could not be serialized.
    #[error("could not encode protocol record")]
    Encode,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Envelope {
    /// Encode a native payload while retaining an explicit wire name.
    pub fn new(v: u8, t: impl Into<String>, payload: &impl Serialize) -> Result<Self, WireError> {
        Ok(Self {
            v,
            t: t.into(),
            p: encode(payload)?,
        })
    }

    /// Encode just the envelope, preserving its already-encoded payload.
    pub fn encode(&self) -> Result<Vec<u8>, WireError> {
        encode(self)
    }

    /// Decode an envelope without restricting application message names.
    pub fn decode(bytes: &[u8]) -> Result<Self, WireError> {
        let value = decode_value(bytes)?;
        validate_record(&value)?;
        let Value::Map(fields) = &value else {
            unreachable!()
        };
        // serde_bytes intentionally accepts integer arrays too. The actual wire
        // envelope requires a CBOR byte string, so enforce that before serde.
        if !fields
            .iter()
            .any(|(key, value)| key.as_text() == Some("p") && matches!(value, Value::Bytes(_)))
        {
            return Err(WireError::InvalidRecord);
        }
        value.deserialized().map_err(|_| WireError::InvalidRecord)
    }

    /// Decode the payload as a checked record. Never required for raw routing.
    pub fn payload<T: DeserializeOwned>(&self) -> Result<T, WireError> {
        decode_record(&self.p)
    }

    /// Attach caller-selected frame routing metadata.
    pub fn frame(&self, id: u32, flags: u8) -> Result<RawFrame, WireError> {
        Ok(RawFrame {
            id,
            flags,
            body: self.encode()?,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for Envelope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Envelope")
            .field("generation", &self.v)
            .field("payload_bytes", &self.p.len())
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Serialize a record without including serializer diagnostics in errors.
pub fn encode(value: &impl Serialize) -> Result<Vec<u8>, WireError> {
    let mut bytes = Vec::new();
    ciborium::ser::into_writer(value, &mut bytes).map_err(|_| WireError::Encode)?;
    if bytes.len() > MAX_FRAME_SIZE as usize {
        return Err(WireError::TooLarge);
    }
    Ok(bytes)
}

/// Decode exactly one record, rejecting duplicate keys and trailing data.
///
/// Unknown fields are ignored by the target type. Their values are not
/// interpreted as application records; this permits future extension values.
pub fn decode_record<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, WireError> {
    let value = decode_value(bytes)?;
    validate_record(&value)?;
    value.deserialized().map_err(|_| WireError::InvalidRecord)
}

/// Decode one CBOR value with the same outer byte bound as framing.
pub fn decode_value(bytes: &[u8]) -> Result<Value, WireError> {
    if bytes.len() > MAX_FRAME_SIZE as usize {
        return Err(WireError::TooLarge);
    }
    let mut reader = Cursor::new(bytes);
    let value = ciborium::de::from_reader(&mut reader).map_err(|_| WireError::InvalidCbor)?;
    if reader.position() != bytes.len() as u64 {
        return Err(WireError::InvalidCbor);
    }
    Ok(value)
}

/// Validate keys of a single record without interpreting unknown field values.
pub fn validate_record(value: &Value) -> Result<(), WireError> {
    let Value::Map(fields) = value else {
        return Err(WireError::InvalidRecord);
    };
    let mut names = HashSet::with_capacity(fields.len());
    for (key, _) in fields {
        let Value::Text(name) = key else {
            return Err(WireError::InvalidRecord);
        };
        if !names.insert(name.as_str()) {
            return Err(WireError::DuplicateKey);
        }
    }
    Ok(())
}
