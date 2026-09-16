//! Native, encoded-payload, and inspectable inbound message surfaces.

use microsandbox_protocol::wire::{self, Envelope};
use serde::{Serialize, de::DeserializeOwned};

use crate::{ClientError, ClientResult, EnvelopeCodec, ErrorKind, Protocol, RawFrame};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Decoded message with its original frame retained for unknown fields/forwarding.
pub struct Message {
    /// Actual envelope generation.
    pub v: u8,
    /// Actual wire name, including unknown future names.
    pub t: String,
    /// Frame correlation ID.
    pub id: u32,
    /// Actual frame flags.
    pub flags: u8,
    /// Original encoded payload.
    pub p: Vec<u8>,
    frame: RawFrame,
}

/// Native payload paired with an explicit wire name; this is not schema proof.
pub struct TypedMessage<T> {
    /// Application wire name.
    pub message_type: String,
    /// Native serializable value, often a borrowed prepared request.
    pub payload: T,
}

/// Already-encoded application payload, separate from the outer envelope.
pub struct EncodedMessage {
    /// Application wire name.
    pub message_type: String,
    /// Exact CBOR payload bytes; never normalized.
    pub payload: Vec<u8>,
}

/// Complete envelope and flags, before the router assigns a correlation ID.
pub struct OutboundMessage {
    /// Protocol-selected flags.
    pub flags: u8,
    /// Opaque envelope bytes.
    pub body: Vec<u8>,
}

/// Prepare a named message using one protocol's availability gates and codec.
pub trait IntoOutboundMessage<P: Protocol> {
    /// Validate before admission and encode only the layer supplied by the caller.
    fn into_outbound(
        self,
        ready: &P::Ready,
        codec: &dyn EnvelopeCodec,
    ) -> ClientResult<OutboundMessage>;
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Message {
    /// Construct a view for a custom envelope codec without losing original bytes.
    pub fn new(frame: RawFrame, envelope: Envelope) -> Self {
        Self {
            v: envelope.v,
            t: envelope.t,
            id: frame.id,
            flags: frame.flags,
            p: envelope.p,
            frame,
        }
    }

    /// Decode a known payload without narrowing the incoming message namespace.
    pub fn payload<T: DeserializeOwned>(&self) -> ClientResult<T> {
        let value = wire::decode_value(&self.p)?;
        value
            .deserialized()
            .map_err(|_| ClientError::new(ErrorKind::InvalidData))
    }

    /// Inspect the original frame, including unknown envelope fields.
    pub fn raw(&self) -> &RawFrame {
        &self.frame
    }

    /// Recover the exact received frame for forwarding.
    pub fn into_raw(self) -> RawFrame {
        self.frame
    }
}

impl<T> TypedMessage<T> {
    /// Pair a native payload with a wire name without performing I/O.
    pub fn new(message_type: impl AsRef<str>, payload: T) -> Self {
        Self {
            message_type: message_type.as_ref().into(),
            payload,
        }
    }
}

impl EncodedMessage {
    /// Pair opaque payload bytes with a wire name without encoding them again.
    pub fn new(message_type: impl AsRef<str>, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            message_type: message_type.as_ref().into(),
            payload: payload.into(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<P: Protocol, T: Serialize> IntoOutboundMessage<P> for TypedMessage<T> {
    fn into_outbound(
        self,
        ready: &P::Ready,
        codec: &dyn EnvelopeCodec,
    ) -> ClientResult<OutboundMessage> {
        let metadata = P::prepare(ready, &self.message_type)?;
        let payload =
            wire::encode(&self.payload).map_err(|_| ClientError::new(ErrorKind::Encode))?;
        let body = codec.encode(metadata.generation, &self.message_type, payload)?;
        Ok(OutboundMessage {
            flags: metadata.flags,
            body,
        })
    }
}

impl<P: Protocol> IntoOutboundMessage<P> for EncodedMessage {
    fn into_outbound(
        self,
        ready: &P::Ready,
        codec: &dyn EnvelopeCodec,
    ) -> ClientResult<OutboundMessage> {
        let metadata = P::prepare(ready, &self.message_type)?;
        let body = codec.encode(metadata.generation, &self.message_type, self.payload)?;
        Ok(OutboundMessage {
            flags: metadata.flags,
            body,
        })
    }
}

impl std::fmt::Debug for Message {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Message")
            .field("id", &self.id)
            .field("flags", &self.flags)
            .field("generation", &self.v)
            .field("payload_bytes", &self.p.len())
            .finish_non_exhaustive()
    }
}
