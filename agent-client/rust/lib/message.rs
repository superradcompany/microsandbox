//! Outbound agent message builders.
//!
//! These types represent the semantic message before the client assigns a
//! correlation ID and writes a transport packet.

use microsandbox_protocol::codec::RawFrame;
use microsandbox_protocol::message::{Message, MessageType};
use serde::Serialize;

use crate::{AgentClientError, AgentClientResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A message described by protocol type and a native serializable payload.
///
/// Use this form when Rust should CBOR-encode the payload. The payload type must
/// serialize to the shape expected by `microsandbox-protocol` for
/// [`message_type`](Self::message_type).
#[derive(Debug, Clone)]
pub struct TypedMessage<T> {
    /// Protocol message type.
    pub message_type: MessageType,
    /// Native payload to CBOR-encode.
    pub payload: T,
}

/// A message described by protocol type and already-CBOR-encoded payload bytes.
///
/// The payload is only the message-type payload, not the outer protocol
/// envelope and not the length-prefixed transport packet. The client still
/// builds `{ v, t, p }`, derives frame flags, and assigns the correlation ID.
#[derive(Debug, Clone)]
pub struct EncodedMessage {
    /// Protocol message type.
    pub message_type: MessageType,
    /// CBOR-encoded payload bytes.
    pub payload: Vec<u8>,
}

/// Fully encoded outbound message body, before correlation ID assignment.
///
/// This is the CBOR protocol envelope body that belongs after the binary frame
/// header. It is mostly useful for transport adapters, tests, and language
/// bindings.
#[derive(Debug, Clone)]
pub struct OutboundMessage {
    /// Protocol message type.
    pub message_type: MessageType,
    /// Frame flags derived from the message type.
    pub flags: u8,
    /// CBOR-encoded protocol envelope body.
    pub body: Vec<u8>,
}

/// Converts a typed or encoded message into an outbound protocol body.
///
/// Implementations must fail before sending when the negotiated peer generation
/// is too old for the selected message type.
pub trait IntoOutboundMessage {
    /// Encode the outbound message for a connection.
    ///
    /// `protocol_version` is the generation written into the envelope.
    /// `negotiated_version` is the capability gate used before encoding.
    fn into_outbound_message(
        self,
        protocol_version: u8,
        negotiated_version: u8,
    ) -> AgentClientResult<OutboundMessage>;
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<T> TypedMessage<T> {
    /// Create a typed message from a protocol type and native payload.
    pub fn new(message_type: MessageType, payload: T) -> Self {
        Self {
            message_type,
            payload,
        }
    }
}

impl EncodedMessage {
    /// Create an encoded message from a protocol type and CBOR payload bytes.
    pub fn new(message_type: MessageType, payload: impl Into<Vec<u8>>) -> Self {
        Self {
            message_type,
            payload: payload.into(),
        }
    }
}

impl OutboundMessage {
    /// Convert the outbound message into a raw frame with an assigned ID.
    pub fn into_raw_frame(self, id: u32) -> RawFrame {
        RawFrame {
            id,
            flags: self.flags,
            body: self.body,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<T> IntoOutboundMessage for TypedMessage<T>
where
    T: Serialize,
{
    fn into_outbound_message(
        self,
        protocol_version: u8,
        negotiated_version: u8,
    ) -> AgentClientResult<OutboundMessage> {
        let mut payload = Vec::new();
        ciborium::into_writer(&self.payload, &mut payload)
            .map_err(|error| AgentClientError::Cbor(error.to_string()))?;
        EncodedMessage::new(self.message_type, payload)
            .into_outbound_message(protocol_version, negotiated_version)
    }
}

impl IntoOutboundMessage for EncodedMessage {
    fn into_outbound_message(
        self,
        protocol_version: u8,
        negotiated_version: u8,
    ) -> AgentClientResult<OutboundMessage> {
        if !self.message_type.is_available_at(negotiated_version) {
            return Err(AgentClientError::UnsupportedOperation {
                msg_type: self.message_type.as_str(),
                needs: self.message_type.min_protocol_version(),
                peer: negotiated_version,
            });
        }

        let flags = self.message_type.flags();
        let message = Message {
            v: protocol_version,
            t: self.message_type,
            id: 0,
            flags,
            p: self.payload,
        };
        let mut body = Vec::new();
        ciborium::into_writer(&message, &mut body)
            .map_err(|error| AgentClientError::Cbor(error.to_string()))?;

        Ok(OutboundMessage {
            message_type: self.message_type,
            flags,
            body,
        })
    }
}
