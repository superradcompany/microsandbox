//! Public protocol extension boundary; no knowledge of agent or control ops.

use std::sync::Arc;

use microsandbox_protocol::wire::Envelope;

use crate::{
    BoxFuture, BoxTransport, ClientError, ClientLimits, ClientResult, ConnectOptions, ErrorKind,
    Message,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Protocol-specific setup and message metadata, leaving routing to `Client`.
pub trait Protocol: Send + Sync + 'static {
    /// Whether terminal completion permits reusing a correlation ID.
    const REUSE_IDS: bool = true;
    /// Shared immutable metadata negotiated during setup.
    type Ready: Send + Sync + 'static;

    /// Consume an owned stream and preserve any prefetched bytes in the result.
    fn establish(
        stream: BoxTransport,
        options: ConnectOptions,
    ) -> BoxFuture<'static, ClientResult<Established<Self::Ready>>>;

    /// Validate availability and select metadata for a named outbound message.
    fn prepare(ready: &Self::Ready, wire_name: &str) -> ClientResult<SendMetadata>;
}

/// Envelope semantics chosen during setup. Raw routing never invokes this.
pub trait EnvelopeCodec: Send + Sync + 'static {
    /// Encode an envelope without modifying already-encoded payload bytes.
    fn encode(&self, generation: u8, wire_name: &str, payload: Vec<u8>) -> ClientResult<Vec<u8>>;

    /// Decode an inspectable message while retaining its original wire frame.
    fn decode(&self, frame: crate::RawFrame) -> ClientResult<Message>;
}

/// Standard `{v,t,p}` CBOR envelope with an open message namespace.
#[derive(Debug, Clone, Copy, Default)]
pub struct CborEnvelopeCodec;

/// Successfully established transport and immutable protocol metadata.
pub struct Established<R> {
    /// Exclusive byte transport, including any unread prefetched bytes.
    pub transport: BoxTransport,
    /// Envelope codec selected by protocol setup.
    pub codec: Arc<dyn EnvelopeCodec>,
    /// Negotiated usable correlation IDs.
    pub ids: IdRange,
    /// Protocol-specific welcome/ready metadata.
    pub ready: R,
    /// Final connection limits, including peer-negotiated ceilings.
    pub limits: ClientLimits,
}

/// Nonzero ID range; the wider upper bound represents the entire u32 space.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdRange {
    /// Inclusive lower bound, at least one.
    pub start: u32,
    /// Exclusive upper bound, at most 2^32.
    pub end_exclusive: u64,
}

/// Protocol-generated envelope generation and frame flags.
#[derive(Debug, Clone, Copy)]
pub struct SendMetadata {
    /// Envelope generation.
    pub generation: u8,
    /// Frame flags, independent of correlation ID allocation.
    pub flags: u8,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl IdRange {
    /// Reject zero, empty, reversed, and overflowing ranges.
    pub fn validate(self) -> ClientResult<()> {
        if self.start == 0
            || u64::from(self.start) >= self.end_exclusive
            || self.end_exclusive > (1u64 << 32)
        {
            return Err(ClientError::new(ErrorKind::InvalidOptions));
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl EnvelopeCodec for CborEnvelopeCodec {
    fn encode(&self, generation: u8, wire_name: &str, payload: Vec<u8>) -> ClientResult<Vec<u8>> {
        Ok(Envelope {
            v: generation,
            t: wire_name.into(),
            p: payload,
        }
        .encode()?)
    }

    fn decode(&self, frame: crate::RawFrame) -> ClientResult<Message> {
        let envelope = Envelope::decode(&frame.body)?;
        Ok(Message::new(frame, envelope))
    }
}
