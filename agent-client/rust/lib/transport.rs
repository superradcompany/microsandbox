//! Transport packet abstraction for agent protocol frames.
//!
//! The transport layer is intentionally CBOR-blind. It moves complete
//! length-prefixed packets and leaves message-type validation to higher layers.

use std::future::Future;
use std::pin::Pin;

use microsandbox_protocol::codec::{self, RawFrame};
use tokio::io::{AsyncRead, AsyncWrite};

use crate::error::{AgentClientError, AgentClientResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Exact bytes sent over an agent transport.
///
/// A packet contains the four-byte length prefix followed by one binary frame:
/// `[len: u32 BE][id: u32 BE][flags: u8][body...]`.
#[derive(Debug, Clone)]
pub struct TransportPacket {
    bytes: Vec<u8>,
}

/// Bidirectional packet transport for the agent protocol.
///
/// Custom transports can implement this trait when they can preserve exact
/// packet boundaries. Byte-stream transports may use
/// [`read_packet_from_io`] and [`write_packet_to_io`].
pub trait AgentTransport: Send + Unpin + 'static {
    /// Read the next packet. Returns `None` when the transport reaches EOF.
    fn read_packet(
        &mut self,
    ) -> Pin<Box<dyn Future<Output = AgentClientResult<Option<TransportPacket>>> + Send + '_>>;

    /// Write one packet to the transport.
    fn write_packet(
        &mut self,
        packet: TransportPacket,
    ) -> Pin<Box<dyn Future<Output = AgentClientResult<()>> + Send + '_>>;
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TransportPacket {
    /// Validate and wrap exact wire bytes.
    ///
    /// The input must contain exactly one complete transport packet. It may be
    /// used by unchecked write paths, but it is still structurally validated so
    /// callers cannot accidentally concatenate packets or pass a truncated
    /// frame.
    pub fn from_bytes(bytes: impl Into<Vec<u8>>) -> AgentClientResult<Self> {
        let bytes = bytes.into();
        let mut buf = bytes.clone();
        let Some(_frame) = codec::try_decode_raw_from_buf(&mut buf)? else {
            return Err(AgentClientError::InvalidPacket(
                "packet does not contain a complete frame".to_string(),
            ));
        };
        if !buf.is_empty() {
            return Err(AgentClientError::InvalidPacket(
                "packet contains trailing bytes".to_string(),
            ));
        }
        Ok(Self { bytes })
    }

    /// Create a packet from a structured raw frame.
    ///
    /// The frame body is left opaque; this method only applies the binary
    /// transport framing.
    pub fn from_frame(frame: &RawFrame) -> AgentClientResult<Self> {
        let mut bytes = Vec::new();
        codec::encode_raw_to_buf(frame, &mut bytes)?;
        Ok(Self { bytes })
    }

    /// Borrow the exact transport bytes.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Consume the packet and return its exact transport bytes.
    pub fn into_bytes(self) -> Vec<u8> {
        self.bytes
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read one length-prefixed packet from a byte stream.
///
/// Returns `Ok(None)` on clean EOF before a new packet begins.
pub async fn read_packet_from_io<R>(reader: &mut R) -> AgentClientResult<Option<TransportPacket>>
where
    R: AsyncRead + Unpin,
{
    match codec::read_raw_frame(reader).await {
        Ok(frame) => TransportPacket::from_frame(&frame).map(Some),
        Err(microsandbox_protocol::ProtocolError::UnexpectedEof) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Write one packet to a byte stream.
pub async fn write_packet_to_io<W>(writer: &mut W, packet: TransportPacket) -> AgentClientResult<()>
where
    W: AsyncWrite + Unpin,
{
    use tokio::io::AsyncWriteExt;

    writer.write_all(packet.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}
