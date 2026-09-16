//! Transport packet abstraction for agent protocol frames.
//!
//! The transport layer is intentionally CBOR-blind. It moves complete
//! length-prefixed packets and leaves message-type validation to higher layers.

use microsandbox_protocol::codec::{self, RawFrame};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{AgentClientError, AgentClientResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Exact bytes sent over an agent transport.
///
/// A packet contains the four-byte length prefix followed by one binary frame:
/// `[len: u32 BE][id: u32 BE][flags: u8][body...]`.
#[derive(Clone)]
pub struct TransportPacket {
    bytes: Vec<u8>,
}

/// Owned byte transport accepted directly by `AgentClient::connect_stream`.
pub use microsandbox_protocol_client::ByteTransport as AgentTransport;

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
        if bytes.len() < 9 {
            return Err(AgentClientError::InvalidPacket(
                "packet does not contain a complete frame".to_string(),
            ));
        }
        let length = u32::from_be_bytes(bytes[..4].try_into().unwrap());
        if !(5..=codec::MAX_FRAME_SIZE).contains(&length) || length as usize + 4 != bytes.len() {
            return Err(AgentClientError::InvalidPacket(
                "packet must contain exactly one bounded frame".to_string(),
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
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for TransportPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransportPacket")
            .field("bytes", &self.bytes.len())
            .finish()
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
    let mut prefix = [0; 4];
    if reader.read(&mut prefix[..1]).await? == 0 {
        return Ok(None);
    }
    // Only EOF before the first byte is clean; a partial prefix is truncation.
    reader.read_exact(&mut prefix[1..]).await?;
    let length = u32::from_be_bytes(prefix);
    if !(5..=codec::MAX_FRAME_SIZE).contains(&length) {
        return Err(AgentClientError::InvalidPacket(
            "invalid frame length".into(),
        ));
    }
    let mut bytes = vec![0; length as usize + 4];
    bytes[..4].copy_from_slice(&prefix);
    reader.read_exact(&mut bytes[4..]).await?;
    Ok(Some(TransportPacket { bytes }))
}

/// Write one packet to a byte stream.
pub async fn write_packet_to_io<W>(writer: &mut W, packet: TransportPacket) -> AgentClientResult<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(packet.as_bytes()).await?;
    writer.flush().await?;
    Ok(())
}
