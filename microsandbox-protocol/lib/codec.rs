//! Length-prefixed CBOR frame codec for reading and writing protocol messages.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{ProtocolError, ProtocolResult};
use crate::message::Message;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum allowed frame size (4 MiB).
pub const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Encodes a message to a byte buffer using the length-prefixed frame format.
///
/// Frame format: `[len: u32 BE][CBOR payload]`
pub fn encode_to_buf(msg: &Message, buf: &mut Vec<u8>) -> ProtocolResult<()> {
    let mut payload = Vec::new();
    ciborium::into_writer(msg, &mut payload)?;

    let len = u32::try_from(payload.len()).map_err(|_| ProtocolError::FrameTooLarge {
        size: u32::MAX,
        max: MAX_FRAME_SIZE,
    })?;

    if len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: len,
            max: MAX_FRAME_SIZE,
        });
    }

    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(&payload);
    Ok(())
}

/// Tries to decode a complete message from a byte buffer.
///
/// Returns `Some(Message)` if a complete frame is available, consuming
/// the bytes. Returns `None` if more data is needed.
///
/// Frame format: `[len: u32 BE][CBOR payload]`
pub fn try_decode_from_buf(buf: &mut Vec<u8>) -> ProtocolResult<Option<Message>> {
    if buf.len() < 4 {
        return Ok(None);
    }

    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

    if len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: len,
            max: MAX_FRAME_SIZE,
        });
    }

    let len = len as usize;
    if buf.len() < 4 + len {
        return Ok(None);
    }

    let payload = &buf[4..4 + len];
    let msg: Message = ciborium::from_reader(payload)?;

    buf.drain(..4 + len);
    Ok(Some(msg))
}

/// Reads a length-prefixed CBOR message from the given reader.
///
/// Frame format: `[len: u32 BE][CBOR payload]`
pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> ProtocolResult<Message> {
    // Read the 4-byte length prefix.
    let mut len_buf = [0u8; 4];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            return Err(ProtocolError::UnexpectedEof);
        }
        Err(e) => return Err(e.into()),
    }

    let len = u32::from_be_bytes(len_buf);

    if len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: len,
            max: MAX_FRAME_SIZE,
        });
    }

    // Read the CBOR payload.
    let mut payload = vec![0u8; len as usize];
    reader.read_exact(&mut payload).await?;

    // Deserialize the message.
    let message: Message = ciborium::from_reader(&payload[..])?;
    Ok(message)
}

/// Writes a length-prefixed CBOR message to the given writer.
///
/// Frame format: `[len: u32 BE][CBOR payload]`
pub async fn write_message<W: AsyncWrite + Unpin>(
    writer: &mut W,
    message: &Message,
) -> ProtocolResult<()> {
    let mut buf = Vec::new();
    encode_to_buf(message, &mut buf)?;
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::{MessageType, PROTOCOL_VERSION};

    #[tokio::test]
    async fn test_codec_roundtrip_empty_payload() {
        let msg = Message {
            v: PROTOCOL_VERSION,
            t: MessageType::Ready,
            id: 0,
            p: Vec::new(),
        };

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = &buf[..];
        let decoded = read_message(&mut cursor).await.unwrap();

        assert_eq!(decoded.v, msg.v);
        assert_eq!(decoded.t, msg.t);
        assert_eq!(decoded.id, msg.id);
    }

    #[tokio::test]
    async fn test_codec_roundtrip_with_payload() {
        use crate::exec::ExecExited;

        let msg = Message::with_payload(
            MessageType::ExecExited,
            7,
            &ExecExited { code: 42 },
        )
        .unwrap();

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = &buf[..];
        let decoded = read_message(&mut cursor).await.unwrap();

        assert_eq!(decoded.v, PROTOCOL_VERSION);
        assert_eq!(decoded.t, MessageType::ExecExited);
        assert_eq!(decoded.id, 7);

        let payload: ExecExited = decoded.payload().unwrap();
        assert_eq!(payload.code, 42);
    }

    #[tokio::test]
    async fn test_codec_multiple_messages() {
        let messages = vec![
            Message::new(MessageType::Ready, 0, Vec::new()),
            Message::new(MessageType::ExecExited, 1, Vec::new()),
            Message::new(MessageType::Shutdown, 2, Vec::new()),
        ];

        let mut buf = Vec::new();
        for msg in &messages {
            write_message(&mut buf, msg).await.unwrap();
        }

        let mut cursor = &buf[..];
        for expected in &messages {
            let decoded = read_message(&mut cursor).await.unwrap();
            assert_eq!(decoded.t, expected.t);
            assert_eq!(decoded.id, expected.id);
        }
    }

    #[tokio::test]
    async fn test_codec_unexpected_eof() {
        let mut cursor: &[u8] = &[];
        let result = read_message(&mut cursor).await;
        assert!(matches!(result, Err(ProtocolError::UnexpectedEof)));
    }

    #[test]
    fn test_sync_encode_decode_roundtrip() {
        use crate::exec::ExecExited;

        let msg = Message::with_payload(
            MessageType::ExecExited,
            5,
            &ExecExited { code: 0 },
        )
        .unwrap();

        let mut buf = Vec::new();
        encode_to_buf(&msg, &mut buf).unwrap();

        let decoded = try_decode_from_buf(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.t, MessageType::ExecExited);
        assert_eq!(decoded.id, 5);

        let payload: ExecExited = decoded.payload().unwrap();
        assert_eq!(payload.code, 0);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_sync_decode_incomplete() {
        let mut buf = vec![0, 0, 0, 10]; // Length 10 but no payload bytes.
        assert!(try_decode_from_buf(&mut buf).unwrap().is_none());
    }

    #[test]
    fn test_sync_decode_frame_too_large() {
        let huge_len: u32 = MAX_FRAME_SIZE + 1;
        let mut buf = Vec::new();
        buf.extend_from_slice(&huge_len.to_be_bytes());
        let result = try_decode_from_buf(&mut buf);
        assert!(matches!(result, Err(ProtocolError::FrameTooLarge { .. })));
    }
}
