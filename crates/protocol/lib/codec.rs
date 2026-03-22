//! Length-prefixed frame codec for reading and writing protocol messages.
//!
//! Wire format: `[len: u32 BE][id: u32 BE][flags: u8][CBOR(v, t, p)]`
//!
//! The correlation ID and flags sit in a fixed-position binary header so that
//! relay intermediaries can route frames without CBOR parsing.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    error::{ProtocolError, ProtocolResult},
    message::{FRAME_HEADER_SIZE, Message},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum allowed frame size (4 MiB).
///
/// This covers everything after the 4-byte length prefix:
/// `id (4) + flags (1) + CBOR payload`.
pub const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Encodes a message to a byte buffer using the length-prefixed frame format.
///
/// Frame format: `[len: u32 BE][id: u32 BE][flags: u8][CBOR(v, t, p)]`
pub fn encode_to_buf(msg: &Message, buf: &mut Vec<u8>) -> ProtocolResult<()> {
    // Serialize the CBOR body (v, t, p — id and flags are excluded via serde(skip)).
    let mut cbor = Vec::new();
    ciborium::into_writer(msg, &mut cbor)?;

    // Total frame payload = id (4) + flags (1) + CBOR body.
    let frame_len = u32::try_from(FRAME_HEADER_SIZE + cbor.len()).map_err(|_| {
        ProtocolError::FrameTooLarge {
            size: u32::MAX,
            max: MAX_FRAME_SIZE,
        }
    })?;

    if frame_len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: frame_len,
            max: MAX_FRAME_SIZE,
        });
    }

    buf.extend_from_slice(&frame_len.to_be_bytes());
    buf.extend_from_slice(&msg.id.to_be_bytes());
    buf.push(msg.flags);
    buf.extend_from_slice(&cbor);
    Ok(())
}

/// Tries to decode a complete message from a byte buffer.
///
/// Returns `Some(Message)` if a complete frame is available, consuming
/// the bytes. Returns `None` if more data is needed.
///
/// Frame format: `[len: u32 BE][id: u32 BE][flags: u8][CBOR(v, t, p)]`
pub fn try_decode_from_buf(buf: &mut Vec<u8>) -> ProtocolResult<Option<Message>> {
    if buf.len() < 4 {
        return Ok(None);
    }

    let frame_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

    if frame_len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: frame_len,
            max: MAX_FRAME_SIZE,
        });
    }

    let frame_len = frame_len as usize;
    let total = 4 + frame_len;

    if buf.len() < total {
        return Ok(None);
    }

    if frame_len < FRAME_HEADER_SIZE {
        return Err(ProtocolError::FrameTooShort {
            size: frame_len as u32,
            min: FRAME_HEADER_SIZE as u32,
        });
    }

    // Extract header fields.
    let id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let flags = buf[8];

    // Deserialize the CBOR body.
    let cbor = &buf[4 + FRAME_HEADER_SIZE..total];
    let mut msg: Message = ciborium::from_reader(cbor)?;
    msg.id = id;
    msg.flags = flags;

    buf.drain(..total);
    Ok(Some(msg))
}

/// Reads a length-prefixed message from the given reader.
///
/// Frame format: `[len: u32 BE][id: u32 BE][flags: u8][CBOR(v, t, p)]`
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

    let frame_len = u32::from_be_bytes(len_buf);

    if frame_len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: frame_len,
            max: MAX_FRAME_SIZE,
        });
    }

    let frame_len = frame_len as usize;

    if frame_len < FRAME_HEADER_SIZE {
        return Err(ProtocolError::FrameTooShort {
            size: frame_len as u32,
            min: FRAME_HEADER_SIZE as u32,
        });
    }

    // Read the full frame payload.
    let mut payload = vec![0u8; frame_len];
    reader.read_exact(&mut payload).await?;

    // Extract header fields.
    let id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let flags = payload[4];

    // Deserialize the CBOR body.
    let cbor = &payload[FRAME_HEADER_SIZE..];
    let mut msg: Message = ciborium::from_reader(cbor)?;
    msg.id = id;
    msg.flags = flags;

    Ok(msg)
}

/// Writes a length-prefixed message to the given writer.
///
/// Frame format: `[len: u32 BE][id: u32 BE][flags: u8][CBOR(v, t, p)]`
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
    use crate::message::{FLAG_SESSION_START, FLAG_TERMINAL, MessageType, PROTOCOL_VERSION};

    #[tokio::test]
    async fn test_codec_roundtrip_empty_payload() {
        let msg = Message::new(MessageType::Ready, 0, Vec::new());

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = &buf[..];
        let decoded = read_message(&mut cursor).await.unwrap();

        assert_eq!(decoded.v, msg.v);
        assert_eq!(decoded.t, msg.t);
        assert_eq!(decoded.id, msg.id);
        assert_eq!(decoded.flags, 0);
    }

    #[tokio::test]
    async fn test_codec_roundtrip_with_payload() {
        use crate::exec::ExecExited;

        let msg =
            Message::with_payload(MessageType::ExecExited, 7, &ExecExited { code: 42 }).unwrap();

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = &buf[..];
        let decoded = read_message(&mut cursor).await.unwrap();

        assert_eq!(decoded.v, PROTOCOL_VERSION);
        assert_eq!(decoded.t, MessageType::ExecExited);
        assert_eq!(decoded.id, 7);
        assert_eq!(decoded.flags, FLAG_TERMINAL);

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
            assert_eq!(decoded.flags, expected.flags);
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

        let msg =
            Message::with_payload(MessageType::ExecExited, 5, &ExecExited { code: 0 }).unwrap();

        let mut buf = Vec::new();
        encode_to_buf(&msg, &mut buf).unwrap();

        let decoded = try_decode_from_buf(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.t, MessageType::ExecExited);
        assert_eq!(decoded.id, 5);
        assert_eq!(decoded.flags, FLAG_TERMINAL);

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

    #[test]
    fn test_frame_header_wire_format() {
        let msg = Message::new(MessageType::ExecRequest, 0x12345678, Vec::new());

        let mut buf = Vec::new();
        encode_to_buf(&msg, &mut buf).unwrap();

        // Bytes 0–3: length prefix (u32 BE).
        let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert_eq!(len as usize + 4, buf.len());

        // Bytes 4–7: correlation ID (u32 BE).
        let id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        assert_eq!(id, 0x12345678);

        // Byte 8: flags.
        assert_eq!(buf[8], FLAG_SESSION_START);

        // Bytes 9..: CBOR body (v, t, p — no id or flags).
    }

    #[test]
    fn test_flags_roundtrip_terminal() {
        let msg = Message::new(MessageType::ExecExited, 99, Vec::new());

        let mut buf = Vec::new();
        encode_to_buf(&msg, &mut buf).unwrap();

        let decoded = try_decode_from_buf(&mut buf).unwrap().unwrap();
        assert_ne!(decoded.flags & FLAG_TERMINAL, 0);
        assert_eq!(decoded.flags & FLAG_SESSION_START, 0);
    }

    #[test]
    fn test_flags_roundtrip_session_start() {
        let msg = Message::new(MessageType::FsRequest, 42, Vec::new());

        let mut buf = Vec::new();
        encode_to_buf(&msg, &mut buf).unwrap();

        let decoded = try_decode_from_buf(&mut buf).unwrap().unwrap();
        assert_ne!(decoded.flags & FLAG_SESSION_START, 0);
        assert_eq!(decoded.flags & FLAG_TERMINAL, 0);
    }

    #[test]
    fn test_sync_decode_frame_too_short() {
        // Frame with len=3 (too short for id+flags header).
        let mut buf = Vec::new();
        buf.extend_from_slice(&3u32.to_be_bytes());
        buf.extend_from_slice(&[0, 0, 0]); // 3 bytes of payload.

        let result = try_decode_from_buf(&mut buf);
        assert!(matches!(result, Err(ProtocolError::FrameTooShort { .. })));
    }
}
