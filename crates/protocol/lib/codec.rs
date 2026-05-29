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
// Types
//--------------------------------------------------------------------------------------------------

/// A frame with the binary header parsed but the CBOR body left untouched.
///
/// Used by routers, relays, and FFI consumers that want to handle framing
/// without paying for CBOR (de)serialization. The [`body`](Self::body) field
/// contains the exact CBOR-encoded `Message` body bytes — `v`, `t`, `p` —
/// the same bytes that follow the binary header on the wire.
#[derive(Debug, Clone)]
pub struct RawFrame {
    /// Correlation ID. Same as [`Message::id`].
    pub id: u32,

    /// Frame flags. Same as [`Message::flags`].
    pub flags: u8,

    /// Raw CBOR bytes of the message body (`v`, `t`, `p`). Not decoded.
    pub body: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Functions: Raw frame codec (CBOR-blind)
//--------------------------------------------------------------------------------------------------

/// Encodes a raw frame to a byte buffer using the length-prefixed format.
///
/// Frame format: `[len: u32 BE][id: u32 BE][flags: u8][body...]`
pub fn encode_raw_to_buf(frame: &RawFrame, buf: &mut Vec<u8>) -> ProtocolResult<()> {
    let frame_len = u32::try_from(FRAME_HEADER_SIZE + frame.body.len()).map_err(|_| {
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
    buf.extend_from_slice(&frame.id.to_be_bytes());
    buf.push(frame.flags);
    buf.extend_from_slice(&frame.body);
    Ok(())
}

/// Tries to decode a complete raw frame from a byte buffer.
///
/// Returns `Some(RawFrame)` if a complete frame is available, consuming
/// the bytes. Returns `None` if more data is needed.
///
/// Frame format: `[len: u32 BE][id: u32 BE][flags: u8][body...]`
pub fn try_decode_raw_from_buf(buf: &mut Vec<u8>) -> ProtocolResult<Option<RawFrame>> {
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

    let id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
    let flags = buf[8];
    let body = buf[4 + FRAME_HEADER_SIZE..total].to_vec();

    buf.drain(..total);
    Ok(Some(RawFrame { id, flags, body }))
}

/// Reads a length-prefixed raw frame from the given reader.
///
/// Frame format: `[len: u32 BE][id: u32 BE][flags: u8][body...]`
pub async fn read_raw_frame<R: AsyncRead + Unpin>(reader: &mut R) -> ProtocolResult<RawFrame> {
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

    let mut payload = vec![0u8; frame_len];
    reader.read_exact(&mut payload).await?;

    let id = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let flags = payload[4];
    let body = payload[FRAME_HEADER_SIZE..].to_vec();

    Ok(RawFrame { id, flags, body })
}

/// Writes a length-prefixed raw frame to the given writer.
///
/// Frame format: `[len: u32 BE][id: u32 BE][flags: u8][body...]`
pub async fn write_raw_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &RawFrame,
) -> ProtocolResult<()> {
    let mut buf = Vec::new();
    encode_raw_to_buf(frame, &mut buf)?;
    writer.write_all(&buf).await?;
    writer.flush().await?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Typed message codec (CBOR-aware)
//--------------------------------------------------------------------------------------------------

/// Encodes a message to a byte buffer using the length-prefixed frame format.
///
/// Frame format: `[len: u32 BE][id: u32 BE][flags: u8][CBOR(v, t, p)]`
pub fn encode_to_buf(msg: &Message, buf: &mut Vec<u8>) -> ProtocolResult<()> {
    let mut body = Vec::new();
    ciborium::into_writer(msg, &mut body)?;
    encode_raw_to_buf(
        &RawFrame {
            id: msg.id,
            flags: msg.flags,
            body,
        },
        buf,
    )
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

    let msg = decode_message_frame(&buf[..total])?;
    buf.drain(..total);
    Ok(Some(msg))
}

/// Reads a length-prefixed message from the given reader.
///
/// Frame format: `[len: u32 BE][id: u32 BE][flags: u8][CBOR(v, t, p)]`
pub async fn read_message<R: AsyncRead + Unpin>(reader: &mut R) -> ProtocolResult<Message> {
    let frame = read_raw_frame(reader).await?;
    raw_frame_to_message(frame)
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

/// Decodes a [`RawFrame`] into a typed [`Message`] by CBOR-deserializing the body.
pub fn raw_frame_to_message(frame: RawFrame) -> ProtocolResult<Message> {
    let mut msg: Message = ciborium::from_reader(&frame.body[..])?;
    msg.id = frame.id;
    msg.flags = frame.flags;
    Ok(msg)
}

/// Decodes one complete length-prefixed frame from a borrowed byte slice.
///
/// The input must include the 4-byte length prefix, frame header, and CBOR body.
/// The slice is not consumed or copied.
pub fn decode_message_frame(frame: &[u8]) -> ProtocolResult<Message> {
    if frame.len() < 4 {
        return Err(ProtocolError::UnexpectedEof);
    }

    let frame_len = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]);
    if frame_len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: frame_len,
            max: MAX_FRAME_SIZE,
        });
    }

    let frame_len = frame_len as usize;
    let total = 4 + frame_len;
    if frame.len() < total {
        return Err(ProtocolError::UnexpectedEof);
    }

    if frame_len < FRAME_HEADER_SIZE {
        return Err(ProtocolError::FrameTooShort {
            size: frame_len as u32,
            min: FRAME_HEADER_SIZE as u32,
        });
    }

    let mut msg: Message = ciborium::from_reader(&frame[4 + FRAME_HEADER_SIZE..total])?;
    msg.id = u32::from_be_bytes([frame[4], frame[5], frame[6], frame[7]]);
    msg.flags = frame[8];
    Ok(msg)
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
    fn test_borrowed_decode_message_frame_roundtrip() {
        use crate::exec::ExecExited;

        let msg =
            Message::with_payload(MessageType::ExecExited, 5, &ExecExited { code: 0 }).unwrap();

        let mut buf = Vec::new();
        encode_to_buf(&msg, &mut buf).unwrap();

        let decoded = decode_message_frame(&buf).unwrap();
        assert_eq!(decoded.t, MessageType::ExecExited);
        assert_eq!(decoded.id, 5);
        assert_eq!(decoded.flags, FLAG_TERMINAL);

        let payload: ExecExited = decoded.payload().unwrap();
        assert_eq!(payload.code, 0);
        assert!(!buf.is_empty(), "borrowed decode must not consume input");
    }

    #[test]
    fn test_borrowed_decode_message_frame_rejects_incomplete() {
        let buf = vec![0, 0, 0, 10];
        assert!(matches!(
            decode_message_frame(&buf),
            Err(ProtocolError::UnexpectedEof)
        ));
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

    #[tokio::test]
    async fn test_raw_frame_roundtrip() {
        let frame = RawFrame {
            id: 0xDEADBEEF,
            flags: FLAG_TERMINAL,
            body: vec![1, 2, 3, 4, 5],
        };

        let mut buf = Vec::new();
        write_raw_frame(&mut buf, &frame).await.unwrap();

        let mut cursor = &buf[..];
        let decoded = read_raw_frame(&mut cursor).await.unwrap();

        assert_eq!(decoded.id, frame.id);
        assert_eq!(decoded.flags, frame.flags);
        assert_eq!(decoded.body, frame.body);
    }

    #[test]
    fn test_raw_frame_sync_roundtrip() {
        let frame = RawFrame {
            id: 42,
            flags: FLAG_SESSION_START,
            body: vec![0xAA; 100],
        };

        let mut buf = Vec::new();
        encode_raw_to_buf(&frame, &mut buf).unwrap();

        let decoded = try_decode_raw_from_buf(&mut buf).unwrap().unwrap();
        assert_eq!(decoded.id, frame.id);
        assert_eq!(decoded.flags, frame.flags);
        assert_eq!(decoded.body, frame.body);
        assert!(buf.is_empty());
    }

    #[test]
    fn test_raw_frame_to_message() {
        use crate::exec::ExecExited;

        let msg =
            Message::with_payload(MessageType::ExecExited, 13, &ExecExited { code: 7 }).unwrap();

        let mut buf = Vec::new();
        encode_to_buf(&msg, &mut buf).unwrap();

        let frame = try_decode_raw_from_buf(&mut buf).unwrap().unwrap();
        let decoded = raw_frame_to_message(frame).unwrap();

        assert_eq!(decoded.id, 13);
        assert_eq!(decoded.t, MessageType::ExecExited);
        let payload: ExecExited = decoded.payload().unwrap();
        assert_eq!(payload.code, 7);
    }
}
