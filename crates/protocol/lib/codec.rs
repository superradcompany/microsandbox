//! Length-prefixed frame codec for reading and writing protocol messages.
//!
//! Wire format: `[len: u32 BE][id: u32 BE][flags: u8][body]`.
//! Control bodies are CBOR; generation-7 bulk bodies use a fixed raw header.
//!
//! The correlation ID and flags sit in a fixed-position binary header so that
//! relay intermediaries can route frames without CBOR parsing.

use std::io::IoSlice;

use bytes::{Buf, Bytes, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::{
    bulk::{BULK_HEADER_SIZE, BulkFlow, BulkKind, BulkRecord, MAX_BULK_RECORD_PAYLOAD},
    error::{ProtocolError, ProtocolResult},
    message::{FLAG_BULK, FRAME_HEADER_SIZE, Message},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum allowed frame size (4 MiB).
///
/// This covers everything after the 4-byte length prefix:
/// `id (4) + flags (1) + control or raw body`.
pub const MAX_FRAME_SIZE: u32 = 4 * 1024 * 1024;

/// Maximum complete encoded frame size, including the four-byte length prefix.
pub const MAX_WIRE_FRAME: usize = 4 + MAX_FRAME_SIZE as usize;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A frame with the binary header parsed but the body left untouched.
///
/// Used by routers, relays, and FFI consumers that want to handle framing
/// without interpreting the control or raw data body. The [`body`](Self::body)
/// field contains the exact bytes that follow the binary header on the wire.
#[derive(Debug, Clone)]
pub struct RawFrame {
    /// Correlation ID. Same as [`Message::id`].
    pub id: u32,

    /// Frame flags. Same as [`Message::flags`].
    pub flags: u8,

    /// Raw body bytes. `flags` determines whether these are CBOR control bytes or raw bulk bytes.
    pub body: Vec<u8>,
}

/// One fully validated control message or raw bulk record.
#[derive(Debug, Clone)]
pub enum DecodedFrame {
    /// CBOR control-plane message.
    Control(Message),

    /// Generation-7 data-plane record.
    Bulk(BulkRecord),
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

    buf.reserve(4 + frame_len as usize);
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

    // Read the fixed header separately so the body is allocated exactly once.
    let mut header = [0u8; FRAME_HEADER_SIZE];
    reader.read_exact(&mut header).await?;
    let id = u32::from_be_bytes(header[..4].try_into().unwrap());
    let flags = header[4];
    let mut body = vec![0u8; frame_len - FRAME_HEADER_SIZE];
    reader.read_exact(&mut body).await?;

    Ok(RawFrame { id, flags, body })
}

/// Writes a length-prefixed raw frame to the given writer.
///
/// Frame format: `[len: u32 BE][id: u32 BE][flags: u8][body...]`
pub async fn write_raw_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &RawFrame,
) -> ProtocolResult<()> {
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

    let mut header = [0u8; 4 + FRAME_HEADER_SIZE];
    header[..4].copy_from_slice(&frame_len.to_be_bytes());
    header[4..8].copy_from_slice(&frame.id.to_be_bytes());
    header[8] = frame.flags;
    write_vectored_all(writer, &header, &frame.body).await?;
    writer.flush().await?;
    Ok(())
}

/// Writes a generation-7 raw bulk record without copying its payload.
pub async fn write_bulk_record<W: AsyncWrite + Unpin>(
    writer: &mut W,
    record: &BulkRecord,
) -> ProtocolResult<()> {
    let header = encode_bulk_header(record)?;
    write_vectored_all(writer, &header, &record.payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Encodes a generation-7 raw bulk record into a contiguous byte buffer.
pub fn encode_bulk_to_buf(record: &BulkRecord, buf: &mut Vec<u8>) -> ProtocolResult<()> {
    let header = encode_bulk_header(record)?;
    buf.reserve(header.len() + record.payload.len());
    buf.extend_from_slice(&header);
    buf.extend_from_slice(&record.payload);
    Ok(())
}

/// Decodes and validates a raw frame as a generation-7 bulk record.
pub fn raw_frame_to_bulk(frame: RawFrame, max_payload: u32) -> ProtocolResult<BulkRecord> {
    if frame.flags != FLAG_BULK {
        return Err(invalid_bulk("bulk flag must be set exclusively"));
    }
    decode_bulk_body(frame.id, Bytes::from(frame.body), max_payload)
}

/// Decodes one complete control or generation-7 bulk frame from a cursor-based buffer.
pub fn try_decode_frame_from_bytes(buf: &mut BytesMut) -> ProtocolResult<Option<DecodedFrame>> {
    let Some((frame_len, total)) = complete_frame_len(buf)? else {
        return Ok(None);
    };

    let flags = buf[8];
    if flags & FLAG_BULK == 0 {
        let message = decode_message_frame(&buf[..total])?;
        buf.advance(total);
        return Ok(Some(DecodedFrame::Control(message)));
    }
    if flags != FLAG_BULK {
        return Err(invalid_bulk(
            "bulk flag cannot be combined with control flags",
        ));
    }
    if frame_len < FRAME_HEADER_SIZE + BULK_HEADER_SIZE + 1 {
        return Err(invalid_bulk("bulk record has no payload"));
    }

    let frame = buf.split_to(total).freeze();
    let id = u32::from_be_bytes(frame[4..8].try_into().unwrap());
    let body = frame.slice(4 + FRAME_HEADER_SIZE..);
    let record = decode_bulk_body(id, body, MAX_BULK_RECORD_PAYLOAD)?;
    Ok(Some(DecodedFrame::Bulk(record)))
}

/// Decode one complete typed frame from a cursor-based buffer without front-draining it.
pub fn try_decode_from_bytes(buf: &mut BytesMut) -> ProtocolResult<Option<Message>> {
    match try_decode_frame_from_bytes(buf)? {
        Some(DecodedFrame::Control(message)) => Ok(Some(message)),
        Some(DecodedFrame::Bulk(_)) => Err(invalid_bulk(
            "raw bulk record passed to the control-message decoder",
        )),
        None => Ok(None),
    }
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
    let mut body = Vec::new();
    ciborium::into_writer(message, &mut body)?;
    write_raw_frame(
        writer,
        &RawFrame {
            id: message.id,
            flags: message.flags,
            body,
        },
    )
    .await
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

/// Encodes the fixed outer and generation-7 bulk headers, leaving the payload separate.
pub fn encode_bulk_header(
    record: &BulkRecord,
) -> ProtocolResult<[u8; 4 + FRAME_HEADER_SIZE + BULK_HEADER_SIZE]> {
    let payload_len = record.payload.len();
    if payload_len == 0 || payload_len > MAX_BULK_RECORD_PAYLOAD as usize {
        return Err(invalid_bulk(format!(
            "payload length {payload_len} is outside 1..={MAX_BULK_RECORD_PAYLOAD}"
        )));
    }
    record
        .offset
        .checked_add(payload_len as u64)
        .ok_or_else(|| invalid_bulk("record end offset overflows u64"))?;

    let frame_len = FRAME_HEADER_SIZE + BULK_HEADER_SIZE + payload_len;
    let frame_len = u32::try_from(frame_len).map_err(|_| ProtocolError::FrameTooLarge {
        size: u32::MAX,
        max: MAX_FRAME_SIZE,
    })?;
    if frame_len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: frame_len,
            max: MAX_FRAME_SIZE,
        });
    }

    let mut header = [0u8; 4 + FRAME_HEADER_SIZE + BULK_HEADER_SIZE];
    header[..4].copy_from_slice(&frame_len.to_be_bytes());
    header[4..8].copy_from_slice(&record.id.to_be_bytes());
    header[8] = FLAG_BULK;
    header[9] = record.kind as u8;
    header[10] = record.flow as u8;
    // Bytes 11..13 are reserved and deliberately remain zero.
    header[13..21].copy_from_slice(&record.offset.to_be_bytes());
    Ok(header)
}

pub(crate) fn decode_bulk_body(
    id: u32,
    body: Bytes,
    max_payload: u32,
) -> ProtocolResult<BulkRecord> {
    if max_payload == 0 || max_payload > MAX_BULK_RECORD_PAYLOAD {
        return Err(invalid_bulk(format!(
            "invalid decoder payload limit {max_payload}"
        )));
    }
    if body.len() < BULK_HEADER_SIZE + 1 {
        return Err(invalid_bulk("bulk record has no payload"));
    }
    if body[2] != 0 || body[3] != 0 {
        return Err(invalid_bulk("reserved bulk header bytes must be zero"));
    }

    let kind = BulkKind::from_wire(body[0])
        .ok_or_else(|| invalid_bulk(format!("unknown bulk kind {}", body[0])))?;
    let flow = BulkFlow::from_wire(body[1])
        .ok_or_else(|| invalid_bulk(format!("unknown bulk flow {}", body[1])))?;
    let offset = u64::from_be_bytes(body[4..12].try_into().unwrap());
    let payload = body.slice(BULK_HEADER_SIZE..);
    if payload.len() > max_payload as usize {
        return Err(invalid_bulk(format!(
            "payload length {} exceeds negotiated maximum {max_payload}",
            payload.len()
        )));
    }
    offset
        .checked_add(payload.len() as u64)
        .ok_or_else(|| invalid_bulk("record end offset overflows u64"))?;

    Ok(BulkRecord {
        id,
        kind,
        flow,
        offset,
        payload,
    })
}

fn complete_frame_len(buf: &BytesMut) -> ProtocolResult<Option<(usize, usize)>> {
    if buf.len() < 4 {
        return Ok(None);
    }

    let frame_len = u32::from_be_bytes(buf[..4].try_into().unwrap());
    if frame_len > MAX_FRAME_SIZE {
        return Err(ProtocolError::FrameTooLarge {
            size: frame_len,
            max: MAX_FRAME_SIZE,
        });
    }
    if frame_len < FRAME_HEADER_SIZE as u32 {
        return Err(ProtocolError::FrameTooShort {
            size: frame_len,
            min: FRAME_HEADER_SIZE as u32,
        });
    }

    let frame_len = frame_len as usize;
    let total = 4 + frame_len;
    if buf.len() < total {
        return Ok(None);
    }
    Ok(Some((frame_len, total)))
}

fn invalid_bulk(message: impl Into<String>) -> ProtocolError {
    ProtocolError::InvalidBulkFrame(message.into())
}

async fn write_vectored_all<W: AsyncWrite + Unpin>(
    writer: &mut W,
    header: &[u8],
    body: &[u8],
) -> std::io::Result<()> {
    let mut header_offset = 0;
    let mut body_offset = 0;

    while header_offset < header.len() || body_offset < body.len() {
        let written = if header_offset < header.len() {
            let slices = [
                IoSlice::new(&header[header_offset..]),
                IoSlice::new(&body[body_offset..]),
            ];
            let slice_count = if body_offset < body.len() { 2 } else { 1 };
            writer.write_vectored(&slices[..slice_count]).await?
        } else {
            // Some AsyncWrite implementations stop at an empty first IoSlice, so never leave the
            // exhausted header in front of a non-empty body.
            writer.write(&body[body_offset..]).await?
        };
        if written == 0 {
            return Err(std::io::ErrorKind::WriteZero.into());
        }

        let header_remaining = header.len() - header_offset;
        if written < header_remaining {
            header_offset += written;
        } else {
            header_offset = header.len();
            body_offset += written - header_remaining;
        }
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::pin::Pin;
    use std::task::{Context, Poll};

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
    fn smallest_bulk_record_has_exact_wire_layout() {
        let record = BulkRecord {
            id: 0x0102_0304,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::HostToGuest,
            offset: 0x0102_0304_0506_0708,
            payload: Bytes::from_static(&[0xFF]),
        };
        let mut encoded = Vec::new();
        encode_bulk_to_buf(&record, &mut encoded).unwrap();

        assert_eq!(
            encoded,
            vec![
                0x00, 0x00, 0x00, 0x12, // frame length: 5 + 12 + 1
                0x01, 0x02, 0x03, 0x04, // correlation ID
                0x08, // FLAG_BULK
                0x01, // filesystem
                0x01, // host to guest
                0x00, 0x00, // reserved
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // offset
                0xFF, // opaque payload
            ]
        );
    }

    #[test]
    fn largest_bulk_record_roundtrips_without_payload_copy() {
        let record = BulkRecord {
            id: 81,
            kind: BulkKind::Tcp,
            flow: BulkFlow::GuestToHost,
            offset: 7,
            payload: Bytes::from(vec![0xA5; MAX_BULK_RECORD_PAYLOAD as usize]),
        };
        let mut encoded = Vec::new();
        encode_bulk_to_buf(&record, &mut encoded).unwrap();
        let mut cursor = BytesMut::from(encoded.as_slice());

        let Some(DecodedFrame::Bulk(decoded)) = try_decode_frame_from_bytes(&mut cursor).unwrap()
        else {
            panic!("expected bulk record");
        };
        assert_eq!(decoded, record);
        assert!(cursor.is_empty());
    }

    #[test]
    fn bulk_payload_is_opaque_even_when_it_looks_like_cbor() {
        let payload = Bytes::from_static(&[0xA3, 0x61, b'v', 0x07, 0x61, b't', 0xF6]);
        let record = BulkRecord {
            id: 3,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::GuestToHost,
            offset: 0,
            payload: payload.clone(),
        };
        let mut encoded = Vec::new();
        encode_bulk_to_buf(&record, &mut encoded).unwrap();
        let mut cursor = BytesMut::from(encoded.as_slice());

        let Some(DecodedFrame::Bulk(decoded)) = try_decode_frame_from_bytes(&mut cursor).unwrap()
        else {
            panic!("expected bulk record");
        };
        assert_eq!(decoded.payload, payload);
    }

    #[test]
    fn bulk_decoder_accepts_every_frame_fragment_boundary() {
        let record = BulkRecord {
            id: 34,
            kind: BulkKind::Tcp,
            flow: BulkFlow::HostToGuest,
            offset: 99,
            payload: Bytes::from(vec![0x73; 128]),
        };
        let mut encoded = Vec::new();
        encode_bulk_to_buf(&record, &mut encoded).unwrap();

        for split in 0..=encoded.len() {
            let mut cursor = BytesMut::from(&encoded[..split]);
            let first = try_decode_frame_from_bytes(&mut cursor).unwrap();
            if split < encoded.len() {
                assert!(first.is_none(), "decoded incomplete frame at split {split}");
                cursor.extend_from_slice(&encoded[split..]);
            }
            let decoded = first
                .or_else(|| try_decode_frame_from_bytes(&mut cursor).unwrap())
                .unwrap();
            assert!(matches!(decoded, DecodedFrame::Bulk(ref value) if value == &record));
            assert!(cursor.is_empty());
        }
    }

    #[test]
    fn bulk_decoder_rejects_malformed_wire_shapes() {
        let record = BulkRecord {
            id: 5,
            kind: BulkKind::Filesystem,
            flow: BulkFlow::HostToGuest,
            offset: 0,
            payload: Bytes::from_static(b"x"),
        };
        let mut valid = Vec::new();
        encode_bulk_to_buf(&record, &mut valid).unwrap();

        for (index, value) in [(8, FLAG_BULK | FLAG_TERMINAL), (9, 0), (10, 3), (11, 1)] {
            let mut malformed = valid.clone();
            malformed[index] = value;
            let error =
                try_decode_frame_from_bytes(&mut BytesMut::from(malformed.as_slice())).unwrap_err();
            assert!(matches!(error, ProtocolError::InvalidBulkFrame(_)));
        }

        let mut no_payload = valid;
        no_payload.truncate(4 + FRAME_HEADER_SIZE + BULK_HEADER_SIZE);
        no_payload[..4]
            .copy_from_slice(&((FRAME_HEADER_SIZE + BULK_HEADER_SIZE) as u32).to_be_bytes());
        let error =
            try_decode_frame_from_bytes(&mut BytesMut::from(no_payload.as_slice())).unwrap_err();
        assert!(matches!(error, ProtocolError::InvalidBulkFrame(_)));
    }

    #[tokio::test]
    async fn bulk_vectored_writer_handles_one_byte_short_writes() {
        let record = BulkRecord {
            id: 91,
            kind: BulkKind::Tcp,
            flow: BulkFlow::GuestToHost,
            offset: 42,
            payload: Bytes::from(vec![0xCD; 257]),
        };
        let mut expected = Vec::new();
        encode_bulk_to_buf(&record, &mut expected).unwrap();

        let mut writer = OneByteWriter::default();
        write_bulk_record(&mut writer, &record).await.unwrap();

        assert_eq!(writer.bytes, expected);
    }

    #[test]
    fn cursor_decoder_accepts_every_frame_fragment_boundary() {
        let msg = Message::new(MessageType::Ready, 77, vec![0xAB; 1024]);
        let mut encoded = Vec::new();
        encode_to_buf(&msg, &mut encoded).unwrap();

        for split in 0..=encoded.len() {
            let mut buf = BytesMut::new();
            buf.extend_from_slice(&encoded[..split]);
            let first = try_decode_from_bytes(&mut buf).unwrap();
            if split < encoded.len() {
                assert!(first.is_none(), "decoded incomplete frame at split {split}");
                buf.extend_from_slice(&encoded[split..]);
            }

            let decoded = first
                .or_else(|| try_decode_from_bytes(&mut buf).unwrap())
                .unwrap();
            assert_eq!(decoded.id, msg.id);
            assert_eq!(decoded.t, msg.t);
            assert!(buf.is_empty());
        }
    }

    #[tokio::test]
    async fn vectored_writer_handles_one_byte_short_writes() {
        let frame = RawFrame {
            id: 91,
            flags: FLAG_TERMINAL,
            body: vec![0xCD; 257],
        };
        let mut expected = Vec::new();
        encode_raw_to_buf(&frame, &mut expected).unwrap();

        let mut writer = OneByteWriter::default();
        write_raw_frame(&mut writer, &frame).await.unwrap();

        assert_eq!(writer.bytes, expected);
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

    #[derive(Default)]
    struct OneByteWriter {
        bytes: Vec<u8>,
    }

    impl AsyncWrite for OneByteWriter {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            if let Some(byte) = buf.first() {
                self.bytes.push(*byte);
                Poll::Ready(Ok(1))
            } else {
                Poll::Ready(Ok(0))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Poll::Ready(Ok(()))
        }

        fn is_write_vectored(&self) -> bool {
            true
        }

        fn poll_write_vectored(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            bufs: &[IoSlice<'_>],
        ) -> Poll<std::io::Result<usize>> {
            if let Some(byte) = bufs.iter().find_map(|buf| buf.first()) {
                self.bytes.push(*byte);
                Poll::Ready(Ok(1))
            } else {
                Poll::Ready(Ok(0))
            }
        }
    }
}
