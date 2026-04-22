//! RFC 1035 §4.2.2 length-prefix framing for DNS over TCP and DoT.
//!
//! Both plain DNS-over-TCP (sibling `mod.rs`) and DNS-over-TLS
//! (sibling `dot.rs`) use the same framing: a 2-byte big-endian length
//! prefix followed by the DNS message bytes. This module hosts the
//! shared helpers so the two proxies stay in sync.

use bytes::Bytes;
use tokio::sync::mpsc;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Pop a single length-prefixed DNS message from the head of `buf` if
/// one is fully buffered. Returns `None` if the prefix or body is still
/// incomplete. Caller must keep feeding bytes until `take_message`
/// returns `Some`.
pub(super) fn take_message(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    if buf.len() < 2 {
        return None;
    }
    let len = u16::from_be_bytes([buf[0], buf[1]]) as usize;
    if buf.len() < 2 + len {
        return None;
    }
    let body = buf[2..2 + len].to_vec();
    buf.drain(..2 + len);
    Some(body)
}

/// Frame a DNS message with the RFC 1035 §4.2.2 2-byte big-endian
/// length prefix. Shared by the plain-TCP and DoT proxies so the wire
/// format can't drift between them.
pub(super) fn frame(body: &[u8]) -> Vec<u8> {
    let len = body.len() as u16;
    let mut framed = Vec::with_capacity(2 + body.len());
    framed.extend_from_slice(&len.to_be_bytes());
    framed.extend_from_slice(body);
    framed
}

/// Send a DNS response back to the guest with the length prefix applied.
pub(super) async fn write_framed(
    to_smoltcp: &mpsc::Sender<Bytes>,
    response: &[u8],
) -> Result<(), mpsc::error::SendError<Bytes>> {
    to_smoltcp.send(Bytes::from(frame(response))).await
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn take_message_returns_none_on_empty() {
        let mut buf: Vec<u8> = Vec::new();
        assert!(take_message(&mut buf).is_none());
    }

    #[test]
    fn take_message_returns_none_on_partial_prefix() {
        let mut buf = vec![0x00];
        assert!(take_message(&mut buf).is_none());
        // Buffer untouched so caller can append the next chunk.
        assert_eq!(buf, vec![0x00]);
    }

    #[test]
    fn take_message_returns_none_on_partial_body() {
        // Length prefix says 4 bytes, only 2 present.
        let mut buf = vec![0x00, 0x04, 0xaa, 0xbb];
        assert!(take_message(&mut buf).is_none());
        assert_eq!(buf, vec![0x00, 0x04, 0xaa, 0xbb]);
    }

    #[test]
    fn take_message_extracts_complete_frame() {
        let mut buf = vec![0x00, 0x03, 0x11, 0x22, 0x33];
        let msg = take_message(&mut buf).expect("complete frame");
        assert_eq!(msg, vec![0x11, 0x22, 0x33]);
        assert!(buf.is_empty());
    }

    #[test]
    fn take_message_extracts_pipelined_frames() {
        // Two frames back-to-back: [len=2, aa bb] [len=1, cc].
        let mut buf = vec![0x00, 0x02, 0xaa, 0xbb, 0x00, 0x01, 0xcc];
        let first = take_message(&mut buf).expect("first frame");
        assert_eq!(first, vec![0xaa, 0xbb]);
        let second = take_message(&mut buf).expect("second frame");
        assert_eq!(second, vec![0xcc]);
        assert!(buf.is_empty());
    }

    #[test]
    fn take_message_handles_zero_length_frame() {
        let mut buf = vec![0x00, 0x00];
        let msg = take_message(&mut buf).expect("zero-length frame");
        assert!(msg.is_empty());
        assert!(buf.is_empty());
    }
}
