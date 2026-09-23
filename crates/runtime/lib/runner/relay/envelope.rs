//! Bounded envelope inspection at the host/guest namespace boundary.
//!
//! Payload bytes stay opaque and borrowed. This is not an agent operation or
//! payload validator: future non-control names and unknown fields still pass.

use ciborium_ll::{Decoder, Header};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

// Match the existing CBOR decoder's recursion bound without allocating a value
// tree. Definite byte strings (including the payload) are skipped in O(1).
const MAX_DEPTH: usize = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Rejection {
    ControlNamespace,
    InvalidEnvelope,
}

struct Cursor<'a>(&'a [u8]);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> Cursor<'a> {
    fn head(&mut self) -> Result<Header, Rejection> {
        let mut decoder = Decoder::from(self.0);
        let header = decoder.pull().map_err(|_| Rejection::InvalidEnvelope)?;
        self.0 = &self.0[decoder.offset()..];
        Ok(header)
    }

    fn take(&mut self, len: usize) -> Result<&'a [u8], Rejection> {
        let bytes = self.0.get(..len).ok_or(Rejection::InvalidEnvelope)?;
        self.0 = &self.0[len..];
        Ok(bytes)
    }

    fn untagged(&mut self) -> Result<Header, Rejection> {
        for _ in 0..MAX_DEPTH {
            let header = self.head()?;
            if !matches!(header, Header::Tag(_)) {
                return Ok(header);
            }
        }
        Err(Rejection::InvalidEnvelope)
    }

    // Compare across indefinite-length chunks without building a String.
    // Saturating the length at prefix.len()+1 is enough for exact key matching.
    fn text_prefix(&mut self, prefix: &[u8]) -> Result<(bool, usize), Rejection> {
        let Header::Text(len) = self.untagged()? else {
            return Err(Rejection::InvalidEnvelope);
        };
        let mut matched = true;
        let mut seen = 0usize;
        let mut chunk = |bytes: &[u8]| -> Result<(), Rejection> {
            std::str::from_utf8(bytes).map_err(|_| Rejection::InvalidEnvelope)?;
            let compared = bytes.len().min(prefix.len().saturating_sub(seen));
            for (offset, &byte) in bytes[..compared].iter().enumerate() {
                matched &= prefix[seen + offset] == byte;
            }
            seen = seen.saturating_add(bytes.len()).min(prefix.len() + 1);
            Ok(())
        };
        if let Some(len) = len {
            chunk(self.take(len)?)?;
        } else {
            loop {
                match self.head()? {
                    Header::Break => break,
                    Header::Text(Some(len)) => chunk(self.take(len)?)?,
                    _ => return Err(Rejection::InvalidEnvelope),
                }
            }
        }
        Ok((matched && seen >= prefix.len(), seen))
    }

    fn skip(&mut self, depth: usize) -> Result<(), Rejection> {
        if depth == MAX_DEPTH {
            return Err(Rejection::InvalidEnvelope);
        }
        match self.head()? {
            Header::Bytes(Some(len)) | Header::Text(Some(len)) => {
                self.take(len)?;
            }
            kind @ (Header::Bytes(None) | Header::Text(None)) => loop {
                match (kind, self.head()?) {
                    (_, Header::Break) => break,
                    (Header::Bytes(_), Header::Bytes(Some(len)))
                    | (Header::Text(_), Header::Text(Some(len))) => {
                        self.take(len)?;
                    }
                    _ => return Err(Rejection::InvalidEnvelope),
                }
            },
            Header::Array(len) => self.skip_container(len, depth, false)?,
            Header::Map(len) => self.skip_container(len, depth, true)?,
            Header::Tag(_) => self.skip(depth + 1)?,
            Header::Break => return Err(Rejection::InvalidEnvelope),
            _ => {}
        }
        Ok(())
    }

    fn skip_container(
        &mut self,
        len: Option<usize>,
        depth: usize,
        map: bool,
    ) -> Result<(), Rejection> {
        let mut remaining = len;
        loop {
            if remaining == Some(0) {
                return Ok(());
            }
            if remaining.is_none() && self.0.first() == Some(&0xff) {
                self.0 = &self.0[1..];
                return Ok(());
            }
            self.skip(depth + 1)?;
            if map {
                self.skip(depth + 1)?;
            }
            if let Some(n) = remaining.as_mut() {
                *n -= 1;
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn inspect(bytes: &[u8]) -> Result<(), Rejection> {
    let mut input = Cursor(bytes);
    let Header::Map(mut remaining) = input.untagged()? else {
        return Err(Rejection::InvalidEnvelope);
    };
    let mut has_type = false;
    loop {
        if remaining == Some(0) {
            break;
        }
        if remaining.is_none() && input.0.first() == Some(&0xff) {
            input.0 = &input.0[1..];
            break;
        }
        let (is_t, len) = input.text_prefix(b"t")?;
        if is_t && len == 1 {
            if has_type {
                return Err(Rejection::InvalidEnvelope);
            }
            has_type = true;
            if input.text_prefix(b"control.")?.0 {
                return Err(Rejection::ControlNamespace);
            }
        } else {
            input.skip(0)?;
        }
        if let Some(n) = remaining.as_mut() {
            *n -= 1;
        }
    }
    if !has_type || !input.0.is_empty() {
        return Err(Rejection::InvalidEnvelope);
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_protocol::wire::Envelope;

    #[test]
    fn permits_unknown_names_and_opaque_payloads() {
        let mut message = Envelope::new(1, "core.future.operation", &()).unwrap();
        // The inner payload need not be valid CBOR for a transparent relay.
        message.p = vec![0xff; 1024 * 1024];
        let mut bytes = message.encode().unwrap();
        assert_eq!(inspect(&bytes), Ok(()));
        // Append an unknown, nested field to the outer map.
        assert_eq!(bytes[0], 0xa3);
        bytes[0] = 0xa4;
        bytes.extend_from_slice(b"\x61x\xbf\x61a\x9f\x01\x02\xff\xff");
        assert_eq!(inspect(&bytes), Ok(()));
    }

    #[test]
    fn checks_chunked_keys_and_names_without_prefix_false_positives() {
        for bytes in [
            b"\xa1\x61t\x7f\x63con\x65trol.\xff".as_slice(),
            b"\xbf\x7f\x60\x61t\x60\xff\x68control.\xff",
            b"\xd9\xd9\xf7\xa1\x61t\x68control.",
        ] {
            assert_eq!(inspect(bytes), Err(Rejection::ControlNamespace));
        }
        for name in ["control", "controls.x", "Control.x", "core.control.x", ""] {
            assert_eq!(
                inspect(&Envelope::new(1, name, &()).unwrap().encode().unwrap()),
                Ok(())
            );
        }
        assert_eq!(inspect(b"\xa1\x61t\x7f\x63con\x64trol\xff"), Ok(()));
    }

    #[test]
    fn rejects_ambiguous_truncated_and_excessively_nested_envelopes() {
        for bytes in [
            b"\xa2\x61t\x64core\x61t\x64core".as_slice(),
            b"\xa1\x61t\x01",
            b"\xa0",
            b"\xa1\x61t\x61\xff",
            b"\xa1\x61t\x7f\x41t\xff",
            b"\xbf\x61t\x64core",
            b"\xa2\x61t\x64core\x61x\xbf\x01\xff",
        ] {
            assert_eq!(inspect(bytes), Err(Rejection::InvalidEnvelope));
        }
        let valid = Envelope::new(1, "core.exec.stdin", &())
            .unwrap()
            .encode()
            .unwrap();
        for end in 0..valid.len() {
            assert_eq!(inspect(&valid[..end]), Err(Rejection::InvalidEnvelope));
        }
        let mut trailing = valid.clone();
        trailing.push(0);
        assert_eq!(inspect(&trailing), Err(Rejection::InvalidEnvelope));
        let mut deep = b"\xa2\x61t\x64core\x61x".to_vec();
        deep.extend(std::iter::repeat_n(0x81, MAX_DEPTH + 1));
        deep.push(0);
        assert_eq!(inspect(&deep), Err(Rejection::InvalidEnvelope));
    }
}
