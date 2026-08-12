//! Encoding conversion at the Windows console boundary.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
pub(super) struct Utf8ToUtf16Decoder {
    pending: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Utf8ToUtf16Decoder {
    pub(super) fn decode(&mut self, data: &[u8]) -> Vec<u16> {
        self.pending.extend_from_slice(data);

        let mut decoded = Vec::new();
        let mut offset = 0usize;
        while offset < self.pending.len() {
            match std::str::from_utf8(&self.pending[offset..]) {
                Ok(valid) => {
                    decoded.extend(valid.encode_utf16());
                    offset = self.pending.len();
                }
                Err(error) => {
                    let valid_end = offset + error.valid_up_to();
                    decoded.extend(
                        std::str::from_utf8(&self.pending[offset..valid_end])
                            .expect("UTF-8 validation identified a valid prefix")
                            .encode_utf16(),
                    );
                    offset = valid_end;

                    let Some(error_len) = error.error_len() else {
                        break;
                    };
                    decoded.push(char::REPLACEMENT_CHARACTER as u16);
                    offset += error_len;
                }
            }
        }

        self.pending.drain(..offset);
        decoded
    }

    pub(super) fn finish(&mut self) -> Vec<u16> {
        let decoded = String::from_utf8_lossy(&self.pending)
            .encode_utf16()
            .collect();
        self.pending.clear();
        decoded
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn console_input_to_utf8(
    data: &[u16],
    pending_high_surrogate: &mut Option<u16>,
) -> Vec<u8> {
    let mut input = Vec::with_capacity(data.len() + usize::from(pending_high_surrogate.is_some()));
    if let Some(high_surrogate) = pending_high_surrogate.take() {
        input.push(high_surrogate);
    }
    input.extend_from_slice(data);

    if input
        .last()
        .is_some_and(|unit| (0xd800..=0xdbff).contains(unit))
    {
        *pending_high_surrogate = input.pop();
    }

    String::from_utf16_lossy(&input).into_bytes()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_utf8_decoder_preserves_ansi_and_unicode() {
        let mut decoder = Utf8ToUtf16Decoder::default();
        let decoded = decoder.decode("\x1b[32municode: — ✓ ⠋\x1b[0m\n".as_bytes());

        assert_eq!(
            String::from_utf16(&decoded).unwrap(),
            "\x1b[32municode: — ✓ ⠋\x1b[0m\n"
        );
        assert!(decoder.finish().is_empty());
    }

    #[test]
    fn test_utf8_decoder_preserves_split_sequences() {
        let expected = "unicode: — ✓ ⠋ 😀\n";

        for split in 0..=expected.len() {
            let mut decoder = Utf8ToUtf16Decoder::default();
            let mut decoded = decoder.decode(&expected.as_bytes()[..split]);
            decoded.extend(decoder.decode(&expected.as_bytes()[split..]));
            decoded.extend(decoder.finish());

            assert_eq!(String::from_utf16(&decoded).unwrap(), expected);
        }
    }

    #[test]
    fn test_utf8_decoder_replaces_invalid_and_incomplete_sequences() {
        let mut decoder = Utf8ToUtf16Decoder::default();
        let mut decoded = decoder.decode(b"valid\xfftail\xe2\x80");

        assert_eq!(String::from_utf16(&decoded).unwrap(), "valid�tail");

        decoded = decoder.finish();
        assert_eq!(String::from_utf16(&decoded).unwrap(), "�");
    }

    #[test]
    fn test_console_input_encodes_utf16_as_utf8() {
        let mut pending = None;
        let input = "\x1b[A café".encode_utf16().collect::<Vec<_>>();

        assert_eq!(
            console_input_to_utf8(&input, &mut pending),
            "\x1b[A café".as_bytes()
        );
        assert_eq!(pending, None);
    }

    #[test]
    fn test_console_input_preserves_split_surrogate_pair() {
        let mut pending = None;

        assert!(console_input_to_utf8(&[0xd83d], &mut pending).is_empty());
        assert_eq!(pending, Some(0xd83d));
        assert_eq!(
            console_input_to_utf8(&[0xde00], &mut pending),
            "😀".as_bytes()
        );
        assert_eq!(pending, None);
    }
}
