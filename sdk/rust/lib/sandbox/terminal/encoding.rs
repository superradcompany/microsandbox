//! Encoding conversion at the Windows console boundary.
//!
//! The console's byte-oriented entry points (`WriteFile`/`ReadFile`, which the
//! console treats as `WriteConsoleA`/`ReadConsoleA`) interpret bytes in the
//! console's current code page, which mangles the UTF-8 a sandbox guest speaks.
//! The wide entry points `WriteConsoleW`/`ReadConsoleW` are code-page
//! independent, but they speak UTF-16, so the host has to convert.
//!
//! Conversion has to be incremental. Guest output reaches the host in transport
//! frames sized by the guest's PTY reads, so a multi-byte character routinely
//! straddles a frame boundary; console input can likewise split a surrogate pair
//! across two reads. Each decoder therefore carries the incomplete tail of one
//! chunk over into the next.
//!
//! The conversion logic is deliberately free of Win32 calls so it can be unit
//! tested on any platform.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum UTF-16 units to hand to a single `WriteConsoleW` call.
///
/// `WriteConsoleW` can fail with `ERROR_NOT_ENOUGH_MEMORY` on very large
/// buffers, so writes are chunked. This matches the standard library, which
/// converts at most `MAX_BUFFER_SIZE / 2` units (8192 bytes' worth) per console
/// write.
pub(super) const MAX_CONSOLE_WRITE_UNITS: usize = 4096;

/// Longest incomplete UTF-8 sequence worth carrying: a 4-byte sequence missing
/// only its last continuation byte.
const MAX_UTF8_CARRY: usize = 3;

/// `U+FFFD REPLACEMENT CHARACTER`, substituted for input that cannot be decoded.
const REPLACEMENT: u16 = 0xFFFD;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Decodes a UTF-8 byte stream into UTF-16 units for `WriteConsoleW`.
///
/// Bytes that are not valid UTF-8 are replaced with `U+FFFD` rather than raising
/// an error, so a guest writing binary data cannot break the session.
#[derive(Debug, Default)]
pub(super) struct Utf8ToUtf16Decoder {
    /// Trailing bytes of an incomplete sequence, awaiting the next chunk.
    carry: Vec<u8>,
}

/// Decodes UTF-16 units read by `ReadConsoleW` into UTF-8 bytes for the guest.
///
/// Unpaired surrogates are replaced with `U+FFFD`; a high surrogate at the end of
/// a chunk is held back in case its low surrogate arrives in the next one.
#[derive(Debug, Default)]
pub(super) struct Utf16ToUtf8Decoder {
    /// A high surrogate awaiting its pair in the next chunk.
    carry: Option<u16>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Utf8ToUtf16Decoder {
    /// Decode `bytes`, returning the UTF-16 units that are now complete.
    ///
    /// An incomplete sequence at the end of `bytes` produces no output and is
    /// carried into the following call.
    pub(super) fn decode(&mut self, bytes: &[u8]) -> Vec<u16> {
        let mut units = Vec::with_capacity(bytes.len());

        // Splicing the carry in front is what stitches a sequence back together
        // across a frame boundary.
        let joined: Vec<u8>;
        let mut rest: &[u8] = if self.carry.is_empty() {
            bytes
        } else {
            joined = self
                .carry
                .iter()
                .copied()
                .chain(bytes.iter().copied())
                .collect();
            self.carry.clear();
            &joined
        };

        loop {
            match std::str::from_utf8(rest) {
                Ok(text) => {
                    units.extend(text.encode_utf16());
                    return units;
                }
                Err(error) => {
                    let valid = error.valid_up_to();
                    if valid > 0 {
                        // Everything before the error is known-good UTF-8.
                        let text = std::str::from_utf8(&rest[..valid])
                            .expect("valid_up_to marks a valid UTF-8 prefix");
                        units.extend(text.encode_utf16());
                    }

                    match error.error_len() {
                        // `None` means the buffer ended mid-sequence rather than
                        // holding something invalid. Distinguishing the two is
                        // why this cannot use `String::from_utf8_lossy`.
                        None => {
                            let tail = &rest[valid..];
                            debug_assert!(
                                tail.len() <= MAX_UTF8_CARRY,
                                "incomplete UTF-8 tail cannot exceed {MAX_UTF8_CARRY} bytes"
                            );
                            self.carry.extend_from_slice(tail);
                            return units;
                        }
                        Some(invalid_len) => {
                            units.push(REPLACEMENT);
                            rest = &rest[valid + invalid_len..];
                        }
                    }
                }
            }
        }
    }

    /// Flush any carried bytes at the end of a session.
    ///
    /// A guest whose final output stops mid-character leaves an incomplete
    /// sequence behind; emit it as `U+FFFD` rather than dropping it silently.
    pub(super) fn finish(&mut self) -> Vec<u16> {
        if self.carry.is_empty() {
            return Vec::new();
        }

        let units = String::from_utf8_lossy(&self.carry)
            .encode_utf16()
            .collect();
        self.carry.clear();
        units
    }
}

impl Utf16ToUtf8Decoder {
    /// Decode `units`, returning the UTF-8 bytes that are now complete.
    ///
    /// A trailing high surrogate produces no output and is carried into the
    /// following call.
    pub(super) fn decode(&mut self, units: &[u16]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(units.len());
        let mut buf = [0u8; 4];
        let mut pending = self.carry.take();

        for &unit in units {
            if let Some(high) = pending.take() {
                if is_low_surrogate(unit) {
                    let code =
                        0x1_0000 + (u32::from(high - 0xD800) << 10) + u32::from(unit - 0xDC00);
                    let ch = char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER);
                    bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                    continue;
                }

                // The carried high surrogate never found its pair.
                bytes.extend_from_slice(
                    char::REPLACEMENT_CHARACTER.encode_utf8(&mut buf).as_bytes(),
                );
            }

            if is_high_surrogate(unit) {
                pending = Some(unit);
            } else if is_low_surrogate(unit) {
                bytes.extend_from_slice(
                    char::REPLACEMENT_CHARACTER.encode_utf8(&mut buf).as_bytes(),
                );
            } else {
                let ch = char::from_u32(u32::from(unit)).unwrap_or(char::REPLACEMENT_CHARACTER);
                bytes.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
            }
        }

        self.carry = pending;
        bytes
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Length of the longest prefix of `units` that is at most `max` units long and
/// does not end between the halves of a surrogate pair.
///
/// Splitting a pair across two `WriteConsoleW` calls would present the console
/// with a lone surrogate, so writes are cut on a safe boundary instead.
pub(super) fn surrogate_safe_split(units: &[u16], max: usize) -> usize {
    if units.len() <= max {
        return units.len();
    }
    if max == 0 {
        return 0;
    }

    if split_separates_surrogate_pair(units, max) {
        max - 1
    } else {
        max
    }
}

/// Whether splitting `units` at `index` separates a UTF-16 surrogate pair.
///
/// Besides choosing safe chunk boundaries, this detects when a successful
/// partial `WriteConsoleW` call stopped between the two halves of a pair.
pub(super) fn split_separates_surrogate_pair(units: &[u16], index: usize) -> bool {
    index > 0
        && index < units.len()
        && is_high_surrogate(units[index - 1])
        && is_low_surrogate(units[index])
}

/// Whether `unit` is the leading half of a UTF-16 surrogate pair.
fn is_high_surrogate(unit: u16) -> bool {
    (0xD800..0xDC00).contains(&unit)
}

/// Whether `unit` is the trailing half of a UTF-16 surrogate pair.
fn is_low_surrogate(unit: u16) -> bool {
    (0xDC00..0xE000).contains(&unit)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn test_utf8_decoder_passes_through_ascii() {
        let mut decoder = Utf8ToUtf16Decoder::default();
        assert_eq!(decoder.decode(b"hello world"), utf16("hello world"));
    }

    #[test]
    fn test_utf8_decoder_preserves_ansi_escapes() {
        let mut decoder = Utf8ToUtf16Decoder::default();
        let ansi = "\x1b[31merror\x1b[0m\x1b[2J\x1b[H";
        assert_eq!(decoder.decode(ansi.as_bytes()), utf16(ansi));
    }

    #[test]
    fn test_utf8_decoder_decodes_issue_repro() {
        // The exact bytes from issue #1230.
        let bytes = [
            0x75, 0x6e, 0x69, 0x63, 0x6f, 0x64, 0x65, 0x3a, 0x20, 0xe2, 0x80, 0x94, 0x20, 0xe2,
            0x9c, 0x93, 0x20, 0xe2, 0xa0, 0x8b, 0x0a,
        ];
        let mut decoder = Utf8ToUtf16Decoder::default();
        assert_eq!(decoder.decode(&bytes), utf16("unicode: — ✓ ⠋\n"));
    }

    #[test]
    fn test_utf8_decoder_joins_sequence_split_across_chunks() {
        let mut decoder = Utf8ToUtf16Decoder::default();

        // First chunk ends mid-character: nothing may be emitted yet.
        assert!(decoder.decode(&[0xE2]).is_empty());
        assert_eq!(decoder.decode(&[0x80, 0x94]), utf16("—"));
    }

    #[test]
    fn test_utf8_decoder_joins_sequences_split_at_every_offset() {
        let text = "unicode: — ✓ ⠋ 😀\n";

        for split in 0..=text.len() {
            let mut decoder = Utf8ToUtf16Decoder::default();
            let mut units = decoder.decode(&text.as_bytes()[..split]);
            units.extend(decoder.decode(&text.as_bytes()[split..]));
            units.extend(decoder.finish());

            assert_eq!(
                String::from_utf16(&units).unwrap(),
                text,
                "split at byte {split}"
            );
        }
    }

    #[test]
    fn test_utf8_decoder_joins_sequence_split_one_byte_at_a_time() {
        let mut decoder = Utf8ToUtf16Decoder::default();
        let mut units = Vec::new();
        for byte in "⠋".as_bytes() {
            units.extend(decoder.decode(&[*byte]));
        }
        assert_eq!(units, utf16("⠋"));
    }

    #[test]
    fn test_utf8_decoder_replaces_invalid_bytes() {
        let mut decoder = Utf8ToUtf16Decoder::default();
        assert_eq!(decoder.decode(&[0xFF]), vec![REPLACEMENT]);
    }

    #[test]
    fn test_utf8_decoder_keeps_going_after_invalid_bytes() {
        let mut decoder = Utf8ToUtf16Decoder::default();
        let mut expected = utf16("ok");
        expected.push(REPLACEMENT);
        expected.extend(utf16("more"));

        assert_eq!(decoder.decode(b"ok\xFFmore"), expected);
    }

    #[test]
    fn test_utf8_decoder_replaces_truncated_sequence_then_resumes() {
        let mut decoder = Utf8ToUtf16Decoder::default();

        // A lead byte followed by a non-continuation byte is invalid, not
        // incomplete: it must not swallow the 'a' that follows.
        let mut expected = vec![REPLACEMENT];
        expected.extend(utf16("a"));
        assert_eq!(decoder.decode(&[0xE2, 0x61]), expected);
    }

    #[test]
    fn test_utf8_decoder_survives_binary_data() {
        let mut decoder = Utf8ToUtf16Decoder::default();
        let garbage: Vec<u8> = (0..=255u8).collect();

        // The only contract for binary input is that it neither panics nor
        // stalls the stream.
        assert!(!decoder.decode(&garbage).is_empty());
        assert_eq!(decoder.decode(b"after"), utf16("after"));
    }

    #[test]
    fn test_utf8_decoder_finish_flushes_incomplete_tail() {
        let mut decoder = Utf8ToUtf16Decoder::default();

        assert!(decoder.decode(&[0xE2, 0x80]).is_empty());
        assert_eq!(decoder.finish(), vec![REPLACEMENT]);

        // The carry is consumed, so a second flush yields nothing.
        assert!(decoder.finish().is_empty());
    }

    #[test]
    fn test_utf8_decoder_finish_is_empty_without_carry() {
        let mut decoder = Utf8ToUtf16Decoder::default();
        assert_eq!(decoder.decode(b"complete"), utf16("complete"));
        assert!(decoder.finish().is_empty());
    }

    #[test]
    fn test_utf16_decoder_encodes_bmp_text() {
        let mut decoder = Utf16ToUtf8Decoder::default();
        assert_eq!(
            decoder.decode(&utf16("héllo 日本語")),
            "héllo 日本語".as_bytes()
        );
    }

    #[test]
    fn test_utf16_decoder_joins_surrogate_pair_across_chunks() {
        let units = utf16("🚀");
        assert_eq!(units.len(), 2, "rocket must be a surrogate pair");

        let mut decoder = Utf16ToUtf8Decoder::default();
        assert!(decoder.decode(&units[..1]).is_empty());
        assert_eq!(decoder.decode(&units[1..]), "🚀".as_bytes());
    }

    #[test]
    fn test_utf16_decoder_replaces_unpaired_low_surrogate() {
        let mut decoder = Utf16ToUtf8Decoder::default();
        assert_eq!(
            decoder.decode(&[0xDC00]),
            char::REPLACEMENT_CHARACTER.to_string().as_bytes()
        );
    }

    #[test]
    fn test_utf16_decoder_replaces_high_surrogate_without_pair() {
        let mut decoder = Utf16ToUtf8Decoder::default();
        assert!(decoder.decode(&[0xD83D]).is_empty());

        // 'a' arrives where the low surrogate should have been.
        let mut expected = char::REPLACEMENT_CHARACTER.to_string().into_bytes();
        expected.extend_from_slice(b"a");
        assert_eq!(decoder.decode(&utf16("a")), expected);
    }

    #[test]
    fn test_utf16_decoder_preserves_ascii_control_bytes() {
        // Detach-key matching runs on the encoded bytes, so control characters
        // must round-trip byte-for-byte.
        let mut decoder = Utf16ToUtf8Decoder::default();
        assert_eq!(decoder.decode(&[0x1D]), vec![0x1D]);
        assert_eq!(decoder.decode(&[0x10, 0x11]), vec![0x10, 0x11]);
    }

    #[test]
    fn test_round_trip_through_both_decoders_one_byte_at_a_time() {
        let text = "ascii — ✓ ⠋ 日本語 🚀 done";
        let mut to_utf16 = Utf8ToUtf16Decoder::default();
        let mut to_utf8 = Utf16ToUtf8Decoder::default();

        let mut bytes = Vec::new();
        for byte in text.as_bytes() {
            let units = to_utf16.decode(&[*byte]);
            bytes.extend(to_utf8.decode(&units));
        }

        assert_eq!(String::from_utf8(bytes).unwrap(), text);
    }

    #[test]
    fn test_surrogate_safe_split_returns_len_when_under_max() {
        let units = utf16("short");
        assert_eq!(
            surrogate_safe_split(&units, MAX_CONSOLE_WRITE_UNITS),
            units.len()
        );
    }

    #[test]
    fn test_surrogate_safe_split_cuts_at_max_on_bmp_text() {
        let units = utf16("aaaaaa");
        assert_eq!(surrogate_safe_split(&units, 4), 4);
    }

    #[test]
    fn test_surrogate_safe_split_backs_off_a_split_pair() {
        // "a🚀a" is [a, high, low, a]; cutting at 2 would orphan the high half.
        let units = utf16("a🚀a");
        assert!(is_high_surrogate(units[1]));
        assert_eq!(surrogate_safe_split(&units, 2), 1);

        // Cutting after the complete pair is fine.
        assert_eq!(surrogate_safe_split(&units, 3), 3);
    }

    #[test]
    fn test_surrogate_safe_split_never_splits_a_pair() {
        let units = utf16("🚀🚀🚀🚀");
        for max in 1..units.len() {
            let split = surrogate_safe_split(&units, max);
            assert!(
                split == 0 || !is_high_surrogate(units[split - 1]),
                "max {max} split at {split}, orphaning a high surrogate"
            );
        }
    }

    #[test]
    fn test_surrogate_safe_split_handles_zero_max() {
        assert_eq!(surrogate_safe_split(&utf16("abc"), 0), 0);
    }

    #[test]
    fn test_split_separates_surrogate_pair_detects_partial_write_boundary() {
        let units = utf16("a🚀a");

        assert!(split_separates_surrogate_pair(&units, 2));
        assert!(!split_separates_surrogate_pair(&units, 0));
        assert!(!split_separates_surrogate_pair(&units, 1));
        assert!(!split_separates_surrogate_pair(&units, 3));
        assert!(!split_separates_surrogate_pair(&units, units.len()));
    }
}
