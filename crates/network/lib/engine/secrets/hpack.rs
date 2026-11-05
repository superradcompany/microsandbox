//! Structural check for guest HTTP/2 header blocks before `httlib-hpack`
//! decodes them.
//!
//! `httlib-hpack` 0.1.3 indexes out of bounds when a header block ends inside
//! an integer or just before a string literal, which aborts release builds
//! (`panic = "abort"`). [`check_header_block`] walks the representations of
//! RFC 7541 §6 with the decoder's own integer limit, so the decoder only sees
//! blocks in which every representation is complete. Index, Huffman and table
//! size errors are still left to the decoder.

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Continuation octets `httlib-hpack` accepts in one integer. It reports a
/// fifth as an error, so this matches it exactly and keeps every value below
/// 2^28 + 2^7.
const MAX_INTEGER_CONTINUATION_OCTETS: usize = 4;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A header block with a truncated representation or an over-long integer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("truncated or over-long HPACK representation at offset {offset}")]
pub(super) struct MalformedHeaderBlock {
    /// Offset of the first octet of the rejected representation.
    pub(super) offset: usize,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Check that every representation in `block` (RFC 7541 §6) is complete,
/// without decoding strings or touching a dynamic table.
pub(super) fn check_header_block(block: &[u8]) -> Result<(), MalformedHeaderBlock> {
    let mut pos = 0;
    while pos < block.len() {
        pos = representation_end(block, pos).ok_or(MalformedHeaderBlock { offset: pos })?;
    }
    Ok(())
}

/// Offset just past the representation that starts at `pos`, in the same
/// dispatch order as `httlib_hpack::Decoder::decode_exact`.
fn representation_end(block: &[u8], pos: usize) -> Option<usize> {
    let first = block[pos];
    let prefix_bits = if first & 0x80 != 0 {
        // Indexed field (RFC 7541 §6.1).
        return Some(pos + read_integer(&block[pos..], 7)?.1);
    } else if first & 0x40 != 0 {
        // Literal with incremental indexing (RFC 7541 §6.2.1).
        6
    } else if first & 0x20 != 0 {
        // Dynamic table size update (RFC 7541 §6.3).
        return Some(pos + read_integer(&block[pos..], 5)?.1);
    } else {
        // Literal without indexing or never indexed (RFC 7541 §6.2.2, §6.2.3).
        4
    };
    let (name_index, used) = read_integer(&block[pos..], prefix_bits)?;
    let mut pos = pos + used;
    if name_index == 0 {
        pos = skip_string(block, pos)?;
    }
    skip_string(block, pos)
}

/// Decode an HPACK integer with a `prefix_bits`-bit prefix (RFC 7541 §5.1). Returns
/// the value and the number of octets used.
fn read_integer(buf: &[u8], prefix_bits: u32) -> Option<(usize, usize)> {
    let mask = (1usize << prefix_bits) - 1;
    let mut value = usize::from(*buf.first()?) & mask;
    if value < mask {
        return Some((value, 1));
    }
    let continuation = buf.get(1..)?.iter().take(MAX_INTEGER_CONTINUATION_OCTETS);
    for (i, &octet) in continuation.enumerate() {
        value += usize::from(octet & 0x7f) << (7 * i);
        if octet & 0x80 == 0 {
            return Some((value, i + 2));
        }
    }
    None
}

/// Skip the string literal at `pos` (RFC 7541 §5.2) and return the offset after it.
fn skip_string(block: &[u8], pos: usize) -> Option<usize> {
    let (len, used) = read_integer(block.get(pos..)?, 7)?;
    let end = pos + used + len;
    (end <= block.len()).then_some(end)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
pub(super) mod tests {
    use std::panic::{self, AssertUnwindSafe};

    use httlib_hpack::{Decoder, Encoder};

    use super::*;

    /// Blocks that made httlib-hpack 0.1.3 index out of bounds.
    pub(crate) const PANICKING_BLOCKS: [&[u8]; 4] =
        [&[0xff], &[0x67], &[0x7f, 0xc5], &[0x34, 0x22, 0x42]];

    /// Valid Huffman-coded strings from RFC 7541 Appendix C.4.
    const HUFFMAN_STRINGS: [&[u8]; 4] = [
        &[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ],
        &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf],
        &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
        &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xb8, 0xe8, 0xb4, 0xbf],
    ];

    /// What plain `httlib-hpack` does with one block.
    #[derive(Debug, PartialEq)]
    enum Decoded {
        Fields(Vec<(Vec<u8>, Vec<u8>, u8)>),
        Error,
        Panic,
    }

    /// Deterministic xorshift64 generator, so failures reproduce from the
    /// printed block without a seed file.
    pub(crate) struct Rng(pub(crate) u64);

    impl Rng {
        pub(crate) fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        pub(crate) fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }

        fn byte(&mut self) -> u8 {
            self.next() as u8
        }
    }

    /// A random header block: up to five HPACK representations (indexed,
    /// size update, literal with a raw, Huffman or random-Huffman string),
    /// then sometimes truncated, corrupted or extended with random bytes.
    /// About half of the blocks are valid, so decoding reaches the dynamic
    /// table and Huffman paths instead of failing on the first octet.
    pub(crate) fn random_block(rng: &mut Rng) -> Vec<u8> {
        let mut block = Vec::new();
        for i in 0..rng.below(6) {
            match rng.below(8) {
                0 if i == 0 => {
                    let size = [0, 64, 4096, 4097, rng.below(5000)][rng.below(5)];
                    push_integer(&mut block, 0x20, 5, size);
                }
                0..=2 => push_integer(&mut block, 0x80, 7, random_index(rng)),
                _ => {
                    // Incremental indexing, without indexing, never indexed.
                    let (pattern, prefix_bits) = [(0x40, 6), (0x00, 4), (0x10, 4)][rng.below(3)];
                    let name_index = [0, 0, random_index(rng)][rng.below(3)];
                    push_integer(&mut block, pattern, prefix_bits, name_index);
                    if name_index == 0 {
                        push_string(&mut block, rng);
                    }
                    push_string(&mut block, rng);
                }
            }
        }
        match rng.below(8) {
            0 => block.truncate(rng.below(block.len() + 1)),
            1 if !block.is_empty() => {
                let at = rng.below(block.len());
                block[at] = rng.byte();
            }
            2 => block.extend((0..1 + rng.below(4)).map(|_| rng.byte())),
            _ => {}
        }
        block
    }

    /// Mostly static-table indices, some early dynamic-table indices, and
    /// occasionally anything up to 127 (including the invalid 0).
    fn random_index(rng: &mut Rng) -> usize {
        match rng.below(16) {
            0 => rng.below(128),
            1..=3 => 62 + rng.below(4),
            _ => 1 + rng.below(61),
        }
    }

    /// Append an RFC 7541 §5.1 integer.
    fn push_integer(block: &mut Vec<u8>, pattern: u8, prefix_bits: u32, value: usize) {
        let mask = (1usize << prefix_bits) - 1;
        if value < mask {
            block.push(pattern | value as u8);
            return;
        }
        block.push(pattern | mask as u8);
        let mut rest = value - mask;
        while rest >= 0x80 {
            block.push(0x80 | (rest & 0x7f) as u8);
            rest >>= 7;
        }
        block.push(rest as u8);
    }

    /// Append an RFC 7541 §5.2 string literal.
    fn push_string(block: &mut Vec<u8>, rng: &mut Rng) {
        match rng.below(10) {
            0..=5 => {
                let len = rng.below(12);
                push_integer(block, 0x00, 7, len);
                block.extend((0..len).map(|_| b'a' + rng.below(26) as u8));
            }
            6..=8 => {
                let huffman = HUFFMAN_STRINGS[rng.below(HUFFMAN_STRINGS.len())];
                push_integer(block, 0x80, 7, huffman.len());
                block.extend_from_slice(huffman);
            }
            _ => {
                // Random Huffman data: exercises padding and EOS checks.
                let len = rng.below(6);
                push_integer(block, 0x80, 7, len);
                block.extend((0..len).map(|_| rng.byte()));
            }
        }
    }

    fn new_decoder() -> Decoder<'static> {
        Decoder::with_dynamic_size(4096)
    }

    /// Decode `block` with plain `httlib-hpack`, turning a panic into
    /// [`Decoded::Panic`]. The panic message is captured by the test harness.
    /// The tests provoke these panics on purpose, so with `--nocapture` their
    /// `panicked at …httlib-hpack…` lines are expected output, not failures.
    fn httlib_decode(decoder: &mut Decoder<'static>, block: &[u8]) -> Decoded {
        let mut buf = block.to_vec();
        let mut fields = Vec::new();
        match panic::catch_unwind(AssertUnwindSafe(|| decoder.decode(&mut buf, &mut fields))) {
            Ok(Ok(_)) => Decoded::Fields(fields),
            Ok(Err(_)) => Decoded::Error,
            Err(_) => Decoded::Panic,
        }
    }

    /// Feed one connection's blocks to a guarded and an unguarded decoder.
    /// Blocks the guard accepts must decode exactly as without it and never
    /// panic; blocks it rejects must be blocks plain `httlib-hpack` rejects or
    /// panics on. Like the handler, stop at the first rejected block.
    fn assert_guard_matches_httlib(blocks: &[Vec<u8>]) {
        let mut guarded = new_decoder();
        let mut unguarded = new_decoder();
        for block in blocks {
            let expected = httlib_decode(&mut unguarded, block);
            if check_header_block(block).is_ok() {
                assert_ne!(expected, Decoded::Panic, "guard accepted {block:02x?}");
                assert_eq!(httlib_decode(&mut guarded, block), expected, "{block:02x?}");
            } else {
                assert!(
                    !matches!(expected, Decoded::Fields(_)),
                    "guard rejected a block httlib-hpack accepts: {block:02x?}"
                );
                return;
            }
            if expected == Decoded::Error {
                return;
            }
        }
    }

    #[test]
    fn panicking_blocks_are_rejected() {
        let truncated: [&[u8]; 5] = [
            // Size update with its integer cut off.
            &[0x3f],
            // Literal with a 4-bit name index of 15+, cut off.
            &[0x0f],
            // `82` (:method GET), then a literal whose value is missing.
            &[0x82, 0x44],
            // Literal name "a" declared 5 bytes long.
            &[0x00, 0x05, 0x61],
            // Name "a", then the last string, value "b", declared 5 bytes long.
            &[0x00, 0x01, 0x61, 0x05, 0x62],
        ];
        for block in PANICKING_BLOCKS.into_iter().chain(truncated) {
            assert!(check_header_block(block).is_err(), "{block:02x?}");
            assert_guard_matches_httlib(&[block.to_vec()]);
        }
        assert_eq!(
            check_header_block(&[0x34, 0x22, 0x42]),
            Err(MalformedHeaderBlock { offset: 2 })
        );
    }

    #[test]
    fn complete_blocks_are_left_to_the_decoder() {
        // Each block is structurally complete, so the guard accepts it and
        // `httlib-hpack` decides, exactly as before the guard existed. The
        // expected result on a fresh decoder is `Some(fields)` or `None` for
        // an error, so a decoder upgrade that changes it fails here.
        let blocks: [(&[u8], Option<usize>); 14] = [
            // Index 0 is never valid.
            (&[0x80], None),
            // Largest 5-octet index: out of range.
            (&[0xff, 0xff, 0xff, 0xff, 0x7f], None),
            // Huffman string of one 0xff byte: padding longer than 7 bits.
            (&[0x00, 0x81, 0xff, 0x80], None),
            // Huffman padding that is not EOS bits, which httlib-hpack accepts,
            // and the same string padded with EOS bits.
            (&[0x10, 0x85, 0xf5, 0xb2, 0x01, 0x01, 0xb3, 0x00], Some(1)),
            (&[0x10, 0x85, 0xf5, 0xb2, 0x01, 0x01, 0xbf, 0x00], Some(1)),
            // Size update above the 4096-byte limit.
            (&[0x3f, 0xe2, 0x1f], None),
            // Size updates after and between fields.
            (&[0x82, 0x20], Some(1)),
            (&[0x82, 0x20, 0x82], Some(2)),
            // A block made only of size updates.
            (&[0x20, 0x3f, 0xe1, 0x1f], Some(0)),
            // For each prefix width w, the value 2^(w-1) - 1 fits in the
            // prefix, but a width one bit narrower would read it as full:
            // index 63 (empty dynamic table), size update 15, and literals
            // with name index 31 (6-bit) and 7 (both 4-bit forms).
            (&[0xbf], None),
            (&[0x2f], Some(0)),
            (&[0x5f, 0x01, b'v'], Some(1)),
            (&[0x07, 0x01, b'v'], Some(1)),
            (&[0x17, 0x01, b'v'], Some(1)),
        ];
        for (block, expected) in blocks {
            assert_eq!(check_header_block(block), Ok(()), "{block:02x?}");
            let decoded = match httlib_decode(&mut new_decoder(), block) {
                Decoded::Fields(fields) => Some(fields.len()),
                Decoded::Error => None,
                Decoded::Panic => panic!("httlib-hpack panicked on {block:02x?}"),
            };
            assert_eq!(decoded, expected, "{block:02x?}");
            assert_guard_matches_httlib(&[block.to_vec()]);
        }
    }

    #[test]
    fn random_blocks_match_unguarded_httlib() {
        // Each connection feeds up to four blocks through one decoder, so
        // dynamic-table entries from earlier blocks are referenced later.
        let mut rng = Rng(0x243f_6a88_85a3_08d3);
        for _ in 0..2_000 {
            let blocks: Vec<_> = (0..4).map(|_| random_block(&mut rng)).collect();
            assert_guard_matches_httlib(&blocks);
        }
    }

    #[test]
    fn uniform_random_bytes_match_unguarded_httlib() {
        // Unstructured input, next to the grammar-based generator above:
        // uniformly random bytes at every length from 0 to 32.
        let mut rng = Rng(0xa409_3822_299f_31d0);
        for _ in 0..500 {
            for len in 0..=32 {
                let block: Vec<u8> = (0..len).map(|_| rng.byte()).collect();
                assert_guard_matches_httlib(&[block]);
            }
        }
    }

    #[test]
    fn integer_boundaries_match_httlib_for_every_prefix() {
        // Indexed (7-bit), literal with incremental indexing (6-bit), without
        // indexing and never indexed (4-bit), and table size update (5-bit).
        for (pattern, prefix_bits) in [(0x80, 7), (0x40, 6), (0x00, 4), (0x10, 4), (0x20, 5)] {
            let mask = (1u8 << prefix_bits) - 1;
            let max = usize::from(mask);
            let full = pattern | mask;
            let integers: [(&[u8], Option<usize>); 8] = [
                // Largest value that fits in the prefix.
                (&[pattern | (mask - 1)], Some(max - 1)),
                // Smallest value that needs a continuation octet.
                (&[full, 0x00], Some(max)),
                // Largest value with four continuation octets: 2^28 - 1 more.
                (&[full, 0xff, 0xff, 0xff, 0x7f], Some(max + (1 << 28) - 1)),
                // A fifth continuation octet is too long.
                (&[full, 0x80, 0x80, 0x80, 0x80, 0x00], None),
                // Truncated after each octet.
                (&[full], None),
                (&[full, 0x80], None),
                (&[full, 0x80, 0x80, 0x80], None),
                (&[full, 0x80, 0x80, 0x80, 0x80], None),
            ];
            for (integer, value) in integers {
                assert_eq!(
                    read_integer(integer, prefix_bits).map(|(value, _)| value),
                    value,
                    "{integer:02x?}"
                );
                // As a whole block: literals get the value `b`.
                let mut block = integer.to_vec();
                if pattern & 0xa0 == 0 {
                    block.extend_from_slice(&[0x01, b'b']);
                }
                assert_eq!(check_header_block(&block).is_ok(), value.is_some());
                assert_guard_matches_httlib(&[block]);
            }
        }
        // String lengths (7-bit prefix, raw and Huffman): a maximum-width
        // length runs past the end, and a fifth continuation octet is rejected.
        for huffman in [0x00, 0x80] {
            for length in [
                [huffman | 0x7f, 0xff, 0xff, 0xff, 0x7f, b'a'],
                [huffman | 0x7f, 0x80, 0x80, 0x80, 0x80, 0x00],
            ] {
                let mut block = vec![0x00];
                block.extend_from_slice(&length);
                assert!(check_header_block(&block).is_err(), "{block:02x?}");
                assert_guard_matches_httlib(&[block]);
            }
        }
    }

    #[test]
    fn integers_with_padding_octets_are_accepted() {
        // Size update 31 with four continuation octets (`80 80 80 00`) is a
        // valid, non-minimal encoding. Five continuation octets are rejected.
        let padded = [0x3f, 0x80, 0x80, 0x80, 0x00, 0x82];
        assert_eq!(check_header_block(&padded), Ok(()));
        assert_eq!(
            httlib_decode(&mut new_decoder(), &padded),
            Decoded::Fields(vec![(b":method".to_vec(), b"GET".to_vec(), 0)])
        );
        let too_long = [0x3f, 0x80, 0x80, 0x80, 0x80, 0x00, 0x82];
        assert!(check_header_block(&too_long).is_err());
        assert_guard_matches_httlib(&[too_long.to_vec()]);
    }

    #[test]
    fn encoder_output_and_every_truncation_match_httlib() {
        // Blocks from `httlib-hpack`'s own encoder, with every format and
        // dynamic-table evictions, are always accepted. Cutting one anywhere
        // gives a block that the guard and a fresh decoder handle alike.
        let mut rng = Rng(0x1319_8a2e_0370_7344);
        let mut encoder = Encoder::with_dynamic_size(4096);
        let mut blocks = Vec::new();
        for round in 0..200 {
            let mut block = Vec::new();
            if round % 50 == 49 {
                // Shrink, then restore the table: evicts every entry.
                encoder.update_max_dynamic_size(0, &mut block).unwrap();
                encoder.update_max_dynamic_size(4096, &mut block).unwrap();
            }
            for _ in 0..1 + rng.below(8) {
                let name = format!("x-h{}", rng.below(6)).into_bytes();
                // Values up to 300 bytes force evictions from a 4 KiB table.
                let value = vec![b'a' + rng.below(4) as u8; rng.below(300)];
                let flags = [
                    Encoder::BEST_FORMAT | Encoder::WITH_INDEXING,
                    Encoder::WITH_INDEXING | Encoder::HUFFMAN_NAME | Encoder::HUFFMAN_VALUE,
                    Encoder::NEVER_INDEXED,
                    Encoder::BEST_FORMAT,
                    0,
                ][rng.below(5)];
                encoder.encode((name, value, flags), &mut block).unwrap();
            }
            assert_eq!(check_header_block(&block), Ok(()), "round {round}");
            blocks.push(block);
        }
        assert_guard_matches_httlib(&blocks);
        for block in &blocks {
            for cut in 0..block.len() {
                assert_guard_matches_httlib(&[block[..cut].to_vec()]);
            }
        }
    }
}
