//! Text helpers for parsing/rendering captured log lines.
//!
//! Shared by the SDK's `microsandbox::sandbox::logs` reader and the
//! CLI's `msb logs` renderer — both consume the same on-disk JSON
//! Lines format and need the same low-level transforms.

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Strip ANSI escape sequences (CSI, OSC, two-byte C1).
///
/// Hand-rolled state machine. Avoids pulling the `regex` crate just
/// for one fixed pattern. Handles:
///
/// - `\x1b[…<final>` — CSI (SGR colors, cursor moves). Final byte is
///   in `0x40..=0x7e`.
/// - `\x1b]…\x07` and `\x1b]…\x1b\\` — OSC (terminated by BEL or ST).
/// - `\x1b<X>` for X in `0x40..=0x5f` — two-byte C1 controls.
pub fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                for c in chars.by_ref() {
                    if matches!(c, '\x40'..='\x7e') {
                        break;
                    }
                }
            }
            Some(']') => {
                while let Some(c) = chars.next() {
                    if c == '\x07' {
                        break;
                    }
                    if c == '\x1b' && chars.peek() == Some(&'\\') {
                        chars.next();
                        break;
                    }
                }
            }
            Some(_) => {}
            None => break,
        }
    }
    out
}

/// Split a `runtime.log`/`kernel.log` line into a leading RFC 3339
/// timestamp token (ending in `Z`, ≥20 chars) and the rest of the
/// line. Returns `None` if the first whitespace-delimited token isn't
/// a plausible timestamp.
pub fn split_leading_timestamp(line: &str) -> Option<(&str, &str)> {
    let (first, rest) = line.split_once(char::is_whitespace)?;
    if first.len() >= 20 && first.ends_with('Z') {
        Some((first, rest))
    } else {
        None
    }
}

/// Decode a standard-alphabet base64 string. Returns `None` on
/// malformed input. Used for the opt-in raw-mode `e: "b64"` log
/// entries; small enough that pulling in the `base64` crate isn't
/// justified.
pub fn base64_decode(s: &str) -> Option<Vec<u8>> {
    static TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.trim().as_bytes();
    if bytes.is_empty() {
        return Some(Vec::new());
    }
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for chunk in bytes.chunks(4) {
        let mut vals = [0u8; 4];
        let mut pad = 0usize;
        for (i, &b) in chunk.iter().enumerate() {
            if b == b'=' {
                pad += 1;
                vals[i] = 0;
            } else {
                let idx = TABLE.iter().position(|&t| t == b)?;
                vals[i] = idx as u8;
            }
        }
        let n = ((vals[0] as u32) << 18)
            | ((vals[1] as u32) << 12)
            | ((vals[2] as u32) << 6)
            | (vals[3] as u32);
        out.push(((n >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if pad < 1 {
            out.push((n & 0xff) as u8);
        }
    }
    Some(out)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_ansi_removes_color_and_cursor() {
        let s = "\x1b[31merror\x1b[0m\x1b[2J\x1b[H text";
        assert_eq!(strip_ansi(s), "error text");
    }

    #[test]
    fn strip_ansi_preserves_plain_text() {
        let s = "hello\nworld\n";
        assert_eq!(strip_ansi(s), s);
    }

    #[test]
    fn split_leading_timestamp_picks_first_token() {
        let line = "2026-04-30T20:32:59.690Z  INFO some message";
        let (t, rest) = split_leading_timestamp(line).unwrap();
        assert_eq!(t, "2026-04-30T20:32:59.690Z");
        assert!(rest.trim_start().starts_with("INFO"));
    }

    #[test]
    fn split_leading_timestamp_returns_none_for_unstructured() {
        let line = "[ 0.123] kernel boot message";
        assert!(split_leading_timestamp(line).is_none());
    }

    #[test]
    fn base64_decode_basic() {
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), b"hello");
        assert_eq!(base64_decode("").unwrap(), Vec::<u8>::new());
    }
}
