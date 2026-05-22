//! The opaque per-source resume handle, [`LogCursor`], plus its
//! string encoding (`Display` + `FromStr`) and parse error type.
//!
//! The cursor is variable-length: it carries one [`FilePosition`]
//! per log file the stream is configured to read. Each position is
//! a `(generation, offset)` pair. The set of files (and thus the
//! cursor's length) is determined at stream-creation time by the
//! caller's requested sources and the `LogFileConfig` list passed
//! to [`super::log_stream`].

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;

//--------------------------------------------------------------------------------------------------
// FilePosition
//--------------------------------------------------------------------------------------------------

/// Position of one log file within a [`LogCursor`]. `generation`
/// identifies the file's underlying inode (or platform-equivalent);
/// `offset` is the byte position just after the most-recent entry
/// observed in that file.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub(super) struct FilePosition {
    pub(super) generation: u64,
    pub(super) offset: u64,
}

//--------------------------------------------------------------------------------------------------
// LogCursor
//--------------------------------------------------------------------------------------------------

/// Opaque per-source resume handle returned on every
/// [`LogEntry`](super::LogEntry) and accepted by
/// [`LogStreamStart::From`](super::LogStreamStart::From).
///
/// Carries one position per log file the stream is reading. The
/// order matches the file order configured at stream creation.
/// Treat the inner data as opaque; round-trip the value via
/// [`Display`](std::fmt::Display) (or
/// [`to_string`](std::string::ToString::to_string)) and
/// [`str::parse`] for persistence or transport.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct LogCursor {
    pub(super) positions: Vec<FilePosition>,
}

/// Bytes per [`FilePosition`] on the wire (`generation` u64 LE +
/// `offset` u64 LE).
const POSITION_BYTES: usize = 8 + 8;

impl LogCursor {
    /// Empty cursor — used as the initial state for a stream that
    /// has not emitted anything yet, and as the cursor on entries
    /// before the stream layer stamps them.
    pub fn empty() -> Self {
        Self::default()
    }

    #[allow(dead_code)] // used by SDK bindings.
    pub(crate) fn exec(&self) -> (u64, u64) {
        self.positions
            .first()
            .map(|p| (p.generation, p.offset))
            .unwrap_or((0, 0))
    }

    #[allow(dead_code)] // used by SDK bindings.
    pub(crate) fn runtime(&self) -> u64 {
        self.positions.get(1).map(|p| p.offset).unwrap_or(0)
    }

    #[allow(dead_code)] // used by SDK bindings.
    pub(crate) fn kernel(&self) -> u64 {
        self.positions.get(2).map(|p| p.offset).unwrap_or(0)
    }
}

impl std::fmt::Display for LogCursor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let count = self.positions.len();
        let mut buf = vec![0u8; 1 + count * POSITION_BYTES];
        buf[0] = count as u8;
        for (i, pos) in self.positions.iter().enumerate() {
            let off = 1 + i * POSITION_BYTES;
            buf[off..off + 8].copy_from_slice(&pos.generation.to_le_bytes());
            buf[off + 8..off + 16].copy_from_slice(&pos.offset.to_le_bytes());
        }
        f.write_str(&BASE64.encode(buf))
    }
}

impl std::str::FromStr for LogCursor {
    type Err = LogCursorParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = BASE64
            .decode(s.as_bytes())
            .map_err(|_| LogCursorParseError::BadBase64)?;
        if bytes.is_empty() {
            return Err(LogCursorParseError::WrongLength(0));
        }
        let count = bytes[0] as usize;
        let expected = 1 + count * POSITION_BYTES;
        if bytes.len() != expected {
            return Err(LogCursorParseError::WrongLength(bytes.len()));
        }
        let mut positions = Vec::with_capacity(count);
        for i in 0..count {
            let off = 1 + i * POSITION_BYTES;
            positions.push(FilePosition {
                generation: u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap()),
                offset: u64::from_le_bytes(bytes[off + 8..off + 16].try_into().unwrap()),
            });
        }
        Ok(Self { positions })
    }
}

//--------------------------------------------------------------------------------------------------
// LogCursorParseError
//--------------------------------------------------------------------------------------------------

/// Error returned when parsing a [`LogCursor`] from a string.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LogCursorParseError {
    /// The string is not valid base64 in the standard alphabet.
    #[error("cursor is not valid base64")]
    BadBase64,
    /// The decoded payload length doesn't match the count byte
    /// (`1 + count * 16`).
    #[error("cursor payload has unexpected length ({0} bytes)")]
    WrongLength(usize),
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_three_positions() {
        let c = LogCursor {
            positions: vec![
                FilePosition {
                    generation: 0xdead_beef_1234_5678,
                    offset: 42,
                },
                FilePosition {
                    generation: 0,
                    offset: 100,
                },
                FilePosition {
                    generation: 0,
                    offset: 200,
                },
            ],
        };
        let s = c.to_string();
        let parsed: LogCursor = s.parse().unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn round_trip_empty() {
        let c = LogCursor::empty();
        let s = c.to_string();
        let parsed: LogCursor = s.parse().unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn round_trip_single_position() {
        let c = LogCursor {
            positions: vec![FilePosition {
                generation: 42,
                offset: 100,
            }],
        };
        let s = c.to_string();
        let parsed: LogCursor = s.parse().unwrap();
        assert_eq!(parsed, c);
    }

    #[test]
    fn parse_rejects_wrong_length() {
        let mut payload = vec![0u8; 6];
        payload[0] = 2;
        let s = BASE64.encode(&payload);
        assert!(matches!(
            s.parse::<LogCursor>(),
            Err(LogCursorParseError::WrongLength(6))
        ));
    }

    #[test]
    fn parse_rejects_garbage() {
        assert!(matches!(
            "not-base64!".parse::<LogCursor>(),
            Err(LogCursorParseError::BadBase64)
        ));
    }

    #[test]
    fn sdk_accessors_handle_short_cursors() {
        let c = LogCursor::empty();
        assert_eq!(c.exec(), (0, 0));
        assert_eq!(c.runtime(), 0);
        assert_eq!(c.kernel(), 0);

        let c = LogCursor {
            positions: vec![FilePosition {
                generation: 5,
                offset: 9,
            }],
        };
        assert_eq!(c.exec(), (5, 9));
        assert_eq!(c.runtime(), 0);
        assert_eq!(c.kernel(), 0);
    }
}
