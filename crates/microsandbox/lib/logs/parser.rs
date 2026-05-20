//! Reading one log file: the [`FileHandle`] wrapper around an open
//! file (tracking inode + offset for rotation-aware identity), and
//! the format-specific [`ParserKind`] dispatcher for JSON Lines
//! and plain text with RFC 3339 prefixes.
//!
//! [`ParserKind::parse_from`] takes a mutable [`FileHandle`], reads
//! up to one chunk, parses, and returns `(entry, position)` pairs.
//! Parsers don't stamp cursors — the stream layer composes the
//! cross-file [`LogCursor`] from the per-file positions returned
//! here.

use std::path::Path;

use bytes::Bytes;
use chrono::{DateTime, Utc};
use microsandbox_utils::log_text::{base64_decode, split_leading_timestamp, strip_ansi};
use serde::Deserialize;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use crate::{MicrosandboxError, MicrosandboxResult};

use super::cursor::{FilePosition, LogCursor};
use super::types::{LogEntry, LogSource};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Per-tick read ceiling. Caps how many bytes one read iteration
/// pulls off disk so very large backfills don't materialize the
/// whole file into memory before yielding the first entry.
const MAX_READ_BYTES: usize = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// FileHandle
//--------------------------------------------------------------------------------------------------

/// Open file handle paired with its inode and current read offset.
/// The handle survives renames (rotation), so once opened we can
/// keep reading the same inode regardless of where its path moves.
pub(super) struct FileHandle {
    pub(super) file: tokio::fs::File,
    pub(super) inode: u64,
    pub(super) offset: u64,
}

impl FileHandle {
    /// Asynchronously open a file as a [`FileHandle`]. Returns
    /// `Ok(None)` if the file doesn't exist (treated as "producer
    /// hasn't created it yet, retry later"); other I/O errors
    /// propagate.
    pub(super) async fn open(path: &Path) -> MicrosandboxResult<Option<Self>> {
        let file = match tokio::fs::File::open(path).await {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(MicrosandboxError::Io(e)),
        };
        let inode = Self::inode_of_file(&file).await?;
        Ok(Some(Self {
            file,
            inode,
            offset: 0,
        }))
    }

    /// Compute the file-identity discriminator (inode on Unix; a
    /// hash of file metadata on other platforms) from a sync
    /// `Metadata`.
    #[cfg(unix)]
    pub(super) fn generation_of_meta(meta: &std::fs::Metadata) -> u64 {
        use std::os::unix::fs::MetadataExt;
        meta.ino()
    }

    #[cfg(not(unix))]
    pub(super) fn generation_of_meta(meta: &std::fs::Metadata) -> u64 {
        use std::hash::{Hash, Hasher};
        let mut h = std::collections::hash_map::DefaultHasher::new();
        if let Ok(created) = meta.created()
            && let Ok(d) = created.duration_since(std::time::UNIX_EPOCH)
        {
            d.as_nanos().hash(&mut h);
        }
        meta.len().hash(&mut h);
        h.finish()
    }

    /// Convenience: stat a path and return its current generation,
    /// or `None` if the path can't be stat'd.
    pub(super) async fn generation_of_path(path: &Path) -> Option<u64> {
        tokio::fs::metadata(path)
            .await
            .ok()
            .map(|m| Self::generation_of_meta(&m))
    }

    /// Inode of an already-open tokio file handle.
    pub(super) async fn inode_of_file(file: &tokio::fs::File) -> MicrosandboxResult<u64> {
        let meta = file.metadata().await.map_err(MicrosandboxError::Io)?;
        Ok(Self::generation_of_meta(&meta))
    }

    /// File modification time of a path, falling back to `Utc::now`
    /// when the path can't be stat'd. Used by the text parser as
    /// the timestamp for lines that don't carry a parseable
    /// leading RFC 3339.
    pub(super) async fn mtime_of_path(path: &Path) -> DateTime<Utc> {
        tokio::fs::metadata(path)
            .await
            .ok()
            .and_then(|m| m.modified().ok())
            .map(|t| -> DateTime<Utc> { t.into() })
            .unwrap_or_else(Utc::now)
    }
}

//--------------------------------------------------------------------------------------------------
// RawEntry — the JSONL wire format
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
pub(super) struct RawEntry {
    pub(super) t: String,
    pub(super) s: String,
    #[serde(default)]
    pub(super) d: String,
    #[serde(default)]
    pub(super) id: Option<u64>,
    #[serde(default)]
    pub(super) e: Option<String>,
}

impl RawEntry {
    /// Decode the body bytes, applying base64 decoding when the
    /// entry is tagged with `e: "b64"` (raw-mode capture).
    pub(super) fn decode_body(&self) -> Bytes {
        if self.e.as_deref() == Some("b64") {
            match base64_decode(&self.d) {
                Some(bytes) => Bytes::from(bytes),
                None => Bytes::from(self.d.clone().into_bytes()),
            }
        } else {
            Bytes::from(self.d.clone().into_bytes())
        }
    }
}

//--------------------------------------------------------------------------------------------------
// ParserKind
//--------------------------------------------------------------------------------------------------

pub(super) struct ParsedChunk {
    pub(super) entries: Vec<(LogEntry, FilePosition)>,
    pub(super) position: Option<FilePosition>,
}

/// How a reader parses bytes from its source file.
pub(super) enum ParserKind {
    /// JSON Lines (one record per line). Filters by `sources`.
    Jsonl { sources: Vec<LogSource> },
    /// Plain text, one entry per line, with optional leading
    /// RFC 3339 timestamp; lines without a parseable timestamp
    /// fall back to the file's `mtime`. Always emits entries
    /// tagged as [`LogSource::System`].
    Text,
}

impl ParserKind {
    /// Read a chunk from `src` and parse it. Advances `src.offset`
    /// by the bytes consumed.
    pub(super) async fn parse_from(
        &self,
        src: &mut FileHandle,
        primary_path: &Path,
        since: Option<DateTime<Utc>>,
    ) -> MicrosandboxResult<ParsedChunk> {
        let mut buf = vec![0u8; MAX_READ_BYTES];
        src.file
            .seek(std::io::SeekFrom::Start(src.offset))
            .await
            .map_err(MicrosandboxError::Io)?;
        let read = src
            .file
            .read(&mut buf)
            .await
            .map_err(MicrosandboxError::Io)?;
        if read == 0 {
            return Ok(ParsedChunk {
                entries: Vec::new(),
                position: None,
            });
        }
        let mut entries = Vec::new();
        let consumed = match self {
            Self::Jsonl { sources } => Self::parse_jsonl(
                &buf[..read],
                src.offset,
                src.inode,
                sources,
                since,
                &mut entries,
            ),
            Self::Text => {
                let mtime = FileHandle::mtime_of_path(primary_path).await;
                Self::parse_text(
                    &buf[..read],
                    src.offset,
                    src.inode,
                    mtime,
                    since,
                    &mut entries,
                )
            }
        };
        src.offset += consumed as u64;
        let position = (consumed > 0).then_some(FilePosition {
            generation: src.inode,
            offset: src.offset,
        });
        Ok(ParsedChunk { entries, position })
    }

    /// Parse JSON Lines bytes. Emits `(entry, position)` pairs;
    /// each `position` carries the file's `generation` and the
    /// byte offset just after the entry's terminating newline.
    pub(super) fn parse_jsonl(
        bytes: &[u8],
        base_offset: u64,
        generation: u64,
        sources: &[LogSource],
        since: Option<DateTime<Utc>>,
        out: &mut Vec<(LogEntry, FilePosition)>,
    ) -> usize {
        Self::walk_lines(bytes, base_offset, out, |line, entry_end_offset| {
            let raw: RawEntry = serde_json::from_slice(line).ok()?;
            let source = match raw.s.as_str() {
                "stdout" => LogSource::Stdout,
                "stderr" => LogSource::Stderr,
                "output" => LogSource::Output,
                "system" => LogSource::System,
                _ => return None,
            };
            if !sources.contains(&source) {
                return None;
            }
            let timestamp = DateTime::parse_from_rfc3339(&raw.t)
                .ok()?
                .with_timezone(&Utc);
            if since.is_some_and(|s| timestamp < s) {
                return None;
            }
            Some((
                LogEntry {
                    timestamp,
                    source,
                    session_id: raw.id,
                    data: raw.decode_body(),
                    cursor: LogCursor::empty(),
                },
                FilePosition {
                    generation,
                    offset: entry_end_offset,
                },
            ))
        })
    }

    /// Parse plain-text bytes. Lines without a parseable leading
    /// RFC 3339 timestamp fall back to `mtime_fallback`. Always
    /// emits entries tagged as [`LogSource::System`].
    pub(super) fn parse_text(
        bytes: &[u8],
        base_offset: u64,
        generation: u64,
        mtime_fallback: DateTime<Utc>,
        since: Option<DateTime<Utc>>,
        out: &mut Vec<(LogEntry, FilePosition)>,
    ) -> usize {
        Self::walk_lines(bytes, base_offset, out, |raw_line, entry_end_offset| {
            let line = String::from_utf8_lossy(raw_line);
            let stripped = strip_ansi(&line);
            let (timestamp, body) = match split_leading_timestamp(&stripped) {
                Some((s, rest)) => (
                    DateTime::parse_from_rfc3339(s)
                        .map(|d| d.with_timezone(&Utc))
                        .unwrap_or(mtime_fallback),
                    rest.trim_start().to_string(),
                ),
                None => (mtime_fallback, stripped.clone()),
            };
            if since.is_some_and(|s| timestamp < s) {
                return None;
            }
            Some((
                LogEntry {
                    timestamp,
                    source: LogSource::System,
                    session_id: None,
                    data: Bytes::from(format!("{body}\n").into_bytes()),
                    cursor: LogCursor::empty(),
                },
                FilePosition {
                    generation,
                    offset: entry_end_offset,
                },
            ))
        })
    }

    /// Walk `bytes` line-by-line (`\n`-delimited), invoking
    /// `handler` on each complete line with its end-of-line file
    /// offset. Trailing partial lines (no terminating `\n`) are
    /// left unconsumed. Returns the number of bytes consumed.
    fn walk_lines<F>(
        bytes: &[u8],
        base_offset: u64,
        out: &mut Vec<(LogEntry, FilePosition)>,
        mut handler: F,
    ) -> usize
    where
        F: FnMut(&[u8], u64) -> Option<(LogEntry, FilePosition)>,
    {
        let mut pos = 0usize;
        while pos < bytes.len() {
            let nl_rel = match bytes[pos..].iter().position(|&b| b == b'\n') {
                Some(n) => n,
                None => break,
            };
            let line_end = pos + nl_rel;
            let line = &bytes[pos..line_end];
            let entry_end_offset = base_offset + (line_end as u64) + 1;
            if !line.is_empty()
                && let Some(pair) = handler(line, entry_end_offset)
            {
                out.push(pair);
            }
            pos = line_end + 1;
        }
        pos
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn ts(s: &str) -> DateTime<Utc> {
        DateTime::parse_from_rfc3339(s).unwrap().with_timezone(&Utc)
    }

    // -- parse_jsonl ---------------------------------------------------

    #[test]
    fn jsonl_parses_single_complete_line() {
        let bytes = br#"{"t":"2026-04-30T20:32:59.000Z","s":"stdout","d":"hi\n","id":7}
"#;
        let mut out = Vec::new();
        let consumed = ParserKind::parse_jsonl(bytes, 0, 42, &[LogSource::Stdout], None, &mut out);
        assert_eq!(consumed, bytes.len());
        assert_eq!(out.len(), 1);
        let (entry, pos) = &out[0];
        assert_eq!(entry.source, LogSource::Stdout);
        assert_eq!(entry.session_id, Some(7));
        assert_eq!(entry.data, Bytes::from("hi\n".as_bytes()));
        assert_eq!(entry.timestamp, ts("2026-04-30T20:32:59Z"));
        assert_eq!(pos.generation, 42);
        assert_eq!(pos.offset, bytes.len() as u64);
    }

    #[test]
    fn jsonl_leaves_trailing_partial_line_unconsumed() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(
            br#"{"t":"2026-04-30T20:32:59.000Z","s":"stdout","d":"a","id":1}
"#,
        );
        let after_first = bytes.len();
        bytes.extend_from_slice(br#"{"t":"2026-04-30T20:33:00.000Z","s":"stdout","d":"b"#);

        let mut out = Vec::new();
        let consumed = ParserKind::parse_jsonl(&bytes, 0, 1, &[LogSource::Stdout], None, &mut out);
        assert_eq!(consumed, after_first);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn jsonl_filters_by_sources() {
        let bytes = b"{\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"stdout\",\"d\":\"a\"}\n\
                      {\"t\":\"2026-04-30T00:00:01Z\",\"s\":\"stderr\",\"d\":\"b\"}\n\
                      {\"t\":\"2026-04-30T00:00:02Z\",\"s\":\"system\",\"d\":\"c\"}\n";
        let mut out = Vec::new();
        ParserKind::parse_jsonl(bytes, 0, 0, &[LogSource::Stderr], None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.source, LogSource::Stderr);
        assert_eq!(out[0].0.data, Bytes::from("b".as_bytes()));
    }

    #[test]
    fn jsonl_filters_by_since() {
        let bytes = b"{\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"stdout\",\"d\":\"early\"}\n\
                      {\"t\":\"2026-04-30T00:00:05Z\",\"s\":\"stdout\",\"d\":\"late\"}\n";
        let mut out = Vec::new();
        let since = Some(ts("2026-04-30T00:00:03Z"));
        ParserKind::parse_jsonl(bytes, 0, 0, &[LogSource::Stdout], since, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.data, Bytes::from("late".as_bytes()));
    }

    #[test]
    fn jsonl_skips_malformed_lines() {
        let bytes = b"this is not json\n\
                      {\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"stdout\",\"d\":\"ok\"}\n\
                      {malformed json\n";
        let mut out = Vec::new();
        ParserKind::parse_jsonl(bytes, 0, 0, &[LogSource::Stdout], None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.data, Bytes::from("ok".as_bytes()));
    }

    #[test]
    fn jsonl_skips_unknown_source_values() {
        let bytes = b"{\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"alien\",\"d\":\"x\"}\n";
        let mut out = Vec::new();
        ParserKind::parse_jsonl(bytes, 0, 0, &[LogSource::Stdout], None, &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn jsonl_decodes_base64_body_when_tagged() {
        let bytes =
            b"{\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"stdout\",\"d\":\"aGVsbG8=\",\"e\":\"b64\"}\n";
        let mut out = Vec::new();
        ParserKind::parse_jsonl(bytes, 0, 0, &[LogSource::Stdout], None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.data, Bytes::from("hello".as_bytes()));
    }

    #[test]
    fn jsonl_position_offsets_are_relative_to_base() {
        let bytes = b"{\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"stdout\",\"d\":\"a\"}\n\
                      {\"t\":\"2026-04-30T00:00:01Z\",\"s\":\"stdout\",\"d\":\"b\"}\n";
        let mut out = Vec::new();
        ParserKind::parse_jsonl(bytes, 1000, 99, &[LogSource::Stdout], None, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].1.generation, 99);
        assert!(out[0].1.offset > 1000);
        assert_eq!(out[1].1.offset, 1000 + bytes.len() as u64);
    }

    #[test]
    fn jsonl_skips_empty_lines() {
        let bytes = b"\n\
                      {\"t\":\"2026-04-30T00:00:00Z\",\"s\":\"stdout\",\"d\":\"a\"}\n\
                      \n";
        let mut out = Vec::new();
        ParserKind::parse_jsonl(bytes, 0, 0, &[LogSource::Stdout], None, &mut out);
        assert_eq!(out.len(), 1);
    }

    // -- parse_text ----------------------------------------------------

    #[test]
    fn text_parses_lines_with_rfc3339_prefix() {
        let bytes = b"2026-04-30T20:30:00.000Z INFO starting up\n\
                      2026-04-30T20:30:01.000Z WARN something\n";
        let mut out = Vec::new();
        let mtime = Utc.with_ymd_and_hms(2030, 1, 1, 0, 0, 0).unwrap();
        ParserKind::parse_text(bytes, 0, 7, mtime, None, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0.source, LogSource::System);
        assert_eq!(out[0].0.timestamp, ts("2026-04-30T20:30:00Z"));
        assert_eq!(out[0].0.data, Bytes::from("INFO starting up\n".as_bytes()));
        assert_eq!(out[0].1.generation, 7);
    }

    #[test]
    fn text_falls_back_to_mtime_without_timestamp_prefix() {
        let bytes = b"[ 0.123] kernel boot message\n";
        let mut out = Vec::new();
        let mtime = ts("2026-01-15T10:00:00Z");
        ParserKind::parse_text(bytes, 0, 0, mtime, None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.timestamp, mtime);
    }

    #[test]
    fn text_replaces_invalid_utf8_lossily() {
        let bytes = b"2026-04-30T20:30:00.000Z bad \xff line\n";
        let mut out = Vec::new();
        ParserKind::parse_text(bytes, 0, 0, Utc::now(), None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(
            std::str::from_utf8(&out[0].0.data).unwrap(),
            "bad \u{fffd} line\n"
        );
    }

    #[test]
    fn text_strips_ansi_escapes() {
        let bytes = b"\x1b[31m2026-04-30T20:30:00.000Z\x1b[0m ERROR boom\n";
        let mut out = Vec::new();
        let mtime = Utc::now();
        ParserKind::parse_text(bytes, 0, 0, mtime, None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.timestamp, ts("2026-04-30T20:30:00Z"));
    }

    #[test]
    fn text_filters_by_since() {
        let bytes = b"2026-04-30T00:00:00Z early line\n\
                      2026-04-30T00:00:10Z late line\n";
        let mut out = Vec::new();
        let mtime = Utc::now();
        let since = Some(ts("2026-04-30T00:00:05Z"));
        ParserKind::parse_text(bytes, 0, 0, mtime, since, &mut out);
        assert_eq!(out.len(), 1);
        assert!(
            std::str::from_utf8(&out[0].0.data)
                .unwrap()
                .contains("late line")
        );
    }

    #[test]
    fn text_leaves_partial_trailing_line_unconsumed() {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(b"2026-04-30T00:00:00Z complete\n");
        let after_first = bytes.len();
        bytes.extend_from_slice(b"2026-04-30T00:00:01Z partial");

        let mut out = Vec::new();
        let consumed = ParserKind::parse_text(&bytes, 0, 0, Utc::now(), None, &mut out);
        assert_eq!(consumed, after_first);
        assert_eq!(out.len(), 1);
    }

    #[test]
    fn text_always_emits_system_source() {
        let bytes = b"hello world\n";
        let mut out = Vec::new();
        ParserKind::parse_text(bytes, 0, 0, Utc::now(), None, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0.source, LogSource::System);
        assert_eq!(out[0].0.session_id, None);
    }

    #[test]
    fn text_position_offsets_are_relative_to_base() {
        let bytes = b"2026-04-30T00:00:00Z first\n2026-04-30T00:00:01Z second\n";
        let mut out = Vec::new();
        ParserKind::parse_text(bytes, 500, 99, Utc::now(), None, &mut out);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].1.generation, 99);
        assert!(out[0].1.offset > 500);
        assert_eq!(out[1].1.offset, 500 + bytes.len() as u64);
    }

    // -- RawEntry::decode_body -----------------------------------------

    #[test]
    fn decode_body_returns_plain_bytes_without_base64_tag() {
        let raw = RawEntry {
            t: "x".into(),
            s: "stdout".into(),
            d: "hello".into(),
            id: None,
            e: None,
        };
        assert_eq!(raw.decode_body(), Bytes::from("hello".as_bytes()));
    }

    #[test]
    fn decode_body_base64_decodes_when_tagged_b64() {
        let raw = RawEntry {
            t: "x".into(),
            s: "stdout".into(),
            d: "aGVsbG8=".into(),
            id: None,
            e: Some("b64".into()),
        };
        assert_eq!(raw.decode_body(), Bytes::from("hello".as_bytes()));
    }

    #[test]
    fn decode_body_falls_back_to_raw_on_invalid_base64() {
        let raw = RawEntry {
            t: "x".into(),
            s: "stdout".into(),
            d: "not valid b64!".into(),
            id: None,
            e: Some("b64".into()),
        };
        assert_eq!(raw.decode_body(), Bytes::from("not valid b64!".as_bytes()));
    }
}
