//! Streaming engine. The [`LogEngine`] takes a
//! `&[LogFileConfig]` describing the streamable files, filters them
//! by the caller's requested sources, opens a reader for each
//! surviving file, and merges their outputs into one async
//! [`futures::Stream`] of [`LogEntry`] values — with optional
//! follow semantics and per-source cursor resume.

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use futures::Stream;
use futures::stream;
use notify::Watcher;

use crate::{MicrosandboxError, MicrosandboxResult};

use super::cursor::{FilePosition, LogCursor};
use super::parser::{FileHandle, ParsedChunk, ParserKind};
use super::types::{LogEntry, LogSource};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const FALLBACK_POLL_INTERVAL: Duration = Duration::from_secs(2);

//--------------------------------------------------------------------------------------------------
// LogFileConfig
//--------------------------------------------------------------------------------------------------

/// On-disk format of a log file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LogFileFormat {
    /// JSON Lines, one record per line.
    Jsonl,
    /// Plain text, one entry per line, RFC 3339 timestamp prefix
    /// optional. All entries surface as [`LogSource::System`].
    Text,
}

/// Static description of one streamable log file. The engine takes
/// a `&[LogFileConfig]` at construction time and builds one reader
/// per entry whose `produces` intersects the caller's requested
/// sources.
pub(crate) struct LogFileConfig {
    /// Base filename within the directory passed to
    /// [`super::log_stream`].
    pub(crate) filename: &'static str,
    /// On-disk format.
    pub(crate) format: LogFileFormat,
    /// Highest rotation index. `0` means non-rotating — the file at
    /// the bare name is the only one ever read; on inode change
    /// the reader silently resets to the new file.
    pub(crate) max_rotation_index: usize,
    /// Which [`LogSource`] values entries from this file may
    /// carry. Used at stream construction to decide whether to
    /// open a reader for the file at all.
    pub(crate) produces: &'static [LogSource],
}

//--------------------------------------------------------------------------------------------------
// RotationConfig
//--------------------------------------------------------------------------------------------------

/// Per-reader rotation policy. `max_index == 0` denotes a
/// non-rotating file. `max_index > 0` enables the chain walker.
struct RotationConfig {
    log_dir: PathBuf,
    filename: String,
    max_index: usize,
}

impl RotationConfig {
    fn rotates(&self) -> bool {
        self.max_index > 0
    }

    /// Resolve the on-disk path for a rotation index. `0` is the
    /// live file (bare filename), `N>0` is `<filename>.N`.
    fn path(&self, index: usize) -> PathBuf {
        if index == 0 {
            self.log_dir.join(&self.filename)
        } else {
            self.log_dir.join(format!("{}.{index}", self.filename))
        }
    }

    /// Find which rotation slot currently holds the file with the
    /// given inode generation, or `None` if it has rotated out of
    /// the retention window.
    async fn find_index(&self, wanted: u64) -> Option<usize> {
        for index in 0..=self.max_index {
            if let Some(found) = FileHandle::generation_of_path(&self.path(index)).await
                && found == wanted
            {
                return Some(index);
            }
        }
        None
    }

    /// Append every existing rotated file (`.max_index` → `.1`) to
    /// `backfill` in oldest-first order so the reader drains
    /// chronologically before reaching the live file.
    async fn queue_all_rotated(
        &self,
        backfill: &mut VecDeque<FileHandle>,
    ) -> MicrosandboxResult<()> {
        for index in (1..=self.max_index).rev() {
            if let Some(src) = FileHandle::open(&self.path(index)).await? {
                backfill.push_back(src);
            }
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// LogStreamStart
//--------------------------------------------------------------------------------------------------

/// Where a [`super::log_stream`] starts emitting from.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub enum LogStreamStart {
    /// Begin at the oldest available entry across the rotation
    /// chain. With `System` in sources, plain-text files like
    /// `runtime.log` / `kernel.log` are also drained from their
    /// start.
    #[default]
    Beginning,

    /// Begin at the first entry whose timestamp is at or after this
    /// instant.
    Since(DateTime<Utc>),

    /// Resume each source from the per-source position recorded in
    /// this cursor.
    ///
    /// Returns [`MicrosandboxError::InvalidCursor`] upfront if any
    /// rotating file's generation can no longer be located in the
    /// current rotation chain.
    From(LogCursor),
}

//--------------------------------------------------------------------------------------------------
// LogStreamOptions
//--------------------------------------------------------------------------------------------------

/// Options for [`super::log_stream`].
#[derive(Debug, Clone, Default)]
pub struct LogStreamOptions {
    /// Sources to include. If empty, defaults to
    /// `Stdout` + `Stderr` + `Output`. Include `System` to also
    /// interleave plain-text system files (and `system`-tagged
    /// JSONL entries) into the stream.
    pub sources: Vec<LogSource>,

    /// Where to begin emitting from.
    pub start: LogStreamStart,

    /// Optional upper bound on entry timestamp. The stream ends as
    /// soon as an entry with timestamp at or after this is observed
    /// (without emitting it).
    pub until: Option<DateTime<Utc>>,

    /// If `true`, the stream stays open past current EOF on each
    /// source and yields new entries as the producers append. If
    /// `false`, the stream ends once the historical content has
    /// been drained.
    pub follow: bool,
}

//--------------------------------------------------------------------------------------------------
// LogEngine
//--------------------------------------------------------------------------------------------------

/// Outcome of one engine step: keep going, end the stream cleanly,
/// or surface a terminal error to the consumer.
enum StepResult {
    Continue,
    Terminate,
    Error(MicrosandboxError),
}

/// One reader plus its most-recently-emitted [`FilePosition`]. The
/// position is folded into each entry's [`LogCursor`] so consumers
/// can resume per-source.
struct ReaderState {
    reader: Reader,
    last_position: FilePosition,
}

struct PositionedLogEntry {
    entry: LogEntry,
    reader_idx: usize,
    position: FilePosition,
}

pub(crate) struct LogEngine {
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    follow: bool,

    readers: Vec<ReaderState>,
    initial_positions: Vec<FilePosition>,
    pending: VecDeque<PositionedLogEntry>,

    _watcher: Option<notify::RecommendedWatcher>,
    event_rx: Option<tokio::sync::mpsc::UnboundedReceiver<()>>,

    finished: bool,
}

impl LogEngine {
    /// Open one reader per [`LogFileConfig`] whose `produces` set
    /// intersects `sources`. When `follow` is true, also subscribe
    /// to filesystem change events on `log_dir` so [`step`] can wake
    /// promptly on new writes.
    pub(crate) async fn new(
        log_dir: PathBuf,
        log_files: &'static [LogFileConfig],
        sources: Vec<LogSource>,
        start: &LogStreamStart,
        until: Option<DateTime<Utc>>,
        follow: bool,
    ) -> MicrosandboxResult<Self> {
        let since = match start {
            LogStreamStart::Since(t) => Some(*t),
            _ => None,
        };

        let selected: Vec<&LogFileConfig> = log_files
            .iter()
            .filter(|c| c.produces.iter().any(|s| sources.contains(s)))
            .collect();

        let mut readers = Vec::with_capacity(selected.len());
        let mut initial_positions = Vec::with_capacity(selected.len());
        for (idx, config) in selected.iter().enumerate() {
            let initial_position = match start {
                LogStreamStart::From(c) => c.positions.get(idx).copied().unwrap_or_default(),
                _ => FilePosition::default(),
            };
            let reader = Reader::open(config, &log_dir, &sources, start, initial_position).await?;
            initial_positions.push(initial_position);
            readers.push(ReaderState {
                reader,
                last_position: initial_position,
            });
        }

        let (watcher, event_rx) = if follow {
            let (w, rx) = Self::build_watcher(&log_dir)?;
            (Some(w), Some(rx))
        } else {
            (None, None)
        };

        Ok(Self {
            since,
            until,
            follow,
            readers,
            initial_positions,
            pending: VecDeque::new(),
            _watcher: watcher,
            event_rx,
            finished: false,
        })
    }

    /// Snapshot the watermark across every active source as a
    /// [`LogCursor`]. Called per emitted entry so the cursor on
    /// that entry reflects the complete cross-source state at emit
    /// time.
    fn snapshot_cursor(&self) -> LogCursor {
        LogCursor {
            positions: self.readers.iter().map(|r| r.last_position).collect(),
        }
    }

    pub(crate) async fn drain_sorted_snapshot(
        mut self,
    ) -> MicrosandboxResult<(Vec<LogEntry>, LogCursor)> {
        let mut entries = Vec::new();
        loop {
            while let Some(entry) = self.pending.pop_front() {
                entries.push(entry);
            }
            if self.finished {
                break;
            }
            match self.step().await {
                StepResult::Continue => continue,
                StepResult::Terminate => break,
                StepResult::Error(e) => return Err(e),
            }
        }
        let end_cursor = self.snapshot_cursor();
        entries.sort_by_key(|e| e.entry.timestamp);

        let mut positions = self.initial_positions.clone();
        for entry in &mut entries {
            positions[entry.reader_idx] = entry.position;
            entry.entry.cursor = LogCursor {
                positions: positions.clone(),
            };
        }

        Ok((entries.into_iter().map(|e| e.entry).collect(), end_cursor))
    }

    /// Drive every reader once: parse any newly-available entries,
    /// stamp them with a fresh cursor, and queue them in `pending`.
    /// If nothing parsed and `follow` is on, await a filesystem
    /// event (or a poll fallback) before signaling `Continue`.
    async fn step(&mut self) -> StepResult {
        let mut any_progress = false;

        for idx in 0..self.readers.len() {
            let since = self.since;
            let parsed = match self.readers[idx].reader.read_chunk(since).await {
                Ok(p) => p,
                Err(e) => return StepResult::Error(e),
            };
            if parsed.position.is_some() || !parsed.entries.is_empty() {
                any_progress = true;
            }
            for (mut entry, position) in parsed.entries {
                self.readers[idx].last_position = position;
                entry.cursor = self.snapshot_cursor();
                self.pending.push_back(PositionedLogEntry {
                    entry,
                    reader_idx: idx,
                    position,
                });
            }
            if let Some(position) = parsed.position {
                self.readers[idx].last_position = position;
            }
        }

        if any_progress {
            return StepResult::Continue;
        }

        if !self.follow {
            return StepResult::Terminate;
        }

        let Some(rx) = self.event_rx.as_mut() else {
            return StepResult::Terminate;
        };
        tokio::select! {
            _ = rx.recv() => StepResult::Continue,
            _ = tokio::time::sleep(FALLBACK_POLL_INTERVAL) => StepResult::Continue,
        }
    }

    /// Wire up a non-recursive [`notify`] watcher on `log_dir` and
    /// return its event receiver. The watcher's callback runs on a
    /// background thread; we forward only the wake signal so the
    /// async [`step`] loop can park efficiently between writes.
    fn build_watcher(
        log_dir: &Path,
    ) -> MicrosandboxResult<(
        notify::RecommendedWatcher,
        tokio::sync::mpsc::UnboundedReceiver<()>,
    )> {
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let tx = Arc::new(tx);
        let tx_clone = Arc::clone(&tx);
        let mut watcher = notify::recommended_watcher(move |res: notify::Result<notify::Event>| {
            if let Ok(event) = res {
                use notify::EventKind;
                if matches!(
                    event.kind,
                    EventKind::Modify(_) | EventKind::Create(_) | EventKind::Remove(_)
                ) {
                    let _ = tx_clone.send(());
                }
            }
        })
        .map_err(|e| MicrosandboxError::Custom(format!("log watcher init failed: {e}")))?;

        watcher
            .watch(log_dir, notify::RecursiveMode::NonRecursive)
            .map_err(|e| MicrosandboxError::Custom(format!("log watcher subscribe failed: {e}")))?;

        Ok((watcher, rx))
    }

    /// Consume the engine and yield its entries as a [`futures::Stream`].
    /// Drains `pending` first, then drives [`step`] until termination;
    /// on error the stream yields one `Err` and ends.
    pub(crate) fn into_stream(
        self,
    ) -> impl Stream<Item = MicrosandboxResult<LogEntry>> + Send + 'static + use<> {
        stream::unfold(self, |mut state| async move {
            loop {
                if let Some(positioned) = state.pending.pop_front() {
                    if let Some(until) = state.until
                        && positioned.entry.timestamp >= until
                    {
                        return None;
                    }
                    return Some((Ok(positioned.entry), state));
                }
                if state.finished {
                    return None;
                }
                match state.step().await {
                    StepResult::Continue => continue,
                    StepResult::Terminate => return None,
                    StepResult::Error(e) => {
                        state.finished = true;
                        return Some((Err(e), state));
                    }
                }
            }
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Reader
//--------------------------------------------------------------------------------------------------

struct Reader {
    primary_path: PathBuf,
    parser: ParserKind,
    rotation: RotationConfig,
    backfill: VecDeque<FileHandle>,
    live: Option<FileHandle>,
    initial_live_offset: u64,
}

impl Reader {
    /// Prepare a reader for one log file. For rotating files we
    /// pre-queue the rotated siblings (oldest-first) when starting
    /// from `Beginning`, or walk the rotation chain to locate the
    /// cursor's generation when resuming from a [`LogCursor`].
    async fn open(
        config: &LogFileConfig,
        log_dir: &Path,
        sources: &[LogSource],
        start: &LogStreamStart,
        initial_position: FilePosition,
    ) -> MicrosandboxResult<Self> {
        let rotation = RotationConfig {
            log_dir: log_dir.to_path_buf(),
            filename: config.filename.to_string(),
            max_index: config.max_rotation_index,
        };
        let primary_path = rotation.path(0);
        let parser = match config.format {
            LogFileFormat::Jsonl => ParserKind::Jsonl {
                sources: sources.to_vec(),
            },
            LogFileFormat::Text => ParserKind::Text,
        };

        let mut backfill = VecDeque::new();
        let mut initial_live_offset = 0u64;

        if rotation.rotates() {
            let resuming_from_cursor = matches!(start, LogStreamStart::From(_))
                && initial_position != FilePosition::default();
            if resuming_from_cursor {
                let Some(index) = rotation.find_index(initial_position.generation).await else {
                    return Err(MicrosandboxError::InvalidCursor(format!(
                        "{} generation {} is not in the current rotation chain",
                        config.filename, initial_position.generation
                    )));
                };
                if index == 0 {
                    initial_live_offset = initial_position.offset;
                } else {
                    if let Some(mut src) = FileHandle::open(&rotation.path(index)).await? {
                        src.offset = initial_position.offset;
                        backfill.push_back(src);
                    }
                    for i in (1..index).rev() {
                        if let Some(src) = FileHandle::open(&rotation.path(i)).await? {
                            backfill.push_back(src);
                        }
                    }
                }
            } else {
                rotation.queue_all_rotated(&mut backfill).await?;
            }
        } else {
            initial_live_offset = initial_position.offset;
        }

        Ok(Self {
            primary_path,
            parser,
            rotation,
            backfill,
            live: None,
            initial_live_offset,
        })
    }

    /// Read whatever's available now: drain any queued rotated
    /// files first, then read from the live file, then check for
    /// rotation and reseat the live FD if the inode changed.
    /// Returns an empty `Vec` when nothing new is on disk yet.
    async fn read_chunk(
        &mut self,
        since: Option<DateTime<Utc>>,
    ) -> MicrosandboxResult<ParsedChunk> {
        while let Some(src) = self.backfill.front_mut() {
            let chunk = self
                .parser
                .parse_from(src, &self.primary_path, since)
                .await?;
            if chunk.position.is_some() || !chunk.entries.is_empty() {
                return Ok(chunk);
            }
            self.backfill.pop_front();
        }

        if self.live.is_none() {
            let Some(mut src) = FileHandle::open(&self.primary_path).await? else {
                return Ok(ParsedChunk {
                    entries: Vec::new(),
                    position: None,
                });
            };
            src.offset = self.initial_live_offset;
            self.live = Some(src);
        }

        let live = self.live.as_mut().unwrap();
        let chunk = self
            .parser
            .parse_from(live, &self.primary_path, since)
            .await?;
        if chunk.position.is_some() || !chunk.entries.is_empty() {
            return Ok(chunk);
        }

        let current_inode = match FileHandle::generation_of_path(&self.primary_path).await {
            Some(g) => g,
            None => {
                return Ok(ParsedChunk {
                    entries: Vec::new(),
                    position: None,
                });
            }
        };
        if current_inode == live.inode {
            return Ok(ParsedChunk {
                entries: Vec::new(),
                position: None,
            });
        }

        if self.rotation.rotates() {
            self.handle_rotation().await
        } else {
            self.replace_live().await
        }
    }

    /// Live inode changed: locate where the formerly-live file
    /// rotated to, queue any intermediate files that appeared
    /// (rotated past in between reads), and open the new live FD.
    /// Returns [`MicrosandboxError::MissedRotation`] when the file
    /// has rotated past the retention window.
    async fn handle_rotation(&mut self) -> MicrosandboxResult<ParsedChunk> {
        let live = self
            .live
            .as_ref()
            .expect("handle_rotation called with no live");
        let live_inode = live.inode;
        let live_offset = live.offset;
        let Some(rotation_index) = self.rotation.find_index(live_inode).await else {
            return Err(MicrosandboxError::MissedRotation {
                dropped_from_offset: live_offset,
            });
        };
        let mut newly_queued: Vec<FileHandle> = Vec::new();
        for i in (1..rotation_index).rev() {
            if let Some(src) = FileHandle::open(&self.rotation.path(i)).await? {
                newly_queued.push(src);
            }
        }
        for src in newly_queued {
            self.backfill.push_back(src);
        }
        if let Some(new_live) = FileHandle::open(&self.primary_path).await? {
            self.live = Some(new_live);
        }
        Ok(ParsedChunk {
            entries: Vec::new(),
            position: None,
        })
    }

    /// Non-rotating file's inode changed (e.g. truncate + rewrite):
    /// reopen the live FD against the new inode. Any data on the
    /// previous inode that wasn't read is lost by design — this
    /// case is reserved for files that don't promise retention.
    async fn replace_live(&mut self) -> MicrosandboxResult<ParsedChunk> {
        if let Some(src) = FileHandle::open(&self.primary_path).await? {
            self.live = Some(src);
        }
        Ok(ParsedChunk {
            entries: Vec::new(),
            position: None,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use futures::StreamExt;

    const LOG_FILES: &[LogFileConfig] = &[
        LogFileConfig {
            filename: "exec.log",
            format: LogFileFormat::Jsonl,
            max_rotation_index: 4,
            produces: &[
                LogSource::Stdout,
                LogSource::Stderr,
                LogSource::Output,
                LogSource::System,
            ],
        },
        LogFileConfig {
            filename: "runtime.log",
            format: LogFileFormat::Text,
            max_rotation_index: 0,
            produces: &[LogSource::System],
        },
        LogFileConfig {
            filename: "kernel.log",
            format: LogFileFormat::Text,
            max_rotation_index: 0,
            produces: &[LogSource::System],
        },
    ];

    fn make_jsonl_line(ts: &str, source: &str, data: &str, id: Option<u64>) -> String {
        match id {
            Some(id) => format!(r#"{{"t":"{ts}","s":"{source}","d":"{data}","id":{id}}}"#),
            None => format!(r#"{{"t":"{ts}","s":"{source}","d":"{data}"}}"#),
        }
    }

    fn write_lines(path: &Path, lines: &[String]) {
        let mut blob = String::new();
        for l in lines {
            blob.push_str(l);
            blob.push('\n');
        }
        std::fs::write(path, blob).unwrap();
    }

    fn make_dir_with_exec(lines: &[String]) -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        write_lines(&dir.path().join("exec.log"), lines);
        dir
    }

    async fn make_state(
        log_dir: PathBuf,
        opts: &LogStreamOptions,
    ) -> MicrosandboxResult<LogEngine> {
        let sources = LogSource::effective(&opts.sources);
        LogEngine::new(
            log_dir,
            LOG_FILES,
            sources,
            &opts.start,
            opts.until,
            opts.follow,
        )
        .await
    }

    async fn collect_with_timeout<S>(
        stream: S,
        timeout: Duration,
    ) -> Vec<MicrosandboxResult<LogEntry>>
    where
        S: Stream<Item = MicrosandboxResult<LogEntry>> + Unpin,
    {
        let mut out = Vec::new();
        let mut s = stream;
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            let now = tokio::time::Instant::now();
            if now >= deadline {
                break;
            }
            let remaining = deadline - now;
            match tokio::time::timeout(remaining, s.next()).await {
                Ok(Some(item)) => out.push(item),
                Ok(None) => break,
                Err(_) => break,
            }
        }
        out
    }

    #[tokio::test]
    async fn backfill_without_follow_drains_and_ends() {
        let lines = vec![
            make_jsonl_line("2026-04-30T20:32:59.000Z", "stdout", "a", Some(1)),
            make_jsonl_line("2026-04-30T20:33:00.000Z", "stdout", "b", Some(1)),
        ];
        let dir = make_dir_with_exec(&lines);
        let state = make_state(
            dir.path().to_path_buf(),
            &LogStreamOptions {
                follow: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let items =
            collect_with_timeout(Box::pin(state.into_stream()), Duration::from_secs(2)).await;
        assert_eq!(items.len(), 2);
        let entries: Vec<_> = items.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(entries[0].data, Bytes::from("a".as_bytes()));
        assert_eq!(entries[1].data, Bytes::from("b".as_bytes()));
        assert!(entries[1].cursor.positions[0].offset > entries[0].cursor.positions[0].offset);
    }

    #[tokio::test]
    async fn follow_picks_up_new_appends() {
        let initial = vec![make_jsonl_line(
            "2026-04-30T20:32:59.000Z",
            "stdout",
            "first",
            Some(1),
        )];
        let dir = make_dir_with_exec(&initial);
        let path = dir.path().to_path_buf();
        let state = make_state(
            path.clone(),
            &LogStreamOptions {
                follow: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let stream = state.into_stream();
        tokio::pin!(stream);

        let first = tokio::time::timeout(Duration::from_secs(3), stream.next())
            .await
            .expect("first entry within 3s")
            .expect("stream not ended")
            .expect("not an error");
        assert_eq!(first.data, Bytes::from("first".as_bytes()));

        let mut blob = String::new();
        for l in &initial {
            blob.push_str(l);
            blob.push('\n');
        }
        blob.push_str(&make_jsonl_line(
            "2026-04-30T20:33:00.000Z",
            "stdout",
            "second",
            Some(1),
        ));
        blob.push('\n');
        std::fs::write(path.join("exec.log"), blob).unwrap();

        let second = tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await
            .expect("second entry within 5s")
            .expect("stream not ended")
            .expect("not an error");
        assert_eq!(second.data, Bytes::from("second".as_bytes()));
    }

    #[tokio::test]
    async fn resume_from_cursor_starts_after_that_entry() {
        let lines = vec![
            make_jsonl_line("2026-04-30T20:32:59.000Z", "stdout", "a", Some(1)),
            make_jsonl_line("2026-04-30T20:33:00.000Z", "stdout", "b", Some(1)),
            make_jsonl_line("2026-04-30T20:33:01.000Z", "stdout", "c", Some(1)),
        ];
        let dir = make_dir_with_exec(&lines);
        let state = make_state(dir.path().to_path_buf(), &LogStreamOptions::default())
            .await
            .unwrap();
        let items =
            collect_with_timeout(Box::pin(state.into_stream()), Duration::from_secs(2)).await;
        let entries: Vec<_> = items.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(entries.len(), 3);
        let cursor_after_b = entries[1].cursor.clone();

        let state2 = make_state(
            dir.path().to_path_buf(),
            &LogStreamOptions {
                start: LogStreamStart::From(cursor_after_b),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let items2 =
            collect_with_timeout(Box::pin(state2.into_stream()), Duration::from_secs(2)).await;
        let entries2: Vec<_> = items2.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(entries2.len(), 1);
        assert_eq!(entries2[0].data, Bytes::from("c".as_bytes()));
    }

    #[tokio::test]
    async fn invalid_cursor_yields_error_upfront() {
        let dir = make_dir_with_exec(&[make_jsonl_line(
            "2026-04-30T20:32:59.000Z",
            "stdout",
            "a",
            Some(1),
        )]);
        let bogus = LogCursor {
            positions: vec![FilePosition {
                generation: 0xffff_ffff_ffff_ffff,
                offset: 0,
            }],
        };
        let result = make_state(
            dir.path().to_path_buf(),
            &LogStreamOptions {
                start: LogStreamStart::From(bogus),
                ..Default::default()
            },
        )
        .await;
        match result {
            Err(MicrosandboxError::InvalidCursor(_)) => {}
            Err(other) => panic!("expected InvalidCursor, got: {other:?}"),
            Ok(_) => panic!("expected InvalidCursor, got Ok state"),
        }
    }

    #[tokio::test]
    async fn drains_rotated_files_in_chronological_order() {
        let dir = tempfile::tempdir().unwrap();
        write_lines(
            &dir.path().join("exec.log.1"),
            &[make_jsonl_line(
                "2026-04-30T20:30:00.000Z",
                "stdout",
                "old",
                Some(1),
            )],
        );
        write_lines(
            &dir.path().join("exec.log"),
            &[make_jsonl_line(
                "2026-04-30T20:33:00.000Z",
                "stdout",
                "new",
                Some(1),
            )],
        );
        let state = make_state(dir.path().to_path_buf(), &LogStreamOptions::default())
            .await
            .unwrap();
        let items =
            collect_with_timeout(Box::pin(state.into_stream()), Duration::from_secs(2)).await;
        let entries: Vec<_> = items.into_iter().map(|r| r.unwrap()).collect();
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].data, Bytes::from("old".as_bytes()));
        assert_eq!(entries[1].data, Bytes::from("new".as_bytes()));
    }

    #[tokio::test]
    async fn includes_runtime_log_when_system_requested() {
        let dir = tempfile::tempdir().unwrap();
        write_lines(
            &dir.path().join("exec.log"),
            &[make_jsonl_line(
                "2026-04-30T20:33:00.000Z",
                "stdout",
                "user-output",
                Some(1),
            )],
        );
        write_lines(
            &dir.path().join("runtime.log"),
            &["2026-04-30T20:30:00.000Z  INFO starting up".to_string()],
        );
        let state = make_state(
            dir.path().to_path_buf(),
            &LogStreamOptions {
                sources: vec![LogSource::Stdout, LogSource::System],
                follow: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        let items =
            collect_with_timeout(Box::pin(state.into_stream()), Duration::from_secs(2)).await;
        let entries: Vec<_> = items.into_iter().map(|r| r.unwrap()).collect();
        assert!(
            entries
                .iter()
                .any(|e| e.data == Bytes::from("user-output".as_bytes())),
            "missing user-output entry: {entries:?}"
        );
        assert!(
            entries.iter().any(|e| e.source == LogSource::System
                && std::str::from_utf8(&e.data)
                    .unwrap_or("")
                    .contains("starting up")),
            "missing runtime.log system entry: {entries:?}"
        );
    }
}
