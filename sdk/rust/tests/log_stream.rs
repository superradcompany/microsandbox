//! Integration tests for the public `log_stream` / `read_logs` API.
//!
//! Drives the full caller path —
//! `microsandbox::logs::log_stream(name, opts)` — against
//! a synthetic on-disk log directory. No real microVM is booted;
//! we set `MSB_HOME` to a tempdir, lay out `sandboxes/<name>/logs/`
//! with hand-crafted `exec.log` / `runtime.log` / `kernel.log`,
//! and verify the streamed entries.
//!
//! Each test uses a unique sandbox name so they can run in
//! parallel under the shared `MSB_HOME`.
//!
//! These tests don't require any external infrastructure
//! (libkrunfw, kernel image, etc.) — they're pure I/O exercises
//! against the streaming engine through its public entry points.

use std::path::PathBuf;
use std::sync::OnceLock;

use futures::TryStreamExt;
use microsandbox::logs;
use microsandbox::logs::{LogCursor, LogOptions, LogSource, LogStreamOptions, LogStreamStart};
use tempfile::TempDir;

/// Singleton MSB_HOME for the whole test binary. We set it once
/// before any code touches the global config; tests share the root
/// and use distinct sandbox names so they don't collide.
static MSB_HOME: OnceLock<TempDir> = OnceLock::new();

fn msb_home() -> &'static TempDir {
    MSB_HOME.get_or_init(|| {
        let dir = tempfile::Builder::new()
            .prefix("msb-log-stream-test-")
            .tempdir()
            .expect("failed to create MSB_HOME tempdir");
        // SAFETY: integration test setup; runs before any other
        // code in this binary reads the env.
        unsafe {
            std::env::set_var("MSB_HOME", dir.path());
        }
        dir
    })
}

/// Create the log directory layout for a fresh sandbox name and
/// return its path.
fn make_log_dir(name: &str) -> PathBuf {
    let root = msb_home().path();
    let log_dir = root.join("sandboxes").join(name).join("logs");
    std::fs::create_dir_all(&log_dir).expect("create log dir");
    log_dir
}

fn jsonl(ts: &str, source: &str, data: &str, id: u64) -> String {
    format!(r#"{{"t":"{ts}","s":"{source}","d":"{data}","id":{id}}}"#)
}

fn ts(s: &str) -> chrono::DateTime<chrono::Utc> {
    chrono::DateTime::parse_from_rfc3339(s)
        .unwrap()
        .with_timezone(&chrono::Utc)
}

fn write_lines(path: &std::path::Path, lines: &[String]) {
    let mut blob = String::new();
    for l in lines {
        blob.push_str(l);
        blob.push('\n');
    }
    std::fs::write(path, blob).expect("write log file");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn log_stream_drains_exec_log_with_default_sources() {
    let name = "log-stream-default-sources";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[
            jsonl("2026-05-01T10:00:00.000Z", "stdout", "first line", 1),
            jsonl("2026-05-01T10:00:01.000Z", "stderr", "warning", 1),
            jsonl("2026-05-01T10:00:02.000Z", "output", "pty out", 1),
        ],
    );

    let stream = logs::log_stream(name, &LogStreamOptions::default())
        .await
        .expect("open stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain stream");

    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].source, LogSource::Stdout);
    assert_eq!(entries[0].data.as_ref(), b"first line");
    assert_eq!(entries[1].source, LogSource::Stderr);
    assert_eq!(entries[2].source, LogSource::Output);
}

#[tokio::test]
async fn log_stream_includes_system_files_when_requested() {
    let name = "log-stream-system-sources";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl(
            "2026-05-01T10:00:00.000Z",
            "stdout",
            "user output",
            1,
        )],
    );
    write_lines(
        &log_dir.join("runtime.log"),
        &["2026-05-01T09:59:00.000Z INFO runtime started".to_string()],
    );
    write_lines(
        &log_dir.join("kernel.log"),
        &["2026-05-01T09:58:00.000Z kernel boot complete".to_string()],
    );

    let stream = logs::log_stream(
        name,
        &LogStreamOptions {
            sources: vec![LogSource::Stdout, LogSource::System],
            follow: false,
            ..Default::default()
        },
    )
    .await
    .expect("open stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain stream");

    // Should see the exec stdout entry and both system entries.
    let has_user = entries
        .iter()
        .any(|e| e.source == LogSource::Stdout && e.data.as_ref() == b"user output");
    let has_runtime = entries.iter().any(|e| {
        e.source == LogSource::System
            && std::str::from_utf8(&e.data)
                .unwrap_or("")
                .contains("runtime started")
    });
    let has_kernel = entries.iter().any(|e| {
        e.source == LogSource::System
            && std::str::from_utf8(&e.data)
                .unwrap_or("")
                .contains("kernel boot complete")
    });
    assert!(has_user, "missing user stdout entry: {entries:?}");
    assert!(has_runtime, "missing runtime.log entry: {entries:?}");
    assert!(has_kernel, "missing kernel.log entry: {entries:?}");
}

#[tokio::test]
async fn log_stream_includes_rotated_exec_files() {
    let name = "log-stream-rotated";
    let log_dir = make_log_dir(name);
    // Older entry in a rotated file, newer in the active file.
    write_lines(
        &log_dir.join("exec.log.1"),
        &[jsonl(
            "2026-05-01T08:00:00.000Z",
            "stdout",
            "from rotated",
            1,
        )],
    );
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl(
            "2026-05-01T09:00:00.000Z",
            "stdout",
            "from active",
            1,
        )],
    );

    let stream = logs::log_stream(name, &LogStreamOptions::default())
        .await
        .expect("open stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain stream");

    assert_eq!(entries.len(), 2);
    // Per-source order: rotated file drained first, then active.
    assert_eq!(entries[0].data.as_ref(), b"from rotated");
    assert_eq!(entries[1].data.as_ref(), b"from active");
}

#[tokio::test]
async fn log_stream_resume_from_cursor_continues_after_seen_entries() {
    let name = "log-stream-resume";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[
            jsonl("2026-05-01T10:00:00.000Z", "stdout", "a", 1),
            jsonl("2026-05-01T10:00:01.000Z", "stdout", "b", 1),
            jsonl("2026-05-01T10:00:02.000Z", "stdout", "c", 1),
        ],
    );

    // First pass: drain everything to grab a cursor.
    let stream = logs::log_stream(name, &LogStreamOptions::default())
        .await
        .expect("first stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain first stream");
    assert_eq!(entries.len(), 3);
    let cursor_after_b = entries[1].cursor.clone();

    // Second pass: resume from cursor; should yield only "c".
    let stream2 = logs::log_stream(
        name,
        &LogStreamOptions {
            start: LogStreamStart::From(cursor_after_b),
            ..Default::default()
        },
    )
    .await
    .expect("resume stream");
    let entries2: Vec<_> = stream2.try_collect().await.expect("drain resumed stream");
    assert_eq!(entries2.len(), 1);
    assert_eq!(entries2[0].data.as_ref(), b"c");
}

#[tokio::test]
async fn log_stream_cursor_serializes_and_round_trips() {
    let name = "log-stream-cursor-rt";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl("2026-05-01T10:00:00.000Z", "stdout", "x", 1)],
    );

    let stream = logs::log_stream(name, &LogStreamOptions::default())
        .await
        .expect("open stream");
    let entries: Vec<_> = stream.try_collect().await.expect("drain");
    assert_eq!(entries.len(), 1);

    // Cursor round-trips through string form.
    let cursor_str = entries[0].cursor.to_string();
    let parsed: LogCursor = cursor_str.parse().expect("cursor parses");
    assert_eq!(parsed, entries[0].cursor);
}

#[tokio::test]
async fn log_stream_follow_picks_up_appended_entries() {
    let name = "log-stream-follow";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl("2026-05-01T10:00:00.000Z", "stdout", "first", 1)],
    );

    let stream = logs::log_stream(
        name,
        &LogStreamOptions {
            follow: true,
            ..Default::default()
        },
    )
    .await
    .expect("open follow stream");
    let mut stream = Box::pin(stream);
    use futures::StreamExt;

    // First entry from backfill.
    let first = tokio::time::timeout(std::time::Duration::from_secs(3), stream.next())
        .await
        .expect("first entry within 3s")
        .expect("stream not ended")
        .expect("not an error");
    assert_eq!(first.data.as_ref(), b"first");

    // Append a new entry.
    write_lines(
        &log_dir.join("exec.log"),
        &[
            jsonl("2026-05-01T10:00:00.000Z", "stdout", "first", 1),
            jsonl("2026-05-01T10:00:01.000Z", "stdout", "second", 1),
        ],
    );

    let second = tokio::time::timeout(std::time::Duration::from_secs(5), stream.next())
        .await
        .expect("second entry within 5s")
        .expect("stream not ended")
        .expect("not an error");
    assert_eq!(second.data.as_ref(), b"second");
}

#[tokio::test]
async fn read_logs_returns_sorted_snapshot() {
    let name = "read-logs-sorted";
    let log_dir = make_log_dir(name);
    // Put runtime.log (older) and exec.log (newer) — read_logs
    // should sort the merged result chronologically.
    write_lines(
        &log_dir.join("runtime.log"),
        &["2026-05-01T08:00:00.000Z INFO early runtime".to_string()],
    );
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl(
            "2026-05-01T09:00:00.000Z",
            "stdout",
            "late stdout",
            1,
        )],
    );

    let entries = logs::read_logs(
        name,
        &LogOptions {
            sources: vec![LogSource::Stdout, LogSource::System],
            ..Default::default()
        },
    )
    .await
    .expect("snapshot read");

    // Chronological order: runtime (08:00) before exec stdout (09:00).
    assert!(
        entries.len() >= 2,
        "expected at least 2 entries: {entries:?}"
    );
    assert!(
        std::str::from_utf8(&entries[0].data)
            .unwrap_or("")
            .contains("early runtime"),
        "expected runtime entry first: {entries:?}",
    );
    assert!(
        entries[entries.len() - 1].data.as_ref() == b"late stdout",
        "expected stdout entry last: {entries:?}",
    );
}

#[tokio::test]
async fn read_logs_sorted_cursor_resumes_after_selected_entry() {
    let name = "read-logs-sorted-cursor-resume";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[
            jsonl("2026-05-01T10:00:00.000Z", "stdout", "a", 1),
            jsonl("2026-05-01T10:02:00.000Z", "stdout", "c", 1),
        ],
    );
    write_lines(
        &log_dir.join("runtime.log"),
        &["2026-05-01T10:01:00.000Z INFO b".to_string()],
    );

    let entries = logs::read_logs(
        name,
        &LogOptions {
            sources: vec![LogSource::Stdout, LogSource::System],
            ..Default::default()
        },
    )
    .await
    .expect("snapshot read");

    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].data.as_ref(), b"a");
    assert!(
        std::str::from_utf8(&entries[1].data)
            .unwrap()
            .contains("INFO b")
    );
    assert_eq!(entries[2].data.as_ref(), b"c");

    let stream = logs::log_stream(
        name,
        &LogStreamOptions {
            sources: vec![LogSource::Stdout, LogSource::System],
            start: LogStreamStart::From(entries[1].cursor.clone()),
            follow: false,
            ..Default::default()
        },
    )
    .await
    .expect("resume stream");
    let resumed: Vec<_> = stream.try_collect().await.expect("drain resumed stream");

    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].data.as_ref(), b"c");
}

#[tokio::test]
async fn read_logs_snapshot_cursor_advances_past_since_filtered_entries() {
    let name = "read-logs-snapshot-cursor-since-filter";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl("2026-05-01T10:00:00.000Z", "stdout", "old", 1)],
    );

    let snapshot = logs::read_logs_snapshot(
        name,
        &LogOptions {
            since: Some(ts("2026-05-01T10:01:00.000Z")),
            ..Default::default()
        },
    )
    .await
    .expect("snapshot read");

    assert!(snapshot.entries.is_empty());

    let stream = logs::log_stream(
        name,
        &LogStreamOptions {
            start: LogStreamStart::From(snapshot.cursor),
            follow: false,
            ..Default::default()
        },
    )
    .await
    .expect("resume stream");
    let resumed: Vec<_> = stream.try_collect().await.expect("drain resumed stream");

    assert!(
        resumed.is_empty(),
        "since-filtered entries replayed after snapshot cursor: {resumed:?}"
    );
}

#[tokio::test]
async fn log_stream_invalid_cursor_returns_error_upfront() {
    let name = "log-stream-invalid-cursor";
    let log_dir = make_log_dir(name);
    write_lines(
        &log_dir.join("exec.log"),
        &[jsonl("2026-05-01T10:00:00.000Z", "stdout", "a", 1)],
    );

    // Craft a cursor pointing at a non-existent exec.log generation.
    // We get a valid cursor first, then mangle the string. Simpler:
    // use a cursor from a different sandbox name.
    let other = "log-stream-invalid-cursor-other";
    let other_dir = make_log_dir(other);
    write_lines(
        &other_dir.join("exec.log"),
        &[jsonl("2026-05-01T10:00:00.000Z", "stdout", "x", 1)],
    );
    let other_stream = logs::log_stream(other, &LogStreamOptions::default())
        .await
        .expect("open other stream");
    let other_entries: Vec<_> = other_stream
        .try_collect()
        .await
        .expect("drain other stream");
    let foreign_cursor = other_entries[0].cursor.clone();

    // Resume the first sandbox with the other sandbox's cursor.
    // The exec generation won't match, so InvalidCursor fires.
    let result = logs::log_stream(
        name,
        &LogStreamOptions {
            start: LogStreamStart::From(foreign_cursor),
            ..Default::default()
        },
    )
    .await;
    assert!(
        matches!(
            result,
            Err(microsandbox::MicrosandboxError::InvalidCursor(_))
        ),
        "expected InvalidCursor, got: {:?}",
        result.as_ref().err(),
    );
}
