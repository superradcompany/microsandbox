//! `msb logs` command — read the captured output of a sandbox.
//!
//! Backed by `microsandbox::logs::read_logs` for the historical
//! snapshot and `microsandbox::logs::log_stream` for `--follow`. Both
//! read `<sandbox-dir>/logs/exec.log` (the JSON Lines file produced by
//! the runtime's relay tap, see `crates/runtime/lib/exec_log.rs`),
//! plus `runtime.log` and `kernel.log` when `--source system` is in
//! scope. This command decodes each entry and renders it to the
//! terminal per `design/runtime/sandbox-logs.md` D5.
//!
//! Supports filtering by source (stdout/stderr/system), time window,
//! tail count, regex search, follow mode (filesystem-watch driven),
//! and JSON-Lines passthrough. ANSI escape sequences are passed
//! through to TTYs and stripped on pipes by default (matching
//! `ls`/`grep` convention).

use std::io::{IsTerminal, Write};
use std::path::Path;
use std::pin::pin;
use std::time::Duration;

use anyhow::{Context, anyhow};
use base64::Engine as _;
use chrono::{DateTime, SecondsFormat, Utc};
use clap::{Args, ValueEnum};
use console::style;
use futures::StreamExt;
use microsandbox::MicrosandboxError;
use microsandbox::logs::{
    self, LogEntry as EngineLogEntry, LogOptions, LogSource, LogStreamOptions, LogStreamStart,
};
use microsandbox_runtime::boot_error::BootError;
use microsandbox_utils::log_text::{base64_decode, strip_ansi};
use regex::Regex;
use serde::Deserialize;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Show the captured output of a sandbox.
#[derive(Debug, Args)]
pub struct LogsArgs {
    /// Sandbox to read logs from.
    pub name: String,

    /// Show only the last N entries.
    #[arg(long)]
    pub tail: Option<usize>,

    /// Show only entries at or after this point. Accepts an RFC 3339
    /// timestamp or a relative duration like `5m`, `2h`, `1d`.
    #[arg(long)]
    pub since: Option<String>,

    /// Show only entries strictly before this point. Same accepted
    /// formats as `--since`.
    #[arg(long)]
    pub until: Option<String>,

    /// Follow the log: keep reading new entries as they are written.
    /// Exits cleanly when the sandbox stops or on Ctrl-C.
    #[arg(short = 'f', long)]
    pub follow: bool,

    /// Prefix each line with the entry's timestamp.
    #[arg(long)]
    pub timestamps: bool,

    /// Sources to include. Repeat or comma-separate to include
    /// multiple. Defaults to `stdout,stderr` (the captured
    /// user-program output).
    #[arg(long, value_enum, value_delimiter = ',')]
    pub source: Vec<SourceFilter>,

    /// Filter entries to those whose body matches this regex.
    #[arg(long)]
    pub grep: Option<String>,

    /// Emit JSON Lines to stdout without decoding (one entry per line).
    #[arg(long)]
    pub json: bool,

    /// ANSI color handling.
    #[arg(long, value_enum, default_value = "auto")]
    pub color: ColorMode,

    /// Alias for `--color=never`.
    #[arg(long, conflicts_with = "color")]
    pub no_color: bool,

    /// Prefix each line with the session id `[id:N]`. Useful when
    /// the same sandbox has many concurrent or sequential exec
    /// sessions and you want to tell them apart.
    #[arg(long)]
    pub show_id: bool,

    /// Color each session's output a distinct color (cycles through
    /// 8 ANSI colors deterministically by session id). Implies
    /// `--show-id`. Honors `--color`/`--no-color`/`NO_COLOR`.
    #[arg(long)]
    pub color_sessions: bool,
}

/// Source-filter selector for `--source`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum SourceFilter {
    /// Captured stdout from the primary exec session (pipe mode).
    Stdout,

    /// Captured stderr from the primary exec session (pipe mode).
    Stderr,

    /// Merged stdout+stderr from the primary session running in pty
    /// mode (pty allocation merges streams in the kernel before they
    /// leave the guest).
    Output,

    /// Synthetic system entries injected by the host writer
    /// (lifecycle markers) plus runtime/kernel diagnostics merged at
    /// read time.
    System,

    /// All sources: `stdout`, `stderr`, `output`, and `system`.
    All,
}

/// ANSI color rendering policy for `--color`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "lowercase")]
pub enum ColorMode {
    /// Pass ANSI through to TTYs, strip on pipes.
    Auto,

    /// Always pass ANSI through.
    Always,

    /// Always strip ANSI.
    Never,
}

//--------------------------------------------------------------------------------------------------
// Types: internal
//--------------------------------------------------------------------------------------------------

/// Parsed JSON Lines entry from `exec.log`.
#[derive(Debug, Deserialize)]
struct LogEntry {
    /// RFC 3339 timestamp.
    t: String,

    /// Source tag — `"stdout"`, `"stderr"`, `"output"`, or `"system"`.
    s: String,

    /// Decoded body bytes.
    d: String,

    /// Relay-monotonic session id. Present for exec-session entries,
    /// absent for `system` lifecycle markers.
    #[serde(default)]
    id: Option<u64>,

    /// Encoding override. Currently the only legal value is `"b64"`,
    /// indicating `d` is base64. Reserved for future raw-mode capture.
    #[serde(default)]
    e: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb logs` command.
pub async fn run(args: LogsArgs) -> anyhow::Result<()> {
    let log_dir = logs::log_dir_for(&args.name);
    if !log_dir.exists() {
        return Err(anyhow!(
            "no logs directory for sandbox {:?} (sandbox not found?)",
            &args.name
        ));
    }

    let mask = resolve_sources(&args.source);
    let engine_sources = mask.to_engine_sources();
    let since = parse_time_arg(args.since.as_deref())?;
    let until = parse_time_arg(args.until.as_deref())?;
    let grep_re = match args.grep.as_deref() {
        Some(pat) => Some(Regex::new(pat).context("invalid --grep regex")?),
        None => None,
    };

    let color_policy = if args.no_color || std::env::var_os("NO_COLOR").is_some() {
        ColorMode::Never
    } else {
        args.color
    };

    // Render the boot-error block first if present (Phase B's
    // boot-error.json sits next to exec.log in the same log_dir).
    render_boot_error_if_present(&log_dir, &args.name, args.json)?;

    // Snapshot: drain the chronologically-sorted history. `read_logs`
    // applies tail / since / until / source filtering; --grep is
    // applied locally so it can match against the decoded body string.
    let snapshot_opts = LogOptions {
        tail: args.tail,
        since,
        until,
        sources: engine_sources.clone(),
    };
    let snapshot = logs::read_logs_snapshot(&args.name, &snapshot_opts)
        .await
        .context("reading logs")?;
    for entry in &snapshot.entries {
        let cli_entry = engine_entry_to_cli(entry);
        if grep_matches(grep_re.as_ref(), &cli_entry.d) {
            render_entry(&cli_entry, &args, color_policy)?;
        }
    }

    if !args.follow {
        return Ok(());
    }

    // Follow: resume from the exact snapshot end cursor so entries
    // written between the snapshot drain and stream startup are not
    // skipped.
    let stream_opts = LogStreamOptions {
        sources: engine_sources,
        start: LogStreamStart::From(snapshot.cursor),
        until,
        follow: true,
    };
    let mut stream = pin!(
        logs::log_stream(&args.name, &stream_opts)
            .await
            .context("starting log stream")?
    );
    while let Some(item) = stream.next().await {
        match item {
            Ok(entry) => {
                let cli_entry = engine_entry_to_cli(&entry);
                if grep_matches(grep_re.as_ref(), &cli_entry.d) {
                    render_entry(&cli_entry, &args, color_policy)?;
                }
            }
            Err(MicrosandboxError::MissedRotation {
                dropped_from_offset,
            }) => {
                eprintln!(
                    "log follower fell behind: missed rotation at offset {dropped_from_offset}. \
                     restart `msb logs -f` to resume."
                );
                return Ok(());
            }
            Err(e) => return Err(anyhow!(e)),
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers — discovery
//--------------------------------------------------------------------------------------------------

fn resolve_sources(picked: &[SourceFilter]) -> SourceMask {
    if picked.is_empty() {
        // Default = all user-program output, regardless of pty/pipe.
        // Including `output` here means a pty session's logs aren't
        // hidden under the default filter.
        return SourceMask {
            stdout: true,
            stderr: true,
            output: true,
            system: false,
        };
    }
    let mut mask = SourceMask::default();
    for s in picked {
        match s {
            SourceFilter::Stdout => mask.stdout = true,
            SourceFilter::Stderr => mask.stderr = true,
            SourceFilter::Output => mask.output = true,
            SourceFilter::System => mask.system = true,
            SourceFilter::All => {
                mask.stdout = true;
                mask.stderr = true;
                mask.output = true;
                mask.system = true;
            }
        }
    }
    mask
}

#[derive(Debug, Clone, Copy, Default)]
struct SourceMask {
    stdout: bool,
    stderr: bool,
    output: bool,
    system: bool,
}

impl SourceMask {
    /// Translate the mask into the engine's flat source list. Order
    /// is fixed (stdout, stderr, output, system) for stable behavior.
    fn to_engine_sources(self) -> Vec<LogSource> {
        let mut out = Vec::with_capacity(4);
        if self.stdout {
            out.push(LogSource::Stdout);
        }
        if self.stderr {
            out.push(LogSource::Stderr);
        }
        if self.output {
            out.push(LogSource::Output);
        }
        if self.system {
            out.push(LogSource::System);
        }
        out
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers — boot-error block
//--------------------------------------------------------------------------------------------------

fn render_boot_error_if_present(log_dir: &Path, name: &str, json_mode: bool) -> anyhow::Result<()> {
    let boot_err = match BootError::read(log_dir) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(()),
        Err(_) => return Ok(()),
    };

    if json_mode {
        // Emit as a synthetic JSON Lines entry tagged s: "boot-error".
        // `d` is a string per the documented schema; consumers that
        // need the structured fields can `JSON.parse(d)`.
        let payload = serde_json::to_string(&boot_err).unwrap_or_default();
        let line = serde_json::json!({
            "t": boot_err.t,
            "s": "boot-error",
            "d": payload,
        });
        println!("{line}");
        return Ok(());
    }

    crate::boot_error_render::render(name, &boot_err);
    eprintln!();
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers — engine bridge
//--------------------------------------------------------------------------------------------------

/// Convert an engine entry into the CLI's local representation. The
/// engine has already decoded base64 bodies; we keep the `e: "b64"`
/// channel alive for `--json` output by re-encoding raw bytes that
/// aren't valid UTF-8, so downstream consumers can round-trip them.
fn engine_entry_to_cli(entry: &EngineLogEntry) -> LogEntry {
    let s = match entry.source {
        LogSource::Stdout => "stdout",
        LogSource::Stderr => "stderr",
        LogSource::Output => "output",
        LogSource::System => "system",
    };
    let (d, e) = match std::str::from_utf8(&entry.data) {
        Ok(text) => (text.to_string(), None),
        Err(_) => (
            base64::engine::general_purpose::STANDARD.encode(&entry.data),
            Some("b64".to_string()),
        ),
    };

    LogEntry {
        t: entry.timestamp.to_rfc3339_opts(SecondsFormat::Millis, true),
        s: s.to_string(),
        d,
        id: entry.session_id,
        e,
    }
}

fn grep_matches(re: Option<&Regex>, body: &str) -> bool {
    re.is_none_or(|r| r.is_match(body))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers — time parsing
//--------------------------------------------------------------------------------------------------

fn parse_time_arg(input: Option<&str>) -> anyhow::Result<Option<DateTime<Utc>>> {
    let Some(raw) = input else {
        return Ok(None);
    };
    // RFC 3339 first.
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Ok(Some(dt.with_timezone(&Utc)));
    }
    // Relative duration like 5m / 2h / 1d / 30s.
    let dur = parse_duration(raw).with_context(|| {
        format!("could not parse time {raw:?} (expected RFC 3339 or `5m` etc.)")
    })?;
    Ok(Some(Utc::now() - chrono::Duration::from_std(dur)?))
}

fn parse_duration(raw: &str) -> Option<Duration> {
    if raw.is_empty() {
        return None;
    }
    let (num_str, unit) = raw.split_at(raw.len() - 1);
    let n: u64 = num_str.parse().ok()?;
    let secs = match unit {
        "s" => n,
        "m" => n * 60,
        "h" => n * 60 * 60,
        "d" => n * 60 * 60 * 24,
        _ => return None,
    };
    Some(Duration::from_secs(secs))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers — rendering
//--------------------------------------------------------------------------------------------------

fn render_entry(entry: &LogEntry, args: &LogsArgs, color: ColorMode) -> anyhow::Result<()> {
    if args.json {
        // Re-emit verbatim as a single JSON Lines line. We serialize
        // from our parsed struct so that any malformed fields are
        // normalized.
        let line = serde_json::to_string(&serde_json::json!({
            "t": entry.t,
            "s": entry.s,
            "d": entry.d,
            "id": entry.id,
            "e": entry.e,
        }))?;
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        writeln!(out, "{line}")?;
        return Ok(());
    }
    render_one(entry, args, color)
}

fn render_one(entry: &LogEntry, args: &LogsArgs, color: ColorMode) -> anyhow::Result<()> {
    // Resolve the body bytes (decode base64 if e == "b64"; else use d).
    let body = decode_body(entry);
    let body = apply_color_policy(&body, color);

    // --color-sessions implies --show-id. Resolve both flags + the
    // ANSI policy into a single per-line decoration.
    let want_id_prefix = args.show_id || args.color_sessions;
    let want_session_color = args.color_sessions && color_active(color);

    let body = if want_session_color && let Some(id) = entry.id {
        wrap_in_session_color(&body, id)
    } else {
        body
    };

    let id_prefix = if want_id_prefix {
        Some(format_id_prefix(entry.id, want_session_color))
    } else {
        None
    };

    let final_text = if args.timestamps {
        prefix_with_timestamp(&entry.t, id_prefix.as_deref(), &body)
    } else if let Some(prefix) = id_prefix {
        // Apply id prefix to each line of the body.
        prefix_each_line(&prefix, &body)
    } else {
        body
    };

    // Write every entry to stdout. Splitting by source across stdout
    // and stderr seemed cleaner in theory but produces visible
    // reordering in practice — the two fds buffer independently and
    // the OS can flush them out of chronological order. Users who
    // want to filter by stream still have `--source` and the JSON
    // output mode for programmatic processing.
    let stdout = std::io::stdout();
    let mut out = stdout.lock();
    out.write_all(final_text.as_bytes())?;
    Ok(())
}

/// Whether ANSI color is being emitted given the current policy
/// (used to decide whether session coloring should produce escapes).
fn color_active(mode: ColorMode) -> bool {
    match mode {
        ColorMode::Always => true,
        ColorMode::Never => false,
        ColorMode::Auto => {
            std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
        }
    }
}

/// 8-color palette used for `--color-sessions`. Skips the colors
/// reserved by the style guide for status semantics
/// (red=error, yellow=warn, dim/gray=secondary) and avoids black /
/// bright-white which collide with terminal background.
const SESSION_PALETTE: &[u8] = &[
    36, // cyan
    35, // magenta
    32, // green
    34, // blue
    96, // bright cyan
    95, // bright magenta
    92, // bright green
    94, // bright blue
];

fn session_color_code(id: u64) -> u8 {
    SESSION_PALETTE[(id as usize) % SESSION_PALETTE.len()]
}

fn wrap_in_session_color(body: &str, id: u64) -> String {
    let code = session_color_code(id);
    // Re-wrap each line independently so background terminal state
    // (e.g. user paging) isn't left with a dangling color escape.
    let mut out = String::with_capacity(body.len() + 16);
    for line in body.split_inclusive('\n') {
        if line == "\n" {
            out.push('\n');
            continue;
        }
        out.push_str(&format!("\x1b[{code}m"));
        if let Some(stripped) = line.strip_suffix('\n') {
            out.push_str(stripped);
            out.push_str("\x1b[0m");
            out.push('\n');
        } else {
            out.push_str(line);
            out.push_str("\x1b[0m");
        }
    }
    out
}

fn format_id_prefix(id: Option<u64>, colored: bool) -> String {
    match id {
        Some(id) => {
            if colored {
                let code = session_color_code(id);
                format!("\x1b[{code}m[id:{id:>3}]\x1b[0m ")
            } else {
                format!("[id:{id:>3}] ")
            }
        }
        None => "[id:sys] ".to_string(),
    }
}

fn prefix_each_line(prefix: &str, body: &str) -> String {
    if body.is_empty() {
        return body.to_string();
    }
    let mut out = String::with_capacity(body.len() + prefix.len() * 2);
    let mut first = true;
    for line in body.split_inclusive('\n') {
        if first {
            out.push_str(prefix);
            first = false;
        } else if !line.is_empty() && line != "\n" {
            out.push_str(prefix);
        }
        out.push_str(line);
    }
    out
}

fn decode_body(entry: &LogEntry) -> String {
    match entry.e.as_deref() {
        Some("b64") => base64_decode(&entry.d)
            .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
            .unwrap_or_else(|| entry.d.clone()),
        _ => entry.d.clone(),
    }
}

fn apply_color_policy(body: &str, mode: ColorMode) -> String {
    let strip = match mode {
        ColorMode::Always => false,
        ColorMode::Never => true,
        ColorMode::Auto => !std::io::stdout().is_terminal(),
    };
    if strip {
        strip_ansi(body)
    } else {
        body.to_string()
    }
}

fn prefix_with_timestamp(t: &str, id_prefix: Option<&str>, body: &str) -> String {
    if body.is_empty() {
        return body.to_string();
    }
    let ts = style(t).dim().to_string();
    let id_prefix = id_prefix.unwrap_or("");
    let mut out = String::with_capacity(body.len() + t.len() + id_prefix.len() + 4);
    let mut first = true;
    for line in body.split_inclusive('\n') {
        if first {
            out.push_str(&ts);
            out.push('\t');
            out.push_str(id_prefix);
            first = false;
        } else if !line.is_empty() && line != "\n" {
            // Continuation lines: pad with spaces of the same visual
            // width as the timestamp + tab so multi-line bodies read
            // cleanly.
            out.push_str(&" ".repeat(t.len()));
            out.push('\t');
            out.push_str(id_prefix);
        }
        out.push_str(line);
    }
    out
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_duration_basic() {
        assert_eq!(parse_duration("5m"), Some(Duration::from_secs(300)));
        assert_eq!(parse_duration("2h"), Some(Duration::from_secs(7200)));
        assert_eq!(parse_duration("30s"), Some(Duration::from_secs(30)));
        assert_eq!(parse_duration("1d"), Some(Duration::from_secs(86400)));
        assert_eq!(parse_duration("xyz"), None);
        assert_eq!(parse_duration(""), None);
    }

    #[test]
    fn parse_time_accepts_rfc3339() {
        let parsed = parse_time_arg(Some("2026-04-30T20:32:59.690Z"))
            .unwrap()
            .unwrap();
        let expected = DateTime::parse_from_rfc3339("2026-04-30T20:32:59.690Z")
            .unwrap()
            .with_timezone(&Utc);
        assert_eq!(parsed, expected);
    }

    #[test]
    fn parse_time_accepts_relative() {
        let parsed = parse_time_arg(Some("5m")).unwrap().unwrap();
        // Should be in the past, within ~10 seconds of "now - 5min".
        let now = Utc::now();
        let diff = (now - parsed).num_seconds();
        assert!((290..=310).contains(&diff), "diff was {diff}");
    }

    #[test]
    fn strip_ansi_removes_color_and_cursor() {
        let s = "\x1b[31merror\x1b[0m\x1b[2J\x1b[H text";
        let stripped = strip_ansi(s);
        assert_eq!(stripped, "error text");
    }

    #[test]
    fn strip_ansi_preserves_plain_text() {
        let s = "hello\nworld\n";
        assert_eq!(strip_ansi(s), s);
    }

    #[test]
    fn source_mask_default_excludes_system() {
        let mask = resolve_sources(&[]);
        assert!(mask.stdout && mask.stderr && mask.output && !mask.system);
    }

    #[test]
    fn source_mask_all() {
        let mask = resolve_sources(&[SourceFilter::All]);
        assert!(mask.stdout && mask.stderr && mask.output && mask.system);
    }

    #[test]
    fn source_mask_output_only() {
        let mask = resolve_sources(&[SourceFilter::Output]);
        assert!(mask.output && !mask.stdout && !mask.stderr && !mask.system);
    }

    #[test]
    fn grep_matches_returns_true_when_no_pattern() {
        assert!(grep_matches(None, "anything"));
    }

    #[test]
    fn grep_matches_filters_by_pattern() {
        let re = Regex::new("err").unwrap();
        assert!(grep_matches(Some(&re), "error: bad"));
        assert!(!grep_matches(Some(&re), "ok"));
    }

    #[test]
    fn source_mask_to_engine_sources_maps_each_flag() {
        let mask = SourceMask {
            stdout: true,
            stderr: false,
            output: true,
            system: true,
        };
        assert_eq!(
            mask.to_engine_sources(),
            vec![LogSource::Stdout, LogSource::Output, LogSource::System],
        );
    }

    #[test]
    fn engine_entry_to_cli_preserves_utf8_body() {
        let entry = EngineLogEntry {
            timestamp: DateTime::parse_from_rfc3339("2026-04-30T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            source: LogSource::Stdout,
            session_id: Some(7),
            data: bytes::Bytes::from_static(b"hello world"),
            cursor: microsandbox::logs::LogCursor::empty(),
        };
        let cli = engine_entry_to_cli(&entry);
        assert_eq!(cli.s, "stdout");
        assert_eq!(cli.id, Some(7));
        assert_eq!(cli.d, "hello world");
        assert!(cli.e.is_none());
    }

    #[test]
    fn engine_entry_to_cli_base64s_non_utf8_body() {
        let entry = EngineLogEntry {
            timestamp: DateTime::parse_from_rfc3339("2026-04-30T00:00:00.000Z")
                .unwrap()
                .with_timezone(&Utc),
            source: LogSource::Output,
            session_id: None,
            data: bytes::Bytes::from_static(&[0xff, 0xfe, 0xfd]),
            cursor: microsandbox::logs::LogCursor::empty(),
        };
        let cli = engine_entry_to_cli(&entry);
        assert_eq!(cli.e.as_deref(), Some("b64"));
        assert_eq!(cli.d, "//79");
    }
}
