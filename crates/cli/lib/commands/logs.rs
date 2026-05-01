//! `msb logs` command — read the captured output of a sandbox.
//!
//! Reads `<sandbox-dir>/logs/exec.log` (the JSON Lines file produced by
//! the runtime's relay tap, see `crates/runtime/lib/exec_log.rs`),
//! decodes each entry, and renders it to the terminal per
//! `design/runtime/sandbox-logs.md` D5.
//!
//! Supports filtering by source (stdout/stderr/system), time window,
//! tail count, regex search, follow mode (polling), and JSON-Lines
//! passthrough. ANSI escape sequences are passed through to TTYs and
//! stripped on pipes by default (matching `ls`/`grep` convention).

use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, anyhow};
use chrono::{DateTime, Utc};
use clap::{Args, ValueEnum};
use console::style;
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

#[derive(Debug, Clone, Copy)]
enum EffectiveSource {
    Stdout,
    Stderr,
    Output,
    System,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb logs` command.
pub async fn run(args: LogsArgs) -> anyhow::Result<()> {
    let log_dir = resolve_log_dir(&args.name)?;
    if !log_dir.exists() {
        return Err(anyhow!(
            "no logs directory for sandbox {:?} (sandbox not found?)",
            &args.name
        ));
    }

    let sources = resolve_sources(&args.source);
    let since = parse_time_arg(args.since.as_deref())?;
    let until = parse_time_arg(args.until.as_deref())?;
    let grep_re = match args.grep.as_deref() {
        Some(pat) => Some(Regex::new(pat).context("invalid --grep regex")?),
        None => None,
    };

    let color_policy = if args.no_color {
        ColorMode::Never
    } else if std::env::var_os("NO_COLOR").is_some() {
        ColorMode::Never
    } else {
        args.color
    };

    // Render the boot-error block first if present (Phase B's
    // boot-error.json sits next to exec.log in the same log_dir).
    render_boot_error_if_present(&log_dir, &args.name, args.json)?;

    // Initial dump (history).
    let mut entries = read_all_entries(&log_dir, sources)?;
    apply_filters(&mut entries, since, until, grep_re.as_ref(), args.tail);
    render_entries(&entries, &args, color_policy)?;

    // Optional follow mode — poll the file for new entries.
    if args.follow {
        let last_t = entries.last().map(|e| e.t.clone());
        follow_loop(&log_dir, sources, &args, color_policy, last_t)?;
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers — discovery
//--------------------------------------------------------------------------------------------------

fn resolve_log_dir(name: &str) -> anyhow::Result<PathBuf> {
    Ok(microsandbox::config::config()
        .sandboxes_dir()
        .join(name)
        .join("logs"))
}

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
    fn includes_exec_sources(&self) -> bool {
        self.stdout || self.stderr || self.output
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers — boot-error block
//--------------------------------------------------------------------------------------------------

fn render_boot_error_if_present(
    log_dir: &Path,
    name: &str,
    json_mode: bool,
) -> anyhow::Result<()> {
    let boot_err = match microsandbox_runtime::boot_error::BootError::read(log_dir) {
        Ok(Some(b)) => b,
        Ok(None) => return Ok(()),
        Err(_) => return Ok(()),
    };

    if json_mode {
        // Emit as a synthetic JSON Lines entry tagged s: "boot-error".
        // Consumers can branch on `s` to detect failed-start sandboxes.
        let line = serde_json::json!({
            "t": boot_err.t,
            "s": "boot-error",
            "d": serde_json::to_value(&boot_err).unwrap_or(serde_json::Value::Null),
        });
        println!("{line}");
        return Ok(());
    }

    crate::boot_error_render::render(name, &boot_err);
    eprintln!();
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers — reading
//--------------------------------------------------------------------------------------------------

/// Read all entries from `exec.log` (and its rotated siblings) plus
/// optional system sources, ordered chronologically.
fn read_all_entries(log_dir: &Path, sources: SourceMask) -> anyhow::Result<Vec<LogEntry>> {
    let mut entries: Vec<LogEntry> = Vec::new();

    if sources.includes_exec_sources() {
        // Rotated files first (.3 → .2 → .1 → current) so output is
        // chronologically ordered.
        for suffix in [".3", ".2", ".1", ""].iter() {
            let path = if suffix.is_empty() {
                log_dir.join("exec.log")
            } else {
                log_dir.join(format!("exec.log{suffix}"))
            };
            if !path.exists() {
                continue;
            }
            append_jsonl_entries(&path, &mut entries, sources)?;
        }
    }

    if sources.system {
        // Cross-merge runtime.log and kernel.log as `s: "system"`.
        // Both are unstructured text; we synthesize timestamps from
        // file mtimes (kernel.log) or per-line tracing prefixes
        // (runtime.log).
        append_text_log_as_system(&log_dir.join("runtime.log"), &mut entries);
        append_text_log_as_system(&log_dir.join("kernel.log"), &mut entries);

        // Stable sort by parsed timestamp. We parse rather than
        // string-compare because runtime.log uses microsecond-precision
        // RFC 3339 (`.615119Z`) while exec.log uses millisecond
        // (`.969Z`) — lexical compare across mixed precisions gives
        // the wrong order.
        entries.sort_by_key(|e| {
            parse_entry_time(&e.t).unwrap_or(DateTime::<Utc>::MIN_UTC)
        });
    }

    Ok(entries)
}

fn append_jsonl_entries(
    path: &Path,
    out: &mut Vec<LogEntry>,
    sources: SourceMask,
) -> anyhow::Result<()> {
    let bytes = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let text = String::from_utf8_lossy(&bytes);
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        match serde_json::from_str::<LogEntry>(line) {
            Ok(entry) => {
                if entry_passes_source_mask(&entry, sources) {
                    out.push(entry);
                }
            }
            Err(_) => {
                // Skip malformed lines — never let one bad entry
                // poison the whole file.
            }
        }
    }
    Ok(())
}

fn entry_passes_source_mask(entry: &LogEntry, mask: SourceMask) -> bool {
    match entry.s.as_str() {
        "stdout" => mask.stdout,
        "stderr" => mask.stderr,
        "output" => mask.output,
        "system" => mask.system,
        _ => true, // Unknown source: include defensively.
    }
}

/// Read a plain-text log file (runtime.log / kernel.log) and append
/// each line as a synthetic `s: "system"` entry.
fn append_text_log_as_system(path: &Path, out: &mut Vec<LogEntry>) {
    if !path.exists() {
        return;
    }
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(_) => return,
    };
    let text = String::from_utf8_lossy(&bytes);
    let mtime_iso = file_mtime_rfc3339(path).unwrap_or_else(now_rfc3339);

    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        // tracing-formatted lines start with ANSI color escapes
        // around the timestamp (`\x1b[2m2026-…Z\x1b[0m  INFO …`).
        // Strip ANSI first so the leading-timestamp parser sees a
        // bare RFC 3339 token. Fall back to file mtime if that
        // still fails (e.g. unstructured kernel.log).
        let stripped = strip_ansi(line);
        let (t, body) = match split_leading_timestamp(&stripped) {
            Some((t, body)) => (t.to_string(), body.to_string()),
            None => (mtime_iso.clone(), stripped.clone()),
        };
        out.push(LogEntry {
            t,
            s: "system".into(),
            d: format!("{}\n", body),
            id: None,
            e: None,
        });
    }
}

fn split_leading_timestamp(line: &str) -> Option<(&str, &str)> {
    // Tracing default format starts with an RFC 3339 timestamp ending
    // in `Z` followed by whitespace. We don't strictly validate — just
    // peel off the first whitespace-delimited token if it ends with Z
    // and is at least 20 chars long.
    let mut split = line.splitn(2, char::is_whitespace);
    let first = split.next()?;
    let rest = split.next()?;
    if first.len() >= 20 && first.ends_with('Z') {
        Some((first, rest))
    } else {
        None
    }
}

fn file_mtime_rfc3339(path: &Path) -> Option<String> {
    let meta = std::fs::metadata(path).ok()?;
    let modified = meta.modified().ok()?;
    let dt: DateTime<Utc> = modified.into();
    Some(dt.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

fn now_rfc3339() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers — filters
//--------------------------------------------------------------------------------------------------

fn apply_filters(
    entries: &mut Vec<LogEntry>,
    since: Option<DateTime<Utc>>,
    until: Option<DateTime<Utc>>,
    grep: Option<&Regex>,
    tail: Option<usize>,
) {
    if let Some(s) = since {
        entries.retain(|e| match parse_entry_time(&e.t) {
            Some(t) => t >= s,
            None => true,
        });
    }
    if let Some(u) = until {
        entries.retain(|e| match parse_entry_time(&e.t) {
            Some(t) => t < u,
            None => true,
        });
    }
    if let Some(re) = grep {
        entries.retain(|e| re.is_match(&e.d));
    }
    if let Some(n) = tail
        && entries.len() > n
    {
        let drop = entries.len() - n;
        entries.drain(0..drop);
    }
}

fn parse_time_arg(input: Option<&str>) -> anyhow::Result<Option<DateTime<Utc>>> {
    let Some(raw) = input else {
        return Ok(None);
    };
    // RFC 3339 first.
    if let Ok(dt) = DateTime::parse_from_rfc3339(raw) {
        return Ok(Some(dt.with_timezone(&Utc)));
    }
    // Relative duration like 5m / 2h / 1d / 30s.
    let dur = parse_duration(raw)
        .with_context(|| format!("could not parse time {raw:?} (expected RFC 3339 or `5m` etc.)"))?;
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

fn parse_entry_time(t: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(t).ok().map(|d| d.with_timezone(&Utc))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers — rendering
//--------------------------------------------------------------------------------------------------

fn render_entries(
    entries: &[LogEntry],
    args: &LogsArgs,
    color: ColorMode,
) -> anyhow::Result<()> {
    if args.json {
        let stdout = std::io::stdout();
        let mut out = stdout.lock();
        for entry in entries {
            // Re-emit verbatim as a single JSON Lines line. We
            // serialize from our parsed struct so that any malformed
            // fields are normalized.
            let line = serde_json::to_string(&serde_json::json!({
                "t": entry.t,
                "s": entry.s,
                "d": entry.d,
                "id": entry.id,
                "e": entry.e,
            }))?;
            writeln!(out, "{line}")?;
        }
        return Ok(());
    }

    for entry in entries {
        render_one(entry, args, color)?;
    }
    Ok(())
}

fn render_one(entry: &LogEntry, args: &LogsArgs, color: ColorMode) -> anyhow::Result<()> {
    let source = match entry.s.as_str() {
        "stdout" => EffectiveSource::Stdout,
        "stderr" => EffectiveSource::Stderr,
        "output" => EffectiveSource::Output,
        "system" => EffectiveSource::System,
        _ => EffectiveSource::Stdout,
    };
    let _ = source;

    // Resolve the body bytes (decode base64 if e == "b64"; else use d).
    let body = decode_body(entry);
    let body = apply_color_policy(&body, color);

    // --color-sessions implies --show-id. Resolve both flags + the
    // ANSI policy into a single per-line decoration.
    let want_id_prefix = args.show_id || args.color_sessions;
    let want_session_color = args.color_sessions && color_active(color);

    let body = if want_session_color
        && let Some(id) = entry.id
    {
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
        ColorMode::Auto => std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none(),
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
        Some("b64") => {
            // base64 decode if present. Use the standard alphabet.
            // We accept either the engine-style or "STANDARD" decoder.
            // Fall back to the encoded form if decode fails.
            base64_decode(&entry.d).unwrap_or_else(|| entry.d.clone())
        }
        _ => entry.d.clone(),
    }
}

fn base64_decode(s: &str) -> Option<String> {
    // Very small decoder using the standard alphabet so we don't have
    // to add the `base64` crate just for the rare opt-in raw mode.
    static TABLE: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let bytes = s.trim().as_bytes();
    if bytes.is_empty() {
        return Some(String::new());
    }
    if bytes.len() % 4 != 0 {
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
        let n = (vals[0] as u32) << 18
            | (vals[1] as u32) << 12
            | (vals[2] as u32) << 6
            | (vals[3] as u32);
        out.push(((n >> 16) & 0xff) as u8);
        if pad < 2 {
            out.push(((n >> 8) & 0xff) as u8);
        }
        if pad < 1 {
            out.push((n & 0xff) as u8);
        }
    }
    Some(String::from_utf8_lossy(&out).into_owned())
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

/// Strip ANSI escape sequences (CSI, OSC, two-byte C1).
///
/// Hand-rolled state machine. We keep the `regex` crate around for
/// `--grep` (actual user-supplied regex matching), but a regex is
/// overkill for a fixed-shape ANSI stripper — this is ~25 lines and
/// handles all three sequence classes cleanly.
pub(crate) fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('[') => {
                // CSI: skip until final byte in 0x40..=0x7e.
                while let Some(c) = chars.next() {
                    if matches!(c, '\x40'..='\x7e') {
                        break;
                    }
                }
            }
            Some(']') => {
                // OSC: skip until BEL or ESC '\'.
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
            // Two-byte C1 (or stray ESC) — drop the next char.
            Some(_) => {}
            None => break,
        }
    }
    out
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers — follow mode
//--------------------------------------------------------------------------------------------------

fn follow_loop(
    log_dir: &Path,
    sources: SourceMask,
    args: &LogsArgs,
    color: ColorMode,
    mut last_t: Option<String>,
) -> anyhow::Result<()> {
    let path = log_dir.join("exec.log");
    let mut last_size: u64 = std::fs::metadata(&path).map(|m| m.len()).unwrap_or(0);
    let mut last_inode: u64 = inode_of(&path);

    loop {
        std::thread::sleep(Duration::from_millis(200));

        let Ok(meta) = std::fs::metadata(&path) else {
            // File missing — sandbox stopped or removed. Exit cleanly.
            break;
        };
        let inode = inode_of(&path);
        let size = meta.len();

        // Detect rotation (inode changed, or size shrank): re-read the
        // whole file from the top.
        let need_full_reread = inode != last_inode || size < last_size;

        if !need_full_reread && size == last_size {
            continue;
        }

        let mut new_entries: Vec<LogEntry> = Vec::new();
        if sources.includes_exec_sources() {
            append_jsonl_entries(&path, &mut new_entries, sources)?;
        }

        // Filter to only entries newer than the last we rendered.
        let cutoff = last_t.clone();
        new_entries.retain(|e| match cutoff.as_deref() {
            Some(c) => e.t.as_str() > c,
            None => true,
        });

        let grep_re = match args.grep.as_deref() {
            Some(p) => Regex::new(p).ok(),
            None => None,
        };
        if let Some(re) = grep_re.as_ref() {
            new_entries.retain(|e| re.is_match(&e.d));
        }

        for entry in &new_entries {
            render_one(entry, args, color)?;
            last_t = Some(entry.t.clone());
        }

        last_size = size;
        last_inode = inode;
    }
    Ok(())
}

#[cfg(unix)]
fn inode_of(path: &Path) -> u64 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(path).map(|m| m.ino()).unwrap_or(0)
}

#[cfg(not(unix))]
fn inode_of(_path: &Path) -> u64 {
    0
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
        let parsed = parse_time_arg(Some("2026-04-30T20:32:59.690Z")).unwrap().unwrap();
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
    fn base64_decode_round_trip() {
        // "hello" → "aGVsbG8="
        assert_eq!(base64_decode("aGVsbG8=").unwrap(), "hello");
        // "" → ""
        assert_eq!(base64_decode("").unwrap(), "");
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
    fn apply_filters_tail_keeps_last_n() {
        let mut entries: Vec<LogEntry> = (0..5)
            .map(|i| LogEntry {
                t: format!("2026-04-30T00:00:0{i}.000Z"),
                s: "stdout".into(),
                d: format!("line {i}"),
                id: Some(1),
                e: None,
            })
            .collect();
        apply_filters(&mut entries, None, None, None, Some(2));
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].d, "line 3");
        assert_eq!(entries[1].d, "line 4");
    }

    #[test]
    fn apply_filters_grep() {
        let mut entries: Vec<LogEntry> = vec![
            LogEntry {
                t: "1".into(),
                s: "stdout".into(),
                d: "ok".into(),
                id: Some(1),
                e: None,
            },
            LogEntry {
                t: "2".into(),
                s: "stdout".into(),
                d: "error: bad".into(),
                id: Some(1),
                e: None,
            },
        ];
        let re = Regex::new("error").unwrap();
        apply_filters(&mut entries, None, None, Some(&re), None);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].d, "error: bad");
    }
}
