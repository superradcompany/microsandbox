//! CLI output styling and helpers.
//!
//! Implements the microsandbox output design system: spinners, tables,
//! detail views, and styled messages. All ephemeral output goes to stderr;
//! final data output goes to stdout.

#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::{
    io::IsTerminal,
    time::{Duration, Instant},
};

use console::style;
use indicatif::{MultiProgress, ProgressBar, ProgressDrawTarget, ProgressStyle};
use microsandbox_image::PullProgress;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const BRAILLE_TICKS: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "⠋"];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Ephemeral braille spinner for long-running operations.
pub struct Spinner {
    pb: Option<ProgressBar>,
    start: Instant,
    target: String,
    quiet: bool,
    _echo_guard: Option<EchoGuard>,
}

/// RAII guard that disables terminal echo while held.
///
/// Prevents stray keypresses (e.g. Enter) from injecting newlines that
/// desync indicatif's cursor tracking, which causes ghost lines.
#[cfg(unix)]
struct EchoGuard {
    original: libc::termios,
    fd: i32,
}

#[cfg(windows)]
struct EchoGuard;

/// Minimal table renderer with column alignment.
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

/// Marker error for commands that already rendered a styled error block.
#[derive(Debug)]
pub struct AlreadyRenderedError;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Spinner {
    /// Start a new spinner. Label is the action verb (e.g., "Creating"),
    /// target is the object name (e.g., "mybox").
    pub fn start(label: &str, target: &str) -> Self {
        let is_tty = std::io::stderr().is_terminal();
        let (pb, echo_guard) = if is_tty {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .tick_strings(BRAILLE_TICKS)
                    .template(&format!("   {{spinner}} {:<12} {{msg}}", label))
                    .unwrap(),
            );
            pb.set_message(target.to_string());
            pb.enable_steady_tick(Duration::from_millis(80));
            (Some(pb), EchoGuard::acquire())
        } else {
            (None, None)
        };

        Self {
            pb,
            start: Instant::now(),
            target: target.to_string(),
            quiet: false,
            _echo_guard: echo_guard,
        }
    }

    /// Create a no-op spinner that produces no output.
    pub fn quiet() -> Self {
        Self {
            pb: None,
            start: Instant::now(),
            target: String::new(),
            quiet: true,
            _echo_guard: None,
        }
    }

    /// Finish with success. Shows `✓ <past_tense> <target> (duration)`.
    pub fn finish_success(self, past_tense: &str) {
        if let Some(pb) = self.pb {
            pb.finish_and_clear();
        }

        if !self.quiet {
            let elapsed = self.start.elapsed();
            let duration = if elapsed.as_millis() > 500 {
                format!(
                    " ({})",
                    microsandbox_utils::format::format_duration(elapsed)
                )
            } else {
                String::new()
            };

            eprintln!(
                "   {} {:<12} {}{}",
                style("✓").green(),
                past_tense,
                self.target,
                style(duration).dim()
            );
        }
    }

    /// Finish with failure. Shows `✗ <label> <target>` in the same completion
    /// format as [`finish_success`](Self::finish_success), in red.
    pub fn finish_fail(self, label: &str) {
        if let Some(pb) = self.pb {
            pb.finish_and_clear();
        }

        if !self.quiet {
            eprintln!("   {} {:<12} {}", style("✗").red(), label, self.target);
        }
    }

    /// Finish and clear entirely — no output remains on screen.
    ///
    /// Used on both success and failure paths: errors are presented by
    /// the top-level error renderer, so the spinner has no failure
    /// state of its own.
    pub fn finish_clear(self) {
        if let Some(pb) = self.pb {
            pb.finish_and_clear();
        }
    }
}

impl EchoGuard {
    /// Disable terminal echo on stdin. Returns `None` if stdin is not a TTY.
    #[cfg(unix)]
    fn acquire() -> Option<Self> {
        if !std::io::stdin().is_terminal() {
            return None;
        }

        let fd = std::io::stdin().as_raw_fd();
        let mut original: libc::termios = unsafe { std::mem::zeroed() };

        if unsafe { libc::tcgetattr(fd, &mut original) } != 0 {
            return None;
        }

        let mut modified = original;
        modified.c_lflag &= !libc::ECHO;
        if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &modified) } != 0 {
            return None;
        }

        Some(Self { original, fd })
    }

    /// Disable terminal echo on stdin. Returns `None` if stdin is not a TTY.
    #[cfg(windows)]
    fn acquire() -> Option<Self> {
        None
    }
}

#[cfg(unix)]
impl Drop for EchoGuard {
    fn drop(&mut self) {
        // Flush any keypresses that accumulated while echo was off,
        // so they don't spill into the shell prompt after we restore.
        unsafe {
            libc::tcflush(self.fd, libc::TCIFLUSH);
            libc::tcsetattr(self.fd, libc::TCSANOW, &self.original);
        }
    }
}

impl Table {
    /// Create a new table with the given column headers.
    pub fn new(headers: &[&str]) -> Self {
        Self {
            headers: headers.iter().map(|h| h.to_string()).collect(),
            rows: Vec::new(),
        }
    }

    /// Add a row to the table.
    pub fn add_row(&mut self, row: Vec<String>) {
        self.rows.push(row);
    }

    /// Print the table to stdout with column alignment.
    ///
    /// Uses visible (display) width so ANSI escape codes in cell values
    /// don't break column alignment.
    pub fn print(&self) {
        if self.rows.is_empty() {
            return;
        }

        let col_count = self.headers.len();
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.len()).collect();

        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < col_count {
                    widths[i] = widths[i].max(console::measure_text_width(cell));
                }
            }
        }

        // Print headers
        let header: String = self
            .headers
            .iter()
            .enumerate()
            .map(|(i, h)| {
                if i < col_count - 1 {
                    format!("{:<width$}    ", h, width = widths[i])
                } else {
                    h.to_string()
                }
            })
            .collect();
        println!("{}", style(header).cyan().bold());

        // Print rows
        for row in &self.rows {
            let line: String = row
                .iter()
                .enumerate()
                .map(|(i, cell)| {
                    if i < col_count - 1 {
                        let vis = console::measure_text_width(cell);
                        let padding = widths[i].saturating_sub(vis) + 4;
                        format!("{cell}{:padding$}", "", padding = padding)
                    } else {
                        cell.clone()
                    }
                })
                .collect();
            println!("{line}");
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Display for AlreadyRenderedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("command failed")
    }
}

impl std::error::Error for AlreadyRenderedError {}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Install a panic hook that restores terminal echo before aborting.
///
/// With `panic = "abort"` in the release profile, `Drop` impls are not called
/// on panic, which would leave the terminal with echo disabled. This hook
/// ensures echo is restored before the default panic handler runs.
pub fn install_panic_hook() {
    let default = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // Best-effort: restore echo on stdin if it's a TTY.
        #[cfg(unix)]
        if std::io::stdin().is_terminal() {
            let fd = std::io::stdin().as_raw_fd();
            let mut termios: libc::termios = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(fd, &mut termios) } == 0 {
                termios.c_lflag |= libc::ECHO;
                unsafe {
                    libc::tcsetattr(fd, libc::TCSANOW, &termios);
                }
            }
        }
        default(info);
    }));
}

/// Print a styled error message to stderr.
pub fn error(msg: &str) {
    eprintln!("{} {msg}", style("error:").red().bold());
}

/// Print an error message with context lines.
pub fn error_context(msg: &str, context: &[&str]) {
    eprintln!("{} {msg}", style("error:").red().bold());
    for line in context {
        eprintln!("  {} {}", style("→").dim(), style(line).dim());
    }
}

/// One context line in a styled error block.
///
/// Both `Cause` and `Hint` lines render with plain (uncolored) text
/// to keep the error block calm and readable; only the leading `→`
/// arrow bullet is dim. The variant is still kept so callers can
/// signal *intent* (cause vs. suggestion) without imposing color —
/// useful if we ever want to add per-line decorations like a screen
/// reader hint or an indent shift.
#[derive(Debug, Clone, Copy)]
pub enum ErrorLine<'a> {
    /// A line describing the cause of the error.
    Cause(&'a str),

    /// A line offering an actionable suggestion.
    Hint(&'a str),
}

/// Print an error message with `→`-prefixed context lines.
///
/// The `error:` label is bold red; the message and all `→` body
/// text render uncolored. Only the arrow bullet is dim. This
/// keeps the error block readable across terminal themes (cyan
/// renders inconsistently as teal/green-ish on Solarized,
/// macOS Terminal default, etc., which previously made hints
/// look like success messages).
pub fn error_with_lines(msg: &str, lines: &[ErrorLine<'_>]) {
    eprintln!("{} {msg}", style("error:").red().bold());
    for line in lines {
        let text = match line {
            ErrorLine::Cause(t) | ErrorLine::Hint(t) => t,
        };
        eprintln!("  {} {}", style("→").dim(), text);
    }
}

/// Print a styled warning message to stderr.
pub fn warn(msg: &str) {
    eprintln!("{} {msg}", style("warn:").yellow().bold());
}

/// Print a warning message with `→`-prefixed context lines.
///
/// Mirrors [`error_with_lines`] but with a yellow `warn:` label. As there, the
/// message and body text render uncolored; only the `→` bullet is dim.
pub fn warn_with_lines(msg: &str, lines: &[ErrorLine<'_>]) {
    eprintln!("{} {msg}", style("warn:").yellow().bold());
    for line in lines {
        let text = match line {
            ErrorLine::Cause(t) | ErrorLine::Hint(t) => t,
        };
        eprintln!("  {} {}", style("→").dim(), text);
    }
}

/// Print a one-shot success action to stderr.
///
/// Follows the same format as spinner completions:
/// `   ✓ {verb:<12} {target}`
pub fn success(verb: &str, target: &str) {
    eprintln!("   {} {:<12} {}", style("✓").green(), verb, target);
}

/// Print a one-shot failure action to stderr, mirroring [`success`].
///
/// Same `   ✗ {label:<12} {detail}` shape as a spinner failure completion.
pub fn failure(label: &str, detail: &str) {
    eprintln!("   {} {:<12} {}", style("✗").red(), label, detail);
}

/// Format a sandbox status with appropriate color.
pub fn format_status(status: &str) -> String {
    match status {
        "Created" => format!("{}", style("created").dim()),
        "Starting" => format!("{}", style("starting").yellow().bold()),
        "Running" => format!("{}", style("running").green().bold()),
        "Stopped" => format!("{}", style("stopped").dim()),
        "Paused" => format!("{}", style("paused").yellow().bold()),
        "Draining" => format!("{}", style("draining").yellow().bold()),
        "Crashed" => format!("{}", style("crashed").red().bold()),
        other => other.to_lowercase(),
    }
}

/// Format a modification disposition with status-badge colors.
pub fn format_disposition(disposition: &str) -> String {
    match disposition {
        "live" => format!("{}", style("live").green().bold()),
        "requires restart" => format!("{}", style("requires restart").yellow().bold()),
        "next start" => format!("{}", style("next start").dim()),
        "unsupported" => format!("{}", style("unsupported").red().bold()),
        other => other.to_lowercase(),
    }
}

/// Print a section header in detail views.
pub fn detail_header(title: &str) {
    println!();
    println!("{}", style(title).bold());
}

/// Print a top-level key-value pair in detail views.
pub fn detail_kv(key: &str, value: &str) {
    println!("{:<16}{value}", style(format!("{key}:")).cyan());
}

/// Print an indented key-value pair in detail views.
pub fn detail_kv_indent(key: &str, value: &str) {
    println!("  {:<14}{value}", style(format!("{key}:")).dim());
}

/// Parse a human-readable size string (e.g., "512M", "1G", "1.5G") into MiB.
///
/// Bare numbers are treated as MiB.
pub fn parse_size_mib(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('G').or_else(|| s.strip_suffix('g')) {
        let val: f64 = n.trim().parse().map_err(|e| format!("invalid size: {e}"))?;
        if val.is_nan() || val.is_infinite() || val < 0.0 {
            return Err("size must be a finite positive number".into());
        }
        let mib = val * 1024.0;
        if mib > u32::MAX as f64 {
            return Err("size too large".into());
        }
        Ok(mib as u32)
    } else if let Some(n) = s.strip_suffix('M').or_else(|| s.strip_suffix('m')) {
        n.trim()
            .parse::<u32>()
            .map_err(|e| format!("invalid size: {e}"))
    } else {
        s.parse::<u32>()
            .map_err(|e| format!("invalid size (expected e.g. 512M, 1G): {e}"))
    }
}

/// Parse an environment variable specification (KEY=value or KEY).
pub fn parse_env(s: &str) -> Result<(String, String), String> {
    if let Some(eq_pos) = s.find('=') {
        Ok((s[..eq_pos].to_string(), s[eq_pos + 1..].to_string()))
    } else {
        match std::env::var(s) {
            Ok(val) => Ok((s.to_string(), val)),
            Err(_) => Err(format!("environment variable '{s}' not set")),
        }
    }
}

/// Parse a `KEY=VALUE` label argument. Unlike [`parse_env`], a missing `=` does
/// not trigger a host-environment lookup — a bare `KEY` is a valueless marker
/// label (empty value), matching Docker's label semantics.
pub fn parse_label(s: &str) -> (String, String) {
    match s.find('=') {
        Some(eq_pos) => (s[..eq_pos].to_string(), s[eq_pos + 1..].to_string()),
        None => (s.to_string(), String::new()),
    }
}

/// Generate a random sandbox name.
pub fn generate_name() -> String {
    use rand::RngExt;
    let id: u32 = rand::rng().random();
    format!("msb-{id:08x}")
}

/// Format a UTC timestamp for human display in the system's local timezone.
pub fn format_datetime(dt: &chrono::DateTime<chrono::Utc>) -> String {
    dt.with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string()
}

/// Format a UTC timestamp for machine-readable JSON output.
pub fn format_json_datetime(dt: &chrono::DateTime<chrono::Utc>) -> String {
    dt.to_rfc3339()
}

/// Format an RFC 3339 timestamp for human display in the system's local timezone.
pub fn format_rfc3339_datetime(s: &str) -> Result<String, chrono::ParseError> {
    chrono::DateTime::parse_from_rfc3339(s).map(|dt| {
        dt.with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string()
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[test]
    fn json_datetime_uses_rfc3339_utc() {
        let dt = chrono::DateTime::parse_from_rfc3339("2026-05-31T09:09:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);

        assert_eq!(
            super::format_json_datetime(&dt),
            "2026-05-31T09:09:00+00:00"
        );
    }

    #[test]
    fn display_datetime_uses_local_timezone() {
        let dt = chrono::DateTime::parse_from_rfc3339("2026-05-31T09:09:00Z")
            .unwrap()
            .with_timezone(&chrono::Utc);
        let expected = dt
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S")
            .to_string();

        assert_eq!(super::format_datetime(&dt), expected);
        assert_eq!(
            super::format_rfc3339_datetime("2026-05-31T09:09:00Z").unwrap(),
            expected
        );
    }
}

//--------------------------------------------------------------------------------------------------
// Types: Pull Progress Display
//--------------------------------------------------------------------------------------------------

/// Ephemeral multi-line pull progress display.
///
/// Shows a header spinner and per-layer progress bars with phase-colored
/// styling. All output is cleared when [`finish`](Self::finish) is called.
pub struct PullProgressDisplay {
    mp: MultiProgress,
    header: ProgressBar,
    layer_bars: Vec<ProgressBar>,
    reference: String,
    download_style: ProgressStyle,
    materialize_style: ProgressStyle,
    done_style: ProgressStyle,
    verb: &'static str,
    _echo_guard: Option<EchoGuard>,
}

//--------------------------------------------------------------------------------------------------
// Methods: Pull Progress Display
//--------------------------------------------------------------------------------------------------

impl PullProgressDisplay {
    /// Create a new pull progress display for the given image reference.
    pub fn new(reference: &str) -> Self {
        Self::new_inner(reference, false, "Pulling")
    }

    /// Create a no-op pull progress display that produces no output.
    pub fn quiet(reference: &str) -> Self {
        Self::new_inner(reference, true, "Pulling")
    }

    /// Create a progress display for `msb image load` (header reads "Loading").
    pub fn load(reference: &str, quiet: bool) -> Self {
        Self::new_inner(reference, quiet, "Loading")
    }

    fn new_inner(reference: &str, quiet: bool, verb: &'static str) -> Self {
        let is_tty = !quiet && std::io::stderr().is_terminal();

        let mp = MultiProgress::new();
        if is_tty {
            mp.set_draw_target(ProgressDrawTarget::stderr_with_hz(10));
        } else {
            mp.set_draw_target(ProgressDrawTarget::hidden());
        }

        let header = mp.add(ProgressBar::new_spinner());
        header.set_style(
            ProgressStyle::default_spinner()
                .tick_strings(BRAILLE_TICKS)
                .template("   {spinner} {msg}")
                .unwrap(),
        );
        header.set_message(format!("{:<12} {}", verb, reference));
        header.enable_steady_tick(Duration::from_millis(80));

        Self {
            mp,
            header,
            layer_bars: Vec::new(),
            reference: reference.to_string(),
            verb,
            _echo_guard: if is_tty { EchoGuard::acquire() } else { None },
            download_style: ProgressStyle::default_bar()
                .template(
                    "     {prefix}  {bar:36.magenta/238}  {bytes}/{total_bytes}  {msg:.magenta}",
                )
                .unwrap()
                .progress_chars("━━╌"),
            materialize_style: ProgressStyle::default_bar()
                .template("     {prefix}  {bar:36.blue/238}  {bytes}/{total_bytes}  {msg:.blue}")
                .unwrap()
                .progress_chars("━━╌"),
            done_style: ProgressStyle::default_bar()
                .template("     {prefix}  {msg}")
                .unwrap(),
        }
    }

    /// Ensure a materialize-styled bar exists for `index`, creating any missing
    /// bars up to it. No-op when the bar already exists (pull pre-creates them on
    /// its `Resolved` event); load has no such event, so bars are made lazily as
    /// each layer starts materializing.
    fn ensure_layer_bar(&mut self, index: usize) {
        while self.layer_bars.len() <= index {
            let n = self.layer_bars.len() + 1;
            let pb = self.mp.add(ProgressBar::new(1));
            pb.set_style(self.materialize_style.clone());
            pb.set_prefix(format!("layer {n}"));
            pb.set_message("materializing");
            self.layer_bars.push(pb);
        }
    }

    /// Process a single pull progress event, updating the display.
    pub fn handle_event(&mut self, event: PullProgress) {
        match event {
            PullProgress::Resolving { .. } => {
                self.header
                    .set_message(format!("{:<12} {}...", "Resolving", self.reference));
            }
            PullProgress::Resolved { layer_count, .. } => {
                self.header.set_message(format!(
                    "{:<12} {} ({} layer{})",
                    self.verb,
                    self.reference,
                    layer_count,
                    if layer_count == 1 { "" } else { "s" }
                ));

                let width = layer_count.to_string().len();
                for i in 0..layer_count {
                    let pb = self.mp.add(ProgressBar::new(1));
                    pb.set_style(self.download_style.clone());
                    pb.set_prefix(format!("layer {:>width$}/{layer_count}", i + 1));
                    pb.set_message("downloading");
                    self.layer_bars.push(pb);
                }
            }
            PullProgress::LayerDownloadProgress {
                layer_index,
                downloaded_bytes,
                total_bytes,
                ..
            } => {
                if let Some(pb) = self.layer_bars.get(layer_index) {
                    if let Some(total) = total_bytes {
                        pb.set_length(total);
                    }
                    pb.set_position(downloaded_bytes);
                }
            }
            PullProgress::LayerDownloadComplete {
                layer_index,
                downloaded_bytes,
                ..
            } => {
                if let Some(pb) = self.layer_bars.get(layer_index) {
                    pb.set_length(downloaded_bytes);
                    pb.set_position(downloaded_bytes);
                }
            }
            PullProgress::LayerDownloadVerifying { layer_index, .. } => {
                if let Some(pb) = self.layer_bars.get(layer_index) {
                    pb.set_message("verifying");
                }
            }
            PullProgress::LayerMaterializeStarted { layer_index, .. } => {
                self.ensure_layer_bar(layer_index);
                if let Some(pb) = self.layer_bars.get(layer_index) {
                    pb.set_style(self.materialize_style.clone());
                    pb.set_position(0);
                    pb.set_length(1);
                    pb.set_message("materializing");
                }
            }
            PullProgress::LayerMaterializeProgress {
                layer_index,
                bytes_read,
                total_bytes,
            } => {
                self.ensure_layer_bar(layer_index);
                if let Some(pb) = self.layer_bars.get(layer_index) {
                    pb.set_length(total_bytes);
                    pb.set_position(bytes_read);
                }
            }
            PullProgress::LayerMaterializeWriting { layer_index } => {
                self.ensure_layer_bar(layer_index);
                if let Some(pb) = self.layer_bars.get(layer_index) {
                    pb.set_position(pb.length().unwrap_or(0));
                    pb.set_message("writing image");
                }
            }
            PullProgress::LayerMaterializeComplete { layer_index, .. } => {
                self.ensure_layer_bar(layer_index);
                if let Some(pb) = self.layer_bars.get(layer_index) {
                    pb.set_position(pb.length().unwrap_or(0));
                    pb.set_style(self.done_style.clone());
                    pb.set_message(format!("{}", style("✓").green()));
                    pb.tick();
                }
            }
            PullProgress::StitchMergingTrees { layer_count } => {
                self.header.set_message(format!(
                    "{:<12} {} ({} layer{})",
                    "Merging",
                    self.reference,
                    layer_count,
                    if layer_count == 1 { "" } else { "s" }
                ));
            }
            PullProgress::StitchWritingFsmeta => {
                self.header
                    .set_message(format!("{:<12} {}", "Writing fsmeta", self.reference));
            }
            PullProgress::StitchWritingVmdk => {
                self.header
                    .set_message(format!("{:<12} {}", "Writing vmdk", self.reference));
            }
            PullProgress::StitchComplete => {
                self.header
                    .set_message(format!("{:<12} {}", "Stitched", self.reference));
            }
            PullProgress::Complete { .. } => {}
        }
    }

    /// Clear all ephemeral progress output from the terminal.
    pub fn finish(self) {
        let _ = self.mp.clear();
    }
}
