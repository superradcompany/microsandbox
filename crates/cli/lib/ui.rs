//! CLI output styling and helpers.
//!
//! Implements the microsandbox output design system: spinners, tables,
//! detail views, and styled messages. All ephemeral output goes to stderr;
//! final data output goes to stdout.

use std::io::IsTerminal;
use std::time::{Duration, Instant};

use console::style;
use indicatif::{ProgressBar, ProgressStyle};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Ephemeral braille spinner for long-running operations.
pub struct Spinner {
    pb: Option<ProgressBar>,
    start: Instant,
    label: String,
    target: String,
}

/// Minimal table renderer with column alignment.
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Spinner {
    /// Start a new spinner. Label is the action verb (e.g., "Creating"),
    /// target is the object name (e.g., "mybox").
    pub fn start(label: &str, target: &str) -> Self {
        let is_tty = std::io::stderr().is_terminal();
        let pb = if is_tty {
            let pb = ProgressBar::new_spinner();
            pb.set_style(
                ProgressStyle::default_spinner()
                    .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏", "⠋"])
                    .template(&format!("   {{spinner}} {:<12} {{msg}}", label))
                    .unwrap(),
            );
            pb.set_message(target.to_string());
            pb.enable_steady_tick(Duration::from_millis(80));
            Some(pb)
        } else {
            None
        };

        Self {
            pb,
            start: Instant::now(),
            label: label.to_string(),
            target: target.to_string(),
        }
    }

    /// Finish with success. Shows `✓ <past_tense> <target> (duration)`.
    pub fn finish_success(self, past_tense: &str) {
        let elapsed = self.start.elapsed();
        let duration = if elapsed.as_millis() > 500 {
            format!(" ({})", format_duration(elapsed))
        } else {
            String::new()
        };

        if let Some(pb) = self.pb {
            pb.finish_and_clear();
        }

        eprintln!(
            "   {} {:<12} {}{}",
            style("✓").green(),
            past_tense,
            self.target,
            style(duration).dim()
        );
    }

    /// Finish with error. Shows `✗ <label> <target>`.
    pub fn finish_error(self) {
        if let Some(pb) = self.pb {
            pb.finish_and_clear();
        }
        eprintln!(
            "   {} {:<12} {}",
            style("✗").red(),
            self.label,
            self.target
        );
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
    pub fn print(&self) {
        if self.rows.is_empty() {
            return;
        }

        let col_count = self.headers.len();
        let mut widths: Vec<usize> = self.headers.iter().map(|h| h.len()).collect();

        for row in &self.rows {
            for (i, cell) in row.iter().enumerate() {
                if i < col_count {
                    widths[i] = widths[i].max(cell.len());
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
                    format!("{:<width$}    ", h.to_uppercase(), width = widths[i])
                } else {
                    h.to_uppercase()
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
                        format!("{:<width$}    ", cell, width = widths[i])
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
// Functions
//--------------------------------------------------------------------------------------------------

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

/// Print a styled warning message to stderr.
pub fn warn(msg: &str) {
    eprintln!("{} {msg}", style("warn:").yellow().bold());
}

/// Print a one-shot success message to stderr.
pub fn success(msg: &str) {
    eprintln!("{} {msg}", style("✓").green());
}

/// Format a sandbox status with appropriate color.
pub fn format_status(status: &str) -> String {
    match status {
        "Running" => format!("{}", style("running").green().bold()),
        "Stopped" => format!("{}", style("stopped").dim()),
        "Paused" => format!("{}", style("paused").yellow().bold()),
        "Draining" => format!("{}", style("draining").yellow().bold()),
        "Crashed" => format!("{}", style("crashed").red().bold()),
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
    println!("  {:<14}{value}", style(format!("{key}:")).cyan());
}

/// Parse a memory size string (e.g., "512M", "1G") into MiB.
pub fn parse_memory(s: &str) -> Result<u32, String> {
    let s = s.trim();
    if let Some(num) = s.strip_suffix('G').or_else(|| s.strip_suffix('g')) {
        num.parse::<u32>()
            .map(|n| n * 1024)
            .map_err(|e| format!("invalid memory size: {e}"))
    } else if let Some(num) = s.strip_suffix('M').or_else(|| s.strip_suffix('m')) {
        num.parse::<u32>()
            .map_err(|e| format!("invalid memory size: {e}"))
    } else {
        s.parse::<u32>()
            .map_err(|e| format!("invalid memory size (expected e.g. 512M, 1G): {e}"))
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

/// Generate a random sandbox name.
pub fn generate_name() -> String {
    use rand::Rng;
    let id: u32 = rand::rng().random();
    format!("msb-{id:08x}")
}

/// Format a duration for display.
pub fn format_duration(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 60.0 {
        format!("{secs:.1}s")
    } else {
        let mins = secs as u64 / 60;
        let remaining = secs as u64 % 60;
        format!("{mins}m{remaining}s")
    }
}

/// Format a chrono NaiveDateTime for display.
pub fn format_datetime(dt: &chrono::NaiveDateTime) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}
