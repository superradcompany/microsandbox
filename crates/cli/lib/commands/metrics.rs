//! `msb metrics` command — show live sandbox metrics.
//!
//! Reads the shared-memory metrics registry through the SDK's report API,
//! which joins each row with the catalog's active config so CPU and memory
//! denominators follow live resizes. Disk and network columns render as
//! per-second rates computed from two samples; `--watch` refreshes the
//! table in place and `--follow` streams one JSON Lines object per sandbox
//! per interval.

use std::collections::HashMap;
use std::io::{IsTerminal, Write};
use std::time::Duration;

use anyhow::{anyhow, bail};
use chrono::Utc;
use clap::Args;
use console::style;
use microsandbox::backend::LocalBackend;
use microsandbox::sandbox::{
    SandboxMetricsReport, SandboxMetricsState, all_sandbox_metrics_reports_local,
    sandbox_metrics_report_local,
};
use microsandbox_utils::format::{format_bytes, format_duration};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Sampling window used to derive rates for a one-shot table render.
const ONE_SHOT_RATE_WINDOW: Duration = Duration::from_millis(500);

/// Smallest accepted `--interval`, guarding against busy-loops.
const MIN_INTERVAL: Duration = Duration::from_millis(100);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Show live metrics for running sandboxes.
#[derive(Debug, Args)]
pub struct MetricsArgs {
    /// Sandbox to inspect. Omit to show all running sandboxes.
    pub name: Option<String>,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,

    /// Continuously refresh the table in place. Ctrl-C to quit.
    #[arg(short = 'w', long, conflicts_with_all = ["follow", "format"])]
    pub watch: bool,

    /// Stream one JSON Lines object per sandbox per interval to stdout.
    #[arg(short = 'f', long, conflicts_with = "format")]
    pub follow: bool,

    /// Refresh interval for --watch/--follow (e.g. 500ms, 2s).
    #[arg(long, value_name = "DURATION", default_value = "1s")]
    pub interval: String,

    /// Include exited sandboxes whose terminal metrics are still recorded.
    #[arg(short = 'a', long)]
    pub all: bool,

    /// Sort rows by column.
    #[arg(long, value_name = "COLUMN", value_parser = ["name", "cpu", "mem"], default_value = "name")]
    pub sort: String,
}

/// Per-second rates derived from two consecutive samples of one run.
#[derive(Clone, Copy, Debug)]
struct Rates {
    disk_read: f64,
    disk_write: f64,
    net_rx: f64,
    net_tx: f64,
}

/// Cumulative counters remembered from the previous sample of one run.
#[derive(Clone, Copy, Debug)]
struct PrevSample {
    timestamp: chrono::DateTime<chrono::Utc>,
    disk_read_bytes: u64,
    disk_write_bytes: u64,
    net_rx_bytes: u64,
    net_tx_bytes: u64,
}

/// Derives per-run rates across successive report collections.
///
/// Keyed by run id so a sandbox restart (new run, counters reset to zero)
/// starts a fresh window instead of producing a bogus negative delta. When a
/// tick observes no new sample (`delta_t == 0`), the previously computed
/// rate is reused so the display doesn't flicker between values and dashes.
#[derive(Default)]
struct RateTracker {
    prev: HashMap<i32, PrevSample>,
    last_rates: HashMap<i32, Rates>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb metrics` command.
pub async fn run(args: MetricsArgs) -> anyhow::Result<()> {
    let interval = parse_interval(&args.interval)?;
    let backend = crate::commands::common::resolve_local_backend()?;
    let local = crate::commands::common::local_backend_ref(&backend)?;

    if args.follow {
        return follow_loop(local, &args, interval).await;
    }
    if args.watch {
        return watch_loop(local, &args, interval).await;
    }

    let reports = collect_reports(local, &args).await?;

    if args.format.as_deref() == Some("json") {
        print_json_snapshot(&args, &reports)?;
        return Ok(());
    }

    if reports.is_empty() {
        eprintln!("No running sandboxes.");
        return Ok(());
    }

    // Rates need two samples spanning at least one sampler tick. A fixed
    // window can straddle zero new samples (samplers default to 1s), so
    // retry a few short windows until every running row has a rate. CPU is
    // already delta-derived by the sampler, so it is correct on either read.
    let mut tracker = RateTracker::default();
    tracker.update(&reports);
    let mut reports = reports;
    let mut rates = HashMap::new();
    for _ in 0..4 {
        tokio::time::sleep(ONE_SHOT_RATE_WINDOW).await;
        reports = collect_reports(local, &args).await?;
        rates = tracker.update(&reports);
        let all_rated = reports.iter().all(|report| {
            report.state != SandboxMetricsState::Running || rates.contains_key(&report.run_id)
        });
        if all_rated {
            break;
        }
    }

    sort_reports(&mut reports, &args.sort);
    print!("{}", render_table(&reports, &rates));
    Ok(())
}

/// Collect reports for the named sandbox (any state) or all sandboxes.
async fn collect_reports(
    local: &LocalBackend,
    args: &MetricsArgs,
) -> anyhow::Result<Vec<SandboxMetricsReport>> {
    match args.name.as_deref() {
        Some(name) => {
            let report = sandbox_metrics_report_local(local, name)
                .await?
                .ok_or_else(|| anyhow!("no metrics recorded for sandbox {name:?}"))?;
            Ok(vec![report])
        }
        None => Ok(all_sandbox_metrics_reports_local(local, args.all).await?),
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: watch / follow loops
//--------------------------------------------------------------------------------------------------

async fn watch_loop(
    local: &LocalBackend,
    args: &MetricsArgs,
    interval: Duration,
) -> anyhow::Result<()> {
    let term = console::Term::stdout();
    if !std::io::stdout().is_terminal() {
        bail!("--watch requires a terminal; use --follow for machine-readable streaming");
    }

    let mut tracker = RateTracker::default();
    // Prime the tracker so the first frame already has rates.
    let reports = collect_reports(local, args).await?;
    tracker.update(&reports);
    tokio::time::sleep(ONE_SHOT_RATE_WINDOW.min(interval)).await;

    let _ = term.hide_cursor();
    let result = watch_frames(local, args, interval, &term, &mut tracker).await;
    let _ = term.show_cursor();
    result
}

async fn watch_frames(
    local: &LocalBackend,
    args: &MetricsArgs,
    interval: Duration,
    term: &console::Term,
    tracker: &mut RateTracker,
) -> anyhow::Result<()> {
    loop {
        let mut reports = collect_reports(local, args).await?;
        let rates = tracker.update(&reports);
        sort_reports(&mut reports, &args.sort);

        let mut frame = String::new();
        frame.push_str(
            &style(format!(
                "every {}  \u{b7}  ctrl-c to quit",
                format_interval(interval)
            ))
            .dim()
            .to_string(),
        );
        frame.push_str("\n\n");
        if reports.is_empty() {
            frame.push_str("No running sandboxes.\n");
        } else {
            frame.push_str(&render_table(&reports, &rates));
        }

        term.clear_screen()?;
        term.write_str(&frame)?;

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

async fn follow_loop(
    local: &LocalBackend,
    args: &MetricsArgs,
    interval: Duration,
) -> anyhow::Result<()> {
    let stdout = std::io::stdout();
    loop {
        let mut reports = collect_reports(local, args).await?;
        sort_reports(&mut reports, &args.sort);
        {
            let mut out = stdout.lock();
            for report in &reports {
                writeln!(out, "{}", metrics_json(report))?;
            }
            out.flush()?;
        }

        tokio::select! {
            _ = tokio::time::sleep(interval) => {}
            _ = tokio::signal::ctrl_c() => return Ok(()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: rendering
//--------------------------------------------------------------------------------------------------

fn render_table(reports: &[SandboxMetricsReport], rates: &HashMap<i32, Rates>) -> String {
    let mut table = ui::Table::new(&[
        "NAME",
        "STATE",
        "CPU",
        "MEM",
        "DISK R/W /s",
        "NET RX/TX /s",
        "UPTIME",
    ]);

    for report in reports {
        let metric = &report.metrics;
        let exited = report.state == SandboxMetricsState::Exited;
        let stalled = report.state == SandboxMetricsState::Stalled;

        let cpu = if exited || stalled {
            "\u{2014}".to_string()
        } else {
            format_cpu(metric.cpu_percent, report.cpus)
        };
        let mem = format!(
            "{} / {}",
            format_bytes(metric.memory_bytes),
            format_bytes(metric.memory_limit_bytes)
        );
        let (disk, net) = if exited {
            (
                format!(
                    "{} / {} total",
                    format_bytes(metric.disk_read_bytes),
                    format_bytes(metric.disk_write_bytes)
                ),
                format!(
                    "{} / {} total",
                    format_bytes(metric.net_rx_bytes),
                    format_bytes(metric.net_tx_bytes)
                ),
            )
        } else if stalled {
            ("\u{2014}".to_string(), "\u{2014}".to_string())
        } else {
            match rates.get(&report.run_id) {
                Some(rates) => (
                    format!(
                        "{} / {}",
                        format_bytes(rates.disk_read as u64),
                        format_bytes(rates.disk_write as u64)
                    ),
                    format!(
                        "{} / {}",
                        format_bytes(rates.net_rx as u64),
                        format_bytes(rates.net_tx as u64)
                    ),
                ),
                None => ("\u{2014}".to_string(), "\u{2014}".to_string()),
            }
        };
        let uptime = match report.state {
            SandboxMetricsState::Running => format_duration(metric.uptime),
            SandboxMetricsState::Stalled => style(format!(
                "no sample {}",
                format_duration(sample_age(metric.timestamp))
            ))
            .yellow()
            .to_string(),
            SandboxMetricsState::Exited => format!("ran {}", format_duration(metric.uptime)),
        };

        let dim_if_exited = |cell: String| {
            if exited {
                style(cell).dim().to_string()
            } else {
                cell
            }
        };

        table.add_row(vec![
            dim_if_exited(report.name.clone()),
            format_state(report.state),
            dim_if_exited(cpu),
            dim_if_exited(mem),
            dim_if_exited(disk),
            dim_if_exited(net),
            if exited {
                style(uptime).dim().to_string()
            } else {
                uptime
            },
        ]);
    }

    table.render()
}

fn format_state(state: SandboxMetricsState) -> String {
    match state {
        SandboxMetricsState::Running => style("running").green().bold().to_string(),
        SandboxMetricsState::Stalled => style("stalled").yellow().bold().to_string(),
        SandboxMetricsState::Exited => style("exited").dim().to_string(),
    }
}

/// Render CPU usage in cores over the allocation (`0.8 / 2c`). Falls back
/// to a bare percentage when the catalog config is unresolvable.
fn format_cpu(cpu_percent: f32, cpus: Option<u32>) -> String {
    match cpus {
        Some(cpus) => format!("{:.2} / {}c", f64::from(cpu_percent) / 100.0, cpus),
        None => format!("{cpu_percent:.1}%"),
    }
}

fn sample_age(timestamp: chrono::DateTime<chrono::Utc>) -> Duration {
    Utc::now()
        .signed_duration_since(timestamp)
        .to_std()
        .unwrap_or_default()
}

fn sort_reports(reports: &mut [SandboxMetricsReport], sort: &str) {
    match sort {
        "cpu" => reports.sort_by(|left, right| {
            right
                .metrics
                .cpu_percent
                .total_cmp(&left.metrics.cpu_percent)
                .then_with(|| left.name.cmp(&right.name))
        }),
        "mem" => reports.sort_by(|left, right| {
            right
                .metrics
                .memory_bytes
                .cmp(&left.metrics.memory_bytes)
                .then_with(|| left.name.cmp(&right.name))
        }),
        _ => reports.sort_by(|left, right| left.name.cmp(&right.name)),
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: JSON output
//--------------------------------------------------------------------------------------------------

fn print_json_snapshot(args: &MetricsArgs, reports: &[SandboxMetricsReport]) -> anyhow::Result<()> {
    if args.name.is_some() {
        let report = reports
            .first()
            .ok_or_else(|| anyhow!("no metrics available"))?;
        println!("{}", serde_json::to_string_pretty(&metrics_json(report))?);
        return Ok(());
    }

    let mut sorted: Vec<&SandboxMetricsReport> = reports.iter().collect();
    sorted.sort_by(|left, right| left.name.cmp(&right.name));
    let json = serde_json::Value::Array(sorted.iter().map(|report| metrics_json(report)).collect());
    println!("{}", serde_json::to_string_pretty(&json)?);
    Ok(())
}

fn metrics_json(report: &SandboxMetricsReport) -> serde_json::Value {
    let metrics = &report.metrics;
    serde_json::json!({
        "name": report.name,
        "state": state_str(report.state),
        "cpus": report.cpus,
        "timestamp": metrics.timestamp.to_rfc3339(),
        "cpu_percent": metrics.cpu_percent,
        "vcpu_time_ns": metrics.vcpu_time_ns,
        "memory_bytes": metrics.memory_bytes,
        "memory_available_bytes": metrics.memory_available_bytes,
        "memory_host_resident_bytes": metrics.memory_host_resident_bytes,
        "memory_limit_bytes": metrics.memory_limit_bytes,
        "disk_read_bytes": metrics.disk_read_bytes,
        "disk_write_bytes": metrics.disk_write_bytes,
        "net_rx_bytes": metrics.net_rx_bytes,
        "net_tx_bytes": metrics.net_tx_bytes,
        "upper_used_bytes": metrics.upper_used_bytes,
        "upper_free_bytes": metrics.upper_free_bytes,
        "upper_host_allocated_bytes": metrics.upper_host_allocated_bytes,
        "uptime_secs": metrics.uptime.as_secs_f64(),
    })
}

fn state_str(state: SandboxMetricsState) -> &'static str {
    match state {
        SandboxMetricsState::Running => "running",
        SandboxMetricsState::Stalled => "stalled",
        SandboxMetricsState::Exited => "exited",
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: helpers
//--------------------------------------------------------------------------------------------------

/// Parse `--interval` values like `500ms`, `2s`, `1m`, or a bare number of
/// seconds. Clamped to [`MIN_INTERVAL`].
fn parse_interval(raw: &str) -> anyhow::Result<Duration> {
    let raw = raw.trim();
    let parsed = if let Some(ms) = raw.strip_suffix("ms") {
        ms.trim().parse::<u64>().ok().map(Duration::from_millis)
    } else if let Some(m) = raw.strip_suffix('m') {
        m.trim()
            .parse::<u64>()
            .ok()
            .map(|mins| Duration::from_secs(mins * 60))
    } else if let Some(s) = raw.strip_suffix('s') {
        s.trim().parse::<f64>().ok().map(Duration::from_secs_f64)
    } else {
        raw.parse::<f64>().ok().map(Duration::from_secs_f64)
    };
    let interval = parsed
        .filter(|duration| !duration.is_zero())
        .ok_or_else(|| anyhow!("invalid --interval {raw:?} (expected e.g. 500ms, 2s)"))?;
    Ok(interval.max(MIN_INTERVAL))
}

fn format_interval(interval: Duration) -> String {
    if interval < Duration::from_secs(1) {
        format!("{}ms", interval.as_millis())
    } else {
        format!("{:.1}s", interval.as_secs_f64())
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RateTracker {
    /// Fold a new collection of reports into the tracker, returning the
    /// per-run rates that could be derived for this tick.
    fn update(&mut self, reports: &[SandboxMetricsReport]) -> HashMap<i32, Rates> {
        let mut out = HashMap::new();
        for report in reports {
            let metric = &report.metrics;
            let current = PrevSample {
                timestamp: metric.timestamp,
                disk_read_bytes: metric.disk_read_bytes,
                disk_write_bytes: metric.disk_write_bytes,
                net_rx_bytes: metric.net_rx_bytes,
                net_tx_bytes: metric.net_tx_bytes,
            };
            if let Some(prev) = self.prev.get(&report.run_id) {
                let delta_t = current
                    .timestamp
                    .signed_duration_since(prev.timestamp)
                    .num_milliseconds() as f64
                    / 1000.0;
                if delta_t > 0.0 {
                    let rate = |cur: u64, old: u64| cur.saturating_sub(old) as f64 / delta_t;
                    let rates = Rates {
                        disk_read: rate(current.disk_read_bytes, prev.disk_read_bytes),
                        disk_write: rate(current.disk_write_bytes, prev.disk_write_bytes),
                        net_rx: rate(current.net_rx_bytes, prev.net_rx_bytes),
                        net_tx: rate(current.net_tx_bytes, prev.net_tx_bytes),
                    };
                    self.last_rates.insert(report.run_id, rates);
                }
            }
            self.prev.insert(report.run_id, current);
            if let Some(rates) = self.last_rates.get(&report.run_id) {
                out.insert(report.run_id, *rates);
            }
        }
        out
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_interval_accepts_common_forms() {
        assert_eq!(parse_interval("500ms").unwrap(), Duration::from_millis(500));
        assert_eq!(parse_interval("2s").unwrap(), Duration::from_secs(2));
        assert_eq!(parse_interval("1m").unwrap(), Duration::from_secs(60));
        assert_eq!(parse_interval("3").unwrap(), Duration::from_secs(3));
        assert_eq!(parse_interval("0.5").unwrap(), Duration::from_millis(500));
    }

    #[test]
    fn parse_interval_clamps_and_rejects() {
        assert_eq!(parse_interval("1ms").unwrap(), MIN_INTERVAL);
        assert!(parse_interval("fast").is_err());
        assert!(parse_interval("0").is_err());
        assert!(parse_interval("").is_err());
    }

    #[test]
    fn format_cpu_prefers_cores_over_percent() {
        assert_eq!(format_cpu(80.0, Some(2)), "0.80 / 2c");
        assert_eq!(format_cpu(80.0, None), "80.0%");
    }

    fn report(run_id: i32, ts_ms: i64, disk_read: u64) -> SandboxMetricsReport {
        use microsandbox::sandbox::SandboxMetrics;
        SandboxMetricsReport {
            name: "x".into(),
            sandbox_id: 1,
            run_id,
            state: SandboxMetricsState::Running,
            cpus: Some(1),
            metrics: SandboxMetrics {
                cpu_percent: 0.0,
                vcpu_time_ns: 0,
                memory_bytes: 0,
                memory_available_bytes: None,
                memory_host_resident_bytes: None,
                memory_limit_bytes: 0,
                disk_read_bytes: disk_read,
                disk_write_bytes: 0,
                net_rx_bytes: 0,
                net_tx_bytes: 0,
                upper_used_bytes: None,
                upper_free_bytes: None,
                upper_host_allocated_bytes: None,
                uptime: Duration::from_secs(1),
                timestamp: chrono::DateTime::from_timestamp_millis(ts_ms).unwrap(),
            },
        }
    }

    #[test]
    fn rate_tracker_derives_per_second_rates() {
        let mut tracker = RateTracker::default();
        assert!(tracker.update(&[report(1, 1_000, 0)]).is_empty());

        // 4096 bytes over 500ms -> 8192 B/s.
        let rates = tracker.update(&[report(1, 1_500, 4096)]);
        assert_eq!(rates.get(&1).unwrap().disk_read, 8192.0);

        // No new sample: previous rate is reused, not dropped.
        let rates = tracker.update(&[report(1, 1_500, 4096)]);
        assert_eq!(rates.get(&1).unwrap().disk_read, 8192.0);

        // A new run id starts a fresh window.
        assert!(!tracker.update(&[report(2, 2_000, 10)]).contains_key(&2));
    }
}
