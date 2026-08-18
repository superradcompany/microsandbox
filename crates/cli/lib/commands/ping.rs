//! `msb ping` command — check agent reachability for running sandboxes.

use std::time::Duration;

use clap::Args;
use microsandbox::sandbox::Sandbox;
use serde::Serialize;

use crate::ui;

use super::common;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Check whether one or more sandbox agents are reachable.
#[derive(Debug, Args)]
pub struct PingArgs {
    /// Sandbox(es) to ping. Required unless `--label` is given.
    #[arg(required_unless_present = "label")]
    pub names: Vec<String>,

    /// Ping every sandbox carrying this label (`KEY=VALUE`). Repeatable;
    /// AND-matched. Unioned with any explicitly named sandboxes.
    #[arg(long)]
    pub label: Vec<String>,

    /// Refresh the sandbox idle timer after a successful ping.
    #[arg(long)]
    pub touch: bool,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,
}

#[derive(Debug, Serialize)]
struct PingReport {
    name: String,
    reachable: bool,
    latency_us: Option<u64>,
    error: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PingReport {
    fn reachable(name: impl Into<String>, latency: Duration) -> Self {
        Self {
            name: name.into(),
            reachable: true,
            latency_us: Some(latency.as_micros().min(u64::MAX as u128) as u64),
            error: None,
        }
    }

    fn unreachable(name: impl Into<String>, error: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            reachable: false,
            latency_us: None,
            error: Some(error.into()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb ping` command.
pub async fn run(args: PingArgs) -> anyhow::Result<()> {
    let json = args.format.as_deref() == Some("json");
    let quiet = args.quiet || json;
    let names = common::resolve_bulk_targets(&args.names, &args.label, quiet).await?;
    let mut failed = false;
    let mut reports = Vec::with_capacity(names.len());

    for name in &names {
        match ping_one(name, args.touch, quiet).await {
            Ok(report) => {
                if let Some(error) = &report.error {
                    if !quiet {
                        ui::error(error);
                    }
                    failed = true;
                }
                reports.push(report);
            }
            Err(e) => {
                if !quiet {
                    ui::error(&format!("{e}"));
                }
                reports.push(PingReport::unreachable(name, e.to_string()));
                failed = true;
            }
        }
    }

    if json {
        println!("{}", serde_json::to_string_pretty(&reports)?);
    }

    if failed {
        std::process::exit(1);
    }

    Ok(())
}

async fn ping_one(name: &str, touch: bool, quiet: bool) -> anyhow::Result<PingReport> {
    let handle = Sandbox::get(name).await?;
    let spinner = if quiet {
        ui::Spinner::quiet()
    } else {
        ui::Spinner::start("Pinging", name)
    };

    match handle.ping().await {
        Ok(result) => {
            let report = PingReport::reachable(&result.name, result.latency);
            spinner.finish_clear();
            if !quiet {
                ui::success(
                    "Reachable",
                    &format!("{} ({})", result.name, format_latency(result.latency)),
                );
            }
            if touch && let Err(error) = touch_after_ping(name, quiet).await {
                return Ok(PingReport {
                    error: Some(format!("touch failed: {error}")),
                    ..report
                });
            }
            Ok(report)
        }
        Err(e) => {
            spinner.finish_clear();
            Err(e.into())
        }
    }
}

async fn touch_after_ping(name: &str, quiet: bool) -> anyhow::Result<()> {
    let handle = Sandbox::get(name).await?;
    let spinner = if quiet {
        ui::Spinner::quiet()
    } else {
        ui::Spinner::start("Touching", name)
    };

    match handle.touch().await {
        Ok(_) => {
            spinner.finish_success("Touched");
            Ok(())
        }
        Err(e) => {
            spinner.finish_clear();
            Err(e.into())
        }
    }
}

fn format_latency(duration: Duration) -> String {
    if duration.as_secs() > 0 {
        return microsandbox_utils::format::format_duration(duration);
    }

    let millis = duration.as_millis();
    if millis > 0 {
        return format!("{millis}ms");
    }

    format!("{}us", duration.as_micros().max(1))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: PingArgs,
    }

    fn parse_ping_args(args: &[&str]) -> PingArgs {
        TestCli::parse_from(std::iter::once("msb").chain(args.iter().copied())).args
    }

    #[test]
    fn parses_one_name() {
        let args = parse_ping_args(&["api"]);

        assert_eq!(args.names, vec!["api"]);
    }

    #[test]
    fn parses_label_touch_and_quiet() {
        let args = parse_ping_args(&["--label", "app=api", "--touch", "--quiet"]);

        assert!(args.names.is_empty());
        assert_eq!(args.label, vec!["app=api"]);
        assert!(args.touch);
        assert!(args.quiet);
    }

    #[test]
    fn parses_json_format() {
        let args = parse_ping_args(&["api", "worker", "--format", "json"]);

        assert_eq!(args.names, vec!["api", "worker"]);
        assert_eq!(args.format.as_deref(), Some("json"));
    }

    #[test]
    fn renders_mixed_ping_results_as_json() {
        let reports = vec![
            PingReport::reachable("api", Duration::from_micros(750)),
            PingReport::unreachable("worker", "connection refused"),
        ];

        assert_eq!(
            serde_json::to_value(&reports).unwrap(),
            serde_json::json!([
                {
                    "name": "api",
                    "reachable": true,
                    "latency_us": 750,
                    "error": null,
                },
                {
                    "name": "worker",
                    "reachable": false,
                    "latency_us": null,
                    "error": "connection refused",
                },
            ])
        );
    }

    #[test]
    fn formats_subsecond_latency() {
        assert_eq!(format_latency(Duration::from_micros(700)), "700us");
        assert_eq!(format_latency(Duration::from_millis(8)), "8ms");
    }
}
