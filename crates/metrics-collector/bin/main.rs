//! `msb-metrics` — sibling-process metrics collector that reads the
//! shared-memory registry and ships data to backends.
//!
//! Skeleton. Subcommands (`otel`, …) land in follow-on commits.

use clap::Parser;

#[derive(Debug, Parser)]
#[command(
    name = "msb-metrics",
    about = "microsandbox metrics collector",
    version
)]
struct Cli {}

fn main() -> anyhow::Result<()> {
    let _cli = Cli::parse();
    eprintln!("msb-metrics: no subcommand wired yet — see docs/msb-metrics-binary-plan.md");
    Ok(())
}
