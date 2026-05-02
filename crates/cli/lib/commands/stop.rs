//! `msb stop` command — stop a running sandbox.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Stop one or more running sandboxes.
#[derive(Debug, Args)]
pub struct StopArgs {
    /// Sandbox(es) to stop.
    #[arg(required = true)]
    pub names: Vec<String>,

    /// Immediately kill the sandbox without graceful shutdown.
    #[arg(short, long)]
    pub force: bool,

    /// Seconds to wait for graceful shutdown before force-killing.
    #[arg(short = 't', long)]
    pub timeout: Option<u64>,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb stop` command.
pub async fn run(args: StopArgs) -> anyhow::Result<()> {
    let mut failed = false;

    for name in &args.names {
        let spinner = if args.quiet {
            ui::Spinner::quiet()
        } else {
            ui::Spinner::start("Stopping", name)
        };

        match stop_one(name, args.force, args.timeout).await {
            Ok(()) => {
                spinner.finish_success("Stopped");
            }
            Err(e) => {
                spinner.finish_error();
                ui::error(&format!("{e}"));
                failed = true;
            }
        }
    }

    if failed {
        std::process::exit(1);
    }

    Ok(())
}

/// Stop a single sandbox.
async fn stop_one(name: &str, force: bool, timeout_secs: Option<u64>) -> anyhow::Result<()> {
    let mut handle = Sandbox::get(name).await?;
    let result = if force {
        handle.kill().await
    } else if let Some(timeout_secs) = timeout_secs {
        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), handle.stop())
            .await
        {
            Ok(stop_result) => stop_result,
            Err(_) => handle.kill().await,
        }
    } else {
        handle.stop().await
    };

    result.map_err(Into::into)
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
        args: StopArgs,
    }

    fn parse_stop_args(args: &[&str]) -> StopArgs {
        TestCli::parse_from(std::iter::once("msb").chain(args.iter().copied())).args
    }

    #[test]
    fn parses_one_name() {
        let args = parse_stop_args(&["reborn"]);

        assert_eq!(args.names, vec!["reborn"]);
    }

    #[test]
    fn parses_multiple_names() {
        let args = parse_stop_args(&["msb-28b6f33e", "reborn", "renamed"]);

        assert_eq!(args.names, vec!["msb-28b6f33e", "reborn", "renamed"]);
    }
}
