//! `msb stop` command — stop a running sandbox.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Stop a running sandbox.
#[derive(Debug, Args)]
pub struct StopArgs {
    /// Sandbox to stop.
    pub name: String,

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
    let spinner = if args.quiet {
        ui::Spinner::quiet()
    } else {
        ui::Spinner::start("Stopping", &args.name)
    };

    let mut handle = Sandbox::get(&args.name).await?;
    let result = if args.force {
        handle.kill().await
    } else if let Some(timeout_secs) = args.timeout {
        match tokio::time::timeout(std::time::Duration::from_secs(timeout_secs), handle.stop())
            .await
        {
            Ok(stop_result) => stop_result,
            Err(_) => handle.kill().await,
        }
    } else {
        handle.stop().await
    };

    match result {
        Ok(()) => {
            spinner.finish_success("Stopped");
        }
        Err(e) => {
            spinner.finish_error();
            return Err(e.into());
        }
    }

    Ok(())
}
