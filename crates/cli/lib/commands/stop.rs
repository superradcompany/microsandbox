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
    /// Name of the sandbox to stop.
    pub name: String,

    /// Force kill (SIGKILL instead of graceful shutdown).
    #[arg(long)]
    pub force: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb stop` command.
pub async fn run(args: StopArgs) -> anyhow::Result<()> {
    let spinner = ui::Spinner::start("Stopping", &args.name);

    let result = if args.force {
        Sandbox::kill_by_name(&args.name).await
    } else {
        Sandbox::stop_by_name(&args.name).await
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
