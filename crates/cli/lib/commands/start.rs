//! `msb start` command — start/resume an existing stopped sandbox.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Start/resume an existing stopped sandbox.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Name of the sandbox to start.
    pub name: String,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb start` command.
pub async fn run(args: StartArgs) -> anyhow::Result<()> {
    let spinner = if args.quiet {
        ui::Spinner::quiet()
    } else {
        ui::Spinner::start("Starting", &args.name)
    };

    match Sandbox::start_detached(&args.name).await {
        Ok(sandbox) => {
            sandbox.detach().await;
            spinner.finish_success("Started");
            // Sandbox stays running — supervisor continues as background process.
        }
        Err(e) => {
            spinner.finish_error();
            return Err(e.into());
        }
    }

    Ok(())
}
