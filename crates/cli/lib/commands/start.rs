//! `msb start` command — start/resume an existing stopped sandbox.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Start a stopped sandbox.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Sandbox(es) to start.
    #[arg(required = true)]
    pub names: Vec<String>,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb start` command.
pub async fn run(args: StartArgs) -> anyhow::Result<()> {
    let mut failed = false;

    for name in &args.names {
        let spinner = if args.quiet {
            ui::Spinner::quiet()
        } else {
            ui::Spinner::start("Starting", name)
        };

        match Sandbox::start_detached(name).await {
            Ok(sandbox) => {
                sandbox.detach().await;
                spinner.finish_success("Started");
            }
            Err(e) => {
                spinner.finish_clear();
                if !args.quiet {
                    ui::error(&format!("{e}"));
                }
                failed = true;
            }
        }
    }

    if failed {
        std::process::exit(1);
    }

    Ok(())
}
