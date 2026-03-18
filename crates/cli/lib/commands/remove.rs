//! `msb remove` command — remove a stopped sandbox.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Remove a stopped sandbox.
#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Name(s) of the sandbox(es) to remove.
    #[arg(required = true)]
    pub names: Vec<String>,

    /// Force removal (stop running sandbox first).
    #[arg(long)]
    pub force: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb remove` command.
pub async fn run(args: RemoveArgs) -> anyhow::Result<()> {
    for name in &args.names {
        if args.force {
            // Try to stop the sandbox first if it's running.
            let _ = Sandbox::stop_by_name(name).await;
            // Give the supervisor a moment to shut down.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
        }

        let spinner = ui::Spinner::start("Removing", name);

        match Sandbox::remove(name).await {
            Ok(()) => {
                spinner.finish_success("Removed");
            }
            Err(e) => {
                spinner.finish_error();
                ui::error(&format!("{e}"));
            }
        }
    }

    Ok(())
}
