//! `msb remove` command — remove a stopped sandbox.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Remove one or more sandboxes.
#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Sandbox(es) to remove.
    #[arg(required = true)]
    pub names: Vec<String>,

    /// Stop the sandbox if running, then remove it.
    #[arg(long)]
    pub force: bool,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb remove` command.
pub async fn run(args: RemoveArgs) -> anyhow::Result<()> {
    let mut failed = false;

    for name in &args.names {
        if args.force {
            // Kill the sandbox first if it's running.
            if let Ok(mut handle) = Sandbox::get(name).await {
                let _ = handle.kill().await;
            }
        }

        let spinner = if args.quiet {
            ui::Spinner::quiet()
        } else {
            ui::Spinner::start("Removing", name)
        };

        match Sandbox::remove(name).await {
            Ok(()) => {
                spinner.finish_success("Removed");
            }
            Err(e) => {
                spinner.finish_error();
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
