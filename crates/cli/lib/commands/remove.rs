//! `msb remove` command — remove a stopped sandbox.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use crate::ui;

use super::common;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Remove one or more sandboxes.
#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Sandbox(es) to remove. Required unless `--label` is given.
    #[arg(required_unless_present = "label")]
    pub names: Vec<String>,

    /// Remove every sandbox carrying this label (`KEY=VALUE`). Repeatable;
    /// AND-matched. Unioned with any explicitly named sandboxes.
    #[arg(long)]
    pub label: Vec<String>,

    /// Stop the sandbox if running, then remove it.
    #[arg(short, long)]
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
    let names = common::resolve_bulk_targets(&args.names, &args.label, args.quiet).await?;
    let mut failed = false;

    for name in &names {
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
