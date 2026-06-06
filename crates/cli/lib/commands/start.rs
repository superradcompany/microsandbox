//! `msb start` command — start/resume an existing stopped sandbox.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use crate::ui;

use super::common;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Start a stopped sandbox.
#[derive(Debug, Args)]
pub struct StartArgs {
    /// Sandbox(es) to start. Required unless `--label` is given.
    #[arg(required_unless_present = "label")]
    pub names: Vec<String>,

    /// Start every sandbox carrying this label (`KEY=VALUE`). Repeatable;
    /// AND-matched. Unioned with any explicitly named sandboxes.
    #[arg(long)]
    pub label: Vec<String>,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb start` command.
pub async fn run(args: StartArgs) -> anyhow::Result<()> {
    let names = common::resolve_bulk_targets(&args.names, &args.label, args.quiet).await?;
    let mut failed = false;

    for name in &names {
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
