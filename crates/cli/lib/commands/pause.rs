//! Explicit resident pause and resume.

use clap::Args;
use microsandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Arguments shared by resident pause and resume.
#[derive(Debug, Args)]
pub struct PauseArgs {
    /// Sandbox name.
    pub name: String,
    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Change resident execution state through host control, without opening the guest agent.
pub async fn run(args: PauseArgs, resume: bool) -> anyhow::Result<()> {
    let sandbox = Sandbox::get_for_control(&args.name).await?;
    if resume {
        sandbox.resume().await?;
    } else {
        sandbox.pause().await?;
    }
    if !args.quiet {
        ui::success(if resume { "Resumed" } else { "Paused" }, &args.name);
    }
    Ok(())
}
