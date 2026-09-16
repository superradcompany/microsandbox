//! Explicit resident pause and resume.

use clap::Args;
use microsandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Arguments for resident pause.
#[derive(Debug, Args)]
pub struct PauseArgs {
    /// Optional guest writeback: auto, required, or skip. Required establishes a flushed pause.
    #[arg(long)]
    pub guest_flush: Option<microsandbox::snapshot::GuestFlush>,
    /// Sandbox name.
    pub name: String,
    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

/// Resume has no writeback option: it cannot improve an already captured disk boundary.
#[derive(Debug, Args)]
pub struct ResumeArgs {
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
    } else if let Some(policy) = args.guest_flush {
        sandbox.pause_with_guest_flush(policy).await?;
    } else {
        sandbox.pause().await?;
    }
    if !args.quiet {
        ui::success(if resume { "Resumed" } else { "Paused" }, &args.name);
    }
    Ok(())
}
