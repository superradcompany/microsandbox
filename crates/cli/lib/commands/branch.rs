//! Direct local execution branching without a durable full snapshot.

use clap::Args;
use microsandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Create an independent child from a running or user-paused local sandbox.
#[derive(Debug, Args)]
pub struct BranchArgs {
    /// Source sandbox name.
    pub source: String,
    /// Name of the new child sandbox.
    #[arg(long)]
    pub name: String,
    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
    /// Compute and record disk content integrity for the captured layers.
    #[arg(long)]
    pub integrity: bool,
    /// Explicit destination resources, with the same defaults as restore.
    #[command(flatten)]
    pub resources: super::restore::RestoreResourceArgs,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Branch source execution. The child's CoW memory is inherent to this operation.
pub async fn run(args: BranchArgs) -> anyhow::Result<()> {
    let source = Sandbox::get(&args.source).await?;
    let mut builder = args.resources.apply_branch(source.branch(&args.name))?;
    if args.integrity {
        builder = builder.record_integrity();
    }
    let (mut progress, task) = builder.branch_with_progress()?;
    let mut display = if args.quiet {
        ui::PullProgressDisplay::quiet(&args.source)
    } else {
        ui::PullProgressDisplay::new(&args.source)
    };
    while let Some(event) = progress.recv().await {
        display.handle_creation_event(event);
    }
    let result = task.await;
    display.finish();
    let child = result.map_err(|error| anyhow::anyhow!("branch task failed: {error}"))??;
    super::common::display_restore_warnings(&child).await;
    if !args.quiet {
        ui::success("Branched", child.name());
    }
    child.detach().await;
    Ok(())
}
