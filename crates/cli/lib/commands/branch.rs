//! Direct local execution forking without a durable full snapshot.

use clap::Args;
use microsandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Create an independent child from a running or user-paused local sandbox.
#[derive(Debug, Args)]
pub struct BranchArgs {
    /// Optional guest writeback: auto, required, or skip. Auto preserves dirty RAM.
    #[arg(long, default_value = "auto")]
    pub guest_flush: microsandbox::snapshot::GuestFlush,
    /// Source sandbox name.
    pub source: String,
    /// Name of the new child sandbox.
    #[arg(
        short,
        long,
        required_unless_present = "names",
        conflicts_with = "names"
    )]
    pub name: Option<String>,
    /// Capture once for these independent children, in input order.
    #[arg(long, num_args = 1.., conflicts_with = "name")]
    pub names: Vec<String>,
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

/// Fork source execution. The child's CoW memory is inherent to this operation.
pub async fn run(args: BranchArgs) -> anyhow::Result<()> {
    let source = Sandbox::get(&args.source).await?;
    if !args.names.is_empty() {
        let mut builder = args
            .resources
            .apply_branch_many(source.fork_many(args.names).guest_flush(args.guest_flush))?;
        if args.integrity {
            builder = builder.record_integrity();
        }
        let outcomes = builder.fork().await?;
        let mut failed = 0;
        for outcome in outcomes {
            match outcome.result {
                Ok(child) => {
                    super::common::display_restore_warnings(&child).await;
                    if !args.quiet {
                        ui::success("Forked", child.name());
                    }
                    child.detach().await;
                }
                Err(error) => {
                    failed += 1;
                    eprintln!("{}: {error}", outcome.name);
                }
            }
        }
        anyhow::ensure!(
            failed == 0,
            "{failed} batch children failed; successful children were retained"
        );
        return Ok(());
    }
    let mut builder = args.resources.apply_branch(
        source
            .fork(args.name.expect("clap requires a child name"))
            .guest_flush(args.guest_flush),
    )?;
    if args.integrity {
        builder = builder.record_integrity();
    }
    let (mut progress, task) = builder.fork_with_progress()?;
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
    let child = result.map_err(|error| anyhow::anyhow!("fork task failed: {error}"))??;
    super::common::display_restore_warnings(&child).await;
    if !args.quiet {
        ui::success("Forked", child.name());
    }
    child.detach().await;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        branch: BranchArgs,
    }

    #[test]
    fn single_and_list_are_mutually_exclusive() {
        let single = Command::try_parse_from(["msb", "source", "--name", "child"]).unwrap();
        assert_eq!(single.branch.name.as_deref(), Some("child"));
        let batch =
            Command::try_parse_from(["msb", "source", "--names", "a", "b", "--integrity"]).unwrap();
        assert_eq!(batch.branch.names, ["a", "b"]);
        assert!(batch.branch.integrity);
        for args in [
            vec!["msb", "source"],
            vec!["msb", "source", "--names"],
            vec!["msb", "source", "--name", "a", "--names", "b"],
            vec!["msb", "source", "-n", "a", "--names", "b"],
        ] {
            assert!(Command::try_parse_from(args).is_err());
        }
    }

    #[test]
    fn both_fork_forms_accept_mount_disk() {
        let spec = "/images/seed.img:/data:ro";
        let single =
            Command::try_parse_from(["msb", "source", "--name", "child", "--mount-disk", spec])
                .unwrap();
        assert_eq!(single.branch.resources.mount_disk, [spec]);
        let batch =
            Command::try_parse_from(["msb", "source", "--names", "a", "b", "--mount-disk", spec])
                .unwrap();
        assert_eq!(batch.branch.resources.mount_disk, [spec]);
    }
}
