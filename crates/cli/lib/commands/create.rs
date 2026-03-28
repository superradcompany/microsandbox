//! `msb create` command — create and boot a fresh sandbox.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use super::common::{SandboxOpts, apply_sandbox_opts};
use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Create a sandbox and boot it in the background.
#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Image to use (e.g. alpine, python:3.12, ./rootfs, ./disk.qcow2).
    pub image: String,

    /// Sandbox configuration options.
    #[command(flatten)]
    pub sandbox: SandboxOpts,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb create` command.
pub async fn run(args: CreateArgs) -> anyhow::Result<()> {
    let is_named = args.sandbox.name.is_some();
    let name = args.sandbox.name.clone().unwrap_or_else(ui::generate_name);

    let builder = Sandbox::builder(&name).image(args.image.as_str());
    let builder = apply_sandbox_opts(builder, &args.sandbox)?;

    let (mut progress, task) = builder.create_detached_with_pull_progress()?;
    let mut display = if args.sandbox.quiet {
        ui::PullProgressDisplay::quiet(&args.image)
    } else {
        ui::PullProgressDisplay::new(&args.image)
    };

    while let Some(event) = progress.recv().await {
        display.handle_event(event);
    }

    match task.await {
        Ok(Ok(sandbox)) => {
            display.finish();
            sandbox.detach().await;
            // Print auto-generated name to stdout so it's scriptable.
            if !is_named {
                println!("{name}");
            }
        }
        Ok(Err(e)) => {
            display.finish();
            return Err(e.into());
        }
        Err(e) => {
            display.finish();
            return Err(anyhow::anyhow!("create task panicked: {e}"));
        }
    }

    Ok(())
}
