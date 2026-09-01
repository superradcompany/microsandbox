//! `msb create` command — create and boot a fresh sandbox.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use super::common::{SandboxOpts, apply_sandbox_opts, apply_sandbox_opts_after_config};
use crate::{sandbox_config, ui};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Create a sandbox and boot it in the background.
#[derive(Debug, Args)]
pub struct CreateArgs {
    /// Image to use (e.g. alpine, python, ./rootfs, ./disk.qcow2).
    ///
    /// May be omitted when a config file supplies `image`.
    #[arg(conflicts_with = "from_snapshot")]
    pub image: Option<String>,

    /// Create from a snapshot artifact instead of an image.
    #[arg(long = "from-snapshot", value_name = "PATH_OR_NAME")]
    pub from_snapshot: Option<String>,

    /// Cold-boot only the disk state when the source is a full snapshot.
    #[arg(long, requires = "from_snapshot")]
    pub disk_only: bool,

    /// Sandbox configuration options.
    #[command(flatten)]
    pub sandbox: SandboxOpts,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb create` command.
pub async fn run(
    mut args: CreateArgs,
    log_level: Option<microsandbox::LogLevel>,
) -> anyhow::Result<()> {
    let is_named = args.sandbox.name.is_some();
    let name = args.sandbox.name.clone().unwrap_or_else(ui::generate_name);

    if args.sandbox.log_level.is_none()
        && let Some(log_level) = log_level
    {
        args.sandbox.log_level = Some(log_level.to_string());
    }

    let resolved = sandbox_config::resolve(&args.sandbox.config)?;
    let image = resolved.image(args.image.as_deref(), args.from_snapshot.as_deref())?;
    let builder = resolved.apply(Sandbox::builder(&name))?;
    let mut builder = image.apply(builder)?;
    if args.disk_only {
        builder = builder.disk_only();
    }
    let builder = if resolved.loaded() {
        apply_sandbox_opts_after_config(builder, &args.sandbox)?
    } else {
        apply_sandbox_opts(builder, &args.sandbox)?
    };

    let (mut progress, task) = builder
        .detached(true)
        .create_detached_with_pull_progress()?;
    let mut display = if args.sandbox.quiet {
        ui::PullProgressDisplay::quiet(&image.display())
    } else {
        ui::PullProgressDisplay::new(&image.display())
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
