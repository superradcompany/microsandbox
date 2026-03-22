//! `msb run` command — create and start a new sandbox.

use std::io::{IsTerminal, Write};

use clap::Args;
use microsandbox::sandbox::Sandbox;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Create and start a new sandbox.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Image reference (OCI image, directory, or disk image).
    pub image: String,

    /// Sandbox name. Auto-generated if not provided.
    #[arg(short, long)]
    pub name: Option<String>,

    /// Number of virtual CPUs.
    #[arg(short = 'c', long)]
    pub cpus: Option<u8>,

    /// Memory limit (e.g., 512M, 1G).
    #[arg(short, long)]
    pub memory: Option<String>,

    /// Volume mount (host:guest or name:guest). Can be repeated.
    #[arg(short, long)]
    pub volume: Vec<String>,

    /// Working directory inside sandbox.
    #[arg(short, long)]
    pub workdir: Option<String>,

    /// Default shell.
    #[arg(long)]
    pub shell: Option<String>,

    /// Environment variable (KEY=value). Can be repeated.
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Replace existing stopped sandbox with same name.
    #[arg(long)]
    pub force: bool,

    /// Run in background (detach).
    #[arg(short, long)]
    pub detach: bool,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,

    /// Command to execute (after --).
    #[arg(last = true)]
    pub command: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb run` command.
pub async fn run(args: RunArgs) -> anyhow::Result<()> {
    let is_named = args.name.is_some();
    let name = args.name.unwrap_or_else(ui::generate_name);

    let mut builder = Sandbox::builder(&name).image(args.image.as_str());

    if let Some(cpus) = args.cpus {
        builder = builder.cpus(cpus);
    }
    if let Some(ref mem) = args.memory {
        builder = builder.memory(ui::parse_size_mib(mem).map_err(anyhow::Error::msg)?);
    }
    if let Some(ref workdir) = args.workdir {
        builder = builder.workdir(workdir);
    }
    if let Some(ref shell) = args.shell {
        builder = builder.shell(shell);
    }
    if args.force {
        builder = builder.overwrite();
    }
    for env_str in &args.env {
        let (k, v) = ui::parse_env(env_str).map_err(anyhow::Error::msg)?;
        builder = builder.env(k, v);
    }
    for vol_str in &args.volume {
        builder = super::create::apply_volume(builder, vol_str)?;
    }

    // Create sandbox with pull progress — select attached vs detached mode.
    let (mut progress, task) = if args.detach {
        builder.create_detached_with_pull_progress()?
    } else {
        builder.create_with_pull_progress()?
    };

    let mut display = if args.quiet {
        ui::PullProgressDisplay::quiet(&args.image)
    } else {
        ui::PullProgressDisplay::new(&args.image)
    };

    while let Some(event) = progress.recv().await {
        display.handle_event(event);
    }

    let sandbox = match task.await {
        Ok(Ok(s)) => {
            display.finish();
            s
        }
        Ok(Err(e)) => {
            display.finish();
            return Err(e.into());
        }
        Err(e) => {
            display.finish();
            return Err(anyhow::anyhow!("create task panicked: {e}"));
        }
    };

    // Detach mode: just print the name and exit.
    if args.detach {
        sandbox.detach().await;
        if !is_named {
            println!("{name}");
        }
        return Ok(());
    }

    let interactive = std::io::stdin().is_terminal();

    let exit_code = if !args.command.is_empty() {
        let mut parts = args.command;
        let cmd = parts.remove(0);
        let cmd_args = parts;

        if interactive {
            sandbox.attach(cmd, |a| a.args(cmd_args)).await?
        } else {
            let output = sandbox.exec(&cmd, |e| e.args(cmd_args)).await?;

            std::io::stdout().write_all(output.stdout_bytes())?;
            std::io::stderr().write_all(output.stderr_bytes())?;

            if output.status().success {
                0
            } else {
                output.status().code
            }
        }
    } else if interactive {
        // No command, TTY — interactive shell.
        let shell = sandbox.config().shell.as_deref().unwrap_or("/bin/sh");
        sandbox.attach(shell, |a| a).await?
    } else {
        // No command, no TTY — nothing to do.
        ui::warn("no command provided and stdin is not a terminal");
        0
    };

    // Stop and clean up.
    if let Err(e) = sandbox.stop_and_wait().await {
        ui::warn(&format!("failed to stop sandbox: {e}"));
    }

    // Remove unnamed (ephemeral) sandboxes.
    if !is_named {
        let _ = Sandbox::remove(&name).await;
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}
