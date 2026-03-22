//! `msb run` command — create and start a new sandbox.

use std::io::Write;

use clap::Args;
use microsandbox::sandbox::{ExecOptionsBuilder, Sandbox};

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

    let sandbox = if args.detach {
        let spinner = if args.quiet {
            ui::Spinner::quiet()
        } else {
            ui::Spinner::start("Creating", &name)
        };
        match builder.create_detached().await {
            Ok(s) => {
                spinner.finish_success("Created");
                s
            }
            Err(e) => {
                spinner.finish_error();
                return Err(e.into());
            }
        }
    } else {
        // Non-detach: use pull progress display for per-layer feedback.
        let (mut progress, task) = builder.create_with_pull_progress()?;
        let mut display = if args.quiet {
            ui::PullProgressDisplay::quiet(&args.image)
        } else {
            ui::PullProgressDisplay::new(&args.image)
        };

        while let Some(event) = progress.recv().await {
            display.handle_event(event);
        }

        match task.await {
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

    let exit_code = if !args.command.is_empty() {
        // Non-interactive: exec command and stream output.
        let cmd = args.command[0].clone();
        let cmd_args: Vec<String> = args.command[1..].to_vec();

        let output = sandbox
            .exec(&cmd, |e: ExecOptionsBuilder| e.args(cmd_args))
            .await?;

        std::io::stdout().write_all(output.stdout_bytes())?;
        std::io::stderr().write_all(output.stderr_bytes())?;

        if output.status().success {
            0
        } else {
            output.status().code
        }
    } else {
        // Interactive: attach to sandbox shell.
        sandbox.attach((), ()).await?
    };

    // Stop and clean up.
    let _ = sandbox.stop_and_wait().await;

    // Remove unnamed (ephemeral) sandboxes.
    if !is_named {
        let _ = Sandbox::remove(&name).await;
    }

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}
