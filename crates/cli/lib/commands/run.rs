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

    let spinner = ui::Spinner::start("Creating", &name);

    let mut builder = Sandbox::builder(&name).image(args.image.as_str());

    if let Some(cpus) = args.cpus {
        builder = builder.cpus(cpus);
    }
    if let Some(ref mem) = args.memory {
        builder = builder.memory(ui::parse_memory(mem).map_err(anyhow::Error::msg)?);
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

    let sandbox = match if args.detach {
        builder.create_detached().await
    } else {
        builder.create().await
    } {
        Ok(s) => {
            spinner.finish_success("Created");
            s
        }
        Err(e) => {
            spinner.finish_error();
            return Err(e.into());
        }
    };

    // Detach mode: just print the name and exit.
    if args.detach {
        sandbox.detach().await;
        println!("{name}");
        return Ok(());
    }

    if !args.command.is_empty() {
        // Non-interactive: exec command and stream output.
        let cmd = args.command[0].clone();
        let cmd_args: Vec<String> = args.command[1..].to_vec();

        let output = sandbox
            .exec(&cmd, |e: ExecOptionsBuilder| e.args(cmd_args))
            .await?;

        std::io::stdout().write_all(&output.stdout)?;
        std::io::stderr().write_all(&output.stderr)?;

        // Stop and clean up.
        let _ = sandbox.stop().await;
        let _ = sandbox.wait().await;

        // Remove unnamed (ephemeral) sandboxes.
        if !is_named {
            let _ = Sandbox::remove(&name).await;
        }

        if !output.status.success {
            std::process::exit(output.status.code);
        }
    } else {
        // Interactive: attach to sandbox shell.
        let exit_code = sandbox.attach((), ()).await?;

        // Stop and clean up.
        let _ = sandbox.stop().await;
        let _ = sandbox.wait().await;

        // Remove unnamed (ephemeral) sandboxes.
        if !is_named {
            let _ = Sandbox::remove(&name).await;
        }

        if exit_code != 0 {
            std::process::exit(exit_code);
        }
    }

    Ok(())
}
