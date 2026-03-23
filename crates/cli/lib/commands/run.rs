//! `msb run` command — create and start a new sandbox.

use std::io::{IsTerminal, Write};

use clap::Args;
use microsandbox::sandbox::Sandbox;
use microsandbox::sandbox::{AttachOptionsBuilder, ExecOptionsBuilder, ExecOutput};

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

    display.finish();
    let sandbox = task
        .await
        .map_err(|e| anyhow::anyhow!("create task panicked: {e}"))??;

    // Detach mode: just print the name and exit.
    if args.detach {
        sandbox.detach().await;
        if !is_named {
            println!("{name}");
        }
        return Ok(());
    }

    let interactive = std::io::stdin().is_terminal();

    // Resolve the command to run (OCI semantics):
    //   - `entrypoint` is always preserved when set.
    //   - `-- <cmd>` from the user replaces the image `cmd` (default args).
    //   - With no user command, image `entrypoint + cmd` is used.
    //   - Shell fallback only when nothing else is available.
    let (cmd, cmd_args) = if !args.command.is_empty() {
        let config = sandbox.config();
        match &config.entrypoint {
            Some(ep) if !ep.is_empty() => {
                // Entrypoint preserved, user command replaces image cmd.
                let bin = ep[0].clone();
                let args = ep[1..].iter().cloned().chain(args.command).collect();
                (bin, args)
            }
            _ => {
                // No entrypoint — user command is the full command.
                let mut parts = args.command;
                let cmd = parts.remove(0);
                (cmd, parts)
            }
        }
    } else if let Some((cmd, cmd_args)) = resolve_image_command(sandbox.config()) {
        (cmd, cmd_args)
    } else if interactive {
        let shell = sandbox.config().shell.as_deref().unwrap_or("/bin/sh");
        (shell.to_string(), vec![])
    } else {
        ui::warn("no command provided and stdin is not a terminal");

        if let Err(e) = sandbox.stop_and_wait().await {
            ui::warn(&format!("failed to stop sandbox: {e}"));
        }
        if !is_named {
            let _ = Sandbox::remove(&name).await;
        }
        return Ok(());
    };

    let result: anyhow::Result<i32> = async {
        if interactive {
            Ok(sandbox
                .attach(&cmd, |a: AttachOptionsBuilder| a.args(cmd_args))
                .await?)
        } else {
            let output: ExecOutput = sandbox
                .exec(&cmd, |e: ExecOptionsBuilder| e.args(cmd_args))
                .await?;

            std::io::stdout().write_all(output.stdout_bytes())?;
            std::io::stderr().write_all(output.stderr_bytes())?;

            Ok(if output.status().success {
                0
            } else {
                output.status().code
            })
        }
    }
    .await;

    // Cleanup always runs, even on exec/attach/IO errors.
    if let Err(e) = sandbox.stop_and_wait().await {
        ui::warn(&format!("failed to stop sandbox: {e}"));
    }

    // Remove unnamed (ephemeral) sandboxes.
    if !is_named {
        let _ = Sandbox::remove(&name).await;
    }

    let exit_code = result?;

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

/// Resolve the default process from OCI image config.
///
/// Follows OCI semantics:
/// - `entrypoint` + `cmd`: entrypoint is the binary, cmd provides default arguments.
/// - `entrypoint` only: entrypoint is the full command.
/// - `cmd` only: cmd[0] is the binary, cmd[1..] are arguments.
/// - Neither set: returns `None`.
fn resolve_image_command(
    config: &microsandbox::sandbox::SandboxConfig,
) -> Option<(String, Vec<String>)> {
    match (&config.entrypoint, &config.cmd) {
        (Some(ep), cmd) if !ep.is_empty() => {
            let bin = ep[0].clone();
            let args = ep[1..]
                .iter()
                .chain(cmd.iter().flatten())
                .cloned()
                .collect();
            Some((bin, args))
        }
        (_, Some(cmd)) if !cmd.is_empty() => {
            let bin = cmd[0].clone();
            let args = cmd[1..].to_vec();
            Some((bin, args))
        }
        _ => None,
    }
}
