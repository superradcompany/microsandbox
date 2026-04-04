//! `msb run` command — create and start a new sandbox.

use std::io::{IsTerminal, Write};
use std::time::Duration;

use clap::Args;
use microsandbox::sandbox::{ExecOutput, RlimitResource, Sandbox};

use super::common::{SandboxOpts, apply_sandbox_opts};
use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Create a sandbox from an image and run a command in it.
#[derive(Debug, Args)]
pub struct RunArgs {
    /// Image to use (e.g. alpine, python, ./rootfs, ./disk.qcow2).
    pub image: String,

    /// Start the sandbox in the background and print its name.
    #[arg(short, long)]
    pub detach: bool,

    /// Allocate a pseudo-terminal (enables colors, line editing).
    #[arg(short = 't', long)]
    pub tty: bool,

    /// Kill the command after this duration (e.g. 30s, 5m, 1h).
    #[arg(long)]
    pub timeout: Option<String>,

    /// Set a POSIX resource limit (e.g. nofile=1024, nproc=64, as=1073741824).
    #[arg(long)]
    pub rlimit: Vec<String>,

    /// Key sequence to detach from interactive session (default: ctrl-]).
    #[arg(long)]
    pub detach_keys: Option<String>,

    /// Command to run inside the sandbox (after --).
    #[arg(last = true)]
    pub command: Vec<String>,

    /// Sandbox configuration options.
    #[command(flatten)]
    pub sandbox: SandboxOpts,
}

/// Parsed per-command execution options for `msb run`.
struct ExecOpts {
    tty: bool,
    timeout: Option<Duration>,
    rlimits: Vec<(RlimitResource, u64, u64)>,
    detach_keys: Option<String>,
}

impl ExecOpts {
    fn parse(args: &RunArgs) -> anyhow::Result<Self> {
        let rlimits: Vec<_> = args
            .rlimit
            .iter()
            .map(|s| super::common::parse_rlimit(s))
            .collect::<anyhow::Result<Vec<_>>>()?;

        let timeout = match &args.timeout {
            Some(t) => Some(Duration::from_secs(super::common::parse_duration_secs(t)?)),
            None => None,
        };

        Ok(Self {
            tty: args.tty,
            timeout,
            rlimits,
            detach_keys: args.detach_keys.clone(),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb run` command.
pub async fn run(args: RunArgs) -> anyhow::Result<()> {
    let is_named = args.sandbox.name.is_some();
    let name = args.sandbox.name.clone().unwrap_or_else(ui::generate_name);

    // Named sandboxes are reused if they already exist (unless --replace).
    if is_named && !args.sandbox.replace && Sandbox::get(&name).await.is_ok() {
        return run_existing(name, args).await;
    }

    run_new(name, is_named, args).await
}

/// Run in an existing named sandbox — start if stopped, connect if running.
async fn run_existing(name: String, args: RunArgs) -> anyhow::Result<()> {
    if args.sandbox.has_creation_flags() {
        ui::warn(&format!(
            "sandbox '{name}' already exists; image and resource flags ignored (use --replace to recreate)"
        ));
    }

    let sandbox = super::resolve_and_start(&name, args.sandbox.quiet).await?;

    // Detach mode: ensure running and exit.
    if args.detach {
        sandbox.detach().await;
        return Ok(());
    }

    let exec_opts = ExecOpts::parse(&args)?;
    let interactive = args.tty && std::io::stdin().is_terminal();

    let result: anyhow::Result<i32> = async {
        let (cmd, cmd_args) = resolve_command(sandbox.config(), args.command, interactive)?;
        match cmd {
            Some(cmd) => exec_in_sandbox(&sandbox, &cmd, cmd_args, interactive, &exec_opts).await,
            None => Ok(0),
        }
    }
    .await;

    // Stop only if we own the lifecycle (i.e., we started it from stopped).
    // Always runs, even if resolve_command or exec failed.
    super::maybe_stop(&sandbox).await;

    handle_exit(result?)
}

/// Create a new sandbox and run in it.
async fn run_new(name: String, is_named: bool, args: RunArgs) -> anyhow::Result<()> {
    let builder = Sandbox::builder(&name).image(args.image.as_str());
    let builder = apply_sandbox_opts(builder, &args.sandbox)?;

    // Create sandbox with pull progress — select attached vs detached mode.
    let (mut progress, task) = if args.detach {
        builder.create_detached_with_pull_progress()?
    } else {
        builder.create_with_pull_progress()?
    };

    let mut display = if args.sandbox.quiet {
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

    let exec_opts = ExecOpts::parse(&args)?;
    let interactive = args.tty && std::io::stdin().is_terminal();

    let (cmd, cmd_args) = resolve_command(sandbox.config(), args.command, interactive)?;
    let (cmd, cmd_args) = match (cmd, cmd_args) {
        (Some(cmd), args) => (cmd, args),
        (None, _) => {
            if let Err(e) = sandbox.stop_and_wait().await {
                ui::warn(&format!("failed to stop sandbox: {e}"));
            }
            if !is_named {
                let _ = sandbox.remove_persisted().await;
            }
            return Ok(());
        }
    };

    let result = exec_in_sandbox(&sandbox, &cmd, cmd_args, interactive, &exec_opts).await;

    // Cleanup always runs, even on exec/attach/IO errors.
    if let Err(e) = sandbox.stop_and_wait().await {
        ui::warn(&format!("failed to stop sandbox: {e}"));
    }

    // Remove unnamed (ephemeral) sandboxes.
    if !is_named {
        let _ = sandbox.remove_persisted().await;
    }

    handle_exit(result?)
}

/// Resolve the command to run following OCI semantics.
///
/// Returns `(Some(cmd), args)` or `(None, _)` when no command is available.
fn resolve_command(
    config: &microsandbox::sandbox::SandboxConfig,
    user_command: Vec<String>,
    interactive: bool,
) -> anyhow::Result<(Option<String>, Vec<String>)> {
    if !user_command.is_empty() {
        match &config.entrypoint {
            Some(ep) if !ep.is_empty() => {
                let bin = ep[0].clone();
                let args = ep[1..].iter().cloned().chain(user_command).collect();
                Ok((Some(bin), args))
            }
            _ => {
                let mut parts = user_command;
                let cmd = parts.remove(0);
                Ok((Some(cmd), parts))
            }
        }
    } else if let Some((cmd, cmd_args)) = resolve_image_command(config) {
        Ok((Some(cmd), cmd_args))
    } else if interactive {
        let shell = config.shell.as_deref().unwrap_or("/bin/sh");
        Ok((Some(shell.to_string()), vec![]))
    } else {
        ui::warn("no command provided and stdin is not a terminal");
        Ok((None, vec![]))
    }
}

/// Execute or attach to a command in a sandbox.
async fn exec_in_sandbox(
    sandbox: &Sandbox,
    cmd: &str,
    cmd_args: Vec<String>,
    interactive: bool,
    opts: &ExecOpts,
) -> anyhow::Result<i32> {
    if interactive {
        let rlimits = opts.rlimits.clone();
        let detach_keys = opts.detach_keys.clone();
        let has_opts = !rlimits.is_empty() || detach_keys.is_some();
        if has_opts {
            Ok(sandbox
                .attach_with(cmd, |a| {
                    let mut a = a.args(cmd_args);
                    for (resource, soft, hard) in rlimits {
                        a = a.rlimit_range(resource, soft, hard);
                    }
                    if let Some(keys) = detach_keys {
                        a = a.detach_keys(keys);
                    }
                    a
                })
                .await?)
        } else {
            Ok(sandbox.attach(cmd, cmd_args).await?)
        }
    } else {
        let rlimits = opts.rlimits.clone();
        let timeout = opts.timeout;
        let tty = opts.tty;
        let has_opts = tty || timeout.is_some() || !rlimits.is_empty();
        let output: ExecOutput = if has_opts {
            sandbox
                .exec_with(cmd, |e| {
                    let mut e = e.args(cmd_args);
                    if tty {
                        e = e.tty(true);
                    }
                    if let Some(t) = timeout {
                        e = e.timeout(t);
                    }
                    for (resource, soft, hard) in rlimits {
                        e = e.rlimit_range(resource, soft, hard);
                    }
                    e
                })
                .await?
        } else {
            sandbox.exec(cmd, cmd_args).await?
        };

        std::io::stdout().write_all(output.stdout_bytes())?;
        std::io::stderr().write_all(output.stderr_bytes())?;

        Ok(if output.status().success {
            0
        } else {
            output.status().code
        })
    }
}

/// Exit the process with a non-zero code if needed.
fn handle_exit(exit_code: i32) -> anyhow::Result<()> {
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
