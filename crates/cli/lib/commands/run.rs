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
    let interactive = std::io::stdin().is_terminal();

    let result: anyhow::Result<i32> = async {
        let (cmd, cmd_args) =
            super::common::resolve_command(sandbox.config(), args.command, interactive)?;
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
    let interactive = std::io::stdin().is_terminal();

    let (cmd, cmd_args) =
        super::common::resolve_command(sandbox.config(), args.command, interactive)?;
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
        let timeout = opts.timeout;
        let has_opts = !rlimits.is_empty() || detach_keys.is_some();

        let attach_fut = async {
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
        };

        match timeout {
            Some(duration) => match tokio::time::timeout(duration, attach_fut).await {
                Ok(result) => result,
                Err(_) => anyhow::bail!("command timed out after {duration:?}"),
            },
            None => attach_fut.await,
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
