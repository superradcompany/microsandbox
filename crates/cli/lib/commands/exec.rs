//! `msb exec` command — execute a command in a sandbox.

use std::io::{IsTerminal, Write};
use std::time::Duration;

use clap::Args;
use microsandbox::sandbox::ExecOutput;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Run a command in a running sandbox.
#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Sandbox to run the command in.
    pub name: String,

    /// Set an environment variable (KEY=value).
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Set the working directory for the command.
    #[arg(short, long)]
    pub workdir: Option<String>,

    /// Run the command as the specified guest user.
    #[arg(short = 'u', long)]
    pub user: Option<String>,

    /// Allocate a pseudo-terminal (enables colors, line editing).
    #[arg(short = 't', long)]
    pub tty: bool,

    /// Kill the command after this duration (e.g. 30s, 5m, 1h).
    #[arg(long)]
    pub timeout: Option<String>,

    /// Set a POSIX resource limit (e.g. nofile=1024, nproc=64, as=1073741824).
    #[arg(long)]
    pub rlimit: Vec<String>,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,

    /// Command to run inside the sandbox (after --).
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb exec` command.
pub async fn run(args: ExecArgs) -> anyhow::Result<()> {
    let sandbox = super::resolve_and_start(&args.name, args.quiet).await?;

    let mut parts = args.command;
    let cmd = parts.remove(0);
    let cmd_args = parts;

    // Build exec options.
    let env_pairs: Vec<(String, String)> = args
        .env
        .iter()
        .map(|s| ui::parse_env(s).map_err(anyhow::Error::msg))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let workdir = args.workdir;
    let interactive = std::io::stdin().is_terminal();

    // Parse rlimits.
    let rlimits: Vec<_> = args
        .rlimit
        .iter()
        .map(|s| super::common::parse_rlimit(s))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Parse timeout.
    let timeout = match &args.timeout {
        Some(t) => Some(Duration::from_secs(super::common::parse_duration_secs(t)?)),
        None => None,
    };

    if interactive {
        // Interactive mode with TTY — use attach.
        let exit_code = sandbox
            .attach_with(cmd, |a| {
                let mut a = a.args(cmd_args);
                for (k, v) in &env_pairs {
                    a = a.env(k, v);
                }
                if let Some(ref cwd) = workdir {
                    a = a.cwd(cwd);
                }
                if let Some(ref user) = args.user {
                    a = a.user(user);
                }
                for &(resource, soft, hard) in &rlimits {
                    a = a.rlimit_range(resource, soft, hard);
                }
                a
            })
            .await?;

        super::maybe_stop(&sandbox).await;

        if exit_code != 0 {
            std::process::exit(exit_code);
        }
    } else {
        // Non-interactive: exec and capture output.
        let output: ExecOutput = sandbox
            .exec_with(cmd, |e| {
                let mut e = e.args(cmd_args);
                for (k, v) in &env_pairs {
                    e = e.env(k, v);
                }
                if let Some(ref cwd) = workdir {
                    e = e.cwd(cwd);
                }
                if let Some(ref user) = args.user {
                    e = e.user(user);
                }
                if args.tty {
                    e = e.tty(true);
                }
                if let Some(t) = timeout {
                    e = e.timeout(t);
                }
                for &(resource, soft, hard) in &rlimits {
                    e = e.rlimit_range(resource, soft, hard);
                }
                e
            })
            .await?;

        std::io::stdout().write_all(output.stdout_bytes())?;
        std::io::stderr().write_all(output.stderr_bytes())?;

        super::maybe_stop(&sandbox).await;

        if !output.status().success {
            std::process::exit(output.status().code);
        }
    }

    Ok(())
}
