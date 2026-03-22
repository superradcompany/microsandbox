//! `msb exec` command — execute a command in a sandbox.

use std::io::{IsTerminal, Write};

use clap::Args;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Execute a command in a sandbox.
#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Name of the sandbox.
    pub name: String,

    /// Environment variable (KEY=value). Can be repeated.
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Working directory inside sandbox.
    #[arg(short, long)]
    pub workdir: Option<String>,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,

    /// Command to execute (after --).
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

    if interactive {
        // Interactive mode with TTY — use attach.
        let exit_code = sandbox
            .attach(cmd, |a| {
                let mut a = a.args(cmd_args);
                for (k, v) in &env_pairs {
                    a = a.env(k, v);
                }
                if let Some(ref cwd) = workdir {
                    a = a.cwd(cwd);
                }
                a
            })
            .await?;

        if let Err(e) = sandbox.stop_and_wait().await {
            ui::warn(&format!("failed to stop sandbox: {e}"));
        }

        if exit_code != 0 {
            std::process::exit(exit_code);
        }
    } else {
        // Non-interactive: exec and capture output.
        let output = sandbox
            .exec(cmd, |e| {
                let mut e = e.args(cmd_args);
                for (k, v) in &env_pairs {
                    e = e.env(k, v);
                }
                if let Some(ref cwd) = workdir {
                    e = e.cwd(cwd);
                }
                e
            })
            .await?;

        std::io::stdout().write_all(output.stdout_bytes())?;
        std::io::stderr().write_all(output.stderr_bytes())?;

        if let Err(e) = sandbox.stop_and_wait().await {
            ui::warn(&format!("failed to stop sandbox: {e}"));
        }

        if !output.status().success {
            std::process::exit(output.status().code);
        }
    }

    Ok(())
}
