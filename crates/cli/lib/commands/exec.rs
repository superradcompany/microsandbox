//! `msb exec` command — execute a command in a sandbox.

use std::io::Write;

use clap::Args;
use microsandbox::sandbox::{AttachOptionsBuilder, ExecOptionsBuilder, Sandbox, SandboxStatus};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Execute a command in a sandbox.
#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Name of the sandbox.
    pub name: String,

    /// Keep stdin open (interactive).
    #[arg(short, long)]
    pub interactive: bool,

    /// Allocate a pseudo-TTY.
    #[arg(short, long)]
    pub tty: bool,

    /// Environment variable (KEY=value). Can be repeated.
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Working directory inside sandbox.
    #[arg(short, long)]
    pub workdir: Option<String>,

    /// Command to execute (after --).
    #[arg(last = true, required = true)]
    pub command: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb exec` command.
pub async fn run(args: ExecArgs) -> anyhow::Result<()> {
    // Check sandbox status.
    let info = Sandbox::get(&args.name).await?;

    let sandbox = match info.status {
        SandboxStatus::Running | SandboxStatus::Draining => {
            anyhow::bail!(
                "sandbox '{}' is already running in another process; \
                 cross-process exec is not yet supported",
                args.name
            );
        }
        SandboxStatus::Stopped | SandboxStatus::Crashed => {
            let spinner = ui::Spinner::start("Starting", &args.name);
            match Sandbox::start(&args.name).await {
                Ok(s) => {
                    spinner.finish_success("Started");
                    s
                }
                Err(e) => {
                    spinner.finish_error();
                    return Err(e.into());
                }
            }
        }
        _ => {
            anyhow::bail!(
                "sandbox '{}' is in state {:?} and cannot be started",
                args.name,
                info.status
            );
        }
    };

    let cmd = args.command[0].clone();
    let cmd_args: Vec<String> = args.command[1..].to_vec();

    // Build exec options.
    let env_pairs: Vec<(String, String)> = args
        .env
        .iter()
        .map(|s| ui::parse_env(s).map_err(anyhow::Error::msg))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let workdir = args.workdir.clone();
    let tty = args.tty;

    if args.interactive && args.tty {
        // Interactive mode with TTY — use attach.
        let exit_code = sandbox
            .attach(cmd, |a: AttachOptionsBuilder| {
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

        let _ = sandbox.stop().await;
        let _ = sandbox.wait().await;

        if exit_code != 0 {
            std::process::exit(exit_code);
        }
    } else {
        // Non-interactive: exec and capture output.
        let output = sandbox
            .exec(cmd, |e: ExecOptionsBuilder| {
                let mut e = e.args(cmd_args).tty(tty);
                for (k, v) in &env_pairs {
                    e = e.env(k, v);
                }
                if let Some(ref cwd) = workdir {
                    e = e.cwd(cwd);
                }
                e
            })
            .await?;

        std::io::stdout().write_all(&output.stdout)?;
        std::io::stderr().write_all(&output.stderr)?;

        let _ = sandbox.stop().await;
        let _ = sandbox.wait().await;

        if !output.status.success {
            std::process::exit(output.status.code);
        }
    }

    Ok(())
}
