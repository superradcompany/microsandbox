//! `msb attach` command — attach to a sandbox with interactive terminal.

use clap::Args;
use microsandbox::sandbox::{AttachOptionsBuilder, Sandbox, SandboxStatus};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Attach to a running sandbox with an interactive terminal.
#[derive(Debug, Args)]
pub struct AttachArgs {
    /// Name of the sandbox.
    pub name: String,

    /// Custom detach key sequence (e.g., "ctrl-p,ctrl-q").
    #[arg(long)]
    pub detach_keys: Option<String>,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,

    /// Command to run interactively (after --).
    #[arg(last = true)]
    pub command: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb attach` command.
pub async fn run(args: AttachArgs) -> anyhow::Result<()> {
    let handle = Sandbox::get(&args.name).await?;

    let sandbox = match handle.status() {
        SandboxStatus::Running | SandboxStatus::Draining => {
            anyhow::bail!(
                "sandbox '{}' is already running in another process; \
                 cross-process attach is not yet supported",
                args.name
            );
        }
        SandboxStatus::Stopped | SandboxStatus::Crashed => {
            let spinner = if args.quiet {
                ui::Spinner::quiet()
            } else {
                ui::Spinner::start("Starting", &args.name)
            };
            match handle.start().await {
                Ok(s) => {
                    spinner.finish_clear();
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
                "sandbox '{}' is in state {:?} and cannot be attached to",
                args.name,
                handle.status()
            );
        }
    };

    // Resolve the command to run (if any, from after --).
    let detach_keys = args.detach_keys;
    let exit_code = if args.command.is_empty() {
        sandbox
            .attach((), |a: AttachOptionsBuilder| {
                let mut a = a;
                if let Some(ref keys) = detach_keys {
                    a = a.detach_keys(keys);
                }
                a
            })
            .await?
    } else {
        let cmd = args.command[0].clone();
        let cmd_args: Vec<String> = args.command[1..].to_vec();
        sandbox
            .attach(cmd, |a: AttachOptionsBuilder| {
                let mut a = a;
                if let Some(ref keys) = detach_keys {
                    a = a.detach_keys(keys);
                }
                if !cmd_args.is_empty() {
                    a = a.args(cmd_args);
                }
                a
            })
            .await?
    };

    let _ = sandbox.stop().await;
    let _ = sandbox.wait().await;

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}
