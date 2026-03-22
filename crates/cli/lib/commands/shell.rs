//! `msb shell` command — interactive shell in a sandbox (alias for attach).

use clap::Args;
use microsandbox::sandbox::{Sandbox, SandboxStatus};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Interactive shell in a running sandbox.
#[derive(Debug, Args)]
pub struct ShellArgs {
    /// Name of the sandbox.
    pub name: String,

    /// Shell to use (overrides sandbox default).
    #[arg(long)]
    pub shell: Option<String>,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb shell` command.
pub async fn run(args: ShellArgs) -> anyhow::Result<()> {
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

    // Use the specified shell or default.
    let exit_code = match args.shell {
        Some(ref shell) => sandbox.attach(shell.as_str(), ()).await?,
        None => sandbox.attach((), ()).await?,
    };

    let _ = sandbox.stop_and_wait().await;

    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}
