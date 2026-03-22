//! `msb shell` command — interactive shell or run a shell script in a sandbox.

use std::io::{IsTerminal, Write};

use clap::Args;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Open an interactive shell or run a shell script in a sandbox.
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

    /// Script to execute (after --). Opens interactive shell if omitted.
    #[arg(last = true)]
    pub command: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum size for stdin script input (1 MiB).
const MAX_STDIN_SCRIPT_SIZE: usize = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb shell` command.
pub async fn run(args: ShellArgs) -> anyhow::Result<()> {
    let sandbox = super::resolve_and_start(&args.name, args.quiet).await?;

    let interactive = std::io::stdin().is_terminal();

    // Resolve which shell to use: CLI flag > sandbox config > /bin/sh.
    let shell = args
        .shell
        .as_deref()
        .or(sandbox.config().shell.as_deref())
        .unwrap_or("/bin/sh");

    if args.command.is_empty() && interactive {
        // No command, TTY present — interactive shell session.
        let exit_code = sandbox.attach(shell, |a| a).await?;

        if let Err(e) = sandbox.stop_and_wait().await {
            ui::warn(&format!("failed to stop sandbox: {e}"));
        }

        if exit_code != 0 {
            std::process::exit(exit_code);
        }
    } else if !args.command.is_empty() && interactive {
        // Command provided with TTY — interactive shell with script.
        let script = args.command.join(" ");

        let exit_code = sandbox.attach(shell, |a| a.args(["-c", &script])).await?;

        if let Err(e) = sandbox.stop_and_wait().await {
            ui::warn(&format!("failed to stop sandbox: {e}"));
        }

        if exit_code != 0 {
            std::process::exit(exit_code);
        }
    } else {
        // Non-interactive — run script and capture output.
        let script = if args.command.is_empty() {
            // Read script from stdin (e.g. `echo "ls" | msb shell test`).
            let buf = tokio::task::spawn_blocking(|| {
                use std::io::Read;
                let mut buf = Vec::new();
                std::io::stdin()
                    .take(MAX_STDIN_SCRIPT_SIZE as u64)
                    .read_to_end(&mut buf)?;
                String::from_utf8(buf).map_err(|_| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "stdin is not valid UTF-8")
                })
            })
            .await??;

            if buf.trim().is_empty() {
                return Ok(());
            }

            buf
        } else {
            args.command.join(" ")
        };

        let output = sandbox.exec(shell, |e| e.args(["-c", &script])).await?;

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
