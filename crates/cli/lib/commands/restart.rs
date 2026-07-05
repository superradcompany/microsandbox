//! `msb restart` command — stop and start one or more sandboxes.

use std::time::Duration;

use clap::Args;
use microsandbox::sandbox::{Sandbox, SandboxStatus};

use crate::ui;

use super::common;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Restart one or more sandboxes.
#[derive(Debug, Args)]
pub struct RestartArgs {
    /// Sandbox(es) to restart. Required unless `--label` is given.
    #[arg(required_unless_present = "label")]
    pub names: Vec<String>,

    /// Restart every sandbox carrying this label (`KEY=VALUE`). Repeatable;
    /// AND-matched. Unioned with any explicitly named sandboxes.
    #[arg(long)]
    pub label: Vec<String>,

    /// Immediately kill the sandbox without graceful shutdown.
    /// Pending writes that the workload hasn't `fsync`'d may be lost.
    #[arg(short, long)]
    pub force: bool,

    /// Seconds to wait for graceful shutdown before force-killing.
    #[arg(short = 't', long)]
    pub timeout: Option<u64>,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RestartAction {
    StopThenStart,
    StartOnly,
    FailAlreadyStarting,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb restart` command.
pub async fn run(args: RestartArgs) -> anyhow::Result<()> {
    let names = common::resolve_bulk_targets(&args.names, &args.label, args.quiet).await?;
    let mut failed = false;

    for name in &names {
        match restart_one(name, args.force, args.timeout, args.quiet).await {
            Ok(()) => {}
            Err(e) => {
                if !args.quiet {
                    ui::error(&format!("{e}"));
                }
                failed = true;
            }
        }
    }

    if failed {
        std::process::exit(1);
    }

    Ok(())
}

async fn restart_one(
    name: &str,
    force: bool,
    timeout_secs: Option<u64>,
    quiet: bool,
) -> anyhow::Result<()> {
    let handle = Sandbox::get(name).await?;

    match restart_action(handle.status_snapshot()) {
        RestartAction::StopThenStart => {
            stop_for_restart(name, force, timeout_secs, quiet).await?;
            start_for_restart(&handle, name, quiet).await
        }
        RestartAction::StartOnly => start_for_restart(&handle, name, quiet).await,
        RestartAction::FailAlreadyStarting => {
            anyhow::bail!("sandbox '{name}' is already starting")
        }
    }
}

async fn stop_for_restart(
    name: &str,
    force: bool,
    timeout_secs: Option<u64>,
    quiet: bool,
) -> anyhow::Result<()> {
    let spinner = if quiet {
        ui::Spinner::quiet()
    } else {
        ui::Spinner::start("Stopping", name)
    };

    let handle = Sandbox::get(name).await?;
    let result = if force {
        handle.kill().await
    } else if let Some(timeout_secs) = timeout_secs {
        handle
            .stop_with_timeout(Duration::from_secs(timeout_secs))
            .await
    } else {
        handle.stop().await
    };

    match result {
        Ok(()) => {
            spinner.finish_success("Stopped");
            Ok(())
        }
        Err(e) => {
            spinner.finish_clear();
            Err(e.into())
        }
    }
}

async fn start_for_restart(
    handle: &microsandbox::sandbox::SandboxHandle,
    name: &str,
    quiet: bool,
) -> anyhow::Result<()> {
    let spinner = if quiet {
        ui::Spinner::quiet()
    } else {
        ui::Spinner::start("Starting", name)
    };

    match handle.start_detached().await {
        Ok(sandbox) => {
            sandbox.detach().await;
            spinner.finish_success("Started");
            Ok(())
        }
        Err(e) => {
            spinner.finish_clear();
            Err(e.into())
        }
    }
}

fn restart_action(status: SandboxStatus) -> RestartAction {
    match status {
        // Paused still represents an active VM, so restart uses the same
        // stop-then-start path rather than pretending a bare start is enough.
        SandboxStatus::Running | SandboxStatus::Draining | SandboxStatus::Paused => {
            RestartAction::StopThenStart
        }
        SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed => {
            RestartAction::StartOnly
        }
        SandboxStatus::Starting => RestartAction::FailAlreadyStarting,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: RestartArgs,
    }

    fn parse_restart_args(args: &[&str]) -> RestartArgs {
        TestCli::parse_from(std::iter::once("msb").chain(args.iter().copied())).args
    }

    #[test]
    fn parses_one_name() {
        let args = parse_restart_args(&["api"]);

        assert_eq!(args.names, vec!["api"]);
    }

    #[test]
    fn parses_multiple_names() {
        let args = parse_restart_args(&["api", "worker"]);

        assert_eq!(args.names, vec!["api", "worker"]);
    }

    #[test]
    fn parses_label_force_timeout_and_quiet() {
        let args = parse_restart_args(&[
            "api",
            "--label",
            "app=api",
            "--force",
            "--timeout",
            "30",
            "--quiet",
        ]);

        assert_eq!(args.names, vec!["api"]);
        assert_eq!(args.label, vec!["app=api"]);
        assert!(args.force);
        assert_eq!(args.timeout, Some(30));
        assert!(args.quiet);
    }

    #[test]
    fn classifies_active_statuses_as_stop_then_start() {
        assert_eq!(
            restart_action(SandboxStatus::Running),
            RestartAction::StopThenStart
        );
        assert_eq!(
            restart_action(SandboxStatus::Draining),
            RestartAction::StopThenStart
        );
        assert_eq!(
            restart_action(SandboxStatus::Paused),
            RestartAction::StopThenStart
        );
    }

    #[test]
    fn classifies_terminal_statuses_as_start_only() {
        assert_eq!(
            restart_action(SandboxStatus::Created),
            RestartAction::StartOnly
        );
        assert_eq!(
            restart_action(SandboxStatus::Stopped),
            RestartAction::StartOnly
        );
        assert_eq!(
            restart_action(SandboxStatus::Crashed),
            RestartAction::StartOnly
        );
    }

    #[test]
    fn classifies_starting_as_failure() {
        assert_eq!(
            restart_action(SandboxStatus::Starting),
            RestartAction::FailAlreadyStarting
        );
    }
}
