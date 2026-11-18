//! Public sandbox commands, shared by the `sandbox` group and top-level shortcuts.

use clap::{Args, Subcommand};
use microsandbox::LogLevel;

use super::{
    branch, copy, create, exec, inspect, jobs, list, logs, metrics, modify, pause, ping, ps,
    remove, restart, restore, run, start, stop, touch, wait,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Arguments for the public `msb sandbox` command group.
#[derive(Debug, Args)]
pub struct SandboxArgs {
    /// Sandbox operation to perform.
    #[command(subcommand)]
    pub command: SandboxCommands,
}

/// Sandbox operations available through `msb`, `msb sandbox`, and `msb sbx`.
// Flattening this enum at the top level keeps every spelling on the same argument definitions.
#[derive(Debug, Subcommand)]
pub enum SandboxCommands {
    /// Create a sandbox from an image and run a command in it.
    Run(run::RunArgs),

    /// Create a sandbox and boot it in the background.
    Create(create::CreateArgs),

    /// Restore a snapshot into a new detached sandbox.
    Restore(restore::RestoreArgs),

    /// Modify sandbox configuration.
    #[command(visible_alias = "mod")]
    Modify(modify::ModifyArgs),

    /// Start a stopped sandbox.
    Start(start::StartArgs),

    /// Stop one or more running sandboxes.
    Stop(stop::StopArgs),

    /// Suspend a resident sandbox without creating a snapshot.
    Pause(pause::PauseArgs),

    /// Fork running execution into a new local CoW child without a durable full snapshot.
    #[command(name = "fork", alias = "branch")]
    Fork(branch::BranchArgs),

    /// Resume a user-paused resident sandbox.
    Resume(pause::ResumeArgs),

    /// Restart one or more sandboxes.
    Restart(restart::RestartArgs),

    /// Wait for a sandbox to stop or crash.
    Wait(wait::WaitArgs),

    /// Check whether one or more sandbox agents are reachable.
    Ping(ping::PingArgs),

    /// Refresh idle activity for one or more running sandboxes.
    Touch(touch::TouchArgs),

    /// List all sandboxes.
    #[command(visible_alias = "ls")]
    List(list::ListArgs),

    /// Show sandbox status.
    #[command(name = "status", visible_alias = "ps")]
    Status(ps::PsArgs),

    /// Show live metrics for a running sandbox.
    Metrics(metrics::MetricsArgs),

    /// Remove one or more sandboxes.
    #[command(visible_alias = "rm")]
    Remove(remove::RemoveArgs),

    /// Run a command in a running sandbox.
    Exec(exec::ExecArgs),

    /// List managed command jobs in a sandbox.
    Jobs(jobs::JobsArgs),

    /// Attach to a managed job's existing input and output.
    Attach(jobs::AttachArgs),

    /// Send a Linux guest signal to a managed job's process group.
    Signal(jobs::SignalArgs),

    /// Send SIGKILL to a managed job's process group.
    Kill(jobs::JobArgs),

    /// Finish a managed job's pipe input without terminating it.
    Eof(jobs::JobArgs),

    /// Copy files between the host and a sandbox.
    #[command(visible_alias = "cp")]
    Copy(copy::CopyArgs),

    /// Show captured output from a sandbox.
    Logs(logs::LogsArgs),

    /// Show detailed sandbox configuration and status.
    Inspect(inspect::InspectArgs),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxCommands {
    /// Whether this operation only needs the resident-control executor.
    pub fn is_resident_control(&self) -> bool {
        matches!(self, Self::Pause(_) | Self::Resume(_))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute a sandbox operation using the same handler for every public spelling.
pub async fn run(command: SandboxCommands, log_level: Option<LogLevel>) -> anyhow::Result<()> {
    match command {
        SandboxCommands::Run(args) => run::run(args, log_level).await,
        SandboxCommands::Create(args) => create::run(args, log_level).await,
        SandboxCommands::Restore(args) => restore::run(args, log_level).await,
        SandboxCommands::Modify(args) => modify::run(args).await,
        SandboxCommands::Start(args) => start::run(args).await,
        SandboxCommands::Stop(args) => stop::run(args).await,
        SandboxCommands::Pause(args) => pause::run(args, false).await,
        SandboxCommands::Fork(args) => branch::run(args).await,
        SandboxCommands::Resume(args) => {
            pause::run(
                pause::PauseArgs {
                    name: args.name,
                    quiet: args.quiet,
                    guest_flush: None,
                },
                true,
            )
            .await
        }
        SandboxCommands::Restart(args) => restart::run(args).await,
        SandboxCommands::Wait(args) => wait::run(args).await,
        SandboxCommands::Ping(args) => ping::run(args).await,
        SandboxCommands::Touch(args) => touch::run(args).await,
        SandboxCommands::List(args) => list::run(args).await,
        SandboxCommands::Status(args) => ps::run(args).await,
        SandboxCommands::Metrics(args) => metrics::run(args).await,
        SandboxCommands::Remove(args) => remove::run(args).await,
        SandboxCommands::Exec(args) => exec::run(args).await,
        SandboxCommands::Jobs(args) => jobs::list(args).await,
        SandboxCommands::Attach(args) => jobs::attach(args).await,
        SandboxCommands::Signal(args) => jobs::signal(args).await,
        SandboxCommands::Kill(args) => jobs::kill(args).await,
        SandboxCommands::Eof(args) => jobs::eof(args).await,
        SandboxCommands::Copy(args) => copy::run(args).await,
        SandboxCommands::Logs(args) => logs::run(args).await,
        SandboxCommands::Inspect(args) => inspect::run(args).await,
    }
}
