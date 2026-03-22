//! Entry point for the `msb` CLI binary.

use clap::{Parser, Subcommand};
use microsandbox_cli::{
    commands::{create, exec, inspect, list, ps, pull, remove, run, shell, start, stop, volume},
    log_args::{self, LogArgs},
    microvm_cmd::{self, MicrovmArgs},
    supervisor_cmd::{self, SupervisorArgs},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Microsandbox CLI.
#[derive(Parser)]
#[command(name = "msb", version, about = "Microsandbox CLI", styles = microsandbox_cli::styles::styles())]
struct Cli {
    #[command(flatten)]
    logs: LogArgs,

    #[command(subcommand)]
    command: Commands,
}

/// Top-level commands.
#[derive(Subcommand)]
enum Commands {
    /// Run the supervisor process.
    #[command(hide = true)]
    Supervisor(Box<SupervisorArgs>),

    /// Run the microVM process.
    #[command(hide = true)]
    Microvm(MicrovmArgs),

    /// Create and start a new sandbox.
    Run(run::RunArgs),

    /// Create and boot a fresh sandbox (no workload).
    Create(create::CreateArgs),

    /// Start/resume an existing stopped sandbox.
    Start(start::StartArgs),

    /// Stop a running sandbox.
    Stop(stop::StopArgs),

    /// List all sandboxes.
    #[command(visible_alias = "ls")]
    List(list::ListArgs),

    /// Show running sandboxes.
    Ps(ps::PsArgs),

    /// Remove a stopped sandbox.
    #[command(visible_alias = "rm")]
    Remove(remove::RemoveArgs),

    /// Execute a command in a sandbox.
    Exec(exec::ExecArgs),

    /// Shell in a sandbox (interactive or scripted).
    Shell(shell::ShellArgs),

    /// Pull an image from a registry.
    Pull(pull::PullArgs),

    /// Show detailed sandbox information.
    Inspect(inspect::InspectArgs),

    /// Manage named volumes.
    Volume(volume::VolumeArgs),
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn main() {
    // Auto-set MSB_PATH so the library can find the msb binary
    // when spawning supervisor processes.
    // Safety: called before any threads are spawned (single-threaded at this point).
    if std::env::var("MSB_PATH").is_err()
        && let Ok(exe) = std::env::current_exe()
    {
        unsafe { std::env::set_var("MSB_PATH", &exe) };
    }

    let cli = Cli::parse();
    let log_level = cli.logs.selected_level();
    log_args::init_tracing(log_level);

    let result: Result<(), Box<dyn std::error::Error>> = match cli.command {
        Commands::Microvm(args) => microvm_cmd::run(args).map_err(Into::into),
        command => run_async_command(command, log_level),
    };

    if let Err(e) = result {
        microsandbox_cli::ui::error(&e.to_string());
        std::process::exit(1);
    }
}

fn run_async_command(
    command: Commands,
    log_level: Option<microsandbox::LogLevel>,
) -> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;

    runtime.block_on(async move {
        match command {
            // Hidden internal commands.
            Commands::Supervisor(args) => supervisor_cmd::run(*args, log_level)
                .await
                .map_err(Into::into),
            Commands::Microvm(_) => unreachable!("microvm is handled before Tokio starts"),

            // User-facing commands.
            Commands::Run(args) => run::run(args).await.map_err(Into::into),
            Commands::Create(args) => create::run(args).await.map_err(Into::into),
            Commands::Start(args) => start::run(args).await.map_err(Into::into),
            Commands::Stop(args) => stop::run(args).await.map_err(Into::into),
            Commands::List(args) => list::run(args).await.map_err(Into::into),
            Commands::Ps(args) => ps::run(args).await.map_err(Into::into),
            Commands::Remove(args) => remove::run(args).await.map_err(Into::into),
            Commands::Exec(args) => exec::run(args).await.map_err(Into::into),
            Commands::Shell(args) => shell::run(args).await.map_err(Into::into),
            Commands::Pull(args) => pull::run(args).await.map_err(Into::into),
            Commands::Inspect(args) => inspect::run(args).await.map_err(Into::into),
            Commands::Volume(args) => volume::run(args).await.map_err(Into::into),
        }
    })
}
