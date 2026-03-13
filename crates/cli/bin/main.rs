//! Entry point for the `msb` CLI binary.

use clap::{Parser, Subcommand};
use microsandbox_cli::{
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
    Supervisor(SupervisorArgs),

    /// Run the microVM process.
    Microvm(MicrovmArgs),
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() {
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

    let result = match cli.command {
        Commands::Supervisor(args) => supervisor_cmd::run(args, log_level).await,
        Commands::Microvm(args) => microvm_cmd::run(args),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
