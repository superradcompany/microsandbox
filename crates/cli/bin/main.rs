//! Entry point for the `msb` CLI binary.

use clap::{Parser, Subcommand};
use microsandbox_cli::microvm_cmd::{self, MicrovmArgs};
use microsandbox_cli::supervisor_cmd::{self, SupervisorArgs};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Microsandbox CLI.
#[derive(Parser)]
#[command(name = "msb", version, about = "Microsandbox CLI", styles = microsandbox_cli::styles::styles())]
struct Cli {
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
    tracing_subscriber::fmt::init();

    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Supervisor(args) => supervisor_cmd::run(args).await,
        Commands::Microvm(args) => microvm_cmd::run(args),
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}
