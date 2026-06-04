//! Entry point for the `microsandbox-api` binary.

use clap::Parser;
use microsandbox_api::{ServeConfig, serve};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Run the local Microsandbox API server.
#[derive(Debug, Parser)]
#[command(name = "microsandbox-api", version)]
struct Args {
    /// Address to bind.
    #[arg(long, default_value = "127.0.0.1:8080")]
    addr: std::net::SocketAddr,

    /// Allow binding to non-loopback addresses.
    #[arg(long)]
    allow_non_loopback: bool,

    /// API execution database path.
    #[arg(long)]
    api_db: Option<std::path::PathBuf>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let mut config = ServeConfig {
        addr: args.addr,
        allow_non_loopback: args.allow_non_loopback,
        ..ServeConfig::default()
    };
    if let Some(path) = args.api_db {
        config.api_db_path = path;
    }
    let handle = serve(config).await?;
    println!("microsandbox-api listening on http://{}", handle.addr);
    tokio::signal::ctrl_c().await?;
    Ok(())
}
