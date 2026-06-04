//! `msb serve` command - serve the local RunLoop-compatible API.

use std::{net::SocketAddr, path::PathBuf};

use clap::Args;
use microsandbox_api::{ServeConfig, serve};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Serve the local RunLoop-compatible API.
#[derive(Debug, Args)]
pub struct ServeArgs {
    /// Address to bind.
    #[arg(long, default_value = "127.0.0.1:8080")]
    pub addr: SocketAddr,

    /// Allow binding to non-loopback addresses.
    #[arg(long)]
    pub allow_non_loopback: bool,

    /// API execution database path.
    #[arg(long)]
    pub api_db: Option<PathBuf>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb serve` command.
pub async fn run(args: ServeArgs) -> anyhow::Result<()> {
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
