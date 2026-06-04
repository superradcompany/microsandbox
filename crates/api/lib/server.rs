//! HTTP server startup.

use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::PathBuf,
};

use tokio::net::TcpListener;

use crate::{routes, state::ApiState};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for the local API server.
#[derive(Debug, Clone)]
pub struct ServeConfig {
    /// Address to bind.
    pub addr: SocketAddr,

    /// Whether non-loopback bind addresses are allowed.
    pub allow_non_loopback: bool,

    /// API execution database path.
    pub api_db_path: PathBuf,
}

/// Handle returned by the server startup path.
#[derive(Debug)]
pub struct ServeHandle {
    /// Address the server is listening on.
    pub addr: SocketAddr,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ServeConfig {
    fn default() -> Self {
        Self {
            addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080),
            allow_non_loopback: false,
            api_db_path: default_api_db_path(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Start the local API server.
pub async fn serve(config: ServeConfig) -> anyhow::Result<ServeHandle> {
    validate_bind_addr(&config)?;
    let listener = TcpListener::bind(config.addr).await?;
    let addr = listener.local_addr()?;
    let state = ApiState::new(config.api_db_path.clone()).await?;

    tokio::spawn(async move {
        let app = routes::router(state);
        if let Err(err) = axum::serve(listener, app).await {
            tracing::error!(error = %err, "microsandbox api server exited");
        }
    });

    Ok(ServeHandle { addr })
}

/// Test-only wrapper for bind address validation.
pub fn validate_bind_addr_for_test(config: &ServeConfig) -> anyhow::Result<()> {
    validate_bind_addr(config)
}

fn validate_bind_addr(config: &ServeConfig) -> anyhow::Result<()> {
    if !config.allow_non_loopback && !config.addr.ip().is_loopback() {
        anyhow::bail!(
            "refusing to bind non-loopback address {}; pass --allow-non-loopback to opt in",
            config.addr
        );
    }
    Ok(())
}

fn default_api_db_path() -> PathBuf {
    dirs::data_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join("microsandbox")
        .join("api.sqlite")
}
