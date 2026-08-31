//! Upstream DNS resolution and host nameserver discovery.

#[cfg(not(windows))]
use std::net::IpAddr;
use std::net::SocketAddr;
#[cfg(not(windows))]
use std::path::Path;

#[cfg(not(windows))]
use resolv_conf::Config as ResolvConfig;

use crate::dns::Nameserver;

#[cfg(target_os = "macos")]
mod scdynamicstore;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// DNS port.
#[cfg(not(windows))]
const DNS_PORT: u16 = 53;

/// Path to the host resolver configuration. Used as a fallback when explicit
/// nameservers are not configured and the macOS dynamic store is unavailable.
#[cfg(not(windows))]
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Nameserver {
    /// Resolve to a concrete address through the host's resolver.
    pub async fn resolve(&self) -> std::io::Result<SocketAddr> {
        match self {
            Self::Addr(address) => Ok(*address),
            Self::Host { host, port } => tokio::net::lookup_host((host.as_str(), *port))
                .await?
                .next()
                .ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        format!("no addresses resolved for {host}:{port}"),
                    )
                }),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve configured nameservers to concrete addresses.
pub(crate) async fn resolve_nameservers(
    nameservers: &[Nameserver],
) -> std::io::Result<Vec<SocketAddr>> {
    let mut addresses = Vec::with_capacity(nameservers.len());
    let mut last_error = None;
    for nameserver in nameservers {
        match nameserver.resolve().await {
            Ok(address) => addresses.push(address),
            Err(error) => {
                tracing::warn!(nameserver = %nameserver, error = %error, "failed to resolve nameserver");
                last_error = Some(error);
            }
        }
    }
    if addresses.is_empty()
        && let Some(error) = last_error
    {
        return Err(error);
    }
    Ok(addresses)
}

/// Read the host's configured DNS servers.
#[cfg(not(windows))]
pub(crate) async fn read_host_dns_servers() -> std::io::Result<Vec<SocketAddr>> {
    #[cfg(target_os = "macos")]
    if let Some(servers) = try_read_scdynamicstore() {
        return Ok(servers);
    }
    read_resolv_conf(Path::new(RESOLV_CONF_PATH)).await
}

#[cfg(target_os = "macos")]
fn try_read_scdynamicstore() -> Option<Vec<SocketAddr>> {
    match scdynamicstore::read_dns_servers() {
        Ok(servers) if !servers.is_empty() => Some(servers),
        Ok(_) => {
            tracing::debug!(
                "SCDynamicStore returned no nameservers; falling back to /etc/resolv.conf"
            );
            None
        }
        Err(error) => {
            tracing::debug!(%error, "SCDynamicStore lookup failed; falling back to /etc/resolv.conf");
            None
        }
    }
}

#[cfg(not(windows))]
async fn read_resolv_conf(path: &Path) -> std::io::Result<Vec<SocketAddr>> {
    let bytes = tokio::fs::read(path).await?;
    let config = ResolvConfig::parse(&bytes)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error.to_string()))?;
    Ok(config
        .nameservers
        .into_iter()
        .map(|nameserver| SocketAddr::new(IpAddr::from(nameserver), DNS_PORT))
        .collect())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, not(windows)))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_resolv_conf_parses_nameservers() {
        let path = std::env::temp_dir().join(format!("msb-resolv-{}.conf", std::process::id()));
        std::fs::write(
            &path,
            "# comment line\n\
             nameserver 1.1.1.1\n\
             nameserver 8.8.8.8  # inline comment\n\
             search example.com\n\
             options ndots:5\n\
             nameserver 2606:4700:4700::1111\n\
             \n",
        )
        .unwrap();

        let servers = read_resolv_conf(&path).await.expect("read ok");
        std::fs::remove_file(&path).ok();

        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0], "1.1.1.1:53".parse().unwrap());
        assert_eq!(servers[1], "8.8.8.8:53".parse().unwrap());
        assert_eq!(servers[2], "[2606:4700:4700::1111]:53".parse().unwrap());
    }

    #[tokio::test]
    async fn read_resolv_conf_missing_file_errs() {
        assert!(
            read_resolv_conf(Path::new("/nonexistent/path/to/resolv.conf"))
                .await
                .is_err()
        );
    }
}
