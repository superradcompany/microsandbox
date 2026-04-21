//! Upstream DNS server discovery.
//!
//! Resolves the list of upstream nameservers the forwarder should talk
//! to. Sources, in order:
//!
//! 1. Explicit [`Nameserver`]s from configuration, if any. Hostnames
//!    are looked up via the host's own OS resolver, never via us —
//!    bootstrapping cannot depend on the interceptor being up already.
//! 2. The host's configured resolvers. On macOS this is the
//!    `SystemConfiguration` dynamic store (`configd`'s view), falling
//!    back to `/etc/resolv.conf` only if the store is unavailable or
//!    empty; VPN + split-DNS setups leave the file stale. On Linux
//!    `/etc/resolv.conf` is authoritative.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;

use resolv_conf::Config as ResolvConfig;

use super::parse::Nameserver;

/// DNS port.
const DNS_PORT: u16 = 53;

/// Path to the host resolver configuration. Used as a fallback when
/// explicit nameservers are not configured and — on macOS — when
/// SCDynamicStore is unavailable.
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

/// Resolve a list of [`Nameserver`]s to concrete `SocketAddr`s.
///
/// Individual lookup failures are logged and skipped; the whole operation
/// errors only if every entry fails.
pub(super) async fn resolve_nameservers(
    nameservers: &[Nameserver],
) -> std::io::Result<Vec<SocketAddr>> {
    let mut out = Vec::with_capacity(nameservers.len());
    let mut last_err: Option<std::io::Error> = None;
    for ns in nameservers {
        match ns.resolve().await {
            Ok(sa) => out.push(sa),
            Err(e) => {
                tracing::warn!(nameserver = %ns, error = %e, "failed to resolve nameserver");
                last_err = Some(e);
            }
        }
    }
    if out.is_empty()
        && let Some(e) = last_err
    {
        return Err(e);
    }
    Ok(out)
}

/// Read the host's configured DNS servers as `SocketAddr`s on port 53.
///
/// On macOS the authoritative source is `SystemConfiguration.framework`
/// (the dynamic store `configd` maintains), not `/etc/resolv.conf` —
/// VPN + split-DNS setups leave the file either stale or pointing at
/// only one leg of the resolver table. We query
/// `State:/Network/Global/DNS` first and only fall back to the file if
/// the dynamic store is unavailable or reports no servers.
///
/// On Linux the file is authoritative.
pub(super) async fn read_host_dns_servers() -> std::io::Result<Vec<SocketAddr>> {
    #[cfg(target_os = "macos")]
    if let Some(servers) = try_read_scdynamicstore() {
        return Ok(servers);
    }
    read_resolv_conf(Path::new(RESOLV_CONF_PATH)).await
}

/// Try to read nameservers from the macOS SystemConfiguration dynamic
/// store. Returns `None` (and logs at debug) if the store is
/// unavailable, reports no servers, or fails — the caller should fall
/// back to `/etc/resolv.conf` in that case.
#[cfg(target_os = "macos")]
fn try_read_scdynamicstore() -> Option<Vec<SocketAddr>> {
    match super::scdynamicstore::read_dns_servers() {
        Ok(servers) if !servers.is_empty() => {
            tracing::debug!(
                count = servers.len(),
                "loaded nameservers from SCDynamicStore"
            );
            Some(servers)
        }
        Ok(_) => {
            tracing::debug!(
                "SCDynamicStore returned no nameservers; falling back to /etc/resolv.conf"
            );
            None
        }
        Err(e) => {
            tracing::debug!(
                error = %e,
                "SCDynamicStore lookup failed; falling back to /etc/resolv.conf"
            );
            None
        }
    }
}

/// Parse a `resolv.conf`-format file and return the `nameserver` entries
/// as `SocketAddr`s on port 53. Uses the same parser as hickory-resolver
/// does internally (`resolv-conf` crate), but without pulling hickory's
/// stub-resolver machinery along with it.
async fn read_resolv_conf(path: &Path) -> std::io::Result<Vec<SocketAddr>> {
    let bytes = tokio::fs::read(path).await?;
    let cfg = ResolvConfig::parse(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(cfg
        .nameservers
        .into_iter()
        .map(|ns| SocketAddr::new(IpAddr::from(ns), DNS_PORT))
        .collect())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_resolv_conf_parses_nameservers() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("msb-resolv-{}.conf", std::process::id()));
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
