//! Linux nftables REDIRECT rule management for TLS interception.
//!
//! Installs a per-sandbox nftables table `inet msb_tls_{sandbox_id}` with a
//! prerouting REDIRECT chain. This is separate from the shared `inet msb`
//! table used for forwarding and NAT masquerade.

use std::io;

use super::RedirectConfig;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Installs nftables REDIRECT rules for TLS interception.
///
/// Creates a per-sandbox table with a prerouting chain that redirects matching
/// TCP traffic from the guest to the local TLS proxy port.
///
/// IPv4 uses `redirect` (rewrites dst to `127.0.0.1:proxy_port`).
/// IPv6 uses `dnat to 127.0.0.1:proxy_port` because the proxy listens on
/// IPv4 loopback only — `redirect` would target `[::1]` which has no listener.
pub fn install(config: &RedirectConfig) -> io::Result<()> {
    if config.intercepted_ports.is_empty() {
        return Ok(()); // Nothing to intercept.
    }

    let table = format!("msb_tls_{}", config.sandbox_id);
    let ports = config
        .intercepted_ports
        .iter()
        .map(|p| p.to_string())
        .collect::<Vec<_>>()
        .join(", ");

    // Delete any stale table from a prior crashed instance before creating fresh.
    let mut script = format!("delete table inet {table}\n");
    // The delete may fail if the table doesn't exist — that's fine, we continue.
    // Use a separate atomic script so failure doesn't abort the install.
    let _ = crate::host::linux::nft_script(&script);

    script.clear();
    script.push_str(&format!(
        "add table inet {table}\n\
         add chain inet {table} prerouting {{ type nat hook prerouting priority dstnat; policy accept; }}\n"
    ));

    if let Some(ipv4) = config.guest_ipv4 {
        script.push_str(&format!(
            "add rule inet {table} prerouting ip saddr {ipv4} tcp dport {{ {ports} }} redirect to :{}\n",
            config.proxy_port
        ));
    }

    // IPv6: use dnat to 127.0.0.1 instead of redirect, because the proxy
    // listens on IPv4 loopback only. nftables redirect would target [::1].
    if let Some(ipv6_prefix) = config.guest_ipv6_prefix {
        script.push_str(&format!(
            "add rule inet {table} prerouting ip6 saddr {ipv6_prefix} tcp dport {{ {ports} }} dnat to 127.0.0.1:{}\n",
            config.proxy_port
        ));
    }

    crate::host::linux::nft_script(&script)
}

/// Removes the per-sandbox nftables table for TLS interception.
pub fn remove(sandbox_id: u32) -> io::Result<()> {
    let script = format!("delete table inet msb_tls_{sandbox_id}\n");
    // Best-effort cleanup — table may already be gone.
    let _ = crate::host::linux::nft_script(&script);
    Ok(())
}
