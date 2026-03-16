//! Platform-specific kernel redirect rule installation and cleanup.
//!
//! Installs nftables REDIRECT rules (Linux) or pf `rdr` anchors (macOS) that
//! route intercepted TCP connections to the TLS proxy listener.

use std::io;
use std::net::Ipv4Addr;

use ipnetwork::Ipv6Network;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for kernel-level redirect rules.
pub struct RedirectConfig {
    /// Guest IPv4 address to match in redirect rules.
    pub guest_ipv4: Option<Ipv4Addr>,

    /// Guest IPv6 /64 prefix to match in redirect rules.
    /// Uses the full prefix (not a single address) to cover SLAAC and
    /// privacy extension addresses within the subnet.
    pub guest_ipv6_prefix: Option<Ipv6Network>,

    /// TCP ports to intercept (e.g. `[443]`).
    pub intercepted_ports: Vec<u16>,

    /// Local port of the TLS proxy listener.
    pub proxy_port: u16,

    /// Sandbox ID (used for unique table/anchor naming).
    pub sandbox_id: u32,

    /// Host-side interface name (e.g. `"msbtap42"`).
    pub ifname: String,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Installs kernel-level redirect rules for TLS interception.
pub fn install(config: &RedirectConfig) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        super::redirect_linux::install(config)
    }

    #[cfg(target_os = "macos")]
    {
        super::redirect_macos::install(config)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = config;
        Err(io::Error::other(
            "TLS redirect rules not supported on this platform",
        ))
    }
}

/// Removes kernel-level redirect rules for a sandbox.
pub fn remove(sandbox_id: u32) -> io::Result<()> {
    #[cfg(target_os = "linux")]
    {
        super::redirect_linux::remove(sandbox_id)
    }

    #[cfg(target_os = "macos")]
    {
        super::redirect_macos::remove(sandbox_id)
    }

    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = sandbox_id;
        Err(io::Error::other(
            "TLS redirect rules not supported on this platform",
        ))
    }
}
