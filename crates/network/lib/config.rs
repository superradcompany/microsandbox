//! Serializable network configuration types.
//!
//! These types represent the user-facing declarative network configuration
//! that flows from `SandboxBuilder` through the supervisor to `msbnet`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::policy::NetworkPolicy;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Complete network configuration for a sandbox.
///
/// Declarative and serializable. Closure-based hooks and custom backend
/// objects are not supported in the subprocess architecture and are deferred.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Whether networking is enabled for this sandbox.
    #[serde(default)]
    pub enabled: bool,

    /// Network interface settings.
    #[serde(default)]
    pub interface: InterfaceConfig,

    /// Port mappings (host:guest).
    #[serde(default)]
    pub ports: Vec<PublishedPort>,

    /// Packet policy enforced by `msbnet`.
    #[serde(default)]
    pub policy: NetworkPolicy,

    /// DNS interception and filtering settings.
    #[serde(default)]
    pub dns: DnsConfig,
}

/// Network interface configuration (dual-stack).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceConfig {
    /// Guest MAC address. Auto-generated if `None`.
    #[serde(default)]
    pub mac: Option<[u8; 6]>,

    /// MTU. Defaults to backend-reported value if `None`.
    #[serde(default)]
    pub mtu: Option<u16>,

    /// IPv4 configuration. Auto-assigned from the pool if `None`.
    #[serde(default)]
    pub ipv4: Option<Ipv4Config>,

    /// IPv6 configuration. Auto-assigned from the pool if `None`.
    #[serde(default)]
    pub ipv6: Option<Ipv6Config>,
}

/// DNS interception settings for the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
    /// Exact domains to refuse locally.
    #[serde(default)]
    pub blocked_domains: Vec<String>,

    /// Domain suffixes to refuse locally.
    #[serde(default)]
    pub blocked_suffixes: Vec<String>,

    /// Whether DNS rebinding protection is enabled.
    #[serde(default = "default_rebind_protection")]
    pub rebind_protection: bool,
}

/// IPv4 address configuration for a sandbox interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv4Config {
    /// Guest IPv4 address.
    pub address: Ipv4Addr,

    /// Prefix length (e.g. `30` for a `/30` subnet).
    pub prefix_len: u8,

    /// Default gateway.
    pub gateway: Ipv4Addr,
}

/// IPv6 address configuration for a sandbox interface.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Ipv6Config {
    /// Guest IPv6 address.
    pub address: Ipv6Addr,

    /// Prefix length (e.g. `64` for a `/64` prefix).
    pub prefix_len: u8,

    /// Default gateway.
    pub gateway: Ipv6Addr,
}

/// A published port mapping between host and guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublishedPort {
    /// Host-side port to bind.
    pub host_port: u16,

    /// Guest-side port to forward to.
    pub guest_port: u16,

    /// Protocol (TCP or UDP).
    #[serde(default)]
    pub protocol: PortProtocol,

    /// Host address to bind. Defaults to loopback.
    #[serde(default = "default_host_bind")]
    pub host_bind: IpAddr,
}

/// Protocol for a published port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum PortProtocol {
    /// TCP (default).
    #[default]
    Tcp,

    /// UDP.
    Udp,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            blocked_domains: Vec::new(),
            blocked_suffixes: Vec::new(),
            rebind_protection: default_rebind_protection(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_host_bind() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn default_rebind_protection() -> bool {
    true
}
