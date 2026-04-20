//! Serializable network configuration types.
//!
//! These types represent the user-facing declarative network configuration
//! for sandbox networking. Designed for the smoltcp in-process engine.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::dns::NameserverSpec;

use crate::policy::NetworkPolicy;
use crate::secrets::config::SecretsConfig;
use crate::tls::TlsConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Complete network configuration for a sandbox.
///
/// Narrowed for the smoltcp in-process engine. Gateway, prefix length, and
/// other host-backend details are engine internals derived from the sandbox
/// slot — the user only specifies what matters: interface overrides, ports,
/// policy, DNS, TLS, and connection limits.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    /// Whether networking is enabled for this sandbox.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Guest interface overrides. Unset fields derived from sandbox slot.
    #[serde(default)]
    pub interface: InterfaceOverrides,

    /// Host → guest port mappings.
    #[serde(default)]
    pub ports: Vec<PublishedPort>,

    /// Egress/ingress policy rules.
    #[serde(default)]
    pub policy: NetworkPolicy,

    /// DNS interception and filtering settings.
    #[serde(default)]
    pub dns: DnsConfig,

    /// TLS interception settings.
    #[serde(default)]
    pub tls: TlsConfig,

    /// Secret injection settings.
    #[serde(default)]
    pub secrets: SecretsConfig,

    /// Max concurrent guest connections. Default: 256.
    #[serde(default)]
    pub max_connections: Option<usize>,

    /// Ship the host's trusted root CAs into the guest at boot so outbound
    /// TLS works behind corporate MITM proxies (Cloudflare Warp Zero
    /// Trust, Zscaler, Netskope, etc.) whose gateway CA is installed on
    /// the host but not shipped in the Mozilla root bundle the guest OS
    /// uses. Opt-in: host trust is not copied into the guest unless
    /// this is explicitly enabled. Default: false.
    #[serde(default)]
    pub trust_host_cas: bool,
}

/// Optional overrides for the guest interface.
///
/// If omitted, values are derived deterministically from the sandbox slot.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct InterfaceOverrides {
    /// Guest MAC address. Default: derived from slot.
    #[serde(default)]
    pub mac: Option<[u8; 6]>,

    /// Interface MTU. Default: 1500.
    #[serde(default)]
    pub mtu: Option<u16>,

    /// Guest IPv4 address. Default: derived from slot (100.96.0.0/11 pool).
    #[serde(default)]
    pub ipv4_address: Option<Ipv4Addr>,

    /// Guest IPv6 address. Default: derived from slot (fd42:6d73:62::/48 pool).
    #[serde(default)]
    pub ipv6_address: Option<Ipv6Addr>,
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
    #[serde(default = "default_true")]
    pub rebind_protection: bool,

    /// Nameservers to forward DNS queries to. When empty, fall back to
    /// the `nameserver` entries in the host's `/etc/resolv.conf`. Set
    /// this to pin specific resolvers (e.g. `1.1.1.1:53`, `dns.google`)
    /// or to work around split-DNS / VPN setups where the host's
    /// resolv.conf is incomplete. Accepts IPs, `IP:PORT`, or hostnames
    /// (resolved once at startup via the host's OS resolver).
    #[serde(default)]
    pub nameservers: Vec<NameserverSpec>,

    /// Per-query timeout in milliseconds. Default: 5000.
    #[serde(default = "default_query_timeout_ms")]
    pub query_timeout_ms: u64,
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

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interface: InterfaceOverrides::default(),
            ports: Vec::new(),
            policy: NetworkPolicy::default(),
            dns: DnsConfig::default(),
            tls: TlsConfig::default(),
            secrets: SecretsConfig::default(),
            max_connections: None,
            trust_host_cas: false,
        }
    }
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            blocked_domains: Vec::new(),
            blocked_suffixes: Vec::new(),
            rebind_protection: true,
            nameservers: Vec::new(),
            query_timeout_ms: default_query_timeout_ms(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_true() -> bool {
    true
}

fn default_host_bind() -> IpAddr {
    IpAddr::V4(Ipv4Addr::LOCALHOST)
}

fn default_query_timeout_ms() -> u64 {
    5000
}
