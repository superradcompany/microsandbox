//! Serializable network configuration types.
//!
//! These types represent the user-facing declarative network configuration
//! for sandbox networking. Designed for the smoltcp in-process engine.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnetwork::{Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};

use crate::dns::Nameserver;

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

    /// Guest IPv4 address. Default: derived from slot within `ipv4_pool`.
    #[serde(default)]
    pub ipv4_address: Option<Ipv4Addr>,

    /// Guest IPv4 pool. Default: derived from slot (172.16.0.0/12 pool).
    #[serde(default)]
    pub ipv4_pool: Option<Ipv4Network>,

    /// Guest IPv6 address. Default: derived from slot within `ipv6_pool`.
    #[serde(default)]
    pub ipv6_address: Option<Ipv6Addr>,

    /// Guest IPv6 pool. Default: derived from slot (fd42:6d73:62::/48 pool).
    #[serde(default)]
    pub ipv6_pool: Option<Ipv6Network>,
}

/// DNS interception settings for the sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsConfig {
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
    pub nameservers: Vec<Nameserver>,

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
    #[serde(rename = "tcp", alias = "Tcp")]
    Tcp,

    /// UDP.
    #[serde(rename = "udp", alias = "Udp")]
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{InterfaceOverrides, NetworkConfig, PortProtocol};
    use crate::dns::Nameserver;
    use crate::policy::{Destination, NetworkPolicy, Rule};

    /// The engine's `policy`/`dns`/`interface` subdocuments must remain
    /// serde-compatible with the wire twins in `microsandbox_types` that the
    /// cloud `NetworkSpec` now carries concretely (replacing `Option<Value>`).
    /// This guards against drift between the two representations.
    #[test]
    fn engine_network_subdocs_round_trip_through_wire_types() {
        let mut config = NetworkConfig::default();
        // Exercise the tricky leaves: a domain rule (validated `DomainName`), a
        // CIDR rule (`IpNetwork`), group rules, parsed nameservers, and the
        // interface IP/MAC/pool.
        let mut policy = NetworkPolicy::public_only()
            .allow_domain("example.com")
            .expect("valid domain")
            .allow_domain_suffix("staging.example.com")
            .expect("valid suffix");
        policy.rules.push(Rule::allow_egress(Destination::Cidr(
            "151.101.0.0/16".parse().unwrap(),
        )));
        config.policy = policy;
        config.dns.nameservers = vec![
            "1.1.1.1:53".parse::<Nameserver>().unwrap(),
            "dns.google".parse::<Nameserver>().unwrap(),
        ];
        config.interface.ipv4_address = Some("172.16.0.2".parse().unwrap());
        config.interface.ipv4_pool = Some("172.16.0.0/12".parse().unwrap());
        config.interface.mac = Some([0x02, 0, 0, 0, 0, 0x01]);

        // The engine's real serialization of each subdocument.
        let policy_json = serde_json::to_value(&config.policy).unwrap();
        let dns_json = serde_json::to_value(&config.dns).unwrap();
        let iface_json = serde_json::to_value(&config.interface).unwrap();

        // It must deserialize into the wire types and re-serialize losslessly
        // (policy/dns serialize every field on both sides, so compare raw JSON).
        let wire_policy: microsandbox_types::NetworkPolicy =
            serde_json::from_value(policy_json.clone()).unwrap();
        let wire_dns: microsandbox_types::DnsConfig =
            serde_json::from_value(dns_json.clone()).unwrap();
        assert_eq!(policy_json, serde_json::to_value(&wire_policy).unwrap());
        assert_eq!(dns_json, serde_json::to_value(&wire_dns).unwrap());

        // `InterfaceOverrides` skips `None` fields on the wire side, so prove
        // losslessness by round-tripping back into the engine type.
        let wire_iface: microsandbox_types::InterfaceOverrides =
            serde_json::from_value(iface_json.clone()).unwrap();
        let back: InterfaceOverrides =
            serde_json::from_value(serde_json::to_value(&wire_iface).unwrap()).unwrap();
        assert_eq!(iface_json, serde_json::to_value(&back).unwrap());

        // Snake_case is canonical; legacy kebab-case tags still deserialize via
        // `#[serde(alias)]` on both the engine and the wire enums.
        assert_eq!(
            serde_json::to_string(&Destination::DomainSuffix(
                "staging.example.com".parse().unwrap()
            ))
            .unwrap(),
            r#"{"domain_suffix":"staging.example.com"}"#
        );
        let legacy: microsandbox_types::Destination =
            serde_json::from_str(r#"{"domain-suffix":"old.example.com"}"#).unwrap();
        assert!(matches!(
            legacy,
            microsandbox_types::Destination::DomainSuffix(_)
        ));
        let legacy_group: microsandbox_types::DestinationGroup =
            serde_json::from_str(r#""link-local""#).unwrap();
        assert_eq!(
            legacy_group,
            microsandbox_types::DestinationGroup::LinkLocal
        );
    }

    #[test]
    fn port_protocol_serializes_lowercase_and_accepts_legacy_case() {
        assert_eq!(
            serde_json::to_string(&PortProtocol::Tcp).unwrap(),
            "\"tcp\""
        );
        assert_eq!(
            serde_json::to_string(&PortProtocol::Udp).unwrap(),
            "\"udp\""
        );
        assert_eq!(
            serde_json::from_str::<PortProtocol>("\"Tcp\"").unwrap(),
            PortProtocol::Tcp
        );
        assert_eq!(
            serde_json::from_str::<PortProtocol>("\"Udp\"").unwrap(),
            PortProtocol::Udp
        );
    }
}
