//! Serializable network configuration types.
//!
//! These types represent the user-facing declarative network configuration
//! for sandbox networking. Designed for the smoltcp in-process engine.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::num::NonZeroUsize;

use ipnetwork::{Ipv4Network, Ipv6Network};
use microsandbox_types::{NetworkRateLimiterConfig, TlsConfig};
use serde::{Deserialize, Serialize};

use crate::dns::Nameserver;
use crate::policy::NetworkPolicy;
use crate::proxy::{OutboundProxy, ResolvedOutboundProxy};
use crate::secrets::config::SecretsConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Explicit connection limit, serialized as zero for unlimited or a positive cap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(from = "usize", into = "usize")]
pub enum ConnectionLimit {
    /// No connection-count cap.
    Unlimited,
    /// Maximum number of concurrent connections.
    Limited(NonZeroUsize),
}

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

    /// Require hostname-based policy allows to use inspectable application authority. Enabled by default.
    #[serde(default = "default_true")]
    pub strict: bool,

    /// Secret injection settings.
    #[serde(default)]
    pub secrets: SecretsConfig,

    /// TCP connection cap. `None` uses the deployment profile's default.
    #[serde(default)]
    // Keep saved configurations readable by releases that predate the TCP-specific name.
    #[serde(rename = "max_connections", alias = "max_tcp_connections")]
    pub max_tcp_connections: Option<ConnectionLimit>,

    /// UDP relay session cap. Omitted is unlimited for single-tenant and 1024 for multi-tenant; zero means unlimited.
    #[serde(default)]
    pub max_udp_connections: Option<ConnectionLimit>,

    /// Egress and ingress rate limits. `None` means unlimited in both directions.
    #[serde(default)]
    pub rate_limiter: Option<NetworkRateLimiterConfig>,

    /// Ship the host's trusted root CAs into the guest at boot so outbound
    /// TLS works behind corporate MITM proxies (Cloudflare Warp Zero
    /// Trust, Zscaler, Netskope, etc.) whose gateway CA is installed on
    /// the host but not shipped in the Mozilla root bundle the guest OS
    /// uses. Opt-in: host trust is not copied into the guest unless
    /// this is explicitly enabled. Default: false.
    #[serde(default)]
    pub trust_host_cas: bool,

    /// Proxy that all outbound sandbox connections are dialed through.
    ///
    /// Applies to TLS-intercepted and bypassed/plain TCP traffic. SOCKS5 also
    /// relays non-DNS UDP; SOCKS4 blocks it because that protocol has no UDP command.
    #[serde(default)]
    pub outbound_proxy: Option<OutboundProxy>,
}

/// Network configuration whose runtime-only values have been resolved.
#[doc(hidden)]
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ResolvedNetworkConfig {
    /// Declarative network configuration with source-backed secret injection
    /// values resolved for this launch.
    config: NetworkConfig,

    /// Fully resolved outbound proxy, including runtime authentication
    /// material when configured.
    outbound_proxy: Option<ResolvedOutboundProxy>,
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
// Methods
//--------------------------------------------------------------------------------------------------

impl ConnectionLimit {
    /// Return the effective cap used by the network stack.
    pub const fn cap(self) -> Option<NonZeroUsize> {
        match self {
            Self::Unlimited => None,
            Self::Limited(limit) => Some(limit),
        }
    }
}

impl ResolvedNetworkConfig {
    /// Creates a runtime configuration from its declarative configuration and
    /// fully resolved outbound proxy.
    #[doc(hidden)]
    pub fn new(config: NetworkConfig, outbound_proxy: Option<ResolvedOutboundProxy>) -> Self {
        Self {
            config,
            outbound_proxy,
        }
    }

    /// Returns the declarative configuration with resolved injection values applied.
    #[doc(hidden)]
    pub fn config(&self) -> &NetworkConfig {
        &self.config
    }

    /// Returns mutable access for applying host-runtime configuration floors.
    #[cfg(feature = "engine")]
    pub(crate) fn config_mut(&mut self) -> &mut NetworkConfig {
        &mut self.config
    }

    /// Returns the fully resolved outbound proxy used by the network runtime.
    #[cfg(feature = "engine")]
    pub(crate) fn outbound_proxy(&self) -> Option<&ResolvedOutboundProxy> {
        self.outbound_proxy.as_ref()
    }

    /// Clears both the declarative and resolved outbound proxy state.
    #[cfg(feature = "engine")]
    pub(crate) fn clear_outbound_proxy(&mut self) {
        self.config.outbound_proxy = None;
        self.outbound_proxy = None;
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<usize> for ConnectionLimit {
    fn from(value: usize) -> Self {
        match NonZeroUsize::new(value) {
            Some(limit) => Self::Limited(limit),
            None => Self::Unlimited,
        }
    }
}

impl From<ConnectionLimit> for usize {
    fn from(value: ConnectionLimit) -> Self {
        value.cap().map_or(0, NonZeroUsize::get)
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interface: InterfaceOverrides::default(),
            ports: Vec::new(),
            policy: NetworkPolicy::default(),
            dns: DnsConfig::default(),
            tls: TlsConfig::default(),
            strict: true,
            secrets: SecretsConfig::default(),
            max_tcp_connections: None,
            max_udp_connections: None,
            rate_limiter: None,
            trust_host_cas: false,
            outbound_proxy: None,
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
    use crate::config::NetworkBuilder;
    use crate::dns::Nameserver;
    use crate::policy::{Destination, NetworkPolicy, Rule};
    use crate::proxy::OutboundProxy;

    #[test]
    fn strict_defaults_and_explicit_opt_out_survive_wire_round_trips() {
        assert!(NetworkConfig::default().strict);
        assert!(NetworkBuilder::new().build().unwrap().strict);
        for value in [
            serde_json::json!({}),
            serde_json::json!({"strict": true}),
            serde_json::json!({"strict": false}),
        ] {
            let expected = value
                .get("strict")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            let config: NetworkConfig = serde_json::from_value(value.clone()).unwrap();
            let domain: microsandbox_types::NetworkSpec =
                serde_json::from_value(value.clone()).unwrap();
            let cloud: microsandbox_types::CloudNetworkSpec =
                serde_json::from_value(value).unwrap();
            assert_eq!(config.strict, expected);
            assert_eq!(domain.strict, expected);
            assert_eq!(cloud.strict, expected);
            let round_trip: NetworkConfig =
                serde_json::from_value(serde_json::to_value(config).unwrap()).unwrap();
            assert_eq!(round_trip.strict, expected);
        }
    }

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
        let mut policy = NetworkPolicy::default()
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
        config.strict = true;

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
        let wire_config: microsandbox_types::NetworkSpec =
            serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
        assert!(wire_config.strict);

        // Snake_case is the canonical serialized form.
        assert_eq!(
            serde_json::to_string(&Destination::DomainSuffix(
                "staging.example.com".parse().unwrap()
            ))
            .unwrap(),
            r#"{"domain_suffix":"staging.example.com"}"#
        );
        let legacy: microsandbox_types::Destination =
            serde_json::from_str(r#"{"domain_suffix":"old.example.com"}"#).unwrap();
        assert!(matches!(
            legacy,
            microsandbox_types::Destination::DomainSuffix(_)
        ));
        let legacy_group: microsandbox_types::DestinationGroup =
            serde_json::from_str(r#""link_local""#).unwrap();
        assert_eq!(
            legacy_group,
            microsandbox_types::DestinationGroup::LinkLocal
        );
    }

    /// `outbound_proxy` round-trips whole-config through the wire type the
    /// same way `network_config_from_spec`/`network_spec_from_config`
    /// (`sdk/rust/lib/sandbox/config.rs`) do in production: a full
    /// `NetworkConfig` -> JSON -> `NetworkSpec` -> JSON -> `NetworkConfig`
    /// hop, not just the field in isolation.
    #[test]
    fn outbound_proxy_round_trips_through_wire_network_spec() {
        let config = NetworkConfig {
            outbound_proxy: Some(OutboundProxy::Socks5 {
                address: "127.0.0.1:1080".parse().unwrap(),
                credentials: None,
            }),
            ..NetworkConfig::default()
        };

        let config_json = serde_json::to_value(&config).unwrap();
        let wire: microsandbox_types::NetworkSpec =
            serde_json::from_value(config_json.clone()).unwrap();
        let wire_proxy = wire.outbound_proxy.as_ref().unwrap();
        assert_eq!(
            wire_proxy,
            &microsandbox_types::OutboundProxy::Socks5 {
                address: "127.0.0.1:1080".to_string(),
                credentials: None,
            }
        );
        assert_eq!(
            serde_json::to_value(wire_proxy).unwrap(),
            serde_json::json!({
                "protocol": "socks5",
                "address": "127.0.0.1:1080",
            })
        );

        let round_tripped: NetworkConfig =
            serde_json::from_value(serde_json::to_value(&wire).unwrap()).unwrap();
        assert_eq!(round_tripped.outbound_proxy, config.outbound_proxy);
    }

    #[test]
    fn socks4_proxy_user_id_round_trips_through_wire_network_spec() {
        let config = NetworkConfig {
            outbound_proxy: Some(OutboundProxy::Socks4 {
                address: "127.0.0.1:1080".parse().unwrap(),
                user_id: Some("sandbox".to_string()),
            }),
            ..NetworkConfig::default()
        };

        let wire: microsandbox_types::NetworkSpec =
            serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
        assert_eq!(
            wire.outbound_proxy,
            Some(microsandbox_types::OutboundProxy::Socks4 {
                address: "127.0.0.1:1080".to_string(),
                user_id: Some("sandbox".to_string()),
            })
        );
        assert_eq!(
            serde_json::to_value(wire.outbound_proxy.as_ref().unwrap()).unwrap(),
            serde_json::json!({
                "protocol": "socks4",
                "address": "127.0.0.1:1080",
                "user_id": "sandbox",
            })
        );

        let round_tripped: NetworkConfig =
            serde_json::from_value(serde_json::to_value(&wire).unwrap()).unwrap();
        assert_eq!(round_tripped.outbound_proxy, config.outbound_proxy);
    }

    #[test]
    fn outbound_proxy_omitted_when_unset() {
        let config = NetworkConfig::default();
        let wire: microsandbox_types::NetworkSpec =
            serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
        assert_eq!(wire.outbound_proxy, None);
        assert!(
            !serde_json::to_value(&wire)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("outbound_proxy"),
            "skip_serializing_if should omit an unset outbound_proxy from the wire form"
        );
    }

    /// A config persisted before rate limiters existed must keep
    /// deserializing, defaulting both directions to unlimited.
    #[test]
    fn config_without_rate_limiter_fields_stays_unlimited() {
        let config: NetworkConfig = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(config.rate_limiter.is_none());
    }

    #[test]
    fn rate_limiters_survive_the_wire_spec_round_trip() {
        use microsandbox_types::{NetworkRateLimiterConfig, RateLimiterConfig, TokenBucketConfig};

        let config = NetworkConfig {
            rate_limiter: Some(NetworkRateLimiterConfig {
                egress: Some(RateLimiterConfig {
                    bandwidth: Some(TokenBucketConfig {
                        size: 1024 * 1024,
                        refill_time_ms: 1000,
                        one_time_burst: 512 * 1024,
                    }),
                    ops: None,
                }),
                ingress: Some(RateLimiterConfig {
                    bandwidth: None,
                    ops: Some(TokenBucketConfig {
                        size: 1000,
                        refill_time_ms: 1000,
                        one_time_burst: 0,
                    }),
                }),
            }),
            ..NetworkConfig::default()
        };

        let spec: microsandbox_types::NetworkSpec =
            serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
        assert_eq!(spec.rate_limiter, config.rate_limiter);

        let back: NetworkConfig =
            serde_json::from_value(serde_json::to_value(&spec).unwrap()).unwrap();
        assert_eq!(back.rate_limiter, config.rate_limiter);
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

#[cfg(test)]
mod connection_limit_tests {
    use super::*;

    #[test]
    fn wire_connection_limits_preserve_default_and_unlimited_through_spec() {
        for requested in [None, Some(0), Some(64), Some(4096)] {
            let config: NetworkConfig =
                serde_json::from_value(serde_json::json!({"max_connections": requested})).unwrap();
            assert_eq!(
                config.max_tcp_connections,
                requested.map(ConnectionLimit::from)
            );
            let spec: microsandbox_types::NetworkSpec =
                serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
            assert_eq!(spec.max_tcp_connections, requested);
            let back: NetworkConfig =
                serde_json::from_value(serde_json::to_value(spec).unwrap()).unwrap();
            assert_eq!(back.max_tcp_connections, config.max_tcp_connections);
        }
    }

    #[test]
    fn wire_udp_connection_limits_preserve_default_and_unlimited_through_spec() {
        for requested in [None, Some(0), Some(64), Some(4096)] {
            let config: NetworkConfig =
                serde_json::from_value(serde_json::json!({"max_udp_connections": requested}))
                    .unwrap();
            assert_eq!(
                config.max_udp_connections,
                requested.map(ConnectionLimit::from)
            );
            let spec: microsandbox_types::NetworkSpec =
                serde_json::from_value(serde_json::to_value(&config).unwrap()).unwrap();
            assert_eq!(spec.max_udp_connections, requested);
            let back: NetworkConfig =
                serde_json::from_value(serde_json::to_value(spec).unwrap()).unwrap();
            assert_eq!(back.max_udp_connections, config.max_udp_connections);
        }
    }

    #[test]
    fn tcp_aliases_are_exclusive_and_udp_is_independent() {
        for key in ["max_connections", "max_tcp_connections"] {
            for value in [0, 64] {
                let config: NetworkConfig = serde_json::from_value(serde_json::json!({
                    key: value, "max_udp_connections": 7
                }))
                .unwrap();
                assert_eq!(
                    config.max_tcp_connections,
                    Some(ConnectionLimit::from(value))
                );
                assert_eq!(config.max_udp_connections, Some(ConnectionLimit::from(7)));
                let serialized = serde_json::to_value(&config).unwrap();
                assert_eq!(serialized["max_connections"], value);
                assert!(serialized.get("max_tcp_connections").is_none());
                let spec: microsandbox_types::NetworkSpec =
                    serde_json::from_value(serialized).unwrap();
                assert_eq!(spec.max_tcp_connections, Some(value));
            }
        }
        for value in [serde_json::json!(0), serde_json::Value::Null] {
            let duplicate =
                serde_json::json!({"max_connections": value, "max_tcp_connections": 64});
            assert!(serde_json::from_value::<NetworkConfig>(duplicate.clone()).is_err());
            assert!(serde_json::from_value::<microsandbox_types::NetworkSpec>(duplicate).is_err());
        }
    }

    #[test]
    fn older_readers_retain_persisted_tcp_caps() {
        // The relevant field from the pre-rename NetworkSpec/NetworkConfig schema.
        // Older serde readers ignore unknown fields, making a changed key unsafe.
        #[derive(serde::Deserialize)]
        struct LegacyNetworkConfig {
            max_connections: Option<usize>,
        }
        for limit in [0, 7, 1024] {
            let config = NetworkConfig {
                max_tcp_connections: Some(ConnectionLimit::from(limit)),
                max_udp_connections: Some(ConnectionLimit::from(9)),
                ..Default::default()
            };
            let wire = serde_json::to_value(&config).unwrap();
            let legacy: LegacyNetworkConfig = serde_json::from_value(wire.clone()).unwrap();
            assert_eq!(legacy.max_connections, Some(limit));
            let spec: microsandbox_types::NetworkSpec = serde_json::from_value(wire).unwrap();
            let legacy: LegacyNetworkConfig =
                serde_json::from_value(serde_json::to_value(spec).unwrap()).unwrap();
            assert_eq!(legacy.max_connections, Some(limit));
        }
    }

    #[test]
    fn wire_limits_normalize_zero_and_preserve_positive_caps() {
        for value in [
            serde_json::json!({}),
            serde_json::json!({"max_connections": null}),
        ] {
            let config: NetworkConfig = serde_json::from_value(value).unwrap();
            assert_eq!(config.max_tcp_connections, None);
        }

        let config: NetworkConfig =
            serde_json::from_value(serde_json::json!({"max_connections": 64})).unwrap();
        assert_eq!(
            config.max_tcp_connections,
            Some(ConnectionLimit::Limited(NonZeroUsize::new(64).unwrap()))
        );
        assert_eq!(serde_json::to_value(config).unwrap()["max_connections"], 64);

        for value in [serde_json::json!(-1), serde_json::json!("unlimited")] {
            assert!(
                serde_json::from_value::<NetworkConfig>(
                    serde_json::json!({"max_connections": value})
                )
                .is_err()
            );
        }
    }
}
