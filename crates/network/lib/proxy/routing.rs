//! Frozen outbound proxy routing for the network engine.
//!
//! The host proxy source is captured once per engine startup, after the
//! deployment-profile floor, and every later TCP SYN or UDP session only selects
//! a leaf from it. Transports therefore learn what to dial, never where the
//! setting came from.

use std::net::SocketAddr;
use std::sync::Arc;

use super::{AmbientHttpProxy, ResolvedOutboundProxy};
use crate::config::ResolvedNetworkConfig;
use crate::engine::netstack::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Frozen outbound proxy source for one network-engine startup.
///
/// Serialization is deliberately unsupported: the captured source, including any
/// runtime endpoint credentials, never enters launch JSON, catalog state,
/// snapshots, or logs.
///
/// ```compile_fail
/// fn assert_serialize<T: serde::Serialize>() {}
/// assert_serialize::<microsandbox_network::proxy::OutboundRouting>();
/// ```
///
/// ```compile_fail
/// fn assert_deserialize<T: serde::de::DeserializeOwned>() {}
/// assert_deserialize::<microsandbox_network::proxy::OutboundRouting>();
/// ```
#[doc(hidden)]
pub struct OutboundRouting {
    source: ProxySource,
}

/// Where an [`OutboundRouting`] value came from.
enum ProxySource {
    /// Connect directly, without reading host proxy state.
    Direct,
    /// Use the explicitly configured proxy for every eligible flow.
    Configured(Arc<ResolvedOutboundProxy>),
    /// Apply discovered host proxy settings and their `NO_PROXY` rules.
    Ambient(AmbientHttpProxy),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OutboundRouting {
    /// Builds routing from an already configured proxy.
    ///
    /// Configured-only callers such as a directly constructed engine pass their
    /// existing `Arc` here. The supplied identity is kept, no host environment
    /// variable is read, and no ambient proxy is discovered.
    pub fn configured(proxy: Option<Arc<ResolvedOutboundProxy>>) -> Self {
        match proxy {
            Some(proxy) => Self {
                source: ProxySource::Configured(proxy),
            },
            None => Self::default(),
        }
    }

    /// Captures the outbound proxy source once for this engine startup.
    ///
    /// Runs after deployment-profile sanitization, so a cleared intent never
    /// reaches the environment. A resolved configured leaf wins without any
    /// environment read; otherwise the durable field, a disabled network, or
    /// false intent keeps routing direct. Only an eligible startup discovers.
    pub(crate) fn capture(config: &ResolvedNetworkConfig) -> Self {
        Self::capture_with(config, AmbientHttpProxy::from_env)
    }

    /// Captures through an injectable discovery closure so tests count reads.
    pub(crate) fn capture_with(
        config: &ResolvedNetworkConfig,
        discover: impl FnOnce() -> Option<AmbientHttpProxy>,
    ) -> Self {
        if let Some(configured) = config.outbound_proxy() {
            return Self {
                source: ProxySource::Configured(Arc::new(configured.clone())),
            };
        }

        let network = config.config();
        if !network.enabled || !network.proxy_from_env || network.outbound_proxy.is_some() {
            return Self::default();
        }

        match discover() {
            Some(ambient) => Self {
                source: ProxySource::Ambient(ambient),
            },
            None => Self::default(),
        }
    }

    /// Builds ambient routing directly for crate tests.
    ///
    /// Tests never read the process environment; they construct the discovery
    /// result explicitly.
    #[cfg(test)]
    pub(crate) fn ambient(proxy: AmbientHttpProxy) -> Self {
        Self {
            source: ProxySource::Ambient(proxy),
        }
    }

    /// Selects the frozen egress route for one destination.
    ///
    /// A host-side rewrite of the destination always stays direct. A configured
    /// proxy then wins over ambient discovery without reading any host proxy
    /// variable. Otherwise the ambient proxy applies unless its `NO_PROXY`
    /// rules, the local dial address, or the destination itself exempt the flow.
    /// A direct decision is `None`.
    ///
    /// This is pure selection: it reads no environment, performs no DNS lookup,
    /// opens no socket, emits no warning, and mutates no policy state.
    pub(crate) fn select(
        &self,
        guest_dst: SocketAddr,
        host_dst: SocketAddr,
        tls: bool,
        shared: &SharedState,
    ) -> Option<Arc<ResolvedOutboundProxy>> {
        if guest_dst != host_dst {
            return None;
        }

        match &self.source {
            ProxySource::Direct => None,
            ProxySource::Configured(proxy) => Some(Arc::clone(proxy)),
            ProxySource::Ambient(ambient) => {
                if ambient.bypasses(guest_dst, host_dst, shared) {
                    return None;
                }

                Some(ambient.endpoint(tls))
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for OutboundRouting {
    /// Routes directly and reads no host proxy state.
    fn default() -> Self {
        Self {
            source: ProxySource::Direct,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use std::time::Duration;

    use crate::config::{NetworkConfig, ResolvedNetworkConfig};
    use crate::engine::netstack::shared::{ResolvedHostnameFamily, SharedState};
    use crate::proxy::{AmbientHttpProxy, OutboundProxy, ResolvedOutboundProxy};

    use super::{OutboundRouting, ProxySource};

    fn resolved(
        config: NetworkConfig,
        outbound_proxy: Option<ResolvedOutboundProxy>,
    ) -> ResolvedNetworkConfig {
        ResolvedNetworkConfig::new(config, outbound_proxy)
    }

    fn configured_socks5() -> ResolvedOutboundProxy {
        ResolvedOutboundProxy::Socks5 {
            address: "127.0.0.1:1080".parse().unwrap(),
            credentials: None,
        }
    }

    fn eligible() -> NetworkConfig {
        NetworkConfig {
            proxy_from_env: true,
            ..Default::default()
        }
    }

    fn ambient(http: &str, no_proxy: Option<&str>) -> AmbientHttpProxy {
        AmbientHttpProxy::from_test_values(http, no_proxy).unwrap()
    }

    /// Count discovery calls and report whether routing stayed direct.
    fn count_discoveries(config: &ResolvedNetworkConfig) -> (usize, bool) {
        let calls = Cell::new(0);
        let routing = OutboundRouting::capture_with(config, || {
            calls.set(calls.get() + 1);
            None
        });
        (calls.get(), matches!(routing.source, ProxySource::Direct))
    }

    #[test]
    fn capture_reads_the_environment_only_for_eligible_startups() {
        // Eligible: enabled networking, ambient intent, no explicit proxy.
        assert_eq!(count_discoveries(&resolved(eligible(), None)), (1, true));

        for (label, config) in [
            (
                "intent off",
                NetworkConfig {
                    proxy_from_env: false,
                    ..Default::default()
                },
            ),
            (
                "networking disabled",
                NetworkConfig {
                    enabled: false,
                    proxy_from_env: true,
                    ..Default::default()
                },
            ),
        ] {
            assert_eq!(
                count_discoveries(&resolved(config, None)),
                (0, true),
                "{label}"
            );
        }

        // A durable configured field suppresses discovery even without a
        // resolved leaf.
        let durable_only = resolved(
            NetworkConfig {
                outbound_proxy: Some(OutboundProxy::Socks5 {
                    address: "127.0.0.1:1080".parse().unwrap(),
                    credentials: None,
                }),
                ..eligible()
            },
            None,
        );
        assert_eq!(count_discoveries(&durable_only), (0, true));

        // A resolved configured leaf wins and is cloned once.
        let resolved_only = resolved(eligible(), Some(configured_socks5()));
        assert_eq!(count_discoveries(&resolved_only), (0, false));

        // Both present: the resolved leaf still wins without discovery.
        let both = resolved(
            NetworkConfig {
                outbound_proxy: Some(OutboundProxy::Socks5 {
                    address: "192.0.2.10:1080".parse().unwrap(),
                    credentials: None,
                }),
                ..eligible()
            },
            Some(configured_socks5()),
        );
        assert_eq!(count_discoveries(&both), (0, false));
    }

    #[test]
    fn capture_uses_one_discovery_result_and_leaves_the_launch_config_unchanged() {
        let config = resolved(eligible(), None);
        let before = serde_json::to_value(&config).unwrap();

        let calls = Cell::new(0);
        let routing = OutboundRouting::capture_with(&config, || {
            calls.set(calls.get() + 1);
            Some(ambient("http://proxy.test:3128", None))
        });
        assert_eq!(calls.get(), 1);
        assert!(matches!(routing.source, ProxySource::Ambient(_)));

        // Capture never writes the runtime leaf back into the launch config.
        assert_eq!(serde_json::to_value(&config).unwrap(), before);
        assert!(!before.to_string().contains("proxy.test"));
    }

    #[test]
    fn configured_keeps_the_supplied_arc_without_discovery() {
        let shared = SharedState::new(8);
        let guest: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let proxy = Arc::new(configured_socks5());

        let routing = OutboundRouting::configured(Some(Arc::clone(&proxy)));
        let ProxySource::Configured(kept) = &routing.source else {
            panic!("configured routing must keep its configured source");
        };
        assert!(Arc::ptr_eq(kept, &proxy));

        let selected = routing.select(guest, guest, false, &shared).unwrap();
        assert!(Arc::ptr_eq(&selected, &proxy));

        assert!(
            OutboundRouting::configured(None)
                .select(guest, guest, false, &shared)
                .is_none()
        );
        assert!(
            OutboundRouting::default()
                .select(guest, guest, false, &shared)
                .is_none()
        );
    }

    /// An explicit configured leaf wins over any discovered ambient settings,
    /// including a wildcard `NO_PROXY`, without reading the environment.
    #[test]
    fn configured_proxy_wins_over_ambient_and_no_proxy() {
        let shared = SharedState::new(8);
        let guest: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let configured = Arc::new(configured_socks5());

        let routing = OutboundRouting::configured(Some(Arc::clone(&configured)));
        assert!(Arc::ptr_eq(
            &routing.select(guest, guest, true, &shared).unwrap(),
            &configured
        ));

        let calls = Cell::new(0);
        let routing =
            OutboundRouting::capture_with(&resolved(eligible(), Some(configured_socks5())), || {
                calls.set(calls.get() + 1);
                Some(ambient("http://proxy.test:3128", Some("*")))
            });
        assert_eq!(calls.get(), 0);
        assert!(matches!(routing.source, ProxySource::Configured(_)));
    }

    #[test]
    fn host_rewrites_always_stay_direct() {
        let shared = SharedState::new(8);
        let guest: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let host: SocketAddr = "127.0.0.1:443".parse().unwrap();
        let proxy = Arc::new(configured_socks5());
        let routing = OutboundRouting::configured(Some(proxy));
        assert!(routing.select(guest, host, false, &shared).is_none());
    }

    #[test]
    fn ambient_route_bypasses_local_and_excluded_destinations() {
        let shared = SharedState::new(8);
        let external: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let local: SocketAddr = "127.0.0.1:9000".parse().unwrap();

        let discovered = ambient("http://proxy.test:3128", None);
        let plain = discovered.endpoint(false);
        let routing = OutboundRouting::ambient(discovered);
        assert!(Arc::ptr_eq(
            &routing.select(external, external, false, &shared).unwrap(),
            &plain
        ));

        // NO_PROXY IP and CIDR exclusions stay direct.
        for rules in ["203.0.113.9", "203.0.113.0/24", "*"] {
            let routing = OutboundRouting::ambient(ambient("http://proxy.test:3128", Some(rules)));
            assert!(
                routing.select(external, external, false, &shared).is_none(),
                "rules {rules}"
            );
        }

        // Loopback, unspecified and mapped-loopback host dial addresses stay direct.
        let routing = OutboundRouting::ambient(ambient("http://proxy.test:3128", None));
        for host in [
            local,
            "0.0.0.0:1".parse().unwrap(),
            "[::]:1".parse().unwrap(),
            "[::1]:1".parse().unwrap(),
            "[::ffff:127.0.0.1]:1".parse().unwrap(),
        ] {
            assert!(
                routing.select(external, host, false, &shared).is_none(),
                "{host}"
            );
        }

        // Direct routing never proxies.
        assert!(
            OutboundRouting::default()
                .select(external, external, false, &shared)
                .is_none()
        );
    }

    #[test]
    fn ambient_endpoint_choice_follows_the_tls_class() {
        let shared = SharedState::new(8);
        let destination: SocketAddr = "203.0.113.9:443".parse().unwrap();

        let discovered = AmbientHttpProxy::from_test_values_split(
            "http://plain.test:3128",
            Some("http://secure.test:3128"),
            None,
        )
        .unwrap();
        let plain = discovered.endpoint(false);
        let secure = discovered.endpoint(true);
        assert!(!Arc::ptr_eq(&plain, &secure));

        let routing = OutboundRouting::ambient(discovered);
        let selected_tls = routing
            .select(destination, destination, true, &shared)
            .unwrap();
        assert!(Arc::ptr_eq(&selected_tls, &secure));
        let selected_plain = routing
            .select(destination, destination, false, &shared)
            .unwrap();
        assert!(Arc::ptr_eq(&selected_plain, &plain));
    }

    #[test]
    fn ambient_domain_rules_need_a_live_dns_index_name() {
        let shared = SharedState::new(8);
        let guest: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let discovered = ambient("http://proxy.test:3128", Some(".internal"));
        let leaf = discovered.endpoint(false);
        let routing = OutboundRouting::ambient(discovered);

        // Unknown name: the domain rule cannot apply, so the flow is proxied.
        assert!(Arc::ptr_eq(
            &routing.select(guest, guest, false, &shared).unwrap(),
            &leaf
        ));

        // Any live name for the destination IP satisfies the rule.
        assert!(shared.cache_resolved_hostname(
            "x.internal",
            ResolvedHostnameFamily::Ipv4,
            [guest.ip()],
            Duration::from_secs(60),
        ));
        assert!(routing.select(guest, guest, false, &shared).is_none());

        // An expired or removed name no longer bypasses.
        shared.clear_resolved_hostname("x.internal", ResolvedHostnameFamily::Ipv4);
        assert!(routing.select(guest, guest, false, &shared).is_some());
    }

    /// Selection allocates nothing new: repeated calls for the same destination
    /// return the same captured leaf.
    #[test]
    fn repeated_selection_returns_the_same_arc() {
        let shared = SharedState::new(8);
        let guest: SocketAddr = "203.0.113.9:443".parse().unwrap();
        let routing = OutboundRouting::ambient(ambient("http://proxy.test:3128", None));

        let first = routing.select(guest, guest, false, &shared).unwrap();
        let second = routing.select(guest, guest, false, &shared).unwrap();
        assert!(Arc::ptr_eq(&first, &second));
    }
}
