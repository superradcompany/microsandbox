//! `SmoltcpNetwork` — orchestration type that ties [`crate::config::NetworkConfig`] to the
//! smoltcp engine.
//!
//! This is the networking analog to `PassthroughFs`/`MemFs` on the filesystem side — the single
//! type the runtime creates from config, wires into the VM builder, and starts
//! the networking stack.

use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::sync::Arc;
use std::thread::JoinHandle;

use ipnetwork::{Ipv4Network, Ipv6Network};
use microsandbox_protocol::bootstrap::{
    BootstrapEnvVar, BootstrapIpv4, BootstrapIpv6, BootstrapNetwork,
};
use microsandbox_protocol::{ENV_HOST_ALIAS, ENV_NET, ENV_NET_IPV4, ENV_NET_IPV6};
use microsandbox_types::{
    DeploymentProfile, NetworkRateLimitDirection, RateLimitConfigError, RateLimiterConfig,
};
use msb_krun::backends::net::NetBackend;

use crate::config::{MAX_NETWORK_CONNECTIONS, ResolvedNetworkConfig};
use crate::netstack::{
    backend::SmoltcpBackend,
    poll::{self, GatewayIps, PollLoopConfig},
    shared::{DEFAULT_QUEUE_CAPACITY, SharedState},
};
use crate::policy::{NetworkPolicy, NetworkProfile};
use crate::secrets::handle::SecretsHandle;
use crate::tls::state::{TlsState, TlsStateError};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Hard ceiling for concurrent connections on shared, multi-tenant hosts.
///
/// This matches the network engine's existing default, preventing a tenant
/// override from increasing host-side socket state above the normal budget.
const MULTI_TENANT_MAX_CONNECTIONS: usize = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The networking engine. Created from [`crate::config::NetworkConfig`] by the runtime.
///
/// Owns the smoltcp poll thread and provides:
/// - [`take_backend()`](Self::take_backend) — the `NetBackend` for `VmBuilder::net()`
/// - [`guest_bootstrap_network()`](Self::guest_bootstrap_network) — typed guest network setup
/// - [`ca_cert_pem()`](Self::ca_cert_pem) — CA certificate for TLS interception
pub struct SmoltcpNetwork {
    config: ResolvedNetworkConfig,
    /// Host-owned policy floor derived from the deployment profile and
    /// enforced in addition to the sandbox's configured network policy.
    platform_policy: Option<NetworkPolicy>,
    shared: Arc<SharedState>,
    backend: Option<SmoltcpBackend>,
    poll_handle: Option<JoinHandle<()>>,

    // Resolved from config + slot.
    guest_mac: [u8; 6],
    gateway_mac: [u8; 6],
    mtu: u16,
    // IPv4 / IPv6 are `Some` when active for this sandbox: the user supplied
    // an explicit address, or the host has a route for that family.
    guest_ipv4: Option<Ipv4Addr>,
    gateway_ipv4: Option<Ipv4Addr>,
    guest_ipv6: Option<Ipv6Addr>,
    gateway_ipv6: Option<Ipv6Addr>,

    // TLS state (if enabled). Created in new(), used for ca_cert_pem().
    tls_state: Option<Arc<TlsState>>,

    // Live-swappable secrets view shared with the poll loop and TLS state.
    secrets: SecretsHandle,
}

#[derive(Clone, Copy)]
struct HostRoutes {
    ipv4: bool,
    ipv6: bool,
}

/// Errors that prevent the smoltcp network from being created safely.
#[derive(Debug, thiserror::Error)]
pub enum NetworkInitError {
    /// The configured connection cap is above the hard safety limit.
    #[error("max_connections {configured} exceeds hard limit {limit}")]
    MaxConnectionsExceeded {
        /// Requested connection limit.
        configured: usize,
        /// Hard cap enforced by the network stack.
        limit: usize,
    },

    /// The configured IPv4 pool cannot provide a `/30` for this slot.
    #[error("IPv4 pool {pool} cannot assign network slot {slot}")]
    Ipv4PoolCapacity {
        /// Configured IPv4 pool.
        pool: Ipv4Network,
        /// Requested sandbox slot.
        slot: u16,
    },

    /// The configured IPv6 pool cannot provide a `/64` for this slot.
    #[error("IPv6 pool {pool} cannot assign network slot {slot}")]
    Ipv6PoolCapacity {
        /// Configured IPv6 pool.
        pool: Ipv6Network,
        /// Requested sandbox slot.
        slot: u16,
    },

    /// TLS interception state failed to initialize.
    #[error("TLS initialization failed: {0}")]
    Tls(#[from] TlsStateError),

    /// A stored rate limiter configuration failed validation.
    #[error("invalid {direction} rate limiter: {source}")]
    InvalidRateLimit {
        /// Which limiter is invalid: `egress` or `ingress`.
        direction: NetworkRateLimitDirection,
        /// Underlying validation error.
        #[source]
        source: RateLimitConfigError,
    },

    /// A stored network rate limiter has neither direction configured.
    #[error("invalid network rate limiter: at least one of egress or ingress is required")]
    EmptyNetworkRateLimiter,
}

/// Handle for installing host-side termination behavior into the network stack.
#[derive(Clone)]
pub struct TerminationHandle {
    shared: Arc<SharedState>,
}

/// Read-only view of aggregate network byte counters.
#[derive(Clone)]
pub struct MetricsHandle {
    shared: Arc<SharedState>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostRoutes {
    fn detect() -> Self {
        Self {
            ipv4: host_has_ipv4_route(),
            ipv6: host_has_ipv6_route(),
        }
    }
}

impl SmoltcpNetwork {
    /// Creates the network backend from a fully resolved runtime configuration.
    ///
    /// `MultiTenant` applies platform-owned configuration floors before any
    /// sockets, resolvers, or TLS state are created. The requested tenant policy
    /// remains separate and is intersected with the platform's public-network
    /// policy by the poll loop.
    ///
    /// # Errors
    ///
    /// Returns an error when the effective network configuration would allocate
    /// unsafe resources or TLS interception cannot initialize.
    pub fn new(
        config: ResolvedNetworkConfig,
        slot: u16,
        deployment_profile: DeploymentProfile,
    ) -> Result<Self, NetworkInitError> {
        Self::build(config, slot, deployment_profile, HostRoutes::detect())
    }

    fn build(
        mut config: ResolvedNetworkConfig,
        slot: u16,
        deployment_profile: DeploymentProfile,
        host_routes: HostRoutes,
    ) -> Result<Self, NetworkInitError> {
        enforce_deployment_profile(&mut config, deployment_profile);
        let platform_policy = Self::platform_policy(deployment_profile);
        let resolved_config = config;
        let config = resolved_config.config();

        if let Some(configured) = config.max_connections
            && configured > MAX_NETWORK_CONNECTIONS
        {
            return Err(NetworkInitError::MaxConnectionsExceeded {
                configured,
                limit: MAX_NETWORK_CONNECTIONS,
            });
        }

        let guest_mac = config
            .interface
            .mac
            .unwrap_or_else(|| derive_guest_mac(slot));
        let gateway_mac = derive_gateway_mac(slot);
        let mtu = config.interface.mtu.unwrap_or(1500);

        let guest_ipv4 = match config.interface.ipv4_address {
            Some(address) => Some(address),
            None if host_routes.ipv4 => Some(derive_guest_ipv4(
                config
                    .interface
                    .ipv4_pool
                    .unwrap_or_else(default_guest_ipv4_pool),
                slot,
            )?),
            None => None,
        };
        let gateway_ipv4 = guest_ipv4.map(gateway_from_guest_ipv4);
        let guest_ipv6 = match config.interface.ipv6_address {
            Some(address) => Some(address),
            None if host_routes.ipv6 => Some(derive_guest_ipv6(
                config
                    .interface
                    .ipv6_pool
                    .unwrap_or_else(default_guest_ipv6_pool),
                slot,
            )?),
            None => None,
        };
        let gateway_ipv6 = guest_ipv6.map(gateway_from_guest_ipv6);

        let queue_capacity = config
            .max_connections
            .unwrap_or(DEFAULT_QUEUE_CAPACITY)
            .max(DEFAULT_QUEUE_CAPACITY);
        let shared = Arc::new(SharedState::new(queue_capacity));
        // Every write path validates rate limiters (`NetworkBuilder::build`),
        // but a stored config bypasses the builder: fail startup cleanly
        // instead of panicking on a corrupted spec.
        if config.rate_limiter.as_ref().is_some_and(|rate_limiter| {
            rate_limiter.egress.is_none() && rate_limiter.ingress.is_none()
        }) {
            return Err(NetworkInitError::EmptyNetworkRateLimiter);
        }
        config
            .rate_limiter
            .as_ref()
            .and_then(|rate_limiter| rate_limiter.ingress.as_ref())
            .map(RateLimiterConfig::validate)
            .transpose()
            .map_err(|source| NetworkInitError::InvalidRateLimit {
                direction: NetworkRateLimitDirection::Ingress,
                source,
            })?;
        config
            .rate_limiter
            .as_ref()
            .and_then(|rate_limiter| rate_limiter.egress.as_ref())
            .map(RateLimiterConfig::validate)
            .transpose()
            .map_err(|source| NetworkInitError::InvalidRateLimit {
                direction: NetworkRateLimitDirection::Egress,
                source,
            })?;
        let backend = SmoltcpBackend::new(shared.clone());

        let secrets = SecretsHandle::new(config.secrets.clone());
        let tls_state = if config.tls.enabled {
            Some(Arc::new(TlsState::new(
                config.tls.clone(),
                secrets.clone(),
            )?))
        } else {
            None
        };

        Ok(Self {
            config: resolved_config,
            platform_policy,
            shared,
            backend: Some(backend),
            poll_handle: None,
            guest_mac,
            gateway_mac,
            mtu,
            guest_ipv4,
            gateway_ipv4,
            guest_ipv6,
            gateway_ipv6,
            tls_state,
            secrets,
        })
    }

    fn platform_policy(deployment_profile: DeploymentProfile) -> Option<NetworkPolicy> {
        match deployment_profile {
            DeploymentProfile::SingleTenant => None,
            DeploymentProfile::MultiTenant => {
                Some(NetworkPolicy::from_profiles([NetworkProfile::Public]))
            }
        }
    }

    /// Get the gateway IPs for virtio-net configuration and domain-based policy rules.
    fn gateway_ips(&self) -> GatewayIps {
        GatewayIps {
            ipv4: self.gateway_ipv4,
            ipv6: self.gateway_ipv6,
        }
    }

    /// Start the smoltcp poll thread.
    ///
    /// Must be called before VM boot. Requires a tokio runtime handle for
    /// spawning proxy tasks, DNS resolution, and published port listeners.
    pub fn start(&mut self, tokio_handle: tokio::runtime::Handle) {
        let shared = self.shared.clone();
        let poll_config = PollLoopConfig {
            gateway_mac: self.gateway_mac,
            guest_mac: self.guest_mac,
            gateway: self.gateway_ips(),
            guest_ipv4: self.guest_ipv4,
            guest_ipv6: self.guest_ipv6,
            mtu: self.mtu as usize,
        };
        let config = self.config.config();
        let network_policy = config.policy.clone();
        let platform_policy = self.platform_policy.clone();
        let dns_config = config.dns.clone();
        let tls_state = self.tls_state.clone();
        let published_ports = config.ports.clone();
        let max_connections = config.max_connections;
        let secrets = self.secrets.clone();
        let outbound_proxy = self.config.outbound_proxy().cloned().map(Arc::new);

        self.poll_handle = Some(
            std::thread::Builder::new()
                .name("smoltcp-poll".into())
                .spawn(move || {
                    poll::smoltcp_poll_loop(
                        shared,
                        poll_config,
                        network_policy,
                        platform_policy,
                        dns_config,
                        tls_state,
                        published_ports,
                        max_connections,
                        tokio_handle,
                        secrets,
                        outbound_proxy,
                    );
                })
                .expect("failed to spawn smoltcp poll thread"),
        );
    }

    /// Take the `NetBackend` for `VmBuilder::net()`. One-shot.
    pub fn take_backend(&mut self) -> Box<dyn NetBackend + Send> {
        Box::new(self.backend.take().expect("backend already taken"))
    }

    /// Guest MAC address for `VmBuilder::net().mac()`.
    pub fn guest_mac(&self) -> [u8; 6] {
        self.guest_mac
    }

    /// Generate `MSB_NET*` environment variables for the guest.
    ///
    /// The guest init (`agentd`) reads these to configure the network
    /// interface via ioctls + netlink.
    pub fn guest_env_vars(&self) -> Vec<(String, String)> {
        let mut vars = vec![
            (
                ENV_NET.into(),
                format!(
                    "iface=eth0,mac={},mtu={}",
                    format_mac(self.guest_mac),
                    self.mtu,
                ),
            ),
            (ENV_HOST_ALIAS.into(), crate::HOST_ALIAS.into()),
        ];

        if let (Some(guest), Some(gateway)) = (self.guest_ipv4, self.gateway_ipv4) {
            vars.push((
                ENV_NET_IPV4.into(),
                format!("addr={guest}/30,gw={gateway},dns={gateway}"),
            ));
        }

        if let (Some(guest), Some(gateway)) = (self.guest_ipv6, self.gateway_ipv6) {
            vars.push((
                ENV_NET_IPV6.into(),
                format!("addr={guest}/64,gw={gateway},dns={gateway}"),
            ));
        }

        // Auto-expose secret placeholders as environment variables.
        for secret in &self.config.config().secrets.secrets {
            vars.push((secret.env_var.clone(), secret.placeholder.clone()));
        }

        vars
    }

    /// Build the typed network payload consumed by agentd during bootstrap.
    pub fn guest_bootstrap_network(&self) -> BootstrapNetwork {
        BootstrapNetwork {
            interface: "eth0".to_string(),
            mac: self.guest_mac,
            mtu: self.mtu,
            ipv4: self
                .guest_ipv4
                .zip(self.gateway_ipv4)
                .map(|(address, gateway)| BootstrapIpv4 {
                    address,
                    prefix_len: 30,
                    gateway,
                    dns: Some(gateway),
                }),
            ipv6: self
                .guest_ipv6
                .zip(self.gateway_ipv6)
                .map(|(address, gateway)| BootstrapIpv6 {
                    address,
                    prefix_len: 64,
                    gateway,
                    dns: Some(gateway),
                }),
        }
    }

    /// Return the stable hostname used by guests to address the host gateway.
    pub fn guest_host_alias(&self) -> &'static str {
        crate::HOST_ALIAS
    }

    /// Return guest-visible secret placeholders for the baseline environment.
    ///
    /// Real secret values stay in the host-side network handler and never
    /// enter this payload.
    pub fn guest_secret_env(&self) -> Vec<BootstrapEnvVar> {
        self.config
            .config()
            .secrets
            .secrets
            .iter()
            .map(|secret| BootstrapEnvVar {
                key: secret.env_var.clone(),
                value: secret.placeholder.clone(),
            })
            .collect()
    }

    /// CA certificate PEM bytes if TLS interception is enabled.
    ///
    /// Write to the runtime mount before VM boot so the guest can trust it.
    pub fn ca_cert_pem(&self) -> Option<Vec<u8>> {
        self.tls_state.as_ref().map(|s| s.ca_cert_pem())
    }

    /// Host-trusted CA bundle to ship into the guest, if
    /// [`crate::config::NetworkConfig::trust_host_cas`] is enabled.
    ///
    /// Returned PEM may concatenate CAs that the Mozilla root bundle in
    /// the guest already trusts; duplicates are harmless and saved the
    /// cost of computing a delta. Returns `None` when the host store is
    /// empty or the feature is disabled.
    pub fn host_cas_cert_pem(&self) -> Option<Vec<u8>> {
        if !self.config.config().trust_host_cas {
            return None;
        }
        crate::tls::host_cas::collect_host_cas()
    }

    /// Create a handle for wiring runtime termination into the network stack.
    pub fn termination_handle(&self) -> TerminationHandle {
        TerminationHandle {
            shared: self.shared.clone(),
        }
    }

    /// Create a handle for reading aggregate network byte counters.
    pub fn metrics_handle(&self) -> MetricsHandle {
        MetricsHandle {
            shared: self.shared.clone(),
        }
    }

    /// Live-swappable view of the secrets configuration. The runtime control
    /// socket uses it to apply secret rotation, removal, and allowed-host
    /// updates without restarting the sandbox.
    pub fn secrets_handle(&self) -> SecretsHandle {
        self.secrets.clone()
    }
}

impl TerminationHandle {
    /// Install the termination hook.
    pub fn set_hook(&self, hook: Arc<dyn Fn() + Send + Sync>) {
        self.shared.set_termination_hook(hook);
    }
}

impl MetricsHandle {
    /// Total guest -> runtime bytes observed at the virtio-net boundary.
    pub fn tx_bytes(&self) -> u64 {
        self.shared.tx_bytes()
    }

    /// Total runtime -> guest bytes observed at the virtio-net boundary.
    pub fn rx_bytes(&self) -> u64 {
        self.shared.rx_bytes()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Apply the platform-owned configuration floor before network resources are created.
///
/// Policy rules are deliberately not flattened here. The poll loop evaluates
/// the platform public-network policy and the tenant policy independently so a
/// broad tenant allow can never outrank the platform floor, while a tenant deny
/// still remains effective.
fn enforce_deployment_profile(config: &mut ResolvedNetworkConfig, profile: DeploymentProfile) {
    if profile == DeploymentProfile::SingleTenant {
        return;
    }

    config.clear_outbound_proxy();

    let config = config.config_mut();
    let interface_overridden = config.interface.mac.is_some()
        || config.interface.mtu.is_some()
        || config.interface.ipv4_address.is_some()
        || config.interface.ipv4_pool.is_some()
        || config.interface.ipv6_address.is_some()
        || config.interface.ipv6_pool.is_some();
    let had_published_ports = !config.ports.is_empty();
    let had_custom_nameservers = !config.dns.nameservers.is_empty();
    let disabled_rebind_protection = !config.dns.rebind_protection;
    let trusted_host_cas = config.trust_host_cas;
    let had_outbound_proxy = config.outbound_proxy.is_some();
    let connection_limit_clamped = config
        .max_connections
        .is_some_and(|limit| limit > MULTI_TENANT_MAX_CONNECTIONS);

    config.interface = Default::default();
    config.ports.clear();
    config.dns.nameservers.clear();
    config.dns.rebind_protection = true;
    config.trust_host_cas = false;
    config.max_connections = Some(
        config
            .max_connections
            .unwrap_or(MULTI_TENANT_MAX_CONNECTIONS)
            .min(MULTI_TENANT_MAX_CONNECTIONS),
    );

    if interface_overridden
        || had_published_ports
        || had_custom_nameservers
        || disabled_rebind_protection
        || trusted_host_cas
        || had_outbound_proxy
        || connection_limit_clamped
    {
        tracing::warn!(
            interface_overridden,
            had_published_ports,
            had_custom_nameservers,
            disabled_rebind_protection,
            trusted_host_cas,
            had_outbound_proxy,
            connection_limit_clamped,
            "multi-tenant deployment profile overrode unsafe network configuration"
        );
    }
}

/// Derive a guest MAC address from the sandbox slot.
///
/// Format: `02:ms:bx:SS:SS:02` where SS:SS encodes the slot.
fn derive_guest_mac(slot: u16) -> [u8; 6] {
    let s = slot.to_be_bytes();
    [0x02, 0x6d, 0x73, s[0], s[1], 0x02]
}

/// Derive a gateway MAC address from the sandbox slot.
///
/// Format: `02:ms:bx:SS:SS:01`.
fn derive_gateway_mac(slot: u16) -> [u8; 6] {
    let s = slot.to_be_bytes();
    [0x02, 0x6d, 0x73, s[0], s[1], 0x01]
}

/// Derive a guest IPv4 address from the sandbox slot.
///
/// Pool: `172.16.0.0/12` by default. Each slot gets a `/30` block (4 IPs).
/// Guest is at offset +2 in the block.
fn derive_guest_ipv4(pool: Ipv4Network, slot: u16) -> Result<Ipv4Addr, NetworkInitError> {
    let capacity = 30_u8
        .checked_sub(pool.prefix())
        .map(|host_bits| 1_u32 << host_bits)
        .ok_or(NetworkInitError::Ipv4PoolCapacity { pool, slot })?;
    if u32::from(slot) >= capacity {
        return Err(NetworkInitError::Ipv4PoolCapacity { pool, slot });
    }

    let base = u32::from(pool.network());
    let offset = u32::from(slot) * 4 + 2; // +2 = guest within /30
    Ok(Ipv4Addr::from(base + offset))
}

/// Gateway IPv4 from guest IPv4: guest - 1 (offset +1 in the /30 block).
fn gateway_from_guest_ipv4(guest: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(guest) - 1)
}

fn default_guest_ipv4_pool() -> Ipv4Network {
    Ipv4Network::new(Ipv4Addr::new(172, 16, 0, 0), 12)
        .expect("default IPv4 pool must be a valid network")
}

/// Derive a guest IPv6 address from the sandbox slot.
///
/// Pool: `fd42:6d73:62::/48`. Each slot gets a `/64` prefix.
/// Guest is `::2` in its prefix.
fn derive_guest_ipv6(pool: Ipv6Network, slot: u16) -> Result<Ipv6Addr, NetworkInitError> {
    let capacity = 64_u8
        .checked_sub(pool.prefix())
        .map(|host_bits| 1_u128 << host_bits)
        .ok_or(NetworkInitError::Ipv6PoolCapacity { pool, slot })?;
    if u128::from(slot) >= capacity {
        return Err(NetworkInitError::Ipv6PoolCapacity { pool, slot });
    }

    let base = u128::from(pool.network());
    let offset = u128::from(slot) << 64;
    Ok(Ipv6Addr::from(base + offset + 2))
}

/// Gateway IPv6 from guest IPv6: `::1` in the same prefix.
fn gateway_from_guest_ipv6(guest: Ipv6Addr) -> Ipv6Addr {
    let segs = guest.segments();
    Ipv6Addr::new(segs[0], segs[1], segs[2], segs[3], 0, 0, 0, 1)
}

fn default_guest_ipv6_pool() -> Ipv6Network {
    Ipv6Network::new(Ipv6Addr::new(0xfd42, 0x6d73, 0x0062, 0, 0, 0, 0, 0), 48)
        .expect("default IPv6 pool must be a valid network")
}

/// Format a MAC address as `xx:xx:xx:xx:xx:xx`.
fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

/// Returns true if the host kernel can select an IPv4 route.
///
/// `UdpSocket::connect` performs a local routing-table lookup against the
/// TEST-NET-1 (`192.0.2.1`) address; it does not send packets or wait on
/// the network.
fn host_has_ipv4_route() -> bool {
    UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .and_then(|socket| socket.connect((Ipv4Addr::new(192, 0, 2, 1), 443)))
        .is_ok()
}

/// Returns true if the host kernel can select an IPv6 route. Probes a
/// `2001:db8::/32` documentation address via `UdpSocket::connect` (no packet
/// is sent).
fn host_has_ipv6_route() -> bool {
    UdpSocket::bind((Ipv6Addr::UNSPECIFIED, 0))
        .and_then(|socket| socket.connect((Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1), 443)))
        .is_ok()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{EnvNetworkSecretResolver, NetworkConfig, PortProtocol, PublishedPort};
    use crate::dns::Nameserver;

    fn resolved(config: NetworkConfig) -> ResolvedNetworkConfig {
        config.resolve(&EnvNetworkSecretResolver).unwrap()
    }

    fn routes(ipv4: bool, ipv6: bool) -> HostRoutes {
        HostRoutes { ipv4, ipv6 }
    }

    #[test]
    fn derive_addresses_slot_0() {
        assert_eq!(derive_guest_mac(0), [0x02, 0x6d, 0x73, 0x00, 0x00, 0x02]);
        assert_eq!(derive_gateway_mac(0), [0x02, 0x6d, 0x73, 0x00, 0x00, 0x01]);
        assert_eq!(
            derive_guest_ipv4(default_guest_ipv4_pool(), 0).unwrap(),
            Ipv4Addr::new(172, 16, 0, 2)
        );
        assert_eq!(
            gateway_from_guest_ipv4(Ipv4Addr::new(172, 16, 0, 2)),
            Ipv4Addr::new(172, 16, 0, 1)
        );
    }

    #[test]
    fn multi_tenant_profile_sanitizes_host_owned_network_controls() {
        let mut config = NetworkConfig::default();
        config.interface.mac = Some([2, 3, 4, 5, 6, 7]);
        config.interface.mtu = Some(9000);
        config.ports.push(PublishedPort {
            host_port: 8080,
            guest_port: 80,
            protocol: PortProtocol::Tcp,
            host_bind: Ipv4Addr::UNSPECIFIED.into(),
        });
        config.dns.nameservers = vec!["10.0.0.53".parse::<Nameserver>().unwrap()];
        config.dns.rebind_protection = false;
        config.trust_host_cas = true;
        config.outbound_proxy = Some(crate::proxy::OutboundProxy::Socks5 {
            address: "127.0.0.1:1080".parse().unwrap(),
            credentials: None,
        });
        config.max_connections = Some(MULTI_TENANT_MAX_CONNECTIONS + 1);
        config.policy = NetworkPolicy::allow_all();
        let mut resolved = resolved(config);

        enforce_deployment_profile(&mut resolved, DeploymentProfile::MultiTenant);
        let config = resolved.config();

        assert!(config.interface.mac.is_none());
        assert!(config.interface.mtu.is_none());
        assert!(config.ports.is_empty());
        assert!(config.dns.nameservers.is_empty());
        assert!(config.dns.rebind_protection);
        assert!(!config.trust_host_cas);
        assert!(config.outbound_proxy.is_none());
        assert_eq!(config.max_connections, Some(MULTI_TENANT_MAX_CONNECTIONS));
        assert!(resolved.config().outbound_proxy.is_none());
        assert!(resolved.outbound_proxy().is_none());
        // Tenant policy stays intact and is intersected with the platform
        // policy at evaluation time instead of being reordered or flattened.
        assert!(config.policy.default_egress.is_allow());
    }

    #[test]
    fn single_tenant_profile_preserves_requested_network_controls() {
        let mut config = NetworkConfig::default();
        config.interface.mtu = Some(9000);
        config.dns.rebind_protection = false;
        config.trust_host_cas = true;
        config.outbound_proxy = Some(crate::proxy::OutboundProxy::Socks5 {
            address: "127.0.0.1:1080".parse().unwrap(),
            credentials: None,
        });

        let mut resolved = resolved(config);
        enforce_deployment_profile(&mut resolved, DeploymentProfile::SingleTenant);
        let config = resolved.config();

        assert_eq!(config.interface.mtu, Some(9000));
        assert!(!config.dns.rebind_protection);
        assert!(config.trust_host_cas);
        assert!(config.outbound_proxy.is_some());
    }

    #[test]
    fn derive_addresses_slot_1() {
        assert_eq!(
            derive_guest_ipv4(default_guest_ipv4_pool(), 1).unwrap(),
            Ipv4Addr::new(172, 16, 0, 6)
        );
        assert_eq!(
            gateway_from_guest_ipv4(Ipv4Addr::new(172, 16, 0, 6)),
            Ipv4Addr::new(172, 16, 0, 5)
        );
    }

    #[test]
    fn derive_addresses_max_slot() {
        assert_eq!(
            derive_guest_mac(u16::MAX),
            [0x02, 0x6d, 0x73, 0xff, 0xff, 0x02]
        );
        assert_eq!(
            derive_guest_ipv4(default_guest_ipv4_pool(), u16::MAX).unwrap(),
            Ipv4Addr::new(172, 19, 255, 254)
        );
        assert_eq!(
            derive_guest_ipv6(default_guest_ipv6_pool(), u16::MAX).unwrap(),
            "fd42:6d73:62:ffff::2".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn derive_addresses_custom_ipv4_pool() {
        let pool = "172.31.240.0/24".parse::<Ipv4Network>().unwrap();
        assert_eq!(
            derive_guest_ipv4(pool, 0).unwrap(),
            Ipv4Addr::new(172, 31, 240, 2)
        );
        assert_eq!(
            derive_guest_ipv4(pool, 63).unwrap(),
            Ipv4Addr::new(172, 31, 240, 254)
        );
    }

    #[test]
    fn custom_ipv4_pool_capacity_is_a_typed_error() {
        let pool = "172.31.240.0/24".parse::<Ipv4Network>().unwrap();
        assert!(matches!(
            derive_guest_ipv4(pool, 64),
            Err(NetworkInitError::Ipv4PoolCapacity { slot: 64, .. })
        ));

        let pool = "172.31.240.0/31".parse::<Ipv4Network>().unwrap();
        assert!(matches!(
            derive_guest_ipv4(pool, 0),
            Err(NetworkInitError::Ipv4PoolCapacity { slot: 0, .. })
        ));
    }

    #[test]
    fn derive_ipv6_slot_0() {
        assert_eq!(
            derive_guest_ipv6(default_guest_ipv6_pool(), 0).unwrap(),
            "fd42:6d73:62:0::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            gateway_from_guest_ipv6(derive_guest_ipv6(default_guest_ipv6_pool(), 0).unwrap()),
            "fd42:6d73:62:0::1".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn derive_addresses_custom_ipv6_pool() {
        let pool = "fd7a:115c:a1e0:100::/56".parse::<Ipv6Network>().unwrap();
        assert_eq!(
            derive_guest_ipv6(pool, 0).unwrap(),
            "fd7a:115c:a1e0:100::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            derive_guest_ipv6(pool, 3).unwrap(),
            "fd7a:115c:a1e0:103::2".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn custom_ipv6_pool_capacity_is_a_typed_error() {
        let pool = "fd7a:115c:a1e0:100::/62".parse::<Ipv6Network>().unwrap();
        assert!(matches!(
            derive_guest_ipv6(pool, 4),
            Err(NetworkInitError::Ipv6PoolCapacity { slot: 4, .. })
        ));

        let pool = "fd7a:115c:a1e0:100::/65".parse::<Ipv6Network>().unwrap();
        assert!(matches!(
            derive_guest_ipv6(pool, 0),
            Err(NetworkInitError::Ipv6PoolCapacity { slot: 0, .. })
        ));
    }

    #[test]
    fn format_mac_address() {
        assert_eq!(
            format_mac([0x02, 0x6d, 0x73, 0x00, 0x00, 0x01]),
            "02:6d:73:00:00:01"
        );
    }

    #[test]
    fn guest_env_vars_includes_ipv4_when_host_has_v4_route() {
        let net = SmoltcpNetwork::build(
            resolved(NetworkConfig::default()),
            0,
            DeploymentProfile::SingleTenant,
            routes(true, false),
        )
        .unwrap();
        let vars = net.guest_env_vars();

        assert_eq!(vars.len(), 3);
        assert_eq!(vars[0].0, ENV_NET);
        assert!(vars[0].1.contains("iface=eth0"));
        assert_eq!(vars[1].0, ENV_HOST_ALIAS);
        assert_eq!(vars[1].1, crate::HOST_ALIAS);
        assert_eq!(vars[2].0, ENV_NET_IPV4);
        assert!(vars[2].1.contains("/30"));
    }

    #[test]
    fn guest_env_vars_includes_ipv6_when_host_has_v6_route() {
        let net = SmoltcpNetwork::build(
            resolved(NetworkConfig::default()),
            0,
            DeploymentProfile::SingleTenant,
            routes(true, true),
        )
        .unwrap();
        let vars = net.guest_env_vars();

        assert_eq!(vars.len(), 4);
        assert_eq!(vars[0].0, ENV_NET);
        assert_eq!(vars[1].0, ENV_HOST_ALIAS);
        assert_eq!(vars[2].0, ENV_NET_IPV4);
        assert_eq!(vars[3].0, ENV_NET_IPV6);
        assert!(vars[3].1.contains("/64"));
    }

    #[test]
    fn guest_env_vars_omit_ipv6_without_host_route() {
        let net = SmoltcpNetwork::build(
            resolved(NetworkConfig::default()),
            0,
            DeploymentProfile::SingleTenant,
            routes(true, false),
        )
        .unwrap();
        let vars = net.guest_env_vars();

        assert!(!vars.iter().any(|(k, _)| k == ENV_NET_IPV6));
    }

    #[test]
    fn guest_env_vars_omit_ipv4_without_host_route() {
        let net = SmoltcpNetwork::build(
            resolved(NetworkConfig::default()),
            0,
            DeploymentProfile::SingleTenant,
            routes(false, true),
        )
        .unwrap();
        let vars = net.guest_env_vars();

        assert_eq!(vars.len(), 3);
        assert_eq!(vars[0].0, ENV_NET);
        assert_eq!(vars[1].0, ENV_HOST_ALIAS);
        assert_eq!(vars[2].0, ENV_NET_IPV6);
    }

    #[test]
    fn explicit_ipv6_address_overrides_missing_host_v6_route() {
        let mut config = NetworkConfig::default();
        config.interface.ipv6_address = Some("fd42:6d73:62:99::2".parse().unwrap());
        let net = SmoltcpNetwork::build(
            resolved(config),
            0,
            DeploymentProfile::SingleTenant,
            routes(true, false),
        )
        .unwrap();
        let vars = net.guest_env_vars();

        let v6 = vars
            .iter()
            .find(|(k, _)| k == ENV_NET_IPV6)
            .expect("explicit ipv6 should publish env var even without host route");
        assert!(v6.1.contains("fd42:6d73:62:99::2/64"));
    }

    #[test]
    fn neither_family_active_emits_only_base_env_vars() {
        let net = SmoltcpNetwork::build(
            resolved(NetworkConfig::default()),
            0,
            DeploymentProfile::SingleTenant,
            routes(false, false),
        )
        .unwrap();
        let vars = net.guest_env_vars();

        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].0, ENV_NET);
        assert_eq!(vars[1].0, ENV_HOST_ALIAS);
    }

    #[test]
    fn guest_bootstrap_network_preserves_active_address_families() {
        let net = SmoltcpNetwork::build(
            resolved(NetworkConfig::default()),
            7,
            DeploymentProfile::SingleTenant,
            routes(true, true),
        )
        .unwrap();

        let bootstrap = net.guest_bootstrap_network();

        assert_eq!(bootstrap.interface, "eth0");
        assert_eq!(bootstrap.mac, net.guest_mac());
        assert_eq!(bootstrap.mtu, 1500);
        assert_eq!(bootstrap.ipv4.unwrap().prefix_len, 30);
        assert_eq!(bootstrap.ipv6.unwrap().prefix_len, 64);
        assert_eq!(net.guest_host_alias(), crate::HOST_ALIAS);
    }

    #[test]
    fn guest_bootstrap_network_allows_no_active_address_family() {
        let net = SmoltcpNetwork::build(
            resolved(NetworkConfig::default()),
            0,
            DeploymentProfile::SingleTenant,
            routes(false, false),
        )
        .unwrap();

        let bootstrap = net.guest_bootstrap_network();

        assert!(bootstrap.ipv4.is_none());
        assert!(bootstrap.ipv6.is_none());
    }

    #[test]
    fn build_rejects_excessive_max_connections() {
        let mut config = NetworkConfig {
            max_connections: Some(MAX_NETWORK_CONNECTIONS + 1),
            ..NetworkConfig::default()
        };
        config.tls.enabled = false;

        let err = match SmoltcpNetwork::build(
            resolved(config),
            0,
            DeploymentProfile::SingleTenant,
            routes(true, false),
        ) {
            Ok(_) => panic!("excessive max_connections should fail"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            NetworkInitError::MaxConnectionsExceeded {
                configured,
                limit: MAX_NETWORK_CONNECTIONS
            } if configured == MAX_NETWORK_CONNECTIONS + 1
        ));
    }

    /// A stored config bypasses the builder's validation, so an invalid
    /// limiter must fail startup cleanly instead of panicking.
    #[test]
    fn build_rejects_invalid_rate_limiter() {
        let mut config = NetworkConfig {
            rate_limiter: Some(microsandbox_types::NetworkRateLimiterConfig {
                egress: None,
                ingress: Some(microsandbox_types::RateLimiterConfig {
                    bandwidth: None,
                    ops: None,
                }),
            }),
            ..NetworkConfig::default()
        };
        config.tls.enabled = false;

        let err = match SmoltcpNetwork::build(
            resolved(config),
            0,
            DeploymentProfile::SingleTenant,
            routes(true, false),
        ) {
            Ok(_) => panic!("empty rate limiter should fail"),
            Err(err) => err,
        };

        assert!(matches!(
            err,
            NetworkInitError::InvalidRateLimit {
                direction: NetworkRateLimitDirection::Ingress,
                source: RateLimitConfigError::EmptyLimiter,
            }
        ));
    }
}
