//! `SmoltcpNetwork` — orchestration type that ties [`NetworkConfig`] to the
//! smoltcp engine.
//!
//! This is the networking analog to `PassthroughFs`/`MemFs` on the filesystem side — the single
//! type the runtime creates from config, wires into the VM builder, and starts
//! the networking stack.

use std::net::{Ipv4Addr, Ipv6Addr, UdpSocket};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Instant;

use ipnetwork::{Ipv4Network, Ipv6Network};
use microsandbox_protocol::{ENV_HOST_ALIAS, ENV_NET, ENV_NET_IPV4, ENV_NET_IPV6};
use microsandbox_types::DeploymentProfile;
use msb_krun::backends::net::NetBackend;

use crate::backend::SmoltcpBackend;
use crate::config::{MAX_NETWORK_CONNECTIONS, NetworkConfig};
use crate::policy::{NetworkPolicy, NetworkProfile};
use crate::rate_limit::RateLimiter;
use crate::secrets::handle::SecretsHandle;
use crate::shared::{DEFAULT_QUEUE_CAPACITY, SharedState};
use crate::stack::{self, GatewayIps, PollLoopConfig};
use crate::tls::state::{TlsState, TlsStateError};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum sandbox slot value. Limited by MAC/IPv6 encoding (16 bits = 65535).
/// The default IPv4 pool (172.16.0.0/12 with /30 blocks) supports 262144 slots,
/// but MAC and IPv6 derivation only encode the low 16 bits, so 65535 is the
/// effective maximum.
const MAX_SLOT: u64 = u16::MAX as u64;

/// Hard ceiling for concurrent connections on shared, multi-tenant hosts.
///
/// This matches the network engine's existing default, preventing a tenant
/// override from increasing host-side socket state above the normal budget.
const MULTI_TENANT_MAX_CONNECTIONS: usize = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The networking engine. Created from [`NetworkConfig`] by the runtime.
///
/// Owns the smoltcp poll thread and provides:
/// - [`take_backend()`](Self::take_backend) — the `NetBackend` for `VmBuilder::net()`
/// - [`guest_env_vars()`](Self::guest_env_vars) — `MSB_NET*` env vars for the guest
/// - [`ca_cert_pem()`](Self::ca_cert_pem) — CA certificate for TLS interception
pub struct SmoltcpNetwork {
    config: NetworkConfig,
    deployment_profile: DeploymentProfile,
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

    /// TLS interception state failed to initialize.
    #[error("TLS initialization failed: {0}")]
    Tls(#[from] TlsStateError),
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

impl SmoltcpNetwork {
    /// Create from user config + sandbox slot (for IP/MAC derivation).
    ///
    /// Each address family is enabled when either the user supplied an
    /// explicit address or the host kernel has a route for that family;
    /// otherwise the corresponding `guest_*`/`gateway_*` fields stay `None`
    /// and the family is omitted from the smoltcp interface, env vars, and
    /// downstream consumers.
    ///
    /// # Errors
    ///
    /// Returns an error when network configuration would allocate unsafe
    /// resources or TLS interception cannot initialize.
    ///
    /// # Panics
    ///
    /// Panics if `slot` exceeds the address pool capacity (65535 for MAC/IPv6,
    /// 524287 for IPv4).
    pub fn new(config: NetworkConfig, slot: u64) -> Result<Self, NetworkInitError> {
        Self::new_with_profile(config, slot, DeploymentProfile::SingleTenant)
    }

    /// Create the network backend with an explicit host-runtime deployment profile.
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
    pub fn new_with_profile(
        mut config: NetworkConfig,
        slot: u64,
        deployment_profile: DeploymentProfile,
    ) -> Result<Self, NetworkInitError> {
        enforce_deployment_profile(&mut config, deployment_profile);
        Self::new_with_profile_and_routes(
            config,
            slot,
            deployment_profile,
            host_has_ipv4_route(),
            host_has_ipv6_route(),
        )
    }

    #[cfg(test)]
    fn new_with_routes(
        config: NetworkConfig,
        slot: u64,
        host_has_ipv4: bool,
        host_has_ipv6: bool,
    ) -> Result<Self, NetworkInitError> {
        Self::new_with_profile_and_routes(
            config,
            slot,
            DeploymentProfile::SingleTenant,
            host_has_ipv4,
            host_has_ipv6,
        )
    }

    fn new_with_profile_and_routes(
        config: NetworkConfig,
        slot: u64,
        deployment_profile: DeploymentProfile,
        host_has_ipv4: bool,
        host_has_ipv6: bool,
    ) -> Result<Self, NetworkInitError> {
        assert!(
            slot <= MAX_SLOT,
            "sandbox slot {slot} exceeds address pool capacity (max {MAX_SLOT})"
        );
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

        let guest_ipv4 = config.interface.ipv4_address.or_else(|| {
            host_has_ipv4.then(|| {
                derive_guest_ipv4(
                    config
                        .interface
                        .ipv4_pool
                        .unwrap_or_else(default_guest_ipv4_pool),
                    slot,
                )
            })
        });
        let gateway_ipv4 = guest_ipv4.map(gateway_from_guest_ipv4);
        let guest_ipv6 = config.interface.ipv6_address.or_else(|| {
            host_has_ipv6.then(|| {
                derive_guest_ipv6(
                    config
                        .interface
                        .ipv6_pool
                        .unwrap_or_else(default_guest_ipv6_pool),
                    slot,
                )
            })
        });
        let gateway_ipv6 = guest_ipv6.map(gateway_from_guest_ipv6);

        let queue_capacity = config
            .max_connections
            .unwrap_or(DEFAULT_QUEUE_CAPACITY)
            .max(DEFAULT_QUEUE_CAPACITY);
        let shared = Arc::new(SharedState::new(queue_capacity));
        // Every path that writes a rate limiter into the config validates it
        // first (`NetworkBuilder::build`), so an invalid one here is a bug.
        let rx_rate_limiter = config.rx_rate_limiter.as_ref().map(|limiter| {
            RateLimiter::new(limiter, Instant::now())
                .expect("rx rate limiter config should be validated before reaching the engine")
        });
        let backend = SmoltcpBackend::new(shared.clone(), rx_rate_limiter);

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
            config,
            deployment_profile,
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
        let network_policy = self.config.policy.clone();
        let platform_policy = match self.deployment_profile {
            DeploymentProfile::SingleTenant => None,
            DeploymentProfile::MultiTenant => {
                Some(NetworkPolicy::from_profiles([NetworkProfile::Public]))
            }
        };
        let dns_config = self.config.dns.clone();
        let tls_state = self.tls_state.clone();
        let published_ports = self.config.ports.clone();
        let max_connections = self.config.max_connections;
        let tx_rate_limiter = self.config.tx_rate_limiter.as_ref().map(|limiter| {
            RateLimiter::new(limiter, Instant::now())
                .expect("tx rate limiter config should be validated before reaching the engine")
        });
        let secrets = self.secrets.clone();

        self.poll_handle = Some(
            std::thread::Builder::new()
                .name("smoltcp-poll".into())
                .spawn(move || {
                    stack::smoltcp_poll_loop(
                        shared,
                        poll_config,
                        network_policy,
                        platform_policy,
                        dns_config,
                        tls_state,
                        published_ports,
                        max_connections,
                        tx_rate_limiter,
                        tokio_handle,
                        secrets,
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
        for secret in &self.config.secrets.secrets {
            vars.push((secret.env_var.clone(), secret.placeholder.clone()));
        }

        vars
    }

    /// CA certificate PEM bytes if TLS interception is enabled.
    ///
    /// Write to the runtime mount before VM boot so the guest can trust it.
    pub fn ca_cert_pem(&self) -> Option<Vec<u8>> {
        self.tls_state.as_ref().map(|s| s.ca_cert_pem())
    }

    /// Host-trusted CA bundle to ship into the guest, if
    /// [`NetworkConfig::trust_host_cas`] is enabled.
    ///
    /// Returned PEM may concatenate CAs that the Mozilla root bundle in
    /// the guest already trusts; duplicates are harmless and saved the
    /// cost of computing a delta. Returns `None` when the host store is
    /// empty or the feature is disabled.
    pub fn host_cas_cert_pem(&self) -> Option<Vec<u8>> {
        if !self.config.trust_host_cas {
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
fn enforce_deployment_profile(config: &mut NetworkConfig, profile: DeploymentProfile) {
    if profile == DeploymentProfile::SingleTenant {
        return;
    }

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
        || connection_limit_clamped
    {
        tracing::warn!(
            interface_overridden,
            had_published_ports,
            had_custom_nameservers,
            disabled_rebind_protection,
            trusted_host_cas,
            connection_limit_clamped,
            "multi-tenant deployment profile overrode unsafe network configuration"
        );
    }
}

/// Derive a guest MAC address from the sandbox slot.
///
/// Format: `02:ms:bx:SS:SS:02` where SS:SS encodes the slot.
fn derive_guest_mac(slot: u64) -> [u8; 6] {
    let s = slot.to_be_bytes();
    [0x02, 0x6d, 0x73, s[6], s[7], 0x02]
}

/// Derive a gateway MAC address from the sandbox slot.
///
/// Format: `02:ms:bx:SS:SS:01`.
fn derive_gateway_mac(slot: u64) -> [u8; 6] {
    let s = slot.to_be_bytes();
    [0x02, 0x6d, 0x73, s[6], s[7], 0x01]
}

/// Derive a guest IPv4 address from the sandbox slot.
///
/// Pool: `172.16.0.0/12` by default. Each slot gets a `/30` block (4 IPs).
/// Guest is at offset +2 in the block.
fn derive_guest_ipv4(pool: Ipv4Network, slot: u64) -> Ipv4Addr {
    assert!(
        pool.prefix() <= 30,
        "IPv4 pool {pool} must be large enough to contain at least one /30 block"
    );

    let capacity = 1u64 << (30 - pool.prefix());
    assert!(
        slot < capacity,
        "sandbox slot {slot} exceeds IPv4 pool {pool} capacity ({capacity} /30 blocks)"
    );

    let base = u32::from(pool.network());
    let offset = (slot as u32) * 4 + 2; // +2 = guest within /30
    Ipv4Addr::from(base + offset)
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
fn derive_guest_ipv6(pool: Ipv6Network, slot: u64) -> Ipv6Addr {
    assert!(
        pool.prefix() <= 64,
        "IPv6 pool {pool} must be large enough to contain at least one /64 prefix"
    );

    let capacity = 1u128 << (64 - pool.prefix());
    assert!(
        (slot as u128) < capacity,
        "sandbox slot {slot} exceeds IPv6 pool {pool} capacity ({capacity} /64 prefixes)"
    );

    let base = u128::from(pool.network());
    let offset = (slot as u128) << 64;
    Ipv6Addr::from(base + offset + 2)
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
    use crate::config::{PortProtocol, PublishedPort};
    use crate::dns::Nameserver;

    #[test]
    fn derive_addresses_slot_0() {
        assert_eq!(derive_guest_mac(0), [0x02, 0x6d, 0x73, 0x00, 0x00, 0x02]);
        assert_eq!(derive_gateway_mac(0), [0x02, 0x6d, 0x73, 0x00, 0x00, 0x01]);
        assert_eq!(
            derive_guest_ipv4(default_guest_ipv4_pool(), 0),
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
        config.max_connections = Some(MULTI_TENANT_MAX_CONNECTIONS + 1);
        config.policy = NetworkPolicy::allow_all();

        enforce_deployment_profile(&mut config, DeploymentProfile::MultiTenant);

        assert!(config.interface.mac.is_none());
        assert!(config.interface.mtu.is_none());
        assert!(config.ports.is_empty());
        assert!(config.dns.nameservers.is_empty());
        assert!(config.dns.rebind_protection);
        assert!(!config.trust_host_cas);
        assert_eq!(config.max_connections, Some(MULTI_TENANT_MAX_CONNECTIONS));
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

        enforce_deployment_profile(&mut config, DeploymentProfile::SingleTenant);

        assert_eq!(config.interface.mtu, Some(9000));
        assert!(!config.dns.rebind_protection);
        assert!(config.trust_host_cas);
    }

    #[test]
    fn derive_addresses_slot_1() {
        assert_eq!(
            derive_guest_ipv4(default_guest_ipv4_pool(), 1),
            Ipv4Addr::new(172, 16, 0, 6)
        );
        assert_eq!(
            gateway_from_guest_ipv4(Ipv4Addr::new(172, 16, 0, 6)),
            Ipv4Addr::new(172, 16, 0, 5)
        );
    }

    #[test]
    fn derive_addresses_custom_ipv4_pool() {
        let pool = "172.31.240.0/24".parse::<Ipv4Network>().unwrap();
        assert_eq!(derive_guest_ipv4(pool, 0), Ipv4Addr::new(172, 31, 240, 2));
        assert_eq!(
            derive_guest_ipv4(pool, 63),
            Ipv4Addr::new(172, 31, 240, 254)
        );
    }

    #[test]
    fn derive_ipv6_slot_0() {
        assert_eq!(
            derive_guest_ipv6(default_guest_ipv6_pool(), 0),
            "fd42:6d73:62:0::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            gateway_from_guest_ipv6(derive_guest_ipv6(default_guest_ipv6_pool(), 0)),
            "fd42:6d73:62:0::1".parse::<Ipv6Addr>().unwrap()
        );
    }

    #[test]
    fn derive_addresses_custom_ipv6_pool() {
        let pool = "fd7a:115c:a1e0:100::/56".parse::<Ipv6Network>().unwrap();
        assert_eq!(
            derive_guest_ipv6(pool, 0),
            "fd7a:115c:a1e0:100::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            derive_guest_ipv6(pool, 3),
            "fd7a:115c:a1e0:103::2".parse::<Ipv6Addr>().unwrap()
        );
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
        let net =
            SmoltcpNetwork::new_with_routes(NetworkConfig::default(), 0, true, false).unwrap();
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
        let net = SmoltcpNetwork::new_with_routes(NetworkConfig::default(), 0, true, true).unwrap();
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
        let net =
            SmoltcpNetwork::new_with_routes(NetworkConfig::default(), 0, true, false).unwrap();
        let vars = net.guest_env_vars();

        assert!(!vars.iter().any(|(k, _)| k == ENV_NET_IPV6));
    }

    #[test]
    fn guest_env_vars_omit_ipv4_without_host_route() {
        let net =
            SmoltcpNetwork::new_with_routes(NetworkConfig::default(), 0, false, true).unwrap();
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
        let net = SmoltcpNetwork::new_with_routes(config, 0, true, false).unwrap();
        let vars = net.guest_env_vars();

        let v6 = vars
            .iter()
            .find(|(k, _)| k == ENV_NET_IPV6)
            .expect("explicit ipv6 should publish env var even without host route");
        assert!(v6.1.contains("fd42:6d73:62:99::2/64"));
    }

    #[test]
    fn neither_family_active_emits_only_base_env_vars() {
        let net =
            SmoltcpNetwork::new_with_routes(NetworkConfig::default(), 0, false, false).unwrap();
        let vars = net.guest_env_vars();

        assert_eq!(vars.len(), 2);
        assert_eq!(vars[0].0, ENV_NET);
        assert_eq!(vars[1].0, ENV_HOST_ALIAS);
    }

    #[test]
    fn new_with_routes_rejects_excessive_max_connections() {
        let mut config = NetworkConfig {
            max_connections: Some(MAX_NETWORK_CONNECTIONS + 1),
            ..NetworkConfig::default()
        };
        config.tls.enabled = false;

        let err = match SmoltcpNetwork::new_with_routes(config, 0, true, false) {
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
}

/// End-to-end rate limit checks: guest ICMP echo requests cross the TX
/// boundary into the gateway echo responder, and the replies cross the RX
/// boundary back to the guest, so one ping exercises both directions.
#[cfg(all(test, unix))]
mod rate_limit_tests {
    use std::time::{Duration, Instant};

    use microsandbox_types::{RateLimiterConfig, TokenBucketConfig};
    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, Icmpv4Packet, Icmpv4Repr,
        IpProtocol, Ipv4Packet, Ipv4Repr,
    };

    use super::*;

    const VIRTIO_NET_HDR_LEN: usize = 12;

    fn ops_limiter(size: u64, refill_time_ms: u64) -> RateLimiterConfig {
        RateLimiterConfig {
            bandwidth: None,
            ops: Some(TokenBucketConfig {
                size,
                refill_time_ms,
                one_time_burst: 0,
            }),
        }
    }

    fn bandwidth_limiter(size: u64, refill_time_ms: u64) -> RateLimiterConfig {
        RateLimiterConfig {
            bandwidth: Some(TokenBucketConfig {
                size,
                refill_time_ms,
                one_time_burst: 0,
            }),
            ops: None,
        }
    }

    /// Build a guest -> gateway ICMP echo request frame.
    fn echo_request_frame(net: &SmoltcpNetwork, seq_no: u16, data: &[u8]) -> Vec<u8> {
        let guest_ipv4 = net.guest_ipv4.expect("guest ipv4 active");
        let gateway_ipv4 = net.gateway_ipv4.expect("gateway ipv4 active");

        let ipv4_repr = Ipv4Repr {
            src_addr: guest_ipv4,
            dst_addr: gateway_ipv4,
            next_header: IpProtocol::Icmp,
            payload_len: 8 + data.len(),
            hop_limit: 64,
        };
        let icmp_repr = Icmpv4Repr::EchoRequest {
            ident: 0x42,
            seq_no,
            data,
        };
        let mut frame = vec![0u8; 14 + ipv4_repr.buffer_len() + icmp_repr.buffer_len()];

        let mut eth = EthernetFrame::new_unchecked(&mut frame);
        EthernetRepr {
            src_addr: EthernetAddress(net.guest_mac),
            dst_addr: EthernetAddress(net.gateway_mac),
            ethertype: EthernetProtocol::Ipv4,
        }
        .emit(&mut eth);
        ipv4_repr.emit(
            &mut Ipv4Packet::new_unchecked(&mut frame[14..34]),
            &ChecksumCapabilities::default(),
        );
        icmp_repr.emit(
            &mut Icmpv4Packet::new_unchecked(&mut frame[34..]),
            &ChecksumCapabilities::default(),
        );

        frame
    }

    /// Wait (bounded) for the backend's wake fd, mirroring the NetWorker.
    fn wait_readable(fd: std::os::fd::RawFd, timeout_ms: i32) {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        // SAFETY: `pfd` points to a valid pollfd for a live file descriptor.
        unsafe { libc::poll(&mut pfd, 1, timeout_ms) };
    }

    /// Send `count` gateway pings with `payload_len`-byte payloads through
    /// a started network and return the time until every reply arrived.
    fn ping_round_trip_time(
        mut config: NetworkConfig,
        count: usize,
        payload_len: usize,
    ) -> Duration {
        // Gateway echo replies are policy-gated; these tests measure rate
        // limiting, not policy.
        config.policy = crate::policy::NetworkPolicy::allow_all();
        let runtime = tokio::runtime::Runtime::new().expect("tokio runtime");
        let mut net =
            SmoltcpNetwork::new_with_routes(config, 0, true, false).expect("network init");
        let mut backend = net.take_backend();
        net.start(runtime.handle().clone());

        let payload = vec![0xab_u8; payload_len];
        let started = Instant::now();
        for seq_no in 0..count {
            let frame = echo_request_frame(&net, seq_no as u16, &payload);
            let mut buf = vec![0u8; VIRTIO_NET_HDR_LEN + frame.len()];
            buf[VIRTIO_NET_HDR_LEN..].copy_from_slice(&frame);
            backend
                .write_frame(VIRTIO_NET_HDR_LEN, &mut buf)
                .expect("guest frame accepted");
        }

        let deadline = started + Duration::from_secs(10);
        let mut received = 0;
        let mut buf = [0u8; 2048];
        while received < count {
            assert!(
                Instant::now() < deadline,
                "timed out after {received}/{count} echo replies"
            );
            if backend.read_frame(&mut buf).is_ok() {
                received += 1;
                continue;
            }
            wait_readable(backend.raw_socket_fd(), 100);
        }
        started.elapsed()
    }

    #[test]
    fn tx_ops_limiter_paces_guest_frames() {
        // 2 frames up front, then one per 50ms: the 6th crosses at +200ms.
        let config = NetworkConfig {
            tx_rate_limiter: Some(ops_limiter(2, 100)),
            ..NetworkConfig::default()
        };

        let elapsed = ping_round_trip_time(config, 6, 8);
        assert!(
            elapsed >= Duration::from_millis(190),
            "tx throttling too fast: {elapsed:?}"
        );
    }

    #[test]
    fn rx_bandwidth_limiter_paces_frames_to_the_guest() {
        // Echo replies are 14 (eth) + 20 (ipv4) + 8 (icmp) + 58 = 100 bytes:
        // the first reply drains the bucket, each next waits a full refill,
        // so the 4th arrives at +300ms.
        let config = NetworkConfig {
            rx_rate_limiter: Some(bandwidth_limiter(100, 100)),
            ..NetworkConfig::default()
        };

        let elapsed = ping_round_trip_time(config, 4, 58);
        assert!(
            elapsed >= Duration::from_millis(290),
            "rx throttling too fast: {elapsed:?}"
        );
    }

    #[test]
    fn unlimited_config_is_not_throttled() {
        let elapsed = ping_round_trip_time(NetworkConfig::default(), 6, 8);
        assert!(elapsed < Duration::from_secs(5), "unexpected {elapsed:?}");
    }
}
