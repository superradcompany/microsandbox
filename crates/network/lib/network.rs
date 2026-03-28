//! `SmoltcpNetwork` — orchestration type that ties [`NetworkConfig`] to the
//! smoltcp engine.
//!
//! This is the networking analog to `OverlayFs` for filesystems — the single
//! type the runtime creates from config, wires into the VM builder, and starts
//! the networking stack.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::thread::JoinHandle;

use msb_krun::backends::net::NetBackend;

use crate::backend::SmoltcpBackend;
use crate::config::NetworkConfig;
use crate::shared::{DEFAULT_QUEUE_CAPACITY, SharedState};
use crate::stack::{self, PollLoopConfig};
use crate::tls::state::TlsState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum sandbox slot value. Limited by MAC/IPv6 encoding (16 bits = 65535).
/// The IPv4 pool (100.96.0.0/11 with /30 blocks) supports up to 524287 slots,
/// but MAC and IPv6 derivation only encode the low 16 bits, so 65535 is the
/// effective maximum.
const MAX_SLOT: u64 = u16::MAX as u64;

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
    shared: Arc<SharedState>,
    backend: Option<SmoltcpBackend>,
    poll_handle: Option<JoinHandle<()>>,

    // Resolved from config + slot.
    guest_mac: [u8; 6],
    gateway_mac: [u8; 6],
    mtu: u16,
    guest_ipv4: Ipv4Addr,
    gateway_ipv4: Ipv4Addr,
    guest_ipv6: Ipv6Addr,
    gateway_ipv6: Ipv6Addr,

    // TLS state (if enabled). Created in new(), used for ca_cert_pem().
    tls_state: Option<Arc<TlsState>>,
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
    /// # Panics
    ///
    /// Panics if `slot` exceeds the address pool capacity (65535 for MAC/IPv6,
    /// 524287 for IPv4).
    pub fn new(config: NetworkConfig, slot: u64) -> Self {
        assert!(
            slot <= MAX_SLOT,
            "sandbox slot {slot} exceeds address pool capacity (max {MAX_SLOT})"
        );

        let guest_mac = config
            .interface
            .mac
            .unwrap_or_else(|| derive_guest_mac(slot));
        let gateway_mac = derive_gateway_mac(slot);
        let mtu = config.interface.mtu.unwrap_or(1500);
        let guest_ipv4 = config
            .interface
            .ipv4_address
            .unwrap_or_else(|| derive_guest_ipv4(slot));
        let gateway_ipv4 = gateway_from_guest_ipv4(guest_ipv4);
        let guest_ipv6 = config
            .interface
            .ipv6_address
            .unwrap_or_else(|| derive_guest_ipv6(slot));
        let gateway_ipv6 = gateway_from_guest_ipv6(guest_ipv6);

        let queue_capacity = config
            .max_connections
            .unwrap_or(DEFAULT_QUEUE_CAPACITY)
            .max(DEFAULT_QUEUE_CAPACITY);
        let shared = Arc::new(SharedState::new(queue_capacity));
        let backend = SmoltcpBackend::new(shared.clone());

        let tls_state = if config.tls.enabled {
            Some(Arc::new(TlsState::new(
                config.tls.clone(),
                config.secrets.clone(),
            )))
        } else {
            None
        };

        Self {
            config,
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
            gateway_ipv4: self.gateway_ipv4,
            guest_ipv4: self.guest_ipv4,
            gateway_ipv6: self.gateway_ipv6,
            mtu: self.mtu as usize,
        };
        let network_policy = self.config.policy.clone();
        let dns_config = self.config.dns.clone();
        let tls_state = self.tls_state.clone();
        let published_ports = self.config.ports.clone();
        let max_connections = self.config.max_connections;

        self.poll_handle = Some(
            std::thread::Builder::new()
                .name("smoltcp-poll".into())
                .spawn(move || {
                    stack::smoltcp_poll_loop(
                        shared,
                        poll_config,
                        network_policy,
                        dns_config,
                        tls_state,
                        published_ports,
                        max_connections,
                        tokio_handle,
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
                "MSB_NET".into(),
                format!(
                    "iface=eth0,mac={},mtu={}",
                    format_mac(self.guest_mac),
                    self.mtu,
                ),
            ),
            (
                "MSB_NET_IPV4".into(),
                format!(
                    "addr={}/30,gw={},dns={}",
                    self.guest_ipv4, self.gateway_ipv4, self.gateway_ipv4,
                ),
            ),
            (
                "MSB_NET_IPV6".into(),
                format!(
                    "addr={}/64,gw={},dns={}",
                    self.guest_ipv6, self.gateway_ipv6, self.gateway_ipv6,
                ),
            ),
        ];

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
/// Pool: `100.96.0.0/11`. Each slot gets a `/30` block (4 IPs).
/// Guest is at offset +2 in the block.
fn derive_guest_ipv4(slot: u64) -> Ipv4Addr {
    let base: u32 = u32::from(Ipv4Addr::new(100, 96, 0, 0));
    let offset = (slot as u32) * 4 + 2; // +2 = guest within /30
    Ipv4Addr::from(base + offset)
}

/// Gateway IPv4 from guest IPv4: guest - 1 (offset +1 in the /30 block).
fn gateway_from_guest_ipv4(guest: Ipv4Addr) -> Ipv4Addr {
    Ipv4Addr::from(u32::from(guest) - 1)
}

/// Derive a guest IPv6 address from the sandbox slot.
///
/// Pool: `fd42:6d73:62::/48`. Each slot gets a `/64` prefix.
/// Guest is `::2` in its prefix.
fn derive_guest_ipv6(slot: u64) -> Ipv6Addr {
    Ipv6Addr::new(0xfd42, 0x6d73, 0x0062, slot as u16, 0, 0, 0, 2)
}

/// Gateway IPv6 from guest IPv6: `::1` in the same prefix.
fn gateway_from_guest_ipv6(guest: Ipv6Addr) -> Ipv6Addr {
    let segs = guest.segments();
    Ipv6Addr::new(segs[0], segs[1], segs[2], segs[3], 0, 0, 0, 1)
}

/// Format a MAC address as `xx:xx:xx:xx:xx:xx`.
fn format_mac(mac: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_addresses_slot_0() {
        assert_eq!(derive_guest_mac(0), [0x02, 0x6d, 0x73, 0x00, 0x00, 0x02]);
        assert_eq!(derive_gateway_mac(0), [0x02, 0x6d, 0x73, 0x00, 0x00, 0x01]);
        assert_eq!(derive_guest_ipv4(0), Ipv4Addr::new(100, 96, 0, 2));
        assert_eq!(
            gateway_from_guest_ipv4(Ipv4Addr::new(100, 96, 0, 2)),
            Ipv4Addr::new(100, 96, 0, 1)
        );
    }

    #[test]
    fn derive_addresses_slot_1() {
        assert_eq!(derive_guest_ipv4(1), Ipv4Addr::new(100, 96, 0, 6));
        assert_eq!(
            gateway_from_guest_ipv4(Ipv4Addr::new(100, 96, 0, 6)),
            Ipv4Addr::new(100, 96, 0, 5)
        );
    }

    #[test]
    fn derive_ipv6_slot_0() {
        assert_eq!(
            derive_guest_ipv6(0),
            "fd42:6d73:62:0::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(
            gateway_from_guest_ipv6(derive_guest_ipv6(0)),
            "fd42:6d73:62:0::1".parse::<Ipv6Addr>().unwrap()
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
    fn guest_env_vars_format() {
        let config = NetworkConfig::default();
        let net = SmoltcpNetwork::new(config, 0);
        let vars = net.guest_env_vars();

        assert_eq!(vars.len(), 3);
        assert_eq!(vars[0].0, "MSB_NET");
        assert!(vars[0].1.contains("iface=eth0"));
        assert_eq!(vars[1].0, "MSB_NET_IPV4");
        assert!(vars[1].1.contains("/30"));
        assert_eq!(vars[2].0, "MSB_NET_IPV6");
        assert!(vars[2].1.contains("/64"));
    }
}
