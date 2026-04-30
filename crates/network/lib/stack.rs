//! smoltcp interface setup, frame classification, and poll loop.
//!
//! This module contains the core networking event loop that runs on a
//! dedicated OS thread. It bridges guest ethernet frames (via
//! [`SmoltcpDevice`]) to smoltcp's TCP/IP stack and services connections
//! through tokio proxy tasks.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::time::Instant;

use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, HardwareAddress, Icmpv4Packet, Icmpv4Repr,
    Icmpv6Packet, Icmpv6Repr, IpAddress, IpCidr, IpProtocol, Ipv4Packet, Ipv4Repr, Ipv6Packet,
    Ipv6Repr, TcpPacket, UdpPacket,
};

use crate::config::{DnsConfig, PublishedPort};
use crate::conn::ConnectionTracker;
use crate::device::SmoltcpDevice;
use crate::dns::common::ports::DnsPortType;
use crate::dns::{
    interceptor::DnsInterceptor,
    proxies::{dot::DotProxy, tcp::DnsTcpProxy},
};
use crate::icmp_relay::IcmpRelay;
use crate::policy::{NetworkPolicy, Protocol};
use crate::proxy;
use crate::publisher::PortPublisher;
use crate::shared::SharedState;
use crate::tls::{proxy as tls_proxy, state::TlsState};
use crate::udp_relay::UdpRelay;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result of classifying a guest ethernet frame before smoltcp processes it.
///
/// Pre-inspection allows the poll loop to:
/// - Create TCP sockets before smoltcp sees a SYN (preventing auto-RST).
/// - Handle non-DNS UDP outside smoltcp (smoltcp lacks wildcard port binding).
/// - Route DNS queries to the interception handler.
pub enum FrameAction {
    /// TCP SYN to a new destination — create a smoltcp socket before
    /// letting smoltcp process the frame.
    TcpSyn { src: SocketAddr, dst: SocketAddr },

    /// Non-DNS UDP datagram — handle entirely outside smoltcp via the UDP
    /// relay.
    UdpRelay { src: SocketAddr, dst: SocketAddr },

    /// DNS query (UDP to port 53) — let smoltcp's bound UDP socket handle it.
    Dns,

    /// Everything else (ARP, NDP, ICMP, TCP data/ACK/FIN, etc.) — let
    /// smoltcp process normally.
    Passthrough,
}

/// Resolved network parameters for the poll loop. Created by
/// `SmoltcpNetwork::new()` from `NetworkConfig` + sandbox slot.
pub struct PollLoopConfig {
    /// Gateway MAC address (smoltcp's identity on the virtual LAN).
    pub gateway_mac: [u8; 6],
    /// Guest MAC address.
    pub guest_mac: [u8; 6],
    /// Gateway addresses (IPv4 + IPv6) owned by the smoltcp virtual
    /// stack.
    pub gateway: GatewayIps,
    /// Guest IPv4 address.
    pub guest_ipv4: Ipv4Addr,
    /// IP-level MTU (e.g. 1500).
    pub mtu: usize,
}

/// Per-sandbox gateway addresses (v4 + v6) owned by the smoltcp virtual stack.
/// Both families are always assigned. The proxy's `resolve_host_dst` helper uses
/// these to rewrite gateway-bound connections to loopback at dial time.
#[derive(Debug, Clone, Copy)]
pub struct GatewayIps {
    /// Gateway IPv4.
    pub ipv4: Ipv4Addr,
    /// Gateway IPv6.
    pub ipv6: Ipv6Addr,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Classify a raw ethernet frame for pre-inspection.
///
/// Uses smoltcp's wire module for zero-copy parsing. Returns
/// [`FrameAction::Passthrough`] for any frame that cannot be parsed or
/// doesn't match a special case.
pub fn classify_frame(frame: &[u8]) -> FrameAction {
    let Ok(eth) = EthernetFrame::new_checked(frame) else {
        return FrameAction::Passthrough;
    };

    match eth.ethertype() {
        EthernetProtocol::Ipv4 => classify_ipv4(eth.payload()),
        EthernetProtocol::Ipv6 => classify_ipv6(eth.payload()),
        _ => FrameAction::Passthrough, // ARP, etc.
    }
}

/// Create and configure the smoltcp [`Interface`].
///
/// The interface is configured as the **gateway**: it owns the gateway IP
/// addresses and responds to ARP/NDP for them. `any_ip` mode is enabled so
/// smoltcp accepts traffic destined for arbitrary remote IPs (not just the
/// gateway), combined with default routes.
pub fn create_interface(device: &mut SmoltcpDevice, config: &PollLoopConfig) -> Interface {
    let hw_addr = HardwareAddress::Ethernet(EthernetAddress(config.gateway_mac));
    let iface_config = Config::new(hw_addr);
    let mut iface = Interface::new(iface_config, device, smoltcp_now());

    // Configure gateway IP addresses.
    iface.update_ip_addrs(|addrs| {
        addrs
            .push(IpCidr::new(
                IpAddress::Ipv4(config.gateway.ipv4),
                // /30 subnet: gateway + guest.
                30,
            ))
            .expect("failed to add gateway IPv4 address");
        addrs
            .push(IpCidr::new(IpAddress::Ipv6(config.gateway.ipv6), 64))
            .expect("failed to add gateway IPv6 address");
    });

    // Default routes so smoltcp accepts traffic for all destinations.
    iface
        .routes_mut()
        .add_default_ipv4_route(config.gateway.ipv4)
        .expect("failed to add default IPv4 route");
    iface
        .routes_mut()
        .add_default_ipv6_route(config.gateway.ipv6)
        .expect("failed to add default IPv6 route");

    // Accept traffic destined for any IP, not just gateway addresses.
    iface.set_any_ip(true);

    iface
}

/// Main smoltcp poll loop. Runs on a dedicated OS thread.
///
/// Processes guest frames with pre-inspection, drives smoltcp's TCP/IP stack,
/// and sleeps via `poll(2)` between events.
///
/// # Phases per iteration
///
/// 1. **Drain guest frames** — pop from `tx_ring`, classify, pre-inspect.
/// 2. **smoltcp egress + maintenance** — transmit queued packets, run timers.
/// 3. **Service connections** — relay data between smoltcp sockets and proxy
///    tasks (added by later tasks).
/// 4. **Sleep** — `poll(2)` on `tx_wake` + `proxy_wake` pipes with smoltcp's
///    requested timeout.
///
/// # Arguments
///
/// * `shared` - Stack-wide shared state: `tx_ring` / `rx_ring` for the virtio-net boundary
///   and the wake eventfds.
/// * `config` - Resolved per-sandbox parameters (gateway / guest MAC + IPv4 + IPv6, MTU).
/// * `network_policy` - User-provided egress policy. Evaluated against the sandbox's
///   gateway IPs (stored on [`SharedState`]) so `DestinationGroup::Host` rules match.
/// * `dns_config` - DNS interception settings (block lists, upstreams, timeout).
/// * `tls_state` - Optional TLS MITM state; drives interception of intercepted ports and DoT
///   when present.
/// * `published_ports` - Host → guest port publishes; the publisher accepts inbound
///   connections on the host-bind address and forwards into the guest.
/// * `max_connections` - Optional cap on concurrent guest connections tracked by
///   [`ConnectionTracker`]; `None` uses the default.
/// * `tokio_handle` - Runtime handle used for proxy tasks, DNS forwarding, port publishing,
///   and ICMP relays.
#[allow(clippy::too_many_arguments)]
pub fn smoltcp_poll_loop(
    shared: Arc<SharedState>,
    config: PollLoopConfig,
    network_policy: NetworkPolicy,
    dns_config: DnsConfig,
    tls_state: Option<Arc<TlsState>>,
    published_ports: Vec<PublishedPort>,
    max_connections: Option<usize>,
    tokio_handle: tokio::runtime::Handle,
) {
    let mut device = SmoltcpDevice::new(shared.clone(), config.mtu);
    let mut iface = create_interface(&mut device, &config);
    let mut sockets = SocketSet::new(vec![]);
    let mut conn_tracker = ConnectionTracker::new(max_connections);

    // The DNS forwarder needs to know which IPs count as "the gateway"
    // (so it routes guest queries to those addresses through the
    // configured upstream) and a policy evaluator (so guest-chosen
    // `@target` resolvers are gated by egress rules just like any
    // other outbound).
    let gateway_ips: Arc<HashSet<IpAddr>> = Arc::new(HashSet::from([
        IpAddr::V4(config.gateway.ipv4),
        IpAddr::V6(config.gateway.ipv6),
    ]));
    // Gateway IPs must be on SharedState before any egress evaluation runs,
    // so `DestinationGroup::Host` rules can resolve to the right address.
    shared.set_gateway_ips(config.gateway.ipv4, config.gateway.ipv6);
    let network_policy = Arc::new(network_policy);

    let (mut dns_interceptor, dns_forwarder_handle) = DnsInterceptor::new(
        &mut sockets,
        dns_config,
        shared.clone(),
        &tokio_handle,
        gateway_ips,
        network_policy.clone(),
        config.gateway,
    );
    let mut port_publisher = PortPublisher::new(
        &published_ports,
        config.guest_ipv4,
        network_policy.clone(),
        shared.clone(),
        &tokio_handle,
    );
    let mut udp_relay = UdpRelay::new(
        shared.clone(),
        config.gateway_mac,
        config.guest_mac,
        tokio_handle.clone(),
    );
    let icmp_relay = IcmpRelay::new(
        shared.clone(),
        config.gateway_mac,
        config.guest_mac,
        tokio_handle.clone(),
    );

    // Rate-limit cleanup operations: run at most once per second.
    let mut last_cleanup = std::time::Instant::now();

    // poll(2) file descriptors for sleeping.
    let mut poll_fds = [
        libc::pollfd {
            fd: shared.tx_wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
        libc::pollfd {
            fd: shared.proxy_wake.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        },
    ];

    loop {
        let now = smoltcp_now();

        // ── Phase 1: Drain all guest frames with pre-inspection ──────────
        while let Some(frame) = device.stage_next_frame() {
            if handle_gateway_icmp_echo(frame, &config, &shared) {
                device.drop_staged_frame();
                continue;
            }

            if icmp_relay.relay_outbound_if_echo(frame, &config, &network_policy) {
                device.drop_staged_frame();
                continue;
            }

            match classify_frame(frame) {
                FrameAction::TcpSyn { src, dst } => {
                    let allow = match DnsPortType::from_tcp(dst.port()) {
                        // Plain DNS: the interceptor enforces policy at
                        // the application layer (block list + rebind
                        // protection); bypass the network egress check.
                        DnsPortType::Dns => true,
                        // DoT: intercept only when TLS MITM is
                        // configured. Without it, the block list can't
                        // apply (traffic is encrypted end-to-end), so
                        // we refuse to force a fall-back to plain
                        // TCP/53. When TLS MITM is configured, bypass
                        // egress policy the same way plain DNS does —
                        // policy for the upstream resolver is applied
                        // per query by the forwarder.
                        DnsPortType::EncryptedDns => {
                            if tls_state.is_some() {
                                true
                            } else {
                                tracing::debug!(%dst, "DoT port refused (TLS interception not configured); stub should fall back to TCP/53");
                                false
                            }
                        }
                        // Alternative DNS protocol we can't proxy:
                        // refuse outright — no socket means smoltcp
                        // emits RST, which the guest's stub treats as
                        // "upstream unavailable" and falls back to
                        // plain TCP/53.
                        DnsPortType::AlternativeDns => {
                            tracing::debug!(%dst, "alternative-DNS TCP port refused; stub should fall back to TCP/53");
                            false
                        }
                        // Other: regular outbound — apply egress policy.
                        DnsPortType::Other => network_policy
                            .evaluate_egress(dst, Protocol::Tcp, &shared)
                            .is_allow(),
                    };
                    if allow && !conn_tracker.has_socket_for(&src, &dst) {
                        conn_tracker.create_tcp_socket(src, dst, &mut sockets);
                    }
                    // Let smoltcp process — matching socket completes
                    // handshake, no socket means auto-RST.
                    iface.poll_ingress_single(now, &mut device, &mut sockets);
                }

                FrameAction::UdpRelay { src, dst } => {
                    // QUIC blocking: drop UDP to intercepted ports when
                    // TLS interception is active.
                    if let Some(ref tls) = tls_state
                        && tls.config.intercepted_ports.contains(&dst.port())
                        && tls.config.block_quic_on_intercept
                    {
                        device.drop_staged_frame();
                        continue;
                    }

                    match DnsPortType::from_udp(dst.port()) {
                        // Dns: unreachable here — classify_transport
                        // routes UDP/53 to FrameAction::Dns, not
                        // UdpRelay. Defensive drop covers regressions.
                        DnsPortType::Dns => {
                            device.drop_staged_frame();
                            continue;
                        }
                        // EncryptedDns: unreachable here —
                        // `DnsPortType::from_udp` never returns it
                        // today (DoT is TCP-only; UDP/853 is DoQ and
                        // returns AlternativeDns). Defensive drop.
                        DnsPortType::EncryptedDns => {
                            device.drop_staged_frame();
                            continue;
                        }
                        // Alternative DNS protocols on well-known UDP
                        // ports are dropped — forces fall-back to UDP/53.
                        DnsPortType::AlternativeDns => {
                            tracing::debug!(%dst, "alternative-DNS UDP port dropped; stub should fall back to UDP/53");
                            device.drop_staged_frame();
                            continue;
                        }
                        DnsPortType::Other => {}
                    }

                    // Policy check.
                    if network_policy
                        .evaluate_egress(dst, Protocol::Udp, &shared)
                        .is_deny()
                    {
                        device.drop_staged_frame();
                        continue;
                    }

                    // Resolve the host-side destination for the dial.
                    // `dst` stays unchanged so reply frames are stamped
                    // with the IP the guest expects.
                    let host_dst = resolve_host_dst(dst, config.gateway);
                    udp_relay.relay_outbound(frame, src, dst, host_dst);
                    device.drop_staged_frame();
                }

                FrameAction::Dns | FrameAction::Passthrough => {
                    // ARP, ICMP, DNS (port 53), TCP data — smoltcp handles.
                    iface.poll_ingress_single(now, &mut device, &mut sockets);
                }
            }
        }

        // ── Phase 2: Ingress egress + maintenance ─────────────────────────
        // Flush frames generated by Phase 1 ingress (ACKs, SYN-ACKs, etc.)
        // before relaying data so smoltcp has up-to-date state.
        loop {
            let result = iface.poll_egress(now, &mut device, &mut sockets);
            if matches!(result, smoltcp::iface::PollResult::None) {
                break;
            }
        }
        iface.poll_maintenance(now);

        // Coalesced wake: if Phase 1/2 emitted any frames, wake the
        // NetWorker once instead of per-frame.
        if device.frames_emitted.swap(false, Ordering::Relaxed) {
            shared.rx_wake.wake();
        }

        // ── Phase 3: Service connections + relay data ────────────────────
        // Relay proxy data INTO smoltcp sockets first, then a single egress
        // pass flushes everything. This eliminates the former "Phase 2b"
        // double-egress pattern.
        conn_tracker.relay_data(&mut sockets);
        dns_interceptor.process(&mut sockets);

        // Accept queued inbound connections from published port listeners.
        port_publisher.accept_inbound(&mut iface, &mut sockets, &shared, &tokio_handle);
        port_publisher.relay_data(&mut sockets);

        // Detect newly-established connections and spawn proxy tasks.
        let new_conns = conn_tracker.take_new_connections(&mut sockets);
        for conn in new_conns {
            if let Some(ref tls_state) = tls_state
                && tls_state
                    .config
                    .intercepted_ports
                    .contains(&conn.dst.port())
            {
                // TLS-intercepted port — spawn TLS MITM proxy.
                let conn_dst = resolve_host_dst(conn.dst, config.gateway);
                tls_proxy::spawn_tls_proxy(
                    &tokio_handle,
                    conn_dst,
                    conn.from_smoltcp,
                    conn.to_smoltcp,
                    shared.clone(),
                    tls_state.clone(),
                    conn.upstream_connected,
                );
                continue;
            }
            if conn.dst.port() == 53 {
                // DNS proxies have no guest-visible
                // "upstream-unreachable" failure mode — even an
                // upstream DNS failure yields SERVFAIL responses
                // rather than a silently-closed connection. Mark the
                // connection as upstream-connected so normal task exit
                // produces FIN, not RST.
                conn.upstream_connected.store(true, Ordering::Release);

                // DNS over TCP: route through the same forwarder the UDP
                // path uses. The forwarder applies the domain block list
                // and rebind protection to every query and routes
                // upstream based on `conn.dst.ip()` — the configured
                // upstream for queries to the gateway, direct forward
                // to the chosen `@target` (subject to egress policy)
                // otherwise. No gateway→loopback rewrite here: the
                // forwarder dials the configured upstream, not the
                // gateway.
                DnsTcpProxy::spawn(
                    &tokio_handle,
                    conn.dst,
                    conn.from_smoltcp,
                    conn.to_smoltcp,
                    dns_forwarder_handle.clone(),
                    shared.clone(),
                );
                continue;
            }
            if conn.dst.port() == 853
                && let Some(ref tls_state) = tls_state
            {
                // Same "always upstream-connected" reasoning as plain DNS over TCP.
                conn.upstream_connected.store(true, Ordering::Release);

                // DNS over TLS: terminate TLS at the gateway with a
                // per-domain cert, hand the inner DNS frames to the
                // same forwarder plain DNS uses. Policy for the
                // chosen `@target` resolver is applied per-query by
                // the forwarder (block list + rebind + egress).
                DotProxy::spawn(
                    &tokio_handle,
                    conn.dst,
                    conn.from_smoltcp,
                    conn.to_smoltcp,
                    dns_forwarder_handle.clone(),
                    tls_state.clone(),
                    shared.clone(),
                );
                continue;
            }
            // Plain TCP proxy.
            let dst = resolve_host_dst(conn.dst, config.gateway);
            proxy::spawn_tcp_proxy(
                &tokio_handle,
                dst,
                conn.from_smoltcp,
                conn.to_smoltcp,
                shared.clone(),
                conn.upstream_connected,
            );
        }

        // Rate-limited cleanup: TIME_WAIT is 60s, session timeout is 60s,
        // so checking once per second is more than sufficient.
        if last_cleanup.elapsed() >= std::time::Duration::from_secs(1) {
            conn_tracker.cleanup_closed(&mut sockets);
            port_publisher.cleanup_closed(&mut sockets);
            udp_relay.cleanup_expired();
            shared.cleanup_resolved_hostnames();
            last_cleanup = std::time::Instant::now();
        }

        // ── Phase 4: Flush relay data + sleep ────────────────────────────
        // Single egress pass flushes all data written by Phase 3.
        loop {
            let result = iface.poll_egress(now, &mut device, &mut sockets);
            if matches!(result, smoltcp::iface::PollResult::None) {
                break;
            }
        }

        // Coalesced wake: if Phase 3/4 emitted any frames, wake once.
        if device.frames_emitted.swap(false, Ordering::Relaxed) {
            shared.rx_wake.wake();
        }

        let timeout_ms = iface
            .poll_delay(now, &sockets)
            .map(|d| d.total_millis().min(i32::MAX as u64) as i32)
            .unwrap_or(100); // 100ms fallback when no timers pending.

        // SAFETY: poll_fds is a valid array of pollfd structs with valid fds.
        unsafe {
            libc::poll(
                poll_fds.as_mut_ptr(),
                poll_fds.len() as libc::nfds_t,
                timeout_ms,
            );
        }

        // Conditional drain: only drain pipes that actually have data.
        if poll_fds[0].revents & libc::POLLIN != 0 {
            shared.tx_wake.drain();
        }
        if poll_fds[1].revents & libc::POLLIN != 0 {
            shared.proxy_wake.drain();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Map a guest-wire destination to its host-socket equivalent.
///
/// Gateway IPs rewrite to loopback (`127.0.0.1` / `::1`); everything else
/// passes through. Shared by the TCP proxy dispatch and the UDP relay.
///
/// # Arguments
///
/// * `dst` - Destination from the guest's packet.
/// * `gateway` - Per-sandbox gateway IPs that trigger the loopback rewrite.
pub(crate) fn resolve_host_dst(dst: SocketAddr, gateway: GatewayIps) -> SocketAddr {
    match dst.ip() {
        IpAddr::V4(v4) if v4 == gateway.ipv4 => {
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), dst.port())
        }
        IpAddr::V6(v6) if v6 == gateway.ipv6 => {
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), dst.port())
        }
        _ => dst,
    }
}

/// Get the current time as a smoltcp [`Instant`] using a monotonic clock.
///
/// Uses `std::time::Instant` (monotonic) instead of `SystemTime` (wall
/// clock) to avoid issues with NTP clock step corrections that could
/// cause smoltcp timers to misbehave.
fn smoltcp_now() -> Instant {
    static EPOCH: std::sync::OnceLock<std::time::Instant> = std::sync::OnceLock::new();
    let epoch = EPOCH.get_or_init(std::time::Instant::now);
    let elapsed = epoch.elapsed();
    Instant::from_millis(elapsed.as_millis() as i64)
}

/// Reply locally to ICMP echo requests aimed at the sandbox gateway.
///
/// `any_ip` is required so smoltcp accepts guest traffic for arbitrary remote
/// destinations, but that would make smoltcp's automatic ICMP echo replies
/// spoof remote hosts. Handle only the real gateway IPs here and leave all
/// other ICMP traffic untouched.
fn handle_gateway_icmp_echo(frame: &[u8], config: &PollLoopConfig, shared: &SharedState) -> bool {
    let Ok(eth) = EthernetFrame::new_checked(frame) else {
        return false;
    };

    let reply = match eth.ethertype() {
        EthernetProtocol::Ipv4 => gateway_icmpv4_echo_reply(&eth, config),
        EthernetProtocol::Ipv6 => gateway_icmpv6_echo_reply(&eth, config),
        _ => None,
    };
    let Some(reply) = reply else {
        return false;
    };

    let reply_len = reply.len();
    if shared.rx_ring.push(reply).is_ok() {
        shared.add_rx_bytes(reply_len);
        shared.rx_wake.wake();
    }

    true
}

/// Build an IPv4 ICMP echo reply when the guest pings the gateway IPv4.
fn gateway_icmpv4_echo_reply(
    eth: &EthernetFrame<&[u8]>,
    config: &PollLoopConfig,
) -> Option<Vec<u8>> {
    let ipv4 = Ipv4Packet::new_checked(eth.payload()).ok()?;
    if ipv4.dst_addr() != config.gateway.ipv4 || ipv4.next_header() != IpProtocol::Icmp {
        return None;
    }

    let icmp = Icmpv4Packet::new_checked(ipv4.payload()).ok()?;
    let Icmpv4Repr::EchoRequest {
        ident,
        seq_no,
        data,
    } = Icmpv4Repr::parse(&icmp, &smoltcp::phy::ChecksumCapabilities::default()).ok()?
    else {
        return None;
    };

    let ipv4_repr = Ipv4Repr {
        src_addr: config.gateway.ipv4,
        dst_addr: ipv4.src_addr(),
        next_header: IpProtocol::Icmp,
        payload_len: 8 + data.len(),
        hop_limit: 64,
    };
    let icmp_repr = Icmpv4Repr::EchoReply {
        ident,
        seq_no,
        data,
    };
    let mut reply = vec![0u8; 14 + ipv4_repr.buffer_len() + icmp_repr.buffer_len()];

    let mut reply_eth = EthernetFrame::new_unchecked(&mut reply);
    reply_eth.set_src_addr(EthernetAddress(config.gateway_mac));
    reply_eth.set_dst_addr(eth.src_addr());
    reply_eth.set_ethertype(EthernetProtocol::Ipv4);

    ipv4_repr.emit(
        &mut Ipv4Packet::new_unchecked(&mut reply[14..34]),
        &smoltcp::phy::ChecksumCapabilities::default(),
    );
    icmp_repr.emit(
        &mut Icmpv4Packet::new_unchecked(&mut reply[34..]),
        &smoltcp::phy::ChecksumCapabilities::default(),
    );

    Some(reply)
}

/// Build an IPv6 ICMP echo reply when the guest pings the gateway IPv6.
fn gateway_icmpv6_echo_reply(
    eth: &EthernetFrame<&[u8]>,
    config: &PollLoopConfig,
) -> Option<Vec<u8>> {
    let ipv6 = Ipv6Packet::new_checked(eth.payload()).ok()?;
    if ipv6.dst_addr() != config.gateway.ipv6 || ipv6.next_header() != IpProtocol::Icmpv6 {
        return None;
    }

    let icmp = Icmpv6Packet::new_checked(ipv6.payload()).ok()?;
    let Icmpv6Repr::EchoRequest {
        ident,
        seq_no,
        data,
    } = Icmpv6Repr::parse(
        &ipv6.src_addr(),
        &ipv6.dst_addr(),
        &icmp,
        &smoltcp::phy::ChecksumCapabilities::default(),
    )
    .ok()?
    else {
        return None;
    };

    let ipv6_repr = Ipv6Repr {
        src_addr: config.gateway.ipv6,
        dst_addr: ipv6.src_addr(),
        next_header: IpProtocol::Icmpv6,
        payload_len: icmp_repr_buffer_len_v6(data),
        hop_limit: 64,
    };
    let icmp_repr = Icmpv6Repr::EchoReply {
        ident,
        seq_no,
        data,
    };
    let ipv6_hdr_len = 40;
    let mut reply = vec![0u8; 14 + ipv6_hdr_len + icmp_repr.buffer_len()];

    let mut reply_eth = EthernetFrame::new_unchecked(&mut reply);
    reply_eth.set_src_addr(EthernetAddress(config.gateway_mac));
    reply_eth.set_dst_addr(eth.src_addr());
    reply_eth.set_ethertype(EthernetProtocol::Ipv6);

    ipv6_repr.emit(&mut Ipv6Packet::new_unchecked(&mut reply[14..54]));
    icmp_repr.emit(
        &config.gateway.ipv6,
        &ipv6.src_addr(),
        &mut Icmpv6Packet::new_unchecked(&mut reply[54..]),
        &smoltcp::phy::ChecksumCapabilities::default(),
    );

    Some(reply)
}

fn icmp_repr_buffer_len_v6(data: &[u8]) -> usize {
    Icmpv6Repr::EchoReply {
        ident: 0,
        seq_no: 0,
        data,
    }
    .buffer_len()
}

/// Classify an IPv4 packet payload (after stripping the Ethernet header).
fn classify_ipv4(payload: &[u8]) -> FrameAction {
    let Ok(ipv4) = Ipv4Packet::new_checked(payload) else {
        return FrameAction::Passthrough;
    };
    classify_transport(
        ipv4.next_header(),
        ipv4.src_addr().into(),
        ipv4.dst_addr().into(),
        ipv4.payload(),
    )
}

/// Classify an IPv6 packet payload (after stripping the Ethernet header).
fn classify_ipv6(payload: &[u8]) -> FrameAction {
    let Ok(ipv6) = Ipv6Packet::new_checked(payload) else {
        return FrameAction::Passthrough;
    };
    classify_transport(
        ipv6.next_header(),
        ipv6.src_addr().into(),
        ipv6.dst_addr().into(),
        ipv6.payload(),
    )
}

/// Classify the transport-layer protocol (shared by IPv4 and IPv6).
fn classify_transport(
    protocol: IpProtocol,
    src_ip: std::net::IpAddr,
    dst_ip: std::net::IpAddr,
    transport_payload: &[u8],
) -> FrameAction {
    match protocol {
        IpProtocol::Tcp => {
            let Ok(tcp) = TcpPacket::new_checked(transport_payload) else {
                return FrameAction::Passthrough;
            };
            if tcp.syn() && !tcp.ack() {
                FrameAction::TcpSyn {
                    src: SocketAddr::new(src_ip, tcp.src_port()),
                    dst: SocketAddr::new(dst_ip, tcp.dst_port()),
                }
            } else {
                FrameAction::Passthrough
            }
        }
        IpProtocol::Udp => {
            let Ok(udp) = UdpPacket::new_checked(transport_payload) else {
                return FrameAction::Passthrough;
            };
            // The plain-DNS port (UDP/53) lives in dns::common::ports so
            // the alternative-DNS refusal logic and this dispatcher
            // share one source of truth for "which UDP ports are DNS".
            if DnsPortType::from_udp(udp.dst_port()) == DnsPortType::Dns {
                FrameAction::Dns
            } else {
                FrameAction::UdpRelay {
                    src: SocketAddr::new(src_ip, udp.src_port()),
                    dst: SocketAddr::new(dst_ip, udp.dst_port()),
                }
            }
        }
        _ => FrameAction::Passthrough, // ICMP, etc.
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use smoltcp::phy::ChecksumCapabilities;
    use smoltcp::wire::{
        ArpOperation, ArpPacket, ArpRepr, EthernetRepr, Icmpv4Packet, Icmpv4Repr, Ipv4Repr,
    };

    use crate::device::SmoltcpDevice;
    use crate::shared::SharedState;

    /// Build a minimal Ethernet + IPv4 + TCP SYN frame.
    fn build_tcp_syn_frame(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + 20]; // eth + ipv4 + tcp

        // Ethernet header.
        frame[12] = 0x08; // EtherType: IPv4
        frame[13] = 0x00;

        // IPv4 header.
        let ip = &mut frame[14..34];
        ip[0] = 0x45; // Version + IHL
        let total_len = 40u16; // 20 (IP) + 20 (TCP)
        ip[2..4].copy_from_slice(&total_len.to_be_bytes());
        ip[6] = 0x40; // Don't Fragment
        ip[8] = 64; // TTL
        ip[9] = 6; // Protocol: TCP
        ip[12..16].copy_from_slice(&src_ip);
        ip[16..20].copy_from_slice(&dst_ip);

        // TCP header.
        let tcp = &mut frame[34..54];
        tcp[0..2].copy_from_slice(&src_port.to_be_bytes());
        tcp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        tcp[12] = 0x50; // Data offset: 5 words
        tcp[13] = 0x02; // SYN flag

        frame
    }

    /// Build a minimal Ethernet + IPv4 + UDP frame.
    fn build_udp_frame(src_ip: [u8; 4], dst_ip: [u8; 4], src_port: u16, dst_port: u16) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 20 + 8]; // eth + ipv4 + udp

        // Ethernet header.
        frame[12] = 0x08;
        frame[13] = 0x00;

        // IPv4 header.
        let ip = &mut frame[14..34];
        ip[0] = 0x45;
        let total_len = 28u16; // 20 (IP) + 8 (UDP)
        ip[2..4].copy_from_slice(&total_len.to_be_bytes());
        ip[8] = 64;
        ip[9] = 17; // Protocol: UDP
        ip[12..16].copy_from_slice(&src_ip);
        ip[16..20].copy_from_slice(&dst_ip);

        // UDP header.
        let udp = &mut frame[34..42];
        udp[0..2].copy_from_slice(&src_port.to_be_bytes());
        udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
        let udp_len = 8u16;
        udp[4..6].copy_from_slice(&udp_len.to_be_bytes());

        frame
    }

    /// Build a minimal Ethernet + IPv4 + ICMP echo request frame.
    fn build_icmpv4_echo_frame(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        ident: u16,
        seq_no: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let ipv4_repr = Ipv4Repr {
            src_addr: Ipv4Addr::from(src_ip).into(),
            dst_addr: Ipv4Addr::from(dst_ip).into(),
            next_header: IpProtocol::Icmp,
            payload_len: 8 + data.len(),
            hop_limit: 64,
        };
        let icmp_repr = Icmpv4Repr::EchoRequest {
            ident,
            seq_no,
            data,
        };
        let frame_len = 14 + ipv4_repr.buffer_len() + icmp_repr.buffer_len();
        let mut frame = vec![0u8; frame_len];

        let mut eth_frame = EthernetFrame::new_unchecked(&mut frame);
        EthernetRepr {
            src_addr: EthernetAddress(src_mac),
            dst_addr: EthernetAddress(dst_mac),
            ethertype: EthernetProtocol::Ipv4,
        }
        .emit(&mut eth_frame);

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

    /// Build a minimal Ethernet + ARP request frame.
    fn build_arp_request_frame(src_mac: [u8; 6], src_ip: [u8; 4], target_ip: [u8; 4]) -> Vec<u8> {
        let mut frame = vec![0u8; 14 + 28];

        let mut eth_frame = EthernetFrame::new_unchecked(&mut frame);
        EthernetRepr {
            src_addr: EthernetAddress(src_mac),
            dst_addr: EthernetAddress([0xff; 6]),
            ethertype: EthernetProtocol::Arp,
        }
        .emit(&mut eth_frame);

        ArpRepr::EthernetIpv4 {
            operation: ArpOperation::Request,
            source_hardware_addr: EthernetAddress(src_mac),
            source_protocol_addr: Ipv4Addr::from(src_ip).into(),
            target_hardware_addr: EthernetAddress([0x00; 6]),
            target_protocol_addr: Ipv4Addr::from(target_ip).into(),
        }
        .emit(&mut ArpPacket::new_unchecked(&mut frame[14..]));

        frame
    }

    #[test]
    fn classify_tcp_syn() {
        let frame = build_tcp_syn_frame([10, 0, 0, 2], [93, 184, 216, 34], 54321, 443);
        match classify_frame(&frame) {
            FrameAction::TcpSyn { src, dst } => {
                assert_eq!(
                    src,
                    SocketAddr::new(Ipv4Addr::new(10, 0, 0, 2).into(), 54321)
                );
                assert_eq!(
                    dst,
                    SocketAddr::new(Ipv4Addr::new(93, 184, 216, 34).into(), 443)
                );
            }
            _ => panic!("expected TcpSyn"),
        }
    }

    #[test]
    fn classify_tcp_ack_is_passthrough() {
        let mut frame = build_tcp_syn_frame([10, 0, 0, 2], [93, 184, 216, 34], 54321, 443);
        // Change flags to ACK only (not SYN).
        frame[34 + 13] = 0x10; // ACK flag
        assert!(matches!(classify_frame(&frame), FrameAction::Passthrough));
    }

    #[test]
    fn classify_udp_dns() {
        let frame = build_udp_frame([10, 0, 0, 2], [10, 0, 0, 1], 12345, 53);
        assert!(matches!(classify_frame(&frame), FrameAction::Dns));
    }

    #[test]
    fn classify_udp_non_dns() {
        let frame = build_udp_frame([10, 0, 0, 2], [8, 8, 8, 8], 12345, 443);
        match classify_frame(&frame) {
            FrameAction::UdpRelay { src, dst } => {
                assert_eq!(src.port(), 12345);
                assert_eq!(dst.port(), 443);
            }
            _ => panic!("expected UdpRelay"),
        }
    }

    #[test]
    fn classify_arp_is_passthrough() {
        let mut frame = vec![0u8; 42]; // ARP frame
        frame[12] = 0x08;
        frame[13] = 0x06; // EtherType: ARP
        assert!(matches!(classify_frame(&frame), FrameAction::Passthrough));
    }

    #[test]
    fn classify_garbage_is_passthrough() {
        assert!(matches!(classify_frame(&[]), FrameAction::Passthrough));
        assert!(matches!(classify_frame(&[0; 5]), FrameAction::Passthrough));
    }

    #[test]
    fn gateway_replies_to_icmp_echo_requests() {
        fn drive_one_frame(
            device: &mut SmoltcpDevice,
            iface: &mut Interface,
            sockets: &mut SocketSet<'_>,
            shared: &Arc<SharedState>,
            poll_config: &PollLoopConfig,
            now: Instant,
        ) {
            let frame = device.stage_next_frame().expect("expected staged frame");
            if handle_gateway_icmp_echo(frame, poll_config, shared) {
                device.drop_staged_frame();
                return;
            }
            let _ = iface.poll_ingress_single(now, device, sockets);
            let _ = iface.poll_egress(now, device, sockets);
        }

        let shared = Arc::new(SharedState::new(4));
        let poll_config = PollLoopConfig {
            gateway_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            guest_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            gateway: GatewayIps {
                ipv4: Ipv4Addr::new(100, 96, 0, 1),
                ipv6: Ipv6Addr::LOCALHOST,
            },
            guest_ipv4: Ipv4Addr::new(100, 96, 0, 2),
            mtu: 1500,
        };
        let mut device = SmoltcpDevice::new(shared.clone(), poll_config.mtu);
        let mut iface = create_interface(&mut device, &poll_config);
        let mut sockets = SocketSet::new(vec![]);
        let now = smoltcp_now();

        // Mirror the real guest flow: resolve the gateway MAC before sending
        // the ICMP echo request.
        shared
            .tx_ring
            .push(build_arp_request_frame(
                poll_config.guest_mac,
                poll_config.guest_ipv4.octets(),
                poll_config.gateway.ipv4.octets(),
            ))
            .unwrap();
        shared
            .tx_ring
            .push(build_icmpv4_echo_frame(
                poll_config.guest_mac,
                poll_config.gateway_mac,
                poll_config.guest_ipv4.octets(),
                poll_config.gateway.ipv4.octets(),
                0x1234,
                0xABCD,
                b"ping",
            ))
            .unwrap();

        drive_one_frame(
            &mut device,
            &mut iface,
            &mut sockets,
            &shared,
            &poll_config,
            now,
        );
        let _ = shared.rx_ring.pop().expect("expected ARP reply");

        drive_one_frame(
            &mut device,
            &mut iface,
            &mut sockets,
            &shared,
            &poll_config,
            now,
        );

        let reply = shared.rx_ring.pop().expect("expected ICMP echo reply");
        let eth = EthernetFrame::new_checked(&reply).expect("valid ethernet frame");
        assert_eq!(eth.src_addr(), EthernetAddress(poll_config.gateway_mac));
        assert_eq!(eth.dst_addr(), EthernetAddress(poll_config.guest_mac));
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);

        let ipv4 = Ipv4Packet::new_checked(eth.payload()).expect("valid IPv4 packet");
        assert_eq!(Ipv4Addr::from(ipv4.src_addr()), poll_config.gateway.ipv4);
        assert_eq!(Ipv4Addr::from(ipv4.dst_addr()), poll_config.guest_ipv4);
        assert_eq!(ipv4.next_header(), IpProtocol::Icmp);

        let icmp = Icmpv4Packet::new_checked(ipv4.payload()).expect("valid ICMP packet");
        let icmp_repr = Icmpv4Repr::parse(&icmp, &ChecksumCapabilities::default())
            .expect("valid ICMP echo reply");
        assert_eq!(
            icmp_repr,
            Icmpv4Repr::EchoReply {
                ident: 0x1234,
                seq_no: 0xABCD,
                data: b"ping",
            }
        );
    }

    fn test_gateway() -> GatewayIps {
        GatewayIps {
            ipv4: Ipv4Addr::new(100, 96, 0, 1),
            ipv6: "fd42:6d73:62::1".parse().unwrap(),
        }
    }

    #[test]
    fn resolve_host_dst_matches_ipv4() {
        let gw = test_gateway();
        let dst = SocketAddr::new(IpAddr::V4(gw.ipv4), 8080);
        assert_eq!(
            resolve_host_dst(dst, gw),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 8080)
        );
    }

    #[test]
    fn resolve_host_dst_matches_ipv6() {
        let gw = test_gateway();
        let dst = SocketAddr::new(IpAddr::V6(gw.ipv6), 8080);
        assert_eq!(
            resolve_host_dst(dst, gw),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8080)
        );
    }

    #[test]
    fn resolve_host_dst_passes_through_non_gateway() {
        let gw = test_gateway();
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 443);
        assert_eq!(resolve_host_dst(dst, gw), dst);
    }

    #[test]
    fn external_icmp_echo_requests_are_not_answered_locally() {
        fn drive_one_frame(
            device: &mut SmoltcpDevice,
            iface: &mut Interface,
            sockets: &mut SocketSet<'_>,
            shared: &Arc<SharedState>,
            poll_config: &PollLoopConfig,
            now: Instant,
        ) {
            let frame = device.stage_next_frame().expect("expected staged frame");
            if handle_gateway_icmp_echo(frame, poll_config, shared) {
                device.drop_staged_frame();
                return;
            }
            let _ = iface.poll_ingress_single(now, device, sockets);
            let _ = iface.poll_egress(now, device, sockets);
        }

        let shared = Arc::new(SharedState::new(4));
        let poll_config = PollLoopConfig {
            gateway_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            guest_mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
            gateway: GatewayIps {
                ipv4: Ipv4Addr::new(100, 96, 0, 1),
                ipv6: Ipv6Addr::LOCALHOST,
            },
            guest_ipv4: Ipv4Addr::new(100, 96, 0, 2),
            mtu: 1500,
        };
        let mut device = SmoltcpDevice::new(shared.clone(), poll_config.mtu);
        let mut iface = create_interface(&mut device, &poll_config);
        let mut sockets = SocketSet::new(vec![]);
        let now = smoltcp_now();

        shared
            .tx_ring
            .push(build_arp_request_frame(
                poll_config.guest_mac,
                poll_config.guest_ipv4.octets(),
                poll_config.gateway.ipv4.octets(),
            ))
            .unwrap();
        shared
            .tx_ring
            .push(build_icmpv4_echo_frame(
                poll_config.guest_mac,
                poll_config.gateway_mac,
                poll_config.guest_ipv4.octets(),
                [142, 251, 216, 46],
                0x1234,
                0xABCD,
                b"ping",
            ))
            .unwrap();

        drive_one_frame(
            &mut device,
            &mut iface,
            &mut sockets,
            &shared,
            &poll_config,
            now,
        );
        let _ = shared.rx_ring.pop().expect("expected ARP reply");

        drive_one_frame(
            &mut device,
            &mut iface,
            &mut sockets,
            &shared,
            &poll_config,
            now,
        );
        assert!(
            shared.rx_ring.pop().is_none(),
            "external ICMP should not be answered locally"
        );
    }
}
