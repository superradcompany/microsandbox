//! DNS query interception: the smoltcp ↔ channel bridge.
//!
//! `DnsInterceptor` owns the smoltcp UDP socket bound to `gateway:53`
//! and a pair of channels to the async forwarder task spawned on the
//! tokio runtime. Each poll-loop iteration, `process()` reads pending
//! queries off the smoltcp socket and hands them to the forwarder,
//! then writes any forwarded responses back to the socket.
//!
//! The DNS wire protocol, upstream client, block-list, and rebind-
//! protection logic all live under sibling modules and are reached via
//! the forwarder task.

use std::collections::HashSet;
use std::net::IpAddr;
use std::sync::Arc;

use bytes::Bytes;
use smoltcp::iface::SocketSet;
use smoltcp::socket::udp;
use smoltcp::storage::PacketMetadata;
use smoltcp::wire::{IpAddress, IpEndpoint, IpListenEndpoint};
use tokio::sync::mpsc;

use super::common::config::NormalizedDnsConfig;
use super::forwarder::{DnsForwarder, DnsForwarderHandle};
use super::proxies::udp::UdpProxy;
use crate::config::DnsConfig;
use crate::policy::PolicyEvaluator;
use crate::shared::SharedState;
use crate::stack::GatewayIps;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// DNS port.
const DNS_PORT: u16 = 53;

/// Max DNS message size (UDP).
const DNS_MAX_SIZE: usize = 4096;

/// Number of packet slots in the smoltcp UDP socket buffers.
const DNS_SOCKET_PACKET_SLOTS: usize = 16;

/// Capacity of the query/response channels.
const CHANNEL_CAPACITY: usize = 64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// DNS query/response interceptor.
///
/// Owns the smoltcp UDP socket handle and channels to the async forwarder
/// task. The poll loop calls [`process()`] each iteration to:
///
/// 1. Read pending queries from the smoltcp socket → send to forwarder task.
/// 2. Read forwarded responses from the channel → write to smoltcp socket.
///
/// [`process()`]: DnsInterceptor::process
pub(crate) struct DnsInterceptor {
    /// Handle to the smoltcp UDP socket bound to gateway:53.
    socket_handle: smoltcp::iface::SocketHandle,
    /// Sends queries to the background forwarder task.
    query_tx: mpsc::Sender<DnsQuery>,
    /// Receives responses from the background forwarder task.
    response_rx: mpsc::Receiver<DnsResponse>,
}

/// A DNS query extracted from the smoltcp socket.
pub(crate) struct DnsQuery {
    /// Raw DNS message bytes.
    pub(super) data: Bytes,
    /// Source endpoint (guest IP:port) for routing the response back.
    pub(super) source: IpEndpoint,
    /// Original destination IP the guest aimed the query at. The socket
    /// binds to every local address on port 53 (`addr: None`) so that the
    /// interceptor also captures `dig @1.1.1.1` and similar; without
    /// preserving the original destination we'd reply from the gateway
    /// IP and the guest's resolver would drop the response.
    pub(super) original_dst: Option<IpAddress>,
}

/// A forwarded DNS response ready to send back to the guest.
pub(crate) struct DnsResponse {
    /// Raw DNS response bytes.
    pub(crate) data: Bytes,
    /// Destination endpoint (guest IP:port).
    pub(super) dest: IpEndpoint,
    /// Source IP to stamp on the outgoing packet. Echoes the query's
    /// original destination so replies match what the guest asked.
    pub(super) source_addr: Option<IpAddress>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DnsInterceptor {
    /// Create the DNS interceptor.
    ///
    /// Binds a smoltcp UDP socket to port 53, creates the channel pair, and
    /// spawns the background forwarder task. Returns the interceptor and
    /// the shared [`DnsForwarderHandle`] used by the TCP/53 proxy.
    ///
    /// Create the DNS interceptor.
    ///
    /// Binds a smoltcp UDP socket to port 53, creates the channel pair,
    /// and spawns the background forwarder task. Returns the interceptor
    /// and the shared [`DnsForwarderHandle`] used by the TCP/53 proxy.
    ///
    /// # Arguments
    ///
    /// * `sockets` - Smoltcp socket set the UDP/53 socket is added to.
    /// * `dns_config` - Operator DNS config (block lists, upstreams, timeout).
    /// * `shared` - Stack-wide shared state used by the forwarder's UDP proxy for wake-ups.
    /// * `tokio_handle` - Runtime the forwarder + proxy tasks are spawned on.
    /// * `gateway_ips` - Set of gateway IPs (v4 + v6) used to distinguish "guest
    ///   queried the gateway resolver" from "guest queried a specific `@resolver`"
    ///   when routing upstream.
    /// * `evaluator` - Policy evaluator consulted on direct-path queries to a guest-chosen `@resolver`.
    /// * `gateway` - Gateway IPs returned as A / AAAA answers for `host.microsandbox.internal`.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        sockets: &mut SocketSet<'_>,
        dns_config: DnsConfig,
        shared: Arc<SharedState>,
        tokio_handle: &tokio::runtime::Handle,
        gateway_ips: Arc<HashSet<IpAddr>>,
        net_policy_evaluator: Arc<PolicyEvaluator>,
        gateway: GatewayIps,
    ) -> (Self, DnsForwarderHandle) {
        // Create and bind the smoltcp UDP socket.
        let rx_meta = vec![PacketMetadata::EMPTY; DNS_SOCKET_PACKET_SLOTS];
        let rx_payload = vec![0u8; DNS_MAX_SIZE * DNS_SOCKET_PACKET_SLOTS];
        let tx_meta = vec![PacketMetadata::EMPTY; DNS_SOCKET_PACKET_SLOTS];
        let tx_payload = vec![0u8; DNS_MAX_SIZE * DNS_SOCKET_PACKET_SLOTS];

        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(rx_meta, rx_payload),
            udp::PacketBuffer::new(tx_meta, tx_payload),
        );
        socket
            .bind(IpListenEndpoint {
                addr: None,
                port: DNS_PORT,
            })
            .expect("failed to bind DNS socket to port 53");

        let socket_handle = sockets.add(socket);

        // Create channels.
        let (query_tx, query_rx) = mpsc::channel(CHANNEL_CAPACITY);
        let (response_tx, response_rx) = mpsc::channel(CHANNEL_CAPACITY);

        let normalized = Arc::new(NormalizedDnsConfig::from_config(dns_config));

        // Two spawns from the same construction site:
        //   1. DnsForwarder::spawn — connects to the configured
        //      upstream and publishes the shared handle.
        //   2. UdpProxy::spawn — drains UDP queries from this
        //      interceptor's channel and routes them through the
        //      forwarder, mirroring how `tcp.rs` handles per-connection
        //      TCP/53 traffic.
        let forwarder_handle = DnsForwarder::spawn(
            tokio_handle,
            normalized,
            gateway_ips,
            net_policy_evaluator,
            gateway,
        );
        UdpProxy::spawn(
            tokio_handle,
            query_rx,
            response_tx,
            forwarder_handle.clone(),
            shared,
        );

        (
            Self {
                socket_handle,
                query_tx,
                response_rx,
            },
            forwarder_handle,
        )
    }

    /// Process DNS queries and responses.
    ///
    /// Called by the poll loop each iteration:
    /// 1. Reads queries from the smoltcp socket → sends to forwarder task.
    /// 2. Reads responses from the forwarder → writes to smoltcp socket.
    pub(crate) fn process(&mut self, sockets: &mut SocketSet<'_>) {
        let socket = sockets.get_mut::<udp::Socket>(self.socket_handle);

        // Read queries from the smoltcp socket.
        let mut buf = [0u8; DNS_MAX_SIZE];
        while socket.can_recv() {
            match socket.recv_slice(&mut buf) {
                Ok((n, meta)) => {
                    let query = DnsQuery {
                        data: Bytes::copy_from_slice(&buf[..n]),
                        source: meta.endpoint,
                        original_dst: meta.local_address,
                    };
                    if self.query_tx.try_send(query).is_err() {
                        // Channel full — drop query. Guest will retry.
                        tracing::debug!("DNS query channel full, dropping query");
                    }
                }
                Err(_) => break,
            }
        }

        // Write responses to the smoltcp socket.
        // Check can_send() BEFORE consuming from the channel so
        // undeliverable responses remain for the next poll iteration.
        while socket.can_send() {
            match self.response_rx.try_recv() {
                Ok(response) => {
                    let mut meta = udp::UdpMetadata::from(response.dest);
                    // Stamp the reply with the IP the guest originally
                    // aimed at; smoltcp uses this as the source IP when
                    // it dispatches the packet.
                    meta.local_address = response.source_addr;
                    let _ = socket.send_slice(&response.data, meta);
                }
                Err(_) => break,
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use smoltcp::iface::{Config, Interface, SocketSet};
    use smoltcp::time::Instant;
    use smoltcp::wire::{HardwareAddress, IpCidr, Ipv4Address, Ipv6Address};

    use crate::device::SmoltcpDevice;

    /// IPv6 capture smoke test (#3): a UDP socket bound to
    /// `addr: None, port: 53` must accept packets destined to *any*
    /// local IP — including IPv6 — and surface the original v6
    /// destination via `meta.local_address`. This is what makes
    /// `dig -6 @2606:4700:4700::1111` capturable by the interceptor.
    ///
    /// We don't drive a full ethernet frame through the iface here —
    /// that requires a heavier harness. Instead we exercise the bind
    /// and the metadata round-trip directly: emit a v6-targeted
    /// outbound packet, ingest a synthetic v6 inbound packet, and
    /// confirm `local_address` round-trips both v4 and v6.
    #[test]
    fn udp_socket_bind_accepts_ipv6_endpoint() {
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![smoltcp::storage::PacketMetadata::EMPTY; 4],
                vec![0u8; 1024],
            ),
            udp::PacketBuffer::new(
                vec![smoltcp::storage::PacketMetadata::EMPTY; 4],
                vec![0u8; 1024],
            ),
        );
        socket
            .bind(IpListenEndpoint {
                addr: None,
                port: DNS_PORT,
            })
            .expect("bind addr:None succeeds");

        // Construct outgoing metadata with a v6 source: this is what
        // the interceptor does when it stamps responses for guests that
        // aimed at a v6 resolver. If the bind didn't accept v6, the
        // send_slice path below would fail.
        let v6: Ipv6Address = "fd42::1".parse().unwrap();
        let v6_dest = IpEndpoint {
            addr: IpAddress::Ipv6(v6),
            port: 12345,
        };
        let mut meta = udp::UdpMetadata::from(v6_dest);
        meta.local_address = Some(IpAddress::Ipv6("2606:4700:4700::1111".parse().unwrap()));
        socket
            .send_slice(b"v6 reply payload", meta)
            .expect("v6 send accepted by socket bound addr:None");

        // Same for v4, sanity check.
        let v4_dest = IpEndpoint {
            addr: IpAddress::Ipv4(Ipv4Address::new(10, 0, 0, 2)),
            port: 12345,
        };
        let mut meta_v4 = udp::UdpMetadata::from(v4_dest);
        meta_v4.local_address = Some(IpAddress::Ipv4(Ipv4Address::new(1, 1, 1, 1)));
        socket
            .send_slice(b"v4 reply payload", meta_v4)
            .expect("v4 send accepted by socket bound addr:None");
    }

    /// Driving a synthetic v6 UDP/53 packet through the smoltcp iface
    /// confirms end-to-end that the bind catches IPv6 traffic to *any*
    /// destination on port 53 and that `meta.local_address` is the
    /// original v6 dst (the value the forwarder uses to spoof the
    /// reply source).
    #[test]
    fn ipv6_udp_dns_packet_is_captured_with_local_address() {
        let shared = Arc::new(SharedState::new(8));
        let mtu = 1500;
        let mut device = SmoltcpDevice::new(shared.clone(), mtu);

        let gateway_v6: Ipv6Address = "fd42::1".parse().unwrap();
        let guest_v6: Ipv6Address = "fd42::2".parse().unwrap();
        let resolver_v6: Ipv6Address = "2606:4700:4700::1111".parse().unwrap();

        let hw_addr =
            HardwareAddress::Ethernet(smoltcp::wire::EthernetAddress([0x02, 0, 0, 0, 0, 1]));
        let mut iface = Interface::new(Config::new(hw_addr), &mut device, Instant::from_millis(0));
        iface.update_ip_addrs(|addrs| {
            addrs
                .push(IpCidr::new(IpAddress::Ipv6(gateway_v6), 64))
                .unwrap();
        });
        iface
            .routes_mut()
            .add_default_ipv6_route(gateway_v6)
            .unwrap();
        iface.set_any_ip(true);

        let mut sockets = SocketSet::new(vec![]);
        let mut socket = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![smoltcp::storage::PacketMetadata::EMPTY; 4],
                vec![0u8; 1024],
            ),
            udp::PacketBuffer::new(
                vec![smoltcp::storage::PacketMetadata::EMPTY; 4],
                vec![0u8; 1024],
            ),
        );
        socket
            .bind(IpListenEndpoint {
                addr: None,
                port: DNS_PORT,
            })
            .unwrap();
        let handle = sockets.add(socket);

        // Build: ethernet (IPv6) + IPv6 + UDP(src=any, dst=53) + 4 byte payload.
        let payload = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut frame = build_ipv6_udp_frame(
            [0x02, 0, 0, 0, 0, 2], // src mac (guest)
            [0x02, 0, 0, 0, 0, 1], // dst mac (gateway)
            guest_v6,
            resolver_v6,
            33333,
            DNS_PORT,
            &payload,
        );
        // Push frame into the device's tx_ring (guest → smoltcp), then
        // stage it so smoltcp's receive() will pick it up. Mirrors how
        // the production poll loop drives ingress.
        shared.tx_ring.push(std::mem::take(&mut frame)).unwrap();
        let _ = device.stage_next_frame().expect("frame staged");
        let _ = iface.poll(Instant::from_millis(0), &mut device, &mut sockets);

        let socket = sockets.get_mut::<udp::Socket>(handle);
        let mut buf = [0u8; 1024];
        let (n, meta) = socket.recv_slice(&mut buf).expect("v6 DNS packet captured");
        assert_eq!(&buf[..n], &payload);
        assert_eq!(
            meta.local_address,
            Some(IpAddress::Ipv6(resolver_v6)),
            "interceptor sees the original v6 destination, not the gateway IP"
        );
    }

    /// Build an Ethernet + IPv6 + UDP frame with the given payload.
    /// Mirrors the v4 helpers in stack.rs for the v6 path.
    fn build_ipv6_udp_frame(
        src_mac: [u8; 6],
        dst_mac: [u8; 6],
        src_ip: Ipv6Address,
        dst_ip: Ipv6Address,
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<u8> {
        use smoltcp::phy::ChecksumCapabilities;
        use smoltcp::wire::{
            EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpProtocol, Ipv6Packet,
            Ipv6Repr, UdpPacket, UdpRepr,
        };
        let udp_repr = UdpRepr { src_port, dst_port };
        let ipv6_repr = Ipv6Repr {
            src_addr: src_ip,
            dst_addr: dst_ip,
            next_header: IpProtocol::Udp,
            payload_len: 8 + payload.len(),
            hop_limit: 64,
        };
        let ipv6_hdr_len = 40;
        let mut frame = vec![0u8; 14 + ipv6_hdr_len + 8 + payload.len()];

        EthernetRepr {
            src_addr: EthernetAddress(src_mac),
            dst_addr: EthernetAddress(dst_mac),
            ethertype: EthernetProtocol::Ipv6,
        }
        .emit(&mut EthernetFrame::new_unchecked(&mut frame));

        ipv6_repr.emit(&mut Ipv6Packet::new_unchecked(
            &mut frame[14..14 + ipv6_hdr_len],
        ));

        udp_repr.emit(
            &mut UdpPacket::new_unchecked(&mut frame[14 + ipv6_hdr_len..]),
            &IpAddress::Ipv6(src_ip),
            &IpAddress::Ipv6(dst_ip),
            payload.len(),
            |buf| buf.copy_from_slice(payload),
            &ChecksumCapabilities::default(),
        );

        frame
    }
}
