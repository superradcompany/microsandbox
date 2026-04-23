//! Non-DNS UDP relay: handles UDP traffic outside smoltcp.
//!
//! smoltcp has no wildcard port binding, so non-DNS UDP is intercepted at
//! the device level, relayed through host UDP sockets via tokio, and
//! responses are injected back into `rx_ring` as constructed ethernet frames.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpProtocol, Ipv4Packet,
    Ipv6Packet, UdpPacket,
};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Session idle timeout.
const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Channel capacity for outbound datagrams to the relay task.
const OUTBOUND_CHANNEL_CAPACITY: usize = 64;

/// Buffer size for receiving responses from the real server.
/// Sized to match the MTU (1500) plus generous headroom for
/// reassembled datagrams while avoiding 64 KiB per session.
const RECV_BUF_SIZE: usize = 4096;

/// Ethernet header length.
const ETH_HDR_LEN: usize = 14;

/// IPv4 header length (no options).
const IPV4_HDR_LEN: usize = 20;

/// UDP header length.
const UDP_HDR_LEN: usize = 8;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Relays non-DNS UDP traffic between the guest and the real network.
///
/// Each unique `(guest_src, guest_dst)` pair gets a host-side UDP socket
/// and a tokio relay task. The poll loop calls [`relay_outbound()`] to
/// send guest datagrams; response frames are injected directly into
/// `rx_ring`.
///
/// [`relay_outbound()`]: UdpRelay::relay_outbound
pub struct UdpRelay {
    shared: Arc<SharedState>,
    sessions: HashMap<(SocketAddr, SocketAddr), UdpSession>,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
    tokio_handle: tokio::runtime::Handle,
}

/// A single UDP relay session.
struct UdpSession {
    /// Channel to send outbound datagrams to the relay task.
    outbound_tx: mpsc::Sender<Bytes>,
    /// Last time this session was used.
    last_active: Instant,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl UdpRelay {
    /// Build a new UDP relay.
    ///
    /// # Arguments
    ///
    /// * `shared` - Stack-wide shared state used to inject response frames into `rx_ring`
    ///   and wake the poll thread.
    /// * `gateway_mac` - MAC address stamped as the source on synthesized response frames.
    /// * `guest_mac` - MAC address stamped as the destination on synthesized response frames.
    /// * `tokio_handle` - Runtime the per-session relay tasks are spawned on.
    pub fn new(
        shared: Arc<SharedState>,
        gateway_mac: [u8; 6],
        guest_mac: [u8; 6],
        tokio_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            shared,
            sessions: HashMap::new(),
            gateway_mac: EthernetAddress(gateway_mac),
            guest_mac: EthernetAddress(guest_mac),
            tokio_handle,
        }
    }

    /// Relay an outbound UDP datagram from the guest.
    ///
    /// # Arguments
    ///
    /// * `frame` - Raw ethernet frame captured from the guest.
    /// * `src` - Guest source address; keys the session and becomes the destination on
    ///   response frames.
    /// * `guest_dst` - Destination the guest wrote on the datagram. Retained as the session
    ///   key and the source IP on replies.
    /// * `host_dst` - Address the host socket actually connects to. Usually equal to
    ///   `guest_dst`; the caller substitutes loopback when `guest_dst` matches the gateway IP.
    pub fn relay_outbound(
        &mut self,
        frame: &[u8],
        src: SocketAddr,
        guest_dst: SocketAddr,
        host_dst: SocketAddr,
    ) {
        // Extract UDP payload from the ethernet frame.
        let Some(payload) = extract_udp_payload(frame) else {
            return;
        };

        let key = (src, guest_dst);

        // Create session if it doesn't exist or has expired.
        if self
            .sessions
            .get(&key)
            .is_none_or(|s| s.last_active.elapsed() > SESSION_TIMEOUT)
        {
            self.sessions.remove(&key);
            if let Some(session) = self.create_session(src, guest_dst, host_dst) {
                self.sessions.insert(key, session);
            } else {
                return;
            }
        }

        if let Some(session) = self.sessions.get_mut(&key) {
            session.last_active = Instant::now();
            let _ = session
                .outbound_tx
                .try_send(Bytes::copy_from_slice(payload));
        }
    }

    /// Remove expired sessions.
    pub fn cleanup_expired(&mut self) {
        self.sessions
            .retain(|_, session| session.last_active.elapsed() <= SESSION_TIMEOUT);
    }
}

impl UdpRelay {
    /// Create a new relay session: bind a host UDP socket and spawn a task.
    fn create_session(
        &self,
        guest_src: SocketAddr,
        guest_dst: SocketAddr,
        host_dst: SocketAddr,
    ) -> Option<UdpSession> {
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_CHANNEL_CAPACITY);

        let shared = self.shared.clone();
        let gateway_mac = self.gateway_mac;
        let guest_mac = self.guest_mac;

        self.tokio_handle.spawn(async move {
            if let Err(e) = udp_relay_task(
                outbound_rx,
                guest_src,
                guest_dst,
                host_dst,
                shared,
                gateway_mac,
                guest_mac,
            )
            .await
            {
                tracing::debug!(
                    guest_src = %guest_src,
                    guest_dst = %guest_dst,
                    error = %e,
                    "UDP relay task ended",
                );
            }
        });

        Some(UdpSession {
            outbound_tx,
            last_active: Instant::now(),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Per-session UDP relay loop: forwards guest datagrams to a host socket, stamps the replies
/// back into frames the guest accepts, and exits on idle timeout or channel close.
///
/// Binds an ephemeral host UDP socket in the address family of `host_dst` and `connect()`s it
/// to that peer. The `connect` restricts the socket to that peer's datagrams, which both sets
/// the default send target and filters spoofed inbound traffic. Responses are wrapped in a
/// synthesised ethernet frame (src IP = `guest_dst`, dst = `guest_src`) and pushed into
/// `rx_ring`.
///
/// # Arguments
///
/// * `outbound_rx` - Receives UDP payloads from the poll-loop side. Channel close signals
///   session drop.
/// * `guest_src` - Guest source address; stamped as the destination on reply frames.
/// * `guest_dst` - Destination the guest wrote on the datagram. Stamped as the source IP on
///   reply frames so the guest sees replies from the same address it dialed.
/// * `host_dst` - Address the host socket connects to. Equal to `guest_dst` for external
///   destinations; rewritten to loopback by [`crate::stack::resolve_host_dst`] when the guest
///   addressed the gateway.
/// * `shared` - Shared state; reply frames go into `rx_ring` and wake the poll thread.
/// * `gateway_mac` - Source MAC on reply frames (guest sees replies from the gateway's MAC).
/// * `guest_mac` - Destination MAC on reply frames.
///
/// # Errors
///
/// Returns [`std::io::Error`] when the initial `bind` or `connect` on
/// the host UDP socket fails, or when the host-side `recv` fails after
/// the socket was established.
#[allow(clippy::too_many_arguments)]
async fn udp_relay_task(
    mut outbound_rx: mpsc::Receiver<Bytes>,
    guest_src: SocketAddr,
    guest_dst: SocketAddr,
    host_dst: SocketAddr,
    shared: Arc<SharedState>,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> std::io::Result<()> {
    // Bind a host UDP socket. Use the same address family as the host destination.
    let bind_addr: SocketAddr = match host_dst {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0u16).into(),
        SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0u16).into(),
    };
    let socket = UdpSocket::bind(bind_addr).await?;
    // Connect to the destination to restrict accepted source addresses,
    // preventing host-network entities from injecting spoofed datagrams.
    socket.connect(host_dst).await?;

    let mut recv_buf = vec![0u8; RECV_BUF_SIZE];
    let timeout = SESSION_TIMEOUT;

    loop {
        tokio::select! {
            // Outbound: guest → server.
            data = outbound_rx.recv() => {
                match data {
                    Some(payload) => {
                        let _ = socket.send(&payload).await;
                    }
                    // Channel closed — session dropped by poll loop.
                    None => break,
                }
            }

            // Inbound: server → guest (only from the connected destination).
            result = socket.recv(&mut recv_buf) => {
                match result {
                    Ok(n) => {
                        if let Some(frame) = construct_udp_response(
                            guest_dst,
                            guest_src,
                            &recv_buf[..n],
                            gateway_mac,
                            guest_mac,
                        ) {
                            let _ = shared.rx_ring.push(frame);
                            shared.rx_wake.wake();
                        }
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "UDP relay recv failed");
                        break;
                    }
                }
            }

            // Idle timeout.
            () = tokio::time::sleep(timeout) => {
                break;
            }
        }
    }

    Ok(())
}

/// Construct an ethernet frame containing a UDP response for the guest.
///
/// Builds Ethernet + IPv4/IPv6 + UDP headers using smoltcp's wire module.
fn construct_udp_response(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> Option<Vec<u8>> {
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => Some(construct_udp_response_v4(
            src_ip,
            src.port(),
            dst_ip,
            dst.port(),
            payload,
            gateway_mac,
            guest_mac,
        )),
        (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => Some(construct_udp_response_v6(
            src_ip,
            src.port(),
            dst_ip,
            dst.port(),
            payload,
            gateway_mac,
            guest_mac,
        )),
        _ => None, // Mismatched address families — shouldn't happen.
    }
}

/// Construct an Ethernet + IPv4 + UDP frame.
fn construct_udp_response_v4(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> Vec<u8> {
    let udp_len = UDP_HDR_LEN + payload.len();
    let ip_total_len = IPV4_HDR_LEN + udp_len;
    let frame_len = ETH_HDR_LEN + ip_total_len;
    let mut buf = vec![0u8; frame_len];

    // Ethernet header.
    let eth_repr = EthernetRepr {
        src_addr: gateway_mac,
        dst_addr: guest_mac,
        ethertype: EthernetProtocol::Ipv4,
    };
    let mut eth_frame = EthernetFrame::new_unchecked(&mut buf);
    eth_repr.emit(&mut eth_frame);

    // IPv4 header.
    let ip_buf = &mut buf[ETH_HDR_LEN..];
    let mut ip_pkt = Ipv4Packet::new_unchecked(ip_buf);
    ip_pkt.set_version(4);
    ip_pkt.set_header_len(20);
    ip_pkt.set_total_len(ip_total_len as u16);
    ip_pkt.clear_flags();
    ip_pkt.set_dont_frag(true);
    ip_pkt.set_hop_limit(64);
    ip_pkt.set_next_header(IpProtocol::Udp);
    ip_pkt.set_src_addr(src_ip);
    ip_pkt.set_dst_addr(dst_ip);
    ip_pkt.fill_checksum();

    // UDP header + payload.
    let udp_buf = &mut buf[ETH_HDR_LEN + IPV4_HDR_LEN..];
    let mut udp_pkt = UdpPacket::new_unchecked(udp_buf);
    udp_pkt.set_src_port(src_port);
    udp_pkt.set_dst_port(dst_port);
    udp_pkt.set_len(udp_len as u16);
    udp_pkt.set_checksum(0); // Optional for UDP over IPv4.
    udp_pkt.payload_mut()[..payload.len()].copy_from_slice(payload);

    buf
}

/// Construct an Ethernet + IPv6 + UDP frame.
fn construct_udp_response_v6(
    src_ip: std::net::Ipv6Addr,
    src_port: u16,
    dst_ip: std::net::Ipv6Addr,
    dst_port: u16,
    payload: &[u8],
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> Vec<u8> {
    let udp_len = UDP_HDR_LEN + payload.len();
    let ipv6_hdr_len = 40;
    let frame_len = ETH_HDR_LEN + ipv6_hdr_len + udp_len;
    let mut buf = vec![0u8; frame_len];

    // Ethernet header.
    let eth_repr = EthernetRepr {
        src_addr: gateway_mac,
        dst_addr: guest_mac,
        ethertype: EthernetProtocol::Ipv6,
    };
    let mut eth_frame = EthernetFrame::new_unchecked(&mut buf);
    eth_repr.emit(&mut eth_frame);

    // IPv6 header.
    let ip_buf = &mut buf[ETH_HDR_LEN..];
    let mut ip_pkt = Ipv6Packet::new_unchecked(ip_buf);
    ip_pkt.set_version(6);
    ip_pkt.set_payload_len(udp_len as u16);
    ip_pkt.set_next_header(IpProtocol::Udp);
    ip_pkt.set_hop_limit(64);
    ip_pkt.set_src_addr(src_ip);
    ip_pkt.set_dst_addr(dst_ip);

    // UDP header + payload.
    let udp_buf = &mut buf[ETH_HDR_LEN + ipv6_hdr_len..];
    let mut udp_pkt = UdpPacket::new_unchecked(udp_buf);
    udp_pkt.set_src_port(src_port);
    udp_pkt.set_dst_port(dst_port);
    udp_pkt.set_len(udp_len as u16);
    // Copy payload BEFORE computing checksum — fill_checksum reads the
    // payload bytes, so they must be in place first.
    udp_pkt.payload_mut()[..payload.len()].copy_from_slice(payload);
    // IPv6 UDP checksum is mandatory per RFC 8200 section 8.1.
    // A zero checksum causes the receiver to discard the packet.
    udp_pkt.fill_checksum(
        &smoltcp::wire::IpAddress::from(src_ip),
        &smoltcp::wire::IpAddress::from(dst_ip),
    );

    buf
}

/// Extract the UDP payload from a raw ethernet frame.
fn extract_udp_payload(frame: &[u8]) -> Option<&[u8]> {
    let eth = EthernetFrame::new_checked(frame).ok()?;
    match eth.ethertype() {
        EthernetProtocol::Ipv4 => {
            let ipv4 = Ipv4Packet::new_checked(eth.payload()).ok()?;
            let udp = UdpPacket::new_checked(ipv4.payload()).ok()?;
            Some(udp.payload())
        }
        EthernetProtocol::Ipv6 => {
            let ipv6 = Ipv6Packet::new_checked(eth.payload()).ok()?;
            let udp = UdpPacket::new_checked(ipv6.payload()).ok()?;
            Some(udp.payload())
        }
        _ => None,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_v4_response_has_correct_structure() {
        let payload = b"hello";
        let frame = construct_udp_response_v4(
            Ipv4Addr::new(8, 8, 8, 8),
            53,
            Ipv4Addr::new(100, 96, 0, 2),
            12345,
            payload,
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
        );

        assert_eq!(frame.len(), ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + 5);

        // Parse back.
        let eth = EthernetFrame::new_checked(&frame).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
        assert_eq!(
            eth.dst_addr(),
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])
        );

        let ipv4 = Ipv4Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(Ipv4Addr::from(ipv4.src_addr()), Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(
            Ipv4Addr::from(ipv4.dst_addr()),
            Ipv4Addr::new(100, 96, 0, 2)
        );
        assert_eq!(ipv4.next_header(), IpProtocol::Udp);

        let udp = UdpPacket::new_checked(ipv4.payload()).unwrap();
        assert_eq!(udp.src_port(), 53);
        assert_eq!(udp.dst_port(), 12345);
        assert_eq!(udp.payload(), b"hello");
    }

    #[test]
    fn construct_v6_response_has_correct_structure() {
        let payload = b"hello ipv6";
        let src = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap();
        let dst = "fd42:6d73:62::2".parse::<std::net::Ipv6Addr>().unwrap();
        let frame = construct_udp_response_v6(
            src,
            53,
            dst,
            12345,
            payload,
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
        );

        let ipv6_hdr_len = 40;
        assert_eq!(
            frame.len(),
            ETH_HDR_LEN + ipv6_hdr_len + UDP_HDR_LEN + payload.len()
        );

        // Parse back.
        let eth = EthernetFrame::new_checked(&frame).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv6);

        let ipv6 = Ipv6Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ipv6.next_header(), IpProtocol::Udp);

        let udp = UdpPacket::new_checked(ipv6.payload()).unwrap();
        assert_eq!(udp.src_port(), 53);
        assert_eq!(udp.dst_port(), 12345);
        assert_eq!(udp.payload(), b"hello ipv6");
        // Verify checksum is non-zero (mandatory for IPv6 UDP per RFC 8200).
        assert_ne!(udp.checksum(), 0, "IPv6 UDP checksum must not be zero");
        // Verify checksum is correct.
        assert!(
            udp.verify_checksum(
                &smoltcp::wire::IpAddress::from(src),
                &smoltcp::wire::IpAddress::from(dst),
            ),
            "IPv6 UDP checksum must be valid"
        );
    }

    #[test]
    fn extract_payload_from_v6_udp_frame() {
        let src = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap();
        let dst = "fd42:6d73:62::2".parse::<std::net::Ipv6Addr>().unwrap();
        let frame = construct_udp_response_v6(
            src,
            80,
            dst,
            54321,
            b"v6 data",
            EthernetAddress([0; 6]),
            EthernetAddress([0; 6]),
        );
        let payload = extract_udp_payload(&frame).unwrap();
        assert_eq!(payload, b"v6 data");
    }

    #[test]
    fn extract_payload_from_v4_udp_frame() {
        // Build a frame then extract the payload.
        let frame = construct_udp_response_v4(
            Ipv4Addr::new(1, 2, 3, 4),
            80,
            Ipv4Addr::new(10, 0, 0, 2),
            54321,
            b"test data",
            EthernetAddress([0; 6]),
            EthernetAddress([0; 6]),
        );
        let payload = extract_udp_payload(&frame).unwrap();
        assert_eq!(payload, b"test data");
    }
}
