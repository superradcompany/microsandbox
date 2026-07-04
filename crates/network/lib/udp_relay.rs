//! Non-DNS UDP relay: handles UDP traffic outside smoltcp.
//!
//! smoltcp has no wildcard port binding, so non-DNS UDP is intercepted at
//! the device level, relayed through host UDP sockets via tokio, and
//! responses are injected back into `rx_ring` as constructed ethernet frames.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::ops::Range;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, AtomicU32, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use smoltcp::wire::{
    EthernetAddress, EthernetFrame, EthernetProtocol, EthernetRepr, IpProtocol, Ipv4Packet,
    Ipv6Packet, UdpPacket,
};
use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
use tokio::io::Interest;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;

use crate::icmp_error::{construct_packet_too_big, ethernet_ip_payload};
use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Session idle timeout.
const SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Channel capacity for outbound datagrams to the relay task.
const OUTBOUND_CHANNEL_CAPACITY: usize = 64;

/// Default max concurrent UDP relay sessions per sandbox.
const MAX_UDP_SESSIONS: usize = 256;

/// Maximum queued bytes for one UDP relay session.
const MAX_QUEUED_BYTES_PER_SESSION: usize = 512 * 1024;

/// Maximum number of sent packet contexts kept for async PMTU errors.
const MAX_PMTU_CONTEXTS: usize = OUTBOUND_CHANNEL_CAPACITY;

/// Maximum UDP payload carried by an IPv4 packet.
const MAX_IPV4_UDP_PAYLOAD_LEN: usize = 65_507;

/// Maximum UDP payload carried by a non-jumbo IPv6 packet.
const MAX_IPV6_UDP_PAYLOAD_LEN: usize = 65_527;

/// Buffer size for receiving responses from the real server.
const RECV_BUF_SIZE: usize = MAX_IPV6_UDP_PAYLOAD_LEN;

/// Ethernet header length.
const ETH_HDR_LEN: usize = 14;

/// IPv4 header length (no options).
const IPV4_HDR_LEN: usize = 20;

/// IPv6 header length.
const IPV6_HDR_LEN: usize = 40;

/// IPv6 Fragment extension header length.
const IPV6_FRAGMENT_HDR_LEN: usize = 8;

/// UDP header length.
const UDP_HDR_LEN: usize = 8;

/// IPv4 identification sequence for fragmented guest-bound UDP responses.
static NEXT_IPV4_RESPONSE_IDENT: AtomicU16 = AtomicU16::new(1);

/// IPv6 fragment identification sequence for guest-bound UDP responses.
static NEXT_IPV6_RESPONSE_IDENT: AtomicU32 = AtomicU32::new(1);

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
    mtu: usize,
    tokio_handle: tokio::runtime::Handle,
}

/// A single UDP relay session.
struct UdpSession {
    /// Channel to send outbound datagrams to the relay task.
    outbound_tx: mpsc::Sender<OutboundDatagram>,
    /// Approximate bytes currently queued on `outbound_tx`.
    queued_bytes: Arc<AtomicUsize>,
    /// Last time this session was used.
    last_active: Instant,
}

/// Outbound datagram plus enough original IP context to synthesize ICMP errors.
struct OutboundDatagram {
    /// UDP payload to send through the host socket.
    payload: Bytes,
    /// Original guest IP packet, without the Ethernet header.
    original_ip_packet: Bytes,
}

impl OutboundDatagram {
    /// Bytes charged against the per-session queue budget.
    fn queued_len(&self) -> usize {
        self.payload.len() + self.original_ip_packet.len()
    }
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
    /// * `mtu` - Guest IP-level MTU. Large UDP replies are fragmented to fit it.
    /// * `tokio_handle` - Runtime the per-session relay tasks are spawned on.
    pub fn new(
        shared: Arc<SharedState>,
        gateway_mac: [u8; 6],
        guest_mac: [u8; 6],
        mtu: usize,
        tokio_handle: tokio::runtime::Handle,
    ) -> Self {
        Self {
            shared,
            sessions: HashMap::new(),
            gateway_mac: EthernetAddress(gateway_mac),
            guest_mac: EthernetAddress(guest_mac),
            mtu,
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
        let key = (src, guest_dst);
        if !self.ensure_session(key, src, guest_dst, host_dst) {
            return;
        }

        // Extract after session admission, so rejected session floods do not
        // pay the large-payload copy cost.
        let Some(mut datagram) = extract_udp_datagram(frame) else {
            return;
        };

        for attempt in 0..2 {
            let Some(session) = self.sessions.get_mut(&key) else {
                return;
            };
            let queued_len = datagram.queued_len();
            if !session.try_reserve(queued_len) {
                tracing::debug!(
                    guest_src = %src,
                    guest_dst = %guest_dst,
                    queued_len,
                    "UDP relay datagram dropped because session queue budget is full",
                );
                return;
            }

            match session.outbound_tx.try_send(datagram) {
                Ok(()) => {
                    session.last_active = Instant::now();
                    return;
                }
                Err(mpsc::error::TrySendError::Full(returned)) => {
                    session.release(queued_len);
                    tracing::debug!(
                        guest_src = %src,
                        guest_dst = %guest_dst,
                        "UDP relay datagram dropped because outbound queue is full",
                    );
                    drop(returned);
                    return;
                }
                Err(mpsc::error::TrySendError::Closed(returned)) => {
                    session.release(queued_len);
                    self.sessions.remove(&key);
                    datagram = returned;
                    if attempt == 0 && self.ensure_session(key, src, guest_dst, host_dst) {
                        continue;
                    }
                    tracing::debug!(
                        guest_src = %src,
                        guest_dst = %guest_dst,
                        "UDP relay datagram dropped because session task is closed",
                    );
                    return;
                }
            }
        }
    }

    /// Remove expired sessions.
    pub fn cleanup_expired(&mut self) {
        self.sessions
            .retain(|_, session| session.last_active.elapsed() <= SESSION_TIMEOUT);
    }
}

impl UdpRelay {
    /// Ensure a relay session exists and is fresh for `key`.
    fn ensure_session(
        &mut self,
        key: (SocketAddr, SocketAddr),
        guest_src: SocketAddr,
        guest_dst: SocketAddr,
        host_dst: SocketAddr,
    ) -> bool {
        if self
            .sessions
            .get(&key)
            .is_some_and(|s| s.last_active.elapsed() <= SESSION_TIMEOUT)
        {
            return true;
        }

        self.sessions.remove(&key);
        if self.sessions.len() >= MAX_UDP_SESSIONS {
            self.evict_oldest();
        }

        let Some(session) = self.create_session(guest_src, guest_dst, host_dst) else {
            return false;
        };
        self.sessions.insert(key, session);
        true
    }

    /// Evict the least recently active relay session.
    fn evict_oldest(&mut self) {
        let Some(oldest_key) = self
            .sessions
            .iter()
            .min_by_key(|(_, session)| session.last_active)
            .map(|(key, _)| *key)
        else {
            return;
        };
        self.sessions.remove(&oldest_key);
    }

    /// Create a new relay session: bind a host UDP socket and spawn a task.
    fn create_session(
        &self,
        guest_src: SocketAddr,
        guest_dst: SocketAddr,
        host_dst: SocketAddr,
    ) -> Option<UdpSession> {
        let (outbound_tx, outbound_rx) = mpsc::channel(OUTBOUND_CHANNEL_CAPACITY);
        let queued_bytes = Arc::new(AtomicUsize::new(0));

        let shared = self.shared.clone();
        let gateway_mac = self.gateway_mac;
        let guest_mac = self.guest_mac;
        let mtu = self.mtu;
        let task_queued_bytes = queued_bytes.clone();

        self.tokio_handle.spawn(async move {
            if let Err(e) = udp_relay_task(
                outbound_rx,
                task_queued_bytes,
                guest_src,
                guest_dst,
                host_dst,
                shared,
                gateway_mac,
                guest_mac,
                mtu,
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
            queued_bytes,
            last_active: Instant::now(),
        })
    }
}

impl UdpSession {
    /// Reserve queued bytes for a datagram before it is sent to the task.
    fn try_reserve(&self, len: usize) -> bool {
        let mut current = self.queued_bytes.load(Ordering::Acquire);
        loop {
            let Some(next) = current.checked_add(len) else {
                return false;
            };
            if next > MAX_QUEUED_BYTES_PER_SESSION {
                return false;
            }
            match self.queued_bytes.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }

    /// Release a prior queued-byte reservation.
    fn release(&self, len: usize) {
        self.queued_bytes.fetch_sub(len, Ordering::AcqRel);
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
/// * `mtu` - Guest IP-level MTU used to fragment large replies before injection.
///
/// # Errors
///
/// Returns [`std::io::Error`] when the initial `bind` or `connect` on
/// the host UDP socket fails, or when the host-side `recv` fails after
/// the socket was established.
#[allow(clippy::too_many_arguments)]
async fn udp_relay_task(
    mut outbound_rx: mpsc::Receiver<OutboundDatagram>,
    queued_bytes: Arc<AtomicUsize>,
    guest_src: SocketAddr,
    guest_dst: SocketAddr,
    host_dst: SocketAddr,
    shared: Arc<SharedState>,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
    mtu: usize,
) -> std::io::Result<()> {
    let socket = open_udp_socket(host_dst)?;
    // Connect to the destination to restrict accepted source addresses,
    // preventing host-network entities from injecting spoofed datagrams.
    socket.connect(host_dst).await?;

    let mut recv_buf = vec![0u8; RECV_BUF_SIZE];
    let mut pmtu_contexts = VecDeque::new();
    let timeout = SESSION_TIMEOUT;

    loop {
        tokio::select! {
            // Outbound: guest → server.
            data = outbound_rx.recv() => {
                match data {
                    Some(datagram) => {
                        queued_bytes.fetch_sub(datagram.queued_len(), Ordering::AcqRel);
                        match socket.send(&datagram.payload).await {
                            Ok(_) => {
                                remember_pmtu_context(&mut pmtu_contexts, datagram.original_ip_packet);
                            }
                            Err(e) if is_message_size_error(&e) => {
                                inject_packet_too_big(
                                    &shared,
                                    datagram.original_ip_packet.as_ref(),
                                    socket_path_mtu(&socket, host_dst).ok(),
                                    gateway_mac,
                                    guest_mac,
                                );
                            }
                            Err(e) => {
                                tracing::debug!(error = %e, "UDP relay send failed");
                            }
                        }
                    }
                    // Channel closed — session dropped by poll loop.
                    None => break,
                }
            }

            // Inbound/error readiness: server → guest data or host PMTU feedback.
            ready = socket.ready(Interest::READABLE | Interest::ERROR) => {
                let ready = ready?;

                #[cfg(target_os = "linux")]
                if ready.is_error() {
                    match drain_pmtu_errors(&socket) {
                        Ok(updates) => {
                            for mtu in updates {
                                if let Some(original_ip_packet) =
                                    take_pmtu_context(&mut pmtu_contexts, mtu)
                                {
                                    inject_packet_too_big(
                                        &shared,
                                        original_ip_packet.as_ref(),
                                        Some(mtu),
                                        gateway_mac,
                                        guest_mac,
                                    );
                                }
                            }
                        }
                        Err(e) => tracing::debug!(error = %e, "UDP relay error queue drain failed"),
                    }
                }

                if ready.is_readable() {
                    match socket.try_recv(&mut recv_buf) {
                        Ok(n) => {
                            if let Some(frames) = construct_udp_response_frames(
                                guest_dst,
                                guest_src,
                                &recv_buf[..n],
                                gateway_mac,
                                guest_mac,
                                mtu,
                            ) {
                                for frame in frames {
                                    if !shared.push_rx_frame_and_wake(frame) {
                                        tracing::debug!("UDP relay response dropped because rx_ring is full");
                                        break;
                                    }
                                }
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
                        Err(e) if is_message_size_error(&e) => {
                            if let Some(original_ip_packet) =
                                take_pmtu_context_without_mtu(&mut pmtu_contexts)
                            {
                                inject_packet_too_big(
                                    &shared,
                                    original_ip_packet.as_ref(),
                                    socket_path_mtu(&socket, host_dst).ok(),
                                    gateway_mac,
                                    guest_mac,
                                );
                            }
                        }
                        Err(e) => {
                            tracing::debug!(error = %e, "UDP relay recv failed");
                            break;
                        }
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
pub(crate) fn construct_udp_response(
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
        )?),
        (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => Some(construct_udp_response_v6(
            src_ip,
            src.port(),
            dst_ip,
            dst.port(),
            payload,
            gateway_mac,
            guest_mac,
        )?),
        _ => None, // Mismatched address families — shouldn't happen.
    }
}

/// Construct one or more ethernet frames containing a UDP response for the guest.
fn construct_udp_response_frames(
    src: SocketAddr,
    dst: SocketAddr,
    payload: &[u8],
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
    mtu: usize,
) -> Option<Vec<Vec<u8>>> {
    match (src.ip(), dst.ip()) {
        (IpAddr::V4(src_ip), IpAddr::V4(dst_ip)) => construct_udp_response_v4_frames(
            src_ip,
            src.port(),
            dst_ip,
            dst.port(),
            payload,
            gateway_mac,
            guest_mac,
            mtu,
        ),
        (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) => construct_udp_response_v6_frames(
            src_ip,
            src.port(),
            dst_ip,
            dst.port(),
            payload,
            gateway_mac,
            guest_mac,
            mtu,
        ),
        _ => None,
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
) -> Option<Vec<u8>> {
    if payload.len() > MAX_IPV4_UDP_PAYLOAD_LEN {
        return None;
    }

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

    Some(buf)
}

/// Construct IPv4 UDP response frames, fragmenting when the guest MTU requires it.
#[allow(clippy::too_many_arguments)]
fn construct_udp_response_v4_frames(
    src_ip: Ipv4Addr,
    src_port: u16,
    dst_ip: Ipv4Addr,
    dst_port: u16,
    payload: &[u8],
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
    mtu: usize,
) -> Option<Vec<Vec<u8>>> {
    if payload.len() > MAX_IPV4_UDP_PAYLOAD_LEN {
        return None;
    }

    let udp_len = UDP_HDR_LEN.checked_add(payload.len())?;
    if IPV4_HDR_LEN.checked_add(udp_len)? <= mtu {
        return construct_udp_response_v4(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            payload,
            gateway_mac,
            guest_mac,
        )
        .map(|frame| vec![frame]);
    }

    let max_fragment_payload_len = fragment_payload_limit(mtu, IPV4_HDR_LEN)?;
    let ident = NEXT_IPV4_RESPONSE_IDENT.fetch_add(1, Ordering::Relaxed);
    let udp_datagram = build_udp_datagram_v4(src_port, dst_port, payload)?;
    let mut frames = Vec::new();
    let mut offset = 0usize;

    while offset < udp_datagram.len() {
        let remaining = udp_datagram.len() - offset;
        let take = remaining.min(max_fragment_payload_len);
        let more_frags = offset + take < udp_datagram.len();
        frames.push(construct_ipv4_udp_fragment(
            src_ip,
            dst_ip,
            ident,
            offset,
            more_frags,
            &udp_datagram[offset..offset + take],
            gateway_mac,
            guest_mac,
        )?);
        offset += take;
    }

    Some(frames)
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
) -> Option<Vec<u8>> {
    if payload.len() > MAX_IPV6_UDP_PAYLOAD_LEN {
        return None;
    }

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

    Some(buf)
}

/// Construct IPv6 UDP response frames, fragmenting when the guest MTU requires it.
#[allow(clippy::too_many_arguments)]
fn construct_udp_response_v6_frames(
    src_ip: std::net::Ipv6Addr,
    src_port: u16,
    dst_ip: std::net::Ipv6Addr,
    dst_port: u16,
    payload: &[u8],
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
    mtu: usize,
) -> Option<Vec<Vec<u8>>> {
    if payload.len() > MAX_IPV6_UDP_PAYLOAD_LEN {
        return None;
    }

    let udp_len = UDP_HDR_LEN.checked_add(payload.len())?;
    if IPV6_HDR_LEN.checked_add(udp_len)? <= mtu {
        return construct_udp_response_v6(
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            payload,
            gateway_mac,
            guest_mac,
        )
        .map(|frame| vec![frame]);
    }

    let max_fragment_payload_len =
        fragment_payload_limit(mtu, IPV6_HDR_LEN + IPV6_FRAGMENT_HDR_LEN)?;
    let ident = NEXT_IPV6_RESPONSE_IDENT.fetch_add(1, Ordering::Relaxed);
    let udp_datagram = build_udp_datagram_v6(src_ip, src_port, dst_ip, dst_port, payload)?;
    let mut frames = Vec::new();
    let mut offset = 0usize;

    while offset < udp_datagram.len() {
        let remaining = udp_datagram.len() - offset;
        let take = remaining.min(max_fragment_payload_len);
        let more_frags = offset + take < udp_datagram.len();
        frames.push(construct_ipv6_udp_fragment(
            src_ip,
            dst_ip,
            ident,
            offset,
            more_frags,
            &udp_datagram[offset..offset + take],
            gateway_mac,
            guest_mac,
        )?);
        offset += take;
    }

    Some(frames)
}

/// Build a UDP datagram buffer for IPv4.
fn build_udp_datagram_v4(src_port: u16, dst_port: u16, payload: &[u8]) -> Option<Vec<u8>> {
    let udp_len = UDP_HDR_LEN.checked_add(payload.len())?;
    if udp_len > u16::MAX as usize {
        return None;
    }

    let mut buf = vec![0u8; udp_len];
    let mut udp = UdpPacket::new_unchecked(&mut buf);
    udp.set_src_port(src_port);
    udp.set_dst_port(dst_port);
    udp.set_len(udp_len as u16);
    udp.set_checksum(0);
    udp.payload_mut()[..payload.len()].copy_from_slice(payload);
    Some(buf)
}

/// Build a UDP datagram buffer for IPv6, including its mandatory checksum.
fn build_udp_datagram_v6(
    src_ip: std::net::Ipv6Addr,
    src_port: u16,
    dst_ip: std::net::Ipv6Addr,
    dst_port: u16,
    payload: &[u8],
) -> Option<Vec<u8>> {
    let udp_len = UDP_HDR_LEN.checked_add(payload.len())?;
    if udp_len > u16::MAX as usize {
        return None;
    }

    let mut buf = vec![0u8; udp_len];
    let mut udp = UdpPacket::new_unchecked(&mut buf);
    udp.set_src_port(src_port);
    udp.set_dst_port(dst_port);
    udp.set_len(udp_len as u16);
    udp.payload_mut()[..payload.len()].copy_from_slice(payload);
    udp.fill_checksum(
        &smoltcp::wire::IpAddress::from(src_ip),
        &smoltcp::wire::IpAddress::from(dst_ip),
    );
    Some(buf)
}

/// Return the largest non-final fragment payload that fits in an IP MTU.
fn fragment_payload_limit(mtu: usize, header_len: usize) -> Option<usize> {
    let available = mtu.checked_sub(header_len)?;
    let limit = available - (available % 8);
    (limit > 0).then_some(limit)
}

/// Construct one Ethernet + IPv4 fragment carrying a UDP datagram slice.
#[allow(clippy::too_many_arguments)]
fn construct_ipv4_udp_fragment(
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    ident: u16,
    fragment_offset: usize,
    more_frags: bool,
    fragment_payload: &[u8],
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> Option<Vec<u8>> {
    let ip_total_len = IPV4_HDR_LEN.checked_add(fragment_payload.len())?;
    if ip_total_len > u16::MAX as usize || fragment_offset > u16::MAX as usize {
        return None;
    }

    let mut buf = vec![0u8; ETH_HDR_LEN + ip_total_len];
    let mut eth_frame = EthernetFrame::new_unchecked(&mut buf);
    EthernetRepr {
        src_addr: gateway_mac,
        dst_addr: guest_mac,
        ethertype: EthernetProtocol::Ipv4,
    }
    .emit(&mut eth_frame);

    let mut ip = Ipv4Packet::new_unchecked(&mut buf[ETH_HDR_LEN..]);
    ip.set_version(4);
    ip.set_header_len(IPV4_HDR_LEN as u8);
    ip.set_total_len(ip_total_len as u16);
    ip.set_ident(ident);
    ip.clear_flags();
    ip.set_more_frags(more_frags);
    ip.set_frag_offset(fragment_offset as u16);
    ip.set_hop_limit(64);
    ip.set_next_header(IpProtocol::Udp);
    ip.set_src_addr(src_ip);
    ip.set_dst_addr(dst_ip);
    ip.payload_mut().copy_from_slice(fragment_payload);
    ip.fill_checksum();

    Some(buf)
}

/// Construct one Ethernet + IPv6 Fragment packet carrying a UDP datagram slice.
#[allow(clippy::too_many_arguments)]
fn construct_ipv6_udp_fragment(
    src_ip: std::net::Ipv6Addr,
    dst_ip: std::net::Ipv6Addr,
    ident: u32,
    fragment_offset: usize,
    more_frags: bool,
    fragment_payload: &[u8],
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> Option<Vec<u8>> {
    let ipv6_payload_len = IPV6_FRAGMENT_HDR_LEN.checked_add(fragment_payload.len())?;
    if ipv6_payload_len > u16::MAX as usize || fragment_offset > u16::MAX as usize {
        return None;
    }

    let mut buf = vec![0u8; ETH_HDR_LEN + IPV6_HDR_LEN + ipv6_payload_len];
    let mut eth_frame = EthernetFrame::new_unchecked(&mut buf);
    EthernetRepr {
        src_addr: gateway_mac,
        dst_addr: guest_mac,
        ethertype: EthernetProtocol::Ipv6,
    }
    .emit(&mut eth_frame);

    {
        let mut ip = Ipv6Packet::new_unchecked(&mut buf[ETH_HDR_LEN..]);
        ip.set_version(6);
        ip.set_payload_len(ipv6_payload_len as u16);
        ip.set_next_header(IpProtocol::Ipv6Frag);
        ip.set_hop_limit(64);
        ip.set_src_addr(src_ip);
        ip.set_dst_addr(dst_ip);
    }

    let fragment_start = ETH_HDR_LEN + IPV6_HDR_LEN;
    let fragment = &mut buf[fragment_start..][..IPV6_FRAGMENT_HDR_LEN];
    fragment[0] = IpProtocol::Udp.into();
    fragment[1] = 0;
    let offset_units = u16::try_from(fragment_offset / 8).ok()?;
    let raw = (offset_units << 3) | u16::from(more_frags);
    fragment[2..4].copy_from_slice(&raw.to_be_bytes());
    fragment[4..8].copy_from_slice(&ident.to_be_bytes());
    buf[fragment_start + IPV6_FRAGMENT_HDR_LEN..].copy_from_slice(fragment_payload);

    Some(buf)
}

/// Extract the UDP payload from a raw ethernet frame.
pub(crate) fn extract_udp_payload(frame: &[u8]) -> Option<&[u8]> {
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

/// Extract the outbound UDP payload and original IP packet from a raw ethernet frame.
fn extract_udp_datagram(frame: &[u8]) -> Option<OutboundDatagram> {
    let original = ethernet_ip_payload(frame)?;
    let payload_range = udp_payload_range(original)?;
    let original_ip_packet = Bytes::copy_from_slice(original);
    let payload = original_ip_packet.slice(payload_range);

    Some(OutboundDatagram {
        payload,
        original_ip_packet,
    })
}

/// Return the UDP payload range inside one Ethernet-stripped IP packet.
fn udp_payload_range(ip_packet: &[u8]) -> Option<Range<usize>> {
    match ip_packet.first()? >> 4 {
        4 => {
            let ipv4 = Ipv4Packet::new_checked(ip_packet).ok()?;
            if ipv4.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp_offset = ipv4.header_len() as usize;
            let udp = UdpPacket::new_checked(&ip_packet[udp_offset..]).ok()?;
            let payload_start = udp_offset + UDP_HDR_LEN;
            let payload_end = udp_offset + usize::from(udp.len());
            (payload_start <= payload_end && payload_end <= ip_packet.len())
                .then_some(payload_start..payload_end)
        }
        6 => {
            let ipv6 = Ipv6Packet::new_checked(ip_packet).ok()?;
            if ipv6.next_header() != IpProtocol::Udp {
                return None;
            }
            let udp_offset = 40;
            let udp = UdpPacket::new_checked(&ip_packet[udp_offset..]).ok()?;
            let payload_start = udp_offset + UDP_HDR_LEN;
            let payload_end = udp_offset + usize::from(udp.len());
            (payload_start <= payload_end && payload_end <= ip_packet.len())
                .then_some(payload_start..payload_end)
        }
        _ => None,
    }
}

/// Open a host UDP socket with PMTU feedback options enabled when available.
fn open_udp_socket(host_dst: SocketAddr) -> io::Result<UdpSocket> {
    let domain = match host_dst {
        SocketAddr::V4(_) => Domain::IPV4,
        SocketAddr::V6(_) => Domain::IPV6,
    };
    let socket = Socket::new(domain, Type::DGRAM, Some(SocketProtocol::UDP))?;
    socket.set_nonblocking(true)?;

    let bind_addr: SocketAddr = match host_dst {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0u16).into(),
        SocketAddr::V6(_) => (std::net::Ipv6Addr::UNSPECIFIED, 0u16).into(),
    };
    socket.bind(&bind_addr.into())?;

    #[cfg(target_os = "linux")]
    enable_linux_pmtu_errors(&socket, host_dst)?;

    UdpSocket::from_std(socket.into())
}

/// Return true when an I/O error represents a datagram exceeding the path MTU.
fn is_message_size_error(error: &io::Error) -> bool {
    error.raw_os_error() == Some(libc::EMSGSIZE)
}

/// Inject an ICMP too-big error toward the guest.
fn inject_packet_too_big(
    shared: &SharedState,
    original_ip_packet: &[u8],
    next_hop_mtu: Option<u32>,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) {
    let Some(next_hop_mtu) =
        next_hop_mtu.filter(|mtu| valid_packet_too_big_mtu(original_ip_packet, *mtu))
    else {
        tracing::debug!("UDP relay skipped ICMP too-big because no valid MTU is available");
        return;
    };

    let Some(frame) =
        construct_packet_too_big(original_ip_packet, next_hop_mtu, gateway_mac, guest_mac)
    else {
        return;
    };

    if !shared.push_rx_frame_and_wake(frame) {
        tracing::debug!("UDP relay ICMP too-big response dropped because rx_ring is full");
    }
}

/// Return whether an MTU value is usable in a guest-facing too-big error.
fn valid_packet_too_big_mtu(original_ip_packet: &[u8], mtu: u32) -> bool {
    if mtu == 0 {
        return false;
    }

    match original_ip_packet.first().map(|byte| byte >> 4) {
        // IPv6 Packet Too Big must carry an actionable MTU. IPv6 links have a
        // minimum MTU of 1280, so lower values are not useful PMTU feedback.
        Some(6) => mtu >= 1280,
        Some(4) => true,
        _ => false,
    }
}

/// Remember one sent packet for later async PMTU attribution.
fn remember_pmtu_context(contexts: &mut VecDeque<Bytes>, original_ip_packet: Bytes) {
    if contexts.len() >= MAX_PMTU_CONTEXTS {
        contexts.pop_front();
    }
    contexts.push_back(original_ip_packet);
}

/// Take the most likely packet that triggered a PMTU update.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn take_pmtu_context(contexts: &mut VecDeque<Bytes>, mtu: u32) -> Option<Bytes> {
    if mtu > 0
        && let Some(position) = contexts.iter().position(|packet| {
            original_ip_packet_len(packet.as_ref()).is_some_and(|len| len > mtu as usize)
        })
    {
        return contexts.remove(position);
    }

    contexts.pop_front()
}

/// Take the oldest PMTU context when the host did not provide an MTU.
fn take_pmtu_context_without_mtu(contexts: &mut VecDeque<Bytes>) -> Option<Bytes> {
    contexts.pop_front()
}

/// Return the wire length declared by an Ethernet-stripped IP packet.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn original_ip_packet_len(packet: &[u8]) -> Option<usize> {
    match packet.first()? >> 4 {
        4 => {
            let ipv4 = Ipv4Packet::new_checked(packet).ok()?;
            Some(usize::from(ipv4.total_len()).min(packet.len()))
        }
        6 => {
            let ipv6 = Ipv6Packet::new_checked(packet).ok()?;
            Some((40 + usize::from(ipv6.payload_len())).min(packet.len()))
        }
        _ => None,
    }
}

/// Return the connected socket's current path MTU when the host exposes it.
#[cfg(target_os = "linux")]
fn socket_path_mtu(socket: &UdpSocket, host_dst: SocketAddr) -> io::Result<u32> {
    let fd = socket.as_raw_fd();
    let (level, optname) = match host_dst {
        SocketAddr::V4(_) => (libc::IPPROTO_IP, libc::IP_MTU),
        SocketAddr::V6(_) => (libc::IPPROTO_IPV6, libc::IPV6_MTU),
    };

    let mut mtu: libc::c_int = 0;
    let mut len = std::mem::size_of_val(&mtu) as libc::socklen_t;
    // SAFETY: `mtu` and `len` point to valid writable storage for getsockopt.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            level,
            optname,
            (&mut mtu as *mut libc::c_int).cast(),
            &mut len,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    if mtu <= 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "connected socket reported a non-positive path MTU",
        ));
    }

    Ok(mtu as u32)
}

/// Return no MTU on platforms without connected-socket path-MTU queries.
#[cfg(not(target_os = "linux"))]
fn socket_path_mtu(_socket: &UdpSocket, _host_dst: SocketAddr) -> io::Result<u32> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "path MTU query is not supported on this platform",
    ))
}

/// Enable Linux per-socket extended errors for PMTU feedback.
#[cfg(target_os = "linux")]
fn enable_linux_pmtu_errors(socket: &Socket, host_dst: SocketAddr) -> io::Result<()> {
    let fd = socket.as_raw_fd();
    match host_dst {
        SocketAddr::V4(_) => set_socket_bool(fd, libc::IPPROTO_IP, libc::IP_RECVERR, true),
        SocketAddr::V6(_) => set_socket_bool(fd, libc::IPPROTO_IPV6, libc::IPV6_RECVERR, true),
    }
}

/// Set a boolean socket option using libc constants not exposed by socket2.
#[cfg(target_os = "linux")]
fn set_socket_bool(
    fd: libc::c_int,
    level: libc::c_int,
    optname: libc::c_int,
    value: bool,
) -> io::Result<()> {
    let value: libc::c_int = i32::from(value);
    // SAFETY: `value` points to a valid c_int option payload.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            level,
            optname,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of_val(&value) as libc::socklen_t,
        )
    };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Drain Linux's UDP error queue and return PMTU updates in queue order.
#[cfg(target_os = "linux")]
fn drain_pmtu_errors(socket: &UdpSocket) -> io::Result<Vec<u32>> {
    socket.try_io(Interest::ERROR, || {
        drain_pmtu_errors_from_fd(socket.as_raw_fd())
    })
}

/// Drain all currently queued extended errors from one socket fd.
#[cfg(target_os = "linux")]
fn drain_pmtu_errors_from_fd(fd: libc::c_int) -> io::Result<Vec<u32>> {
    let mut mtus = Vec::new();
    let mut drained_any = false;

    loop {
        match recv_one_pmtu_error(fd) {
            Ok(mtu) => {
                drained_any = true;
                if let Some(mtu) = mtu {
                    mtus.push(mtu);
                }
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock && drained_any => return Ok(mtus),
            Err(e) => return Err(e),
        }
    }
}

/// Receive and parse one Linux MSG_ERRQUEUE entry.
#[cfg(target_os = "linux")]
fn recv_one_pmtu_error(fd: libc::c_int) -> io::Result<Option<u32>> {
    let mut data = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: data.as_mut_ptr().cast(),
        iov_len: data.len(),
    };
    let mut control = [0u8; 512];
    // SAFETY: zeroed msghdr is filled with valid pointers immediately below.
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr().cast();
    msg.msg_controllen = control.len();

    // SAFETY: `msg` contains valid iovec/control buffers and `fd` is a UDP socket.
    let rc = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_ERRQUEUE | libc::MSG_DONTWAIT) };
    if rc == -1 {
        return Err(io::Error::last_os_error());
    }

    let control_len = msg.msg_controllen.min(control.len());
    Ok(parse_pmtu_from_control_messages(&control[..control_len]))
}

/// Parse a PMTU value out of one recvmsg control-message list.
#[cfg(target_os = "linux")]
fn parse_pmtu_from_control_messages(control: &[u8]) -> Option<u32> {
    let header_len = std::mem::size_of::<libc::cmsghdr>();
    let data_offset = cmsg_align(header_len)?;
    let mut offset = 0usize;

    while offset.checked_add(header_len)? <= control.len() {
        let header = control.get(offset..offset + header_len)?;
        let cmsg_len = read_native_usize(header)?;
        if cmsg_len < data_offset {
            return None;
        }

        let message_end = offset.checked_add(cmsg_len)?;
        if message_end > control.len() {
            return None;
        }

        let cmsg_level = read_native_c_int(header.get(std::mem::size_of::<usize>()..)?)?;
        let cmsg_type = read_native_c_int(
            header.get(std::mem::size_of::<usize>() + std::mem::size_of::<libc::c_int>()..)?,
        )?;
        let is_extended_error = (cmsg_level == libc::IPPROTO_IP && cmsg_type == libc::IP_RECVERR)
            || (cmsg_level == libc::IPPROTO_IPV6 && cmsg_type == libc::IPV6_RECVERR);

        if is_extended_error {
            let data_start = offset.checked_add(data_offset)?;
            if data_start > message_end {
                return None;
            }

            if let Some(mtu) = parse_sock_extended_err_mtu(control.get(data_start..message_end)?) {
                return Some(mtu);
            }
        }

        offset = offset.checked_add(cmsg_align(cmsg_len)?)?;
    }

    None
}

/// Parse Linux's `sock_extended_err` control payload without pointer casts.
#[cfg(target_os = "linux")]
fn parse_sock_extended_err_mtu(data: &[u8]) -> Option<u32> {
    let error_len = std::mem::size_of::<libc::sock_extended_err>();
    if data.len() < error_len {
        return None;
    }

    let ee_errno = read_native_u32(data)?;
    let ee_origin = *data.get(4)?;
    let ee_info = read_native_u32(data.get(8..)?)?;

    if ee_errno == libc::EMSGSIZE as u32
        && matches!(
            ee_origin,
            libc::SO_EE_ORIGIN_ICMP | libc::SO_EE_ORIGIN_ICMP6 | libc::SO_EE_ORIGIN_LOCAL
        )
    {
        return Some(ee_info);
    }

    None
}

/// Read a native-endian C `size_t` from the start of a byte slice.
#[cfg(target_os = "linux")]
fn read_native_usize(bytes: &[u8]) -> Option<usize> {
    match std::mem::size_of::<usize>() {
        4 => Some(u32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?) as usize),
        8 => Some(u64::from_ne_bytes(bytes.get(..8)?.try_into().ok()?) as usize),
        _ => None,
    }
}

/// Read a native-endian C `int` from the start of a byte slice.
#[cfg(target_os = "linux")]
fn read_native_c_int(bytes: &[u8]) -> Option<libc::c_int> {
    match std::mem::size_of::<libc::c_int>() {
        4 => Some(i32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?) as libc::c_int),
        _ => None,
    }
}

/// Read a native-endian `u32` from the start of a byte slice.
#[cfg(target_os = "linux")]
fn read_native_u32(bytes: &[u8]) -> Option<u32> {
    Some(u32::from_ne_bytes(bytes.get(..4)?.try_into().ok()?))
}

/// Linux control messages are aligned to pointer width.
#[cfg(target_os = "linux")]
fn cmsg_align(len: usize) -> Option<usize> {
    let align = std::mem::size_of::<usize>();
    len.checked_add(align - 1).map(|value| value & !(align - 1))
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
        )
        .unwrap();

        assert_eq!(frame.len(), ETH_HDR_LEN + IPV4_HDR_LEN + UDP_HDR_LEN + 5);

        // Parse back.
        let eth = EthernetFrame::new_checked(&frame).unwrap();
        assert_eq!(eth.ethertype(), EthernetProtocol::Ipv4);
        assert_eq!(
            eth.dst_addr(),
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02])
        );

        let ipv4 = Ipv4Packet::new_checked(eth.payload()).unwrap();
        assert_eq!(ipv4.src_addr(), Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(ipv4.dst_addr(), Ipv4Addr::new(100, 96, 0, 2));
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
        )
        .unwrap();

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
        )
        .unwrap();
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
        )
        .unwrap();
        let payload = extract_udp_payload(&frame).unwrap();
        assert_eq!(payload, b"test data");
    }

    #[test]
    fn construct_v4_response_rejects_payload_over_ipv4_limit() {
        let payload = vec![0u8; MAX_IPV4_UDP_PAYLOAD_LEN + 1];
        assert!(
            construct_udp_response_v4(
                Ipv4Addr::new(8, 8, 8, 8),
                53,
                Ipv4Addr::new(100, 96, 0, 2),
                12345,
                &payload,
                EthernetAddress([0; 6]),
                EthernetAddress([0; 6]),
            )
            .is_none()
        );
    }

    #[test]
    fn construct_v4_response_frames_fragment_large_payload_to_mtu() {
        let payload = vec![b'x'; 2000];
        let frames = construct_udp_response_frames(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 53),
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(100, 96, 0, 2)), 12345),
            &payload,
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
            1500,
        )
        .unwrap();

        assert_eq!(frames.len(), 2);
        assert!(frames.iter().all(|frame| frame.len() <= ETH_HDR_LEN + 1500));

        let first_eth = EthernetFrame::new_checked(frames[0].as_slice()).unwrap();
        let first_ip = Ipv4Packet::new_checked(first_eth.payload()).unwrap();
        assert!(first_ip.more_frags());
        assert_eq!(first_ip.frag_offset(), 0);
        assert_eq!(&first_ip.payload()[..2], &53u16.to_be_bytes());
        assert_eq!(&first_ip.payload()[2..4], &12345u16.to_be_bytes());
        assert_eq!(
            u16::from_be_bytes([first_ip.payload()[4], first_ip.payload()[5]]) as usize,
            UDP_HDR_LEN + payload.len()
        );

        let second_eth = EthernetFrame::new_checked(frames[1].as_slice()).unwrap();
        let second_ip = Ipv4Packet::new_checked(second_eth.payload()).unwrap();
        assert!(!second_ip.more_frags());
        assert_eq!(second_ip.frag_offset(), 1480);
    }

    #[test]
    fn construct_v6_response_frames_fragment_large_payload_to_mtu() {
        let src = "2001:db8::1".parse::<std::net::Ipv6Addr>().unwrap();
        let dst = "fd42:6d73:62::2".parse::<std::net::Ipv6Addr>().unwrap();
        let payload = vec![b'x'; 2000];
        let frames = construct_udp_response_frames(
            SocketAddr::new(IpAddr::V6(src), 53),
            SocketAddr::new(IpAddr::V6(dst), 12345),
            &payload,
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x01]),
            EthernetAddress([0x02, 0x00, 0x00, 0x00, 0x00, 0x02]),
            1500,
        )
        .unwrap();

        assert_eq!(frames.len(), 2);
        assert!(frames.iter().all(|frame| frame.len() <= ETH_HDR_LEN + 1500));

        let first_eth = EthernetFrame::new_checked(frames[0].as_slice()).unwrap();
        let first_ip = Ipv6Packet::new_checked(first_eth.payload()).unwrap();
        assert_eq!(first_ip.next_header(), IpProtocol::Ipv6Frag);
        let first_fragment = &first_ip.payload()[..IPV6_FRAGMENT_HDR_LEN];
        let first_raw = u16::from_be_bytes([first_fragment[2], first_fragment[3]]);
        assert_eq!(IpProtocol::from(first_fragment[0]), IpProtocol::Udp);
        assert_eq!(first_raw >> 3, 0);
        assert_eq!(first_raw & 1, 1);

        let second_eth = EthernetFrame::new_checked(frames[1].as_slice()).unwrap();
        let second_ip = Ipv6Packet::new_checked(second_eth.payload()).unwrap();
        assert_eq!(second_ip.next_header(), IpProtocol::Ipv6Frag);
        let second_fragment = &second_ip.payload()[..IPV6_FRAGMENT_HDR_LEN];
        let second_raw = u16::from_be_bytes([second_fragment[2], second_fragment[3]]);
        assert_eq!(usize::from(second_raw >> 3) * 8, 1448);
        assert_eq!(second_raw & 1, 0);
        assert_eq!(
            &second_ip.payload()[IPV6_FRAGMENT_HDR_LEN..][..2],
            &payload[1440..1442]
        );
    }

    #[test]
    fn packet_too_big_mtu_validation_rejects_unusable_ipv6_values() {
        let frame = construct_udp_response_v6(
            "2001:db8::1".parse().unwrap(),
            443,
            "fd42:6d73:62::2".parse().unwrap(),
            12345,
            b"payload",
            EthernetAddress([0; 6]),
            EthernetAddress([0; 6]),
        )
        .unwrap();
        let original = ethernet_ip_payload(&frame).unwrap();

        assert!(!valid_packet_too_big_mtu(original, 0));
        assert!(!valid_packet_too_big_mtu(original, 1279));
        assert!(valid_packet_too_big_mtu(original, 1280));
    }

    #[test]
    fn pmtu_context_prefers_packet_larger_than_reported_mtu() {
        let small = Bytes::from(build_ipv4_udp_packet_for_test(100));
        let large = Bytes::from(build_ipv4_udp_packet_for_test(1400));
        let mut contexts = VecDeque::from([small.clone(), large.clone()]);

        let selected = take_pmtu_context(&mut contexts, 1280).unwrap();
        assert_eq!(selected, large);
        assert_eq!(contexts.pop_front().unwrap(), small);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_extended_error_control_message_without_pointer_walk() {
        let mut error = vec![0u8; std::mem::size_of::<libc::sock_extended_err>()];
        write_native_u32_for_test(&mut error, libc::EMSGSIZE as u32);
        error[4] = libc::SO_EE_ORIGIN_ICMP;
        write_native_u32_for_test(&mut error[8..], 1280);

        let mut control = Vec::new();
        push_control_message_for_test(&mut control, libc::IPPROTO_IP, libc::IP_RECVERR, &error);

        assert_eq!(parse_pmtu_from_control_messages(&control), Some(1280));
        assert_eq!(parse_pmtu_from_control_messages(&control[..8]), None);
    }

    fn build_ipv4_udp_packet_for_test(payload_len: usize) -> Vec<u8> {
        let payload = vec![0u8; payload_len];
        let udp_len = UDP_HDR_LEN + payload.len();
        let ip_total_len = IPV4_HDR_LEN + udp_len;
        let mut packet = vec![0u8; ip_total_len];

        {
            let mut ip = Ipv4Packet::new_unchecked(&mut packet);
            ip.set_version(4);
            ip.set_header_len(IPV4_HDR_LEN as u8);
            ip.set_total_len(ip_total_len as u16);
            ip.clear_flags();
            ip.set_hop_limit(64);
            ip.set_next_header(IpProtocol::Udp);
            ip.set_src_addr(Ipv4Addr::new(100, 96, 0, 2));
            ip.set_dst_addr(Ipv4Addr::new(203, 0, 113, 10));
            ip.fill_checksum();
        }

        let mut udp = UdpPacket::new_unchecked(&mut packet[IPV4_HDR_LEN..]);
        udp.set_src_port(12345);
        udp.set_dst_port(443);
        udp.set_len(udp_len as u16);
        udp.payload_mut().copy_from_slice(&payload);

        packet
    }

    #[cfg(target_os = "linux")]
    fn push_control_message_for_test(
        control: &mut Vec<u8>,
        level: libc::c_int,
        message_type: libc::c_int,
        data: &[u8],
    ) {
        let header_len = std::mem::size_of::<libc::cmsghdr>();
        let data_offset = cmsg_align(header_len).unwrap();
        let cmsg_len = data_offset + data.len();
        let aligned_len = cmsg_align(cmsg_len).unwrap();
        let start = control.len();
        control.resize(start + aligned_len, 0);

        write_native_usize_for_test(&mut control[start..], cmsg_len);
        write_native_c_int_for_test(&mut control[start + std::mem::size_of::<usize>()..], level);
        write_native_c_int_for_test(
            &mut control
                [start + std::mem::size_of::<usize>() + std::mem::size_of::<libc::c_int>()..],
            message_type,
        );
        control[start + data_offset..start + data_offset + data.len()].copy_from_slice(data);
    }

    #[cfg(target_os = "linux")]
    fn write_native_usize_for_test(bytes: &mut [u8], value: usize) {
        match std::mem::size_of::<usize>() {
            4 => bytes[..4].copy_from_slice(&(value as u32).to_ne_bytes()),
            8 => bytes[..8].copy_from_slice(&(value as u64).to_ne_bytes()),
            _ => unreachable!("unsupported size_t width"),
        }
    }

    #[cfg(target_os = "linux")]
    fn write_native_c_int_for_test(bytes: &mut [u8], value: libc::c_int) {
        match std::mem::size_of::<libc::c_int>() {
            4 => bytes[..4].copy_from_slice(&(value as i32).to_ne_bytes()),
            _ => unreachable!("unsupported c_int width"),
        }
    }

    #[cfg(target_os = "linux")]
    fn write_native_u32_for_test(bytes: &mut [u8], value: u32) {
        bytes[..4].copy_from_slice(&value.to_ne_bytes());
    }
}
