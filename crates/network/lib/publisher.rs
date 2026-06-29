//! Published port handling: host-side listeners that forward connections
//! into the guest VM via smoltcp.
//!
//! For each configured [`PublishedPort`], a tokio TCP listener or UDP socket
//! binds on the host. TCP connections are queued for the poll loop to create
//! smoltcp sockets into the guest. UDP datagrams are injected as guest-visible
//! packets, and guest replies to active peers are sent back through the same
//! host socket.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex;
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::{EthernetAddress, IpEndpoint};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::config::{PortProtocol, PublishedPort};
use crate::policy::{NetworkPolicy, Protocol};
use crate::shared::SharedState;
use crate::udp_relay::{construct_udp_response, extract_udp_payload};

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

/// Set zero-linger on a stream so the kernel sends a TCP RST instead of
/// the default FIN close when the stream drops. Used for deliberate
/// rejection paths (policy deny, max-inbound exhaustion,
/// smoltcp-connect failure) so the peer sees `ECONNRESET` rather than
/// a graceful close that looks like the server simply went away.
///
/// Goes through `socket2` rather than tokio's deprecated
/// `TcpStream::set_linger` so the call site doesn't trip
/// `#[deny(deprecated)]` in clippy. The cast to `SockRef` is
/// zero-cost — it borrows the underlying fd.
fn reject_with_rst(stream: &TcpStream) {
    let _ = socket2::SockRef::from(stream).set_linger(Some(Duration::ZERO));
}

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// TCP socket buffer sizes for inbound connections.
const TCP_RX_BUF_SIZE: usize = 65536;
const TCP_TX_BUF_SIZE: usize = 65536;

/// Channel capacity for relay tasks.
const CHANNEL_CAPACITY: usize = 32;

/// Buffer size for reading from host sockets.
const RELAY_BUF_SIZE: usize = 16384;

/// Buffer size for host-side UDP published-port sockets.
const UDP_RELAY_BUF_SIZE: usize = 65535;

/// Idle timeout for UDP peers that have contacted a published port.
const UDP_PEER_TIMEOUT: Duration = Duration::from_secs(60);

/// First ephemeral source port used to represent host UDP peers inside the guest.
const UDP_EPHEMERAL_PORT_START: u16 = 49152;

/// Number of usable ephemeral ports from [`UDP_EPHEMERAL_PORT_START`] through `u16::MAX`.
const UDP_EPHEMERAL_PORT_COUNT: usize =
    (u16::MAX as usize) - (UDP_EPHEMERAL_PORT_START as usize) + 1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Manages published port listeners and inbound connections.
///
/// Spawns tokio listeners for each published port. When connections arrive,
/// they are queued for the poll loop to create smoltcp sockets and initiate
/// connections to the guest.
pub struct PortPublisher {
    /// Receives accepted connections from listener tasks.
    inbound_rx: mpsc::Receiver<InboundConnection>,
    /// Held to keep the channel open (listener tasks hold clones).
    _inbound_tx: mpsc::Sender<InboundConnection>,
    /// Tracked inbound connections (smoltcp socket → relay state).
    connections: Vec<InboundRelay>,
    /// Guest IP that inbound connections are dialed to. Prefers IPv4 (the
    /// common case — most services bind `0.0.0.0` or dual-stack `::`, both
    /// of which accept v4) and falls back to IPv6 for v6-only sandboxes.
    /// `None` when neither family is active; listeners are not spawned.
    guest_ip: Option<IpAddr>,
    /// Guest IPv4, when active.
    guest_ipv4: Option<Ipv4Addr>,
    /// Guest IPv6, when active.
    guest_ipv6: Option<Ipv6Addr>,
    /// Ephemeral port counter.
    ephemeral_port: Arc<AtomicU16>,
    /// Maximum inbound connections (prevents resource exhaustion from host-side floods).
    max_inbound: usize,
    /// UDP published-port routes, keyed by guest-side port.
    udp_routes: PublishedUdpRoutes,
}

/// An accepted host-side connection waiting to be wired to the guest.
struct InboundConnection {
    /// The accepted host-side TCP stream.
    stream: TcpStream,
    /// Guest port to connect to.
    guest_port: u16,
}

/// Shared UDP published-port route table.
type PublishedUdpRoutes = Arc<Mutex<HashMap<u16, Vec<PublishedUdpRoute>>>>;

/// A host UDP socket that can send replies for active peers.
struct PublishedUdpRoute {
    /// Host bind address for diagnostics.
    bind_addr: SocketAddr,
    /// Send guest reply payloads to the UDP listener task.
    outbound_tx: mpsc::Sender<PublishedUdpOutbound>,
    /// NAT mappings for peers that recently sent datagrams to this published port.
    peers: Arc<Mutex<PublishedUdpPeers>>,
}

/// Guest response payload for a host peer.
struct PublishedUdpOutbound {
    peer: SocketAddr,
    payload: Bytes,
}

/// Active UDP peer NAT mappings for one published route.
#[derive(Default)]
struct PublishedUdpPeers {
    host_to_guest: HashMap<SocketAddr, PublishedUdpPeer>,
    guest_to_host: HashMap<SocketAddr, SocketAddr>,
}

/// One host peer as represented on the guest-side virtual network.
struct PublishedUdpPeer {
    guest_addr: SocketAddr,
    last_seen: Instant,
}

/// Maximum number of poll iterations to attempt flushing remaining data
/// after the relay task has exited before force-aborting the socket.
const DEFERRED_CLOSE_LIMIT: u16 = 64;

/// A single inbound connection relay (host socket ↔ smoltcp socket).
struct InboundRelay {
    handle: SocketHandle,
    /// Send data from smoltcp socket to host relay task.
    to_host: mpsc::Sender<Bytes>,
    /// Receive data from host relay task to write to smoltcp socket.
    from_host: mpsc::Receiver<Bytes>,
    /// Partial data that couldn't be fully written to smoltcp socket.
    write_buf: Option<(Bytes, usize)>,
    /// Counter for deferred close attempts (prevents stalling forever).
    close_attempts: u16,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
enum BindExposure {
    /// Listener is reachable only through host loopback.
    Loopback,
    /// Listener is reachable through every host interface in that address family.
    Wildcard,
    /// Listener is reachable through one non-loopback host interface address.
    Interface,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PortPublisher {
    /// Create a new publisher and spawn listeners for all published ports.
    ///
    /// Listeners are only spawned when at least one of `guest_ipv4` /
    /// `guest_ipv6` is `Some`; published ports need a smoltcp dial target.
    /// Each TCP listener task gates accepted connections through the
    /// supplied [`NetworkPolicy`]'s `evaluate_ingress` before queuing
    /// them; rejected connections drop with TCP RST (zero-linger) so
    /// the peer observes `ECONNRESET`.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        ports: &[PublishedPort],
        guest_ipv4: Option<Ipv4Addr>,
        guest_ipv6: Option<Ipv6Addr>,
        gateway_ipv4: Option<Ipv4Addr>,
        gateway_ipv6: Option<Ipv6Addr>,
        gateway_mac: [u8; 6],
        guest_mac: [u8; 6],
        policy: Arc<NetworkPolicy>,
        shared: Arc<SharedState>,
        tokio_handle: &tokio::runtime::Handle,
    ) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(64);
        let udp_routes = Arc::new(Mutex::new(HashMap::new()));
        let ephemeral_port = Arc::new(AtomicU16::new(49152));

        let guest_ip = guest_ipv4
            .map(IpAddr::V4)
            .or_else(|| guest_ipv6.map(IpAddr::V6));

        if guest_ip.is_some() {
            Self::spawn_listeners(
                ports,
                &inbound_tx,
                udp_routes.clone(),
                guest_ipv4,
                guest_ipv6,
                gateway_ipv4,
                gateway_ipv6,
                ephemeral_port.clone(),
                gateway_mac,
                guest_mac,
                policy,
                shared,
                tokio_handle,
            );
        } else if !ports.is_empty() {
            tracing::warn!(
                count = ports.len(),
                "skipping published port listeners: guest has no IPv4 or IPv6 address",
            );
        }

        Self {
            inbound_rx,
            _inbound_tx: inbound_tx,
            connections: Vec::new(),
            guest_ip,
            guest_ipv4,
            guest_ipv6,
            ephemeral_port,
            max_inbound: 256,
            udp_routes,
        }
    }

    /// Accept queued inbound connections: create smoltcp sockets and
    /// initiate connections to the guest.
    ///
    /// Must be called each poll iteration.
    pub fn accept_inbound(
        &mut self,
        iface: &mut Interface,
        sockets: &mut SocketSet<'_>,
        shared: &Arc<SharedState>,
        tokio_handle: &tokio::runtime::Handle,
    ) {
        // No guest IP means listeners weren't spawned; the channel is empty
        // and there's nothing to do.
        let Some(guest_ip) = self.guest_ip else {
            return;
        };

        while let Ok(conn) = self.inbound_rx.try_recv() {
            if self.connections.len() >= self.max_inbound {
                tracing::debug!("published port: max inbound connections reached, rejecting");
                reject_with_rst(&conn.stream);
                continue;
            }
            // Create smoltcp TCP socket.
            let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_SIZE]);
            let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_SIZE]);
            let mut socket = tcp::Socket::new(rx_buf, tx_buf);

            // Connect to the guest.
            let remote = IpEndpoint::new(guest_ip.into(), conn.guest_port);
            let local_port = self.alloc_ephemeral_port();

            if socket.connect(iface.context(), remote, local_port).is_err() {
                tracing::debug!(
                    guest_port = conn.guest_port,
                    "failed to connect smoltcp socket to guest",
                );
                reject_with_rst(&conn.stream);
                continue;
            }

            let handle = sockets.add(socket);

            // Create channel pair for relay.
            let (to_host_tx, to_host_rx) = mpsc::channel(CHANNEL_CAPACITY);
            let (from_host_tx, from_host_rx) = mpsc::channel(CHANNEL_CAPACITY);

            // Spawn relay task: host TcpStream ↔ channels.
            let shared_clone = shared.clone();
            tokio_handle.spawn(async move {
                let _ =
                    inbound_relay_task(conn.stream, to_host_rx, from_host_tx, shared_clone).await;
            });

            self.connections.push(InboundRelay {
                handle,
                to_host: to_host_tx,
                from_host: from_host_rx,
                write_buf: None,
                close_attempts: 0,
            });
        }
    }

    /// Relay data between smoltcp sockets and host relay tasks.
    pub fn relay_data(&mut self, sockets: &mut SocketSet<'_>) {
        let mut relay_buf = [0u8; RELAY_BUF_SIZE];

        for relay in &mut self.connections {
            let socket = sockets.get_mut::<tcp::Socket>(relay.handle);

            // Detect relay task exit — close the smoltcp socket.
            if relay.to_host.is_closed() {
                write_host_data(socket, relay);
                if relay.write_buf.is_none() {
                    socket.close();
                } else {
                    // Abort if we've been trying to flush for too long
                    // (guest stopped reading, socket send buffer full).
                    relay.close_attempts += 1;
                    if relay.close_attempts >= DEFERRED_CLOSE_LIMIT {
                        socket.abort();
                    }
                }
                continue;
            }

            // smoltcp → host: read from socket, send via channel.
            while socket.can_recv() {
                match socket.recv_slice(&mut relay_buf) {
                    Ok(n) if n > 0 => {
                        let data = Bytes::copy_from_slice(&relay_buf[..n]);
                        if relay.to_host.try_send(data).is_err() {
                            break;
                        }
                    }
                    _ => break,
                }
            }

            // host → smoltcp: write pending data, then drain channel.
            write_host_data(socket, relay);
        }
    }

    /// Relay a guest UDP datagram to a host peer that recently sent traffic
    /// to a UDP published port.
    ///
    /// Returns `true` when the frame belongs to a published-port flow and
    /// should be consumed by the caller.
    pub fn relay_udp_outbound(&self, frame: &[u8], src: SocketAddr, dst: SocketAddr) -> bool {
        if !self.is_guest_ip(src.ip()) {
            return false;
        }

        let Some(payload) = extract_udp_payload(frame) else {
            return false;
        };

        let routes = self.udp_routes.lock();
        let Some(routes) = routes.get(&src.port()) else {
            return false;
        };

        let now = Instant::now();
        for route in routes {
            let mut peers = route.peers.lock();
            cleanup_udp_peer_mappings(&mut peers, now);
            let Some(peer) = peers.guest_to_host.get(&dst).copied() else {
                continue;
            };
            drop(peers);

            let outbound = PublishedUdpOutbound {
                peer,
                payload: Bytes::copy_from_slice(payload),
            };
            if route.outbound_tx.try_send(outbound).is_err() {
                tracing::debug!(
                    bind = %route.bind_addr,
                    peer = %peer,
                    "published UDP reply dropped because outbound queue is unavailable",
                );
            }
            return true;
        }

        false
    }

    /// Remove closed inbound connections.
    ///
    /// Only removes sockets in `Closed` state. Sockets in `TimeWait` are
    /// left for smoltcp's 2*MSL timer to handle naturally.
    pub fn cleanup_closed(&mut self, sockets: &mut SocketSet<'_>) {
        self.connections.retain(|relay| {
            let socket = sockets.get::<tcp::Socket>(relay.handle);
            let closed = matches!(socket.state(), tcp::State::Closed);
            if closed {
                sockets.remove(relay.handle);
            }
            !closed
        });
        self.cleanup_udp_peers();
    }

    /// Spawn one tokio listener task per TCP published port.
    #[allow(clippy::too_many_arguments)]
    fn spawn_listeners(
        ports: &[PublishedPort],
        inbound_tx: &mpsc::Sender<InboundConnection>,
        udp_routes: PublishedUdpRoutes,
        guest_ipv4: Option<Ipv4Addr>,
        guest_ipv6: Option<Ipv6Addr>,
        gateway_ipv4: Option<Ipv4Addr>,
        gateway_ipv6: Option<Ipv6Addr>,
        ephemeral_port: Arc<AtomicU16>,
        gateway_mac: [u8; 6],
        guest_mac: [u8; 6],
        policy: Arc<NetworkPolicy>,
        shared: Arc<SharedState>,
        tokio_handle: &tokio::runtime::Handle,
    ) {
        for port in ports {
            let bind_addr = SocketAddr::new(port.host_bind, port.host_port);
            let guest_port = port.guest_port;

            match port.protocol {
                PortProtocol::Tcp => {
                    let tx = inbound_tx.clone();
                    let policy = policy.clone();
                    let shared = shared.clone();
                    tokio_handle.spawn(async move {
                        if let Err(e) =
                            tcp_listener_task(bind_addr, guest_port, tx, policy, shared).await
                        {
                            tracing::error!(
                                bind = %bind_addr,
                                error = %e,
                                "published TCP port listener failed",
                            );
                        }
                    });
                }
                PortProtocol::Udp => {
                    let Some((guest_ip, gateway_ip)) = udp_ips_for_bind(
                        port.host_bind,
                        guest_ipv4,
                        guest_ipv6,
                        gateway_ipv4,
                        gateway_ipv6,
                    ) else {
                        tracing::warn!(
                            bind = %bind_addr,
                            guest_port,
                            "skipping UDP published port: guest has no matching gateway/guest IP family",
                        );
                        continue;
                    };

                    let (outbound_tx, outbound_rx) = mpsc::channel(CHANNEL_CAPACITY);
                    let peers = Arc::new(Mutex::new(PublishedUdpPeers::default()));
                    udp_routes
                        .lock()
                        .entry(guest_port)
                        .or_default()
                        .push(PublishedUdpRoute {
                            bind_addr,
                            outbound_tx,
                            peers: peers.clone(),
                        });

                    let policy = policy.clone();
                    let shared = shared.clone();
                    let ephemeral_port = ephemeral_port.clone();
                    tokio_handle.spawn(async move {
                        if let Err(e) = udp_listener_task(
                            bind_addr,
                            guest_ip,
                            gateway_ip,
                            guest_port,
                            outbound_rx,
                            peers,
                            ephemeral_port.clone(),
                            policy,
                            shared,
                            EthernetAddress(gateway_mac),
                            EthernetAddress(guest_mac),
                        )
                        .await
                        {
                            tracing::error!(
                                bind = %bind_addr,
                                error = %e,
                                "published UDP port listener failed",
                            );
                        }
                    });
                }
            }
        }
    }

    fn alloc_ephemeral_port(&self) -> u16 {
        loop {
            let port = self.ephemeral_port.fetch_add(1, Ordering::Relaxed);
            // Wrap around in the ephemeral range.
            if port == 0 || port < UDP_EPHEMERAL_PORT_START {
                self.ephemeral_port
                    .store(UDP_EPHEMERAL_PORT_START, Ordering::Relaxed);
                continue;
            }
            return port;
        }
    }

    fn cleanup_udp_peers(&self) {
        let now = Instant::now();
        for routes in self.udp_routes.lock().values() {
            for route in routes {
                cleanup_udp_peer_mappings(&mut route.peers.lock(), now);
            }
        }
    }

    fn is_guest_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ip) => self.guest_ipv4 == Some(ip),
            IpAddr::V6(ip) => self.guest_ipv6 == Some(ip),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Listener task: accepts TCP connections on the host, runs each
/// through the network policy's ingress evaluator, and queues
/// allowed connections for the publisher's accept loop. Denied
/// connections are dropped with TCP RST (zero-linger) so the peer
/// sees `ECONNRESET` rather than a graceful close.
async fn tcp_listener_task(
    bind_addr: SocketAddr,
    guest_port: u16,
    inbound_tx: mpsc::Sender<InboundConnection>,
    policy: Arc<NetworkPolicy>,
    shared: Arc<SharedState>,
) -> std::io::Result<()> {
    let listener = TcpListener::bind(bind_addr).await?;
    log_published_port_listener("TCP", bind_addr, guest_port);

    loop {
        let (stream, peer) = listener.accept().await?;

        // Policy gate: peer source IP and the guest's listening port.
        let action = policy.evaluate_ingress(peer, guest_port, Protocol::Tcp, &shared);
        if action.is_deny() {
            tracing::debug!(
                peer = %peer,
                guest_port,
                "ingress denied by policy; sending RST",
            );
            reject_with_rst(&stream);
            drop(stream);
            continue;
        }

        let conn = InboundConnection { stream, guest_port };
        if !queue_inbound_connection(&inbound_tx, conn, &shared).await {
            break; // Publisher dropped.
        }
    }

    Ok(())
}

/// UDP listener task: receives host datagrams, injects them into the guest,
/// and sends guest replies back to active peers through the same socket.
#[allow(clippy::too_many_arguments)]
async fn udp_listener_task(
    bind_addr: SocketAddr,
    guest_ip: IpAddr,
    gateway_ip: IpAddr,
    guest_port: u16,
    mut outbound_rx: mpsc::Receiver<PublishedUdpOutbound>,
    peers: Arc<Mutex<PublishedUdpPeers>>,
    ephemeral_port: Arc<AtomicU16>,
    policy: Arc<NetworkPolicy>,
    shared: Arc<SharedState>,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) -> std::io::Result<()> {
    let socket = UdpSocket::bind(bind_addr).await?;
    log_published_port_listener("UDP", bind_addr, guest_port);

    let mut buf = vec![0u8; UDP_RELAY_BUF_SIZE];
    loop {
        tokio::select! {
            inbound = socket.recv_from(&mut buf) => {
                let (n, peer) = inbound?;
                let action = policy.evaluate_ingress(peer, guest_port, Protocol::Udp, &shared);
                if action.is_deny() {
                    tracing::debug!(
                        peer = %peer,
                        guest_port,
                        "UDP ingress denied by policy",
                    );
                    continue;
                }

                let Some(guest_peer) =
                    resolve_udp_guest_peer(peer, gateway_ip, &peers, &ephemeral_port)
                else {
                    tracing::debug!(
                        peer = %peer,
                        guest_port,
                        "UDP ingress dropped because published-port peer table is full",
                    );
                    continue;
                };
                inject_udp_datagram_to_guest(
                    guest_peer,
                    SocketAddr::new(guest_ip, guest_port),
                    &buf[..n],
                    &shared,
                    gateway_mac,
                    guest_mac,
                );
            }
            outbound = outbound_rx.recv() => {
                let Some(outbound) = outbound else {
                    break;
                };
                if let Err(e) = socket.send_to(&outbound.payload, outbound.peer).await {
                    tracing::debug!(
                        peer = %outbound.peer,
                        error = %e,
                        "published UDP send to host peer failed",
                    );
                }
            }
        }
    }

    Ok(())
}

fn log_published_port_listener(protocol: &'static str, bind_addr: SocketAddr, guest_port: u16) {
    match bind_exposure(bind_addr.ip()) {
        BindExposure::Loopback => {
            tracing::debug!(
                protocol,
                bind = %bind_addr,
                guest_port,
                "published port listener started on host loopback",
            );
        }
        BindExposure::Wildcard => {
            tracing::warn!(
                protocol,
                bind = %bind_addr,
                guest_port,
                windows_firewall_prompt = cfg!(windows),
                "published port is listening on all host interfaces",
            );
        }
        BindExposure::Interface => {
            tracing::warn!(
                protocol,
                bind = %bind_addr,
                guest_port,
                windows_firewall_prompt = cfg!(windows),
                "published port is listening on a non-loopback host interface",
            );
        }
    }
}

fn bind_exposure(ip: IpAddr) -> BindExposure {
    if ip.is_loopback() {
        BindExposure::Loopback
    } else if ip.is_unspecified() {
        BindExposure::Wildcard
    } else {
        BindExposure::Interface
    }
}

async fn queue_inbound_connection<T>(
    inbound_tx: &mpsc::Sender<T>,
    conn: T,
    shared: &SharedState,
) -> bool {
    if inbound_tx.send(conn).await.is_err() {
        return false;
    }

    shared.proxy_wake.wake();
    true
}

fn udp_ips_for_bind(
    host_bind: IpAddr,
    guest_ipv4: Option<Ipv4Addr>,
    guest_ipv6: Option<Ipv6Addr>,
    gateway_ipv4: Option<Ipv4Addr>,
    gateway_ipv6: Option<Ipv6Addr>,
) -> Option<(IpAddr, IpAddr)> {
    match host_bind {
        IpAddr::V4(_) => Some((IpAddr::V4(guest_ipv4?), IpAddr::V4(gateway_ipv4?))),
        IpAddr::V6(_) => Some((IpAddr::V6(guest_ipv6?), IpAddr::V6(gateway_ipv6?))),
    }
}

fn resolve_udp_guest_peer(
    host_peer: SocketAddr,
    gateway_ip: IpAddr,
    peers: &Arc<Mutex<PublishedUdpPeers>>,
    ephemeral_port: &AtomicU16,
) -> Option<SocketAddr> {
    let now = Instant::now();
    let mut peers = peers.lock();
    cleanup_udp_peer_mappings(&mut peers, now);

    if let Some(peer) = peers.host_to_guest.get_mut(&host_peer) {
        peer.last_seen = now;
        return Some(peer.guest_addr);
    }

    let guest_addr = (0..UDP_EPHEMERAL_PORT_COUNT).find_map(|_| {
        let candidate = SocketAddr::new(gateway_ip, next_ephemeral_port(ephemeral_port));
        if !peers.guest_to_host.contains_key(&candidate) {
            Some(candidate)
        } else {
            None
        }
    })?;

    peers.host_to_guest.insert(
        host_peer,
        PublishedUdpPeer {
            guest_addr,
            last_seen: now,
        },
    );
    peers.guest_to_host.insert(guest_addr, host_peer);
    Some(guest_addr)
}

fn cleanup_udp_peer_mappings(peers: &mut PublishedUdpPeers, now: Instant) {
    peers
        .host_to_guest
        .retain(|_, peer| now.duration_since(peer.last_seen) <= UDP_PEER_TIMEOUT);
    let host_to_guest = &peers.host_to_guest;
    peers
        .guest_to_host
        .retain(|_, host_peer| host_to_guest.contains_key(host_peer));
}

fn next_ephemeral_port(ephemeral_port: &AtomicU16) -> u16 {
    loop {
        let port = ephemeral_port.fetch_add(1, Ordering::Relaxed);
        if port == 0 || port < UDP_EPHEMERAL_PORT_START {
            ephemeral_port.store(UDP_EPHEMERAL_PORT_START, Ordering::Relaxed);
            continue;
        }
        return port;
    }
}

fn inject_udp_datagram_to_guest(
    peer: SocketAddr,
    guest_dst: SocketAddr,
    payload: &[u8],
    shared: &SharedState,
    gateway_mac: EthernetAddress,
    guest_mac: EthernetAddress,
) {
    let Some(frame) = construct_udp_response(peer, guest_dst, payload, gateway_mac, guest_mac)
    else {
        tracing::debug!(
            peer = %peer,
            guest = %guest_dst,
            "published UDP datagram dropped because address families differ",
        );
        return;
    };

    if !shared.push_rx_frame_and_wake(frame) {
        tracing::debug!("published UDP datagram dropped because rx_ring is full");
    }
}

/// Relay task: bridges a host TcpStream to channels connected to smoltcp.
async fn inbound_relay_task(
    stream: TcpStream,
    mut to_host_rx: mpsc::Receiver<Bytes>,
    from_host_tx: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
) -> std::io::Result<()> {
    let (mut rx, mut tx) = stream.into_split();
    let mut buf = vec![0u8; RELAY_BUF_SIZE];

    loop {
        tokio::select! {
            // smoltcp → host: data from guest arrives via channel.
            data = to_host_rx.recv() => {
                match data {
                    Some(bytes) => {
                        // Wake as soon as recv frees channel capacity. Waiting
                        // for write_all can stall the poll loop behind a slow
                        // host client.
                        shared.proxy_wake.wake();
                        if let Err(e) = tx.write_all(&bytes).await {
                            tracing::debug!(error = %e, "write to host client failed");
                            break;
                        }
                    }
                    None => break,
                }
            }

            // host → smoltcp: data from host client to write to guest.
            result = rx.read(&mut buf) => {
                match result {
                    Ok(0) => break,
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&buf[..n]);
                        if from_host_tx.send(data).await.is_err() {
                            break;
                        }
                        shared.proxy_wake.wake();
                    }
                    Err(e) => {
                        tracing::debug!(error = %e, "read from host client failed");
                        break;
                    }
                }
            }
        }
    }

    Ok(())
}

/// Write data from the host relay channel to the smoltcp socket.
fn write_host_data(socket: &mut tcp::Socket<'_>, relay: &mut InboundRelay) {
    // First, try to finish writing any pending partial data.
    if let Some((data, offset)) = &mut relay.write_buf {
        if socket.can_send() {
            match socket.send_slice(&data[*offset..]) {
                Ok(written) => {
                    *offset += written;
                    if *offset >= data.len() {
                        relay.write_buf = None;
                    }
                }
                Err(_) => return,
            }
        } else {
            return;
        }
    }

    // Then drain the channel.
    while relay.write_buf.is_none() {
        match relay.from_host.try_recv() {
            Ok(data) => {
                if socket.can_send() {
                    match socket.send_slice(&data) {
                        Ok(written) if written < data.len() => {
                            relay.write_buf = Some((data, written));
                        }
                        Err(_) => {
                            relay.write_buf = Some((data, 0));
                        }
                        _ => {}
                    }
                } else {
                    relay.write_buf = Some((data, 0));
                }
            }
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn queue_inbound_connection_wakes_poll_loop() {
        let shared = SharedState::new(4);
        shared.proxy_wake.drain();

        let (tx, mut rx) = mpsc::channel(1);

        assert!(queue_inbound_connection(&tx, (), &shared).await);
        assert!(rx.try_recv().is_ok());
        assert!(shared.proxy_wake.wait_timeout(Duration::ZERO));
    }

    #[tokio::test]
    async fn inbound_relay_wakes_when_to_host_channel_slot_is_freed() {
        let shared = Arc::new(SharedState::new(4));
        shared.proxy_wake.drain();

        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let client = tokio::spawn(TcpStream::connect(addr));
        let (server_stream, _) = listener.accept().await.unwrap();
        let client = client.await.unwrap().unwrap();

        socket2::SockRef::from(&server_stream)
            .set_send_buffer_size(4096)
            .unwrap();

        let (to_host_tx, to_host_rx) = mpsc::channel(1);
        let (from_host_tx, _from_host_rx) = mpsc::channel(1);
        let task = tokio::spawn(inbound_relay_task(
            server_stream,
            to_host_rx,
            from_host_tx,
            shared.clone(),
        ));

        to_host_tx
            .send(Bytes::from(vec![b'a'; 64 * 1024 * 1024]))
            .await
            .unwrap();

        tokio::time::timeout(
            Duration::from_secs(1),
            to_host_tx.send(Bytes::from_static(b"next")),
        )
        .await
        .unwrap()
        .unwrap();

        assert!(shared.proxy_wake.wait_timeout(Duration::ZERO));

        drop(client);
        drop(to_host_tx);
        task.abort();
        let _ = task.await;
    }

    #[test]
    fn inject_udp_datagram_to_guest_counts_rx_bytes() {
        let shared = SharedState::new(4);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 50000);
        let guest = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 2)), 5353);

        inject_udp_datagram_to_guest(
            peer,
            guest,
            b"hello",
            &shared,
            EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            EthernetAddress([0x02, 0, 0, 0, 0, 2]),
        );

        let frame = shared.rx_ring.pop().expect("published UDP frame");
        assert_eq!(shared.rx_bytes(), frame.len() as u64);
    }

    #[test]
    fn relay_udp_outbound_queues_reply_for_active_peer() {
        let (inbound_tx, inbound_rx) = mpsc::channel(1);
        let (outbound_tx, mut outbound_rx) = mpsc::channel(1);
        let routes = Arc::new(Mutex::new(HashMap::new()));
        let peers = Arc::new(Mutex::new(PublishedUdpPeers::default()));
        let guest_ip = Ipv4Addr::new(172, 16, 0, 2);
        let host_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50000);
        let guest_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1)), 49152);

        {
            let mut peers = peers.lock();
            peers.host_to_guest.insert(
                host_peer,
                PublishedUdpPeer {
                    guest_addr: guest_peer,
                    last_seen: Instant::now(),
                },
            );
            peers.guest_to_host.insert(guest_peer, host_peer);
        }
        routes.lock().insert(
            5353,
            vec![PublishedUdpRoute {
                bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353),
                outbound_tx,
                peers,
            }],
        );

        let publisher = PortPublisher {
            inbound_rx,
            _inbound_tx: inbound_tx,
            connections: Vec::new(),
            guest_ip: Some(IpAddr::V4(guest_ip)),
            guest_ipv4: Some(guest_ip),
            guest_ipv6: None,
            ephemeral_port: Arc::new(AtomicU16::new(49152)),
            max_inbound: 256,
            udp_routes: routes,
        };
        let src = SocketAddr::new(IpAddr::V4(guest_ip), 5353);
        let frame = construct_udp_response(
            src,
            guest_peer,
            b"pong",
            EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            EthernetAddress([0x02, 0, 0, 0, 0, 2]),
        )
        .unwrap();

        assert!(publisher.relay_udp_outbound(&frame, src, guest_peer));
        let outbound = outbound_rx.try_recv().unwrap();
        assert_eq!(outbound.peer, host_peer);
        assert_eq!(outbound.payload.as_ref(), b"pong");
    }

    #[test]
    fn relay_udp_outbound_ignores_inactive_peer() {
        let (inbound_tx, inbound_rx) = mpsc::channel(1);
        let (outbound_tx, _outbound_rx) = mpsc::channel(1);
        let routes = Arc::new(Mutex::new(HashMap::new()));
        let guest_ip = Ipv4Addr::new(172, 16, 0, 2);
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 50000);

        routes.lock().insert(
            5353,
            vec![PublishedUdpRoute {
                bind_addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 5353),
                outbound_tx,
                peers: Arc::new(Mutex::new(PublishedUdpPeers::default())),
            }],
        );

        let publisher = PortPublisher {
            inbound_rx,
            _inbound_tx: inbound_tx,
            connections: Vec::new(),
            guest_ip: Some(IpAddr::V4(guest_ip)),
            guest_ipv4: Some(guest_ip),
            guest_ipv6: None,
            ephemeral_port: Arc::new(AtomicU16::new(49152)),
            max_inbound: 256,
            udp_routes: routes,
        };
        let src = SocketAddr::new(IpAddr::V4(guest_ip), 5353);
        let frame = construct_udp_response(
            src,
            peer,
            b"pong",
            EthernetAddress([0x02, 0, 0, 0, 0, 1]),
            EthernetAddress([0x02, 0, 0, 0, 0, 2]),
        )
        .unwrap();

        assert!(!publisher.relay_udp_outbound(&frame, src, peer));
    }

    #[test]
    fn resolve_udp_guest_peer_returns_none_when_ephemeral_ports_exhausted() {
        let peers = Arc::new(Mutex::new(PublishedUdpPeers::default()));
        let gateway_ip = IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1));
        let now = Instant::now();

        {
            let mut peers = peers.lock();
            for port in UDP_EPHEMERAL_PORT_START..=u16::MAX {
                let host_peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
                let guest_addr = SocketAddr::new(gateway_ip, port);
                peers.host_to_guest.insert(
                    host_peer,
                    PublishedUdpPeer {
                        guest_addr,
                        last_seen: now,
                    },
                );
                peers.guest_to_host.insert(guest_addr, host_peer);
            }
        }

        let next = resolve_udp_guest_peer(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 40000),
            gateway_ip,
            &peers,
            &AtomicU16::new(UDP_EPHEMERAL_PORT_START),
        );

        assert!(next.is_none());
    }

    #[test]
    fn bind_exposure_keeps_loopback_distinct_from_lan_binds() {
        assert_eq!(
            bind_exposure(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            BindExposure::Loopback
        );
        assert_eq!(
            bind_exposure(IpAddr::V6(Ipv6Addr::LOCALHOST)),
            BindExposure::Loopback
        );
        assert_eq!(
            bind_exposure(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
            BindExposure::Wildcard
        );
        assert_eq!(
            bind_exposure(IpAddr::V6(Ipv6Addr::UNSPECIFIED)),
            BindExposure::Wildcard
        );
        assert_eq!(
            bind_exposure(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10))),
            BindExposure::Interface
        );
    }
}
