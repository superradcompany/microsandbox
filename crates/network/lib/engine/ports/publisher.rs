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
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};
use tokio::sync::mpsc;

use crate::config::{PortProtocol, PublishedPort, TcpAcceptQueueSize};
use crate::netstack::shared::SharedState;
use crate::policy::{NetworkPolicy, Protocol};
use crate::tcp::deferred_close::DeferredClose;
use crate::udp::relay::{construct_udp_response, extract_udp_payload};

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

/// A single inbound connection relay (host socket ↔ smoltcp socket).
struct InboundRelay {
    handle: SocketHandle,
    /// Sends guest data to the host. Dropped after guest FIN and buffered data drain.
    to_host: Option<mpsc::Sender<Bytes>>,
    /// Data removed from smoltcp while the host relay channel was full.
    read_buf: Option<Bytes>,
    /// Receives host data. Sender closure signals host EOF or relay task exit.
    from_host: mpsc::Receiver<Bytes>,
    /// Partial data that couldn't be fully written to smoltcp socket.
    write_buf: Option<(Bytes, usize)>,
    /// Progress deadline while draining after the host task exits.
    deferred_close: DeferredClose,
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
        tcp_accept_queue_size: TcpAcceptQueueSize,
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
                tcp_accept_queue_size,
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
                to_host: Some(to_host_tx),
                read_buf: None,
                from_host: from_host_rx,
                write_buf: None,
                deferred_close: DeferredClose::default(),
            });
        }
    }

    /// Earliest pending drain deadline for the network poll loop.
    pub(crate) fn deferred_close_delay(&self) -> Option<std::time::Duration> {
        self.connections
            .iter()
            .filter_map(|relay| relay.deferred_close.poll_delay())
            .min()
    }

    /// Relay data between smoltcp sockets and host relay tasks.
    pub fn relay_data(&mut self, sockets: &mut SocketSet<'_>) {
        let mut relay_buf = [0u8; RELAY_BUF_SIZE];

        for relay in &mut self.connections {
            let socket = sockets.get_mut::<tcp::Socket>(relay.handle);

            if matches!(socket.state(), tcp::State::Closed) {
                relay.deferred_close = DeferredClose::default();
                continue;
            }

            // Detect relay task exit — close the smoltcp socket.
            let relay_exited = match &relay.to_host {
                Some(to_host) => to_host.is_closed(),
                // After guest FIN, use the remaining channel to detect host EOF or task exit.
                None => relay.from_host.is_closed(),
            };
            if relay_exited {
                let queued_before = socket.send_queue();
                write_host_data(socket, relay);
                let written = socket.send_queue() - queued_before;
                relay
                    .deferred_close
                    .finish(socket, relay.write_buf.is_some(), written);

                continue;
            }

            // smoltcp → host: flush read_buf first, then read from socket.
            if let Some(to_host) = &relay.to_host {
                if let Some(pending) = relay.read_buf.take()
                    && let Err(unsent) = try_send_to_host_relay(to_host, pending)
                {
                    relay.read_buf = Some(unsent);
                }

                if relay.read_buf.is_none() {
                    while socket.can_recv() {
                        match socket.recv_slice(&mut relay_buf) {
                            Ok(n) if n > 0 => {
                                let data = Bytes::copy_from_slice(&relay_buf[..n]);
                                if let Err(unsent) = try_send_to_host_relay(to_host, data) {
                                    relay.read_buf = Some(unsent);
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                }

                // CLOSE-WAIT covers guest-first FIN; the other states cover FIN
                // after the host half-closes. Forward EOF only after draining guest data.
                if matches!(
                    socket.state(),
                    tcp::State::CloseWait
                        | tcp::State::LastAck
                        | tcp::State::Closing
                        | tcp::State::TimeWait
                ) && relay.read_buf.is_none()
                    && !socket.can_recv()
                {
                    relay.to_host = None;
                }
            }

            // host → smoltcp: write pending data, then drain channel.
            write_host_data(socket, relay);

            // Forward host EOF after draining its data and completing the handshake.
            // Closing in SYN-SENT would drop the connection instead of sending FIN.
            if relay.from_host.is_closed()
                && relay.from_host.is_empty()
                && relay.write_buf.is_none()
                && socket.may_send()
            {
                socket.close();
            }
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
        tcp_accept_queue_size: TcpAcceptQueueSize,
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
                        if let Err(e) = tcp_listener_task(
                            bind_addr,
                            tcp_accept_queue_size,
                            guest_port,
                            tx,
                            policy,
                            shared,
                        )
                        .await
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

/// Bind a published port's listener with an explicit accept-queue depth.
///
/// `TcpListener::bind` leaves the backlog to mio, which passes 128. Connections that arrive while
/// the queue is full never reach the accept loop, so a burst larger than the queue -- for example
/// a reverse proxy fanning out one browser's page load of a modern web app -- can surface as
/// failed upstream connections and, behind the proxy, as 502s. That is one possible cause of such
/// failures, not the only one: the publisher's own cap on tracked inbound connections
/// (`max_inbound`) resets connections past it, independently of this queue.
///
/// Goes through `TcpSocket` only so the backlog can be stated; everything else matches
/// `TcpListener::bind`. That includes `SO_REUSEADDR` on Unix, so a listener can be re-created
/// without waiting out `TIME_WAIT`, and deliberately not on Windows, where the option would let
/// another socket bind over a port that is still in use.
fn bind_listener(
    bind_addr: SocketAddr,
    backlog: TcpAcceptQueueSize,
) -> std::io::Result<TcpListener> {
    let socket = if bind_addr.is_ipv4() {
        TcpSocket::new_v4()?
    } else {
        TcpSocket::new_v6()?
    };
    #[cfg(not(windows))]
    socket.set_reuseaddr(true)?;
    socket.bind(bind_addr)?;
    socket.listen(backlog.get())
}

/// Listener task: accepts TCP connections on the host, runs each
/// through the network policy's ingress evaluator, and queues
/// allowed connections for the publisher's accept loop. Denied
/// connections are dropped with TCP RST (zero-linger) so the peer
/// sees `ECONNRESET` rather than a graceful close.
async fn tcp_listener_task(
    bind_addr: SocketAddr,
    backlog: TcpAcceptQueueSize,
    guest_port: u16,
    inbound_tx: mpsc::Sender<InboundConnection>,
    policy: Arc<NetworkPolicy>,
    shared: Arc<SharedState>,
) -> std::io::Result<()> {
    let listener = bind_listener(bind_addr, backlog)?;
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

/// Try to queue guest data for the host relay, returning it when backpressured.
fn try_send_to_host_relay(to_host: &mpsc::Sender<Bytes>, data: Bytes) -> Result<(), Bytes> {
    to_host.try_send(data).map_err(|err| err.into_inner())
}

/// Bridges a host TCP stream to smoltcp channels, closing each direction independently.
async fn inbound_relay_task(
    stream: TcpStream,
    mut to_host_rx: mpsc::Receiver<Bytes>,
    from_host_tx: mpsc::Sender<Bytes>,
    shared: Arc<SharedState>,
) -> std::io::Result<()> {
    let (mut rx, mut tx) = stream.into_split();
    let mut buf = vec![0u8; RELAY_BUF_SIZE];
    let mut from_host_tx = Some(from_host_tx);
    let mut guest_eof = false;

    loop {
        tokio::select! {
            // smoltcp → host: data from guest arrives via channel.
            data = to_host_rx.recv(), if !guest_eof => {
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
                    None => {
                        guest_eof = true;
                        if tx.shutdown().await.is_err() || from_host_tx.is_none() {
                            break;
                        }
                    }
                }
            }

            // host → smoltcp: data from host client to write to guest.
            result = rx.read(&mut buf), if from_host_tx.is_some() => {
                match result {
                    Ok(0) => {
                        from_host_tx = None;
                        shared.proxy_wake.wake();
                        if guest_eof {
                            break;
                        }
                    }
                    Ok(n) => {
                        let data = Bytes::copy_from_slice(&buf[..n]);
                        let Some(from_host_tx) = &from_host_tx else {
                            break;
                        };
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

            // The poll loop dropped the relay (e.g. guest reset), so the
            // guest connection is gone. Stop waiting on an idle host.
            _ = async { from_host_tx.as_ref().unwrap().closed().await }, if from_host_tx.is_some() => {
                break;
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use smoltcp::iface::Config;
    use smoltcp::phy::{Loopback, Medium};
    use smoltcp::time::{Duration as SmolDuration, Instant as SmolInstant};
    use smoltcp::wire::{IpAddress, IpCidr};

    use super::*;

    const TEST_GUEST_PORT: u16 = 8080;

    /// Simulated time each harness step advances the smoltcp clock.
    const STEP_MILLIS: u64 = 50;

    /// Step budget for data and EOF to cross the relay: 5 s of simulated
    /// time, below smoltcp's 10 s TIME-WAIT. A FIN that only reaches the
    /// host once TIME-WAIT expires and the relay is dropped must fail.
    const PROMPT_STEPS: usize = 100;

    /// Step budget for relay cleanup, which may wait out TIME-WAIT.
    const CLEANUP_STEPS: usize = 2000;

    /// Exercises the real relay with a loopback smoltcp guest and a host TCP client.
    struct Harness {
        device: Loopback,
        iface: Interface,
        sockets: SocketSet<'static>,
        publisher: PortPublisher,
        guest: SocketHandle,
        shared: Arc<SharedState>,
        now: SmolInstant,
    }

    impl Harness {
        fn new() -> Self {
            let mut device = Loopback::new(Medium::Ethernet);
            let config = Config::new(EthernetAddress([0x02, 0, 0, 0, 0, 1]).into());
            let mut iface = Interface::new(config, &mut device, SmolInstant::from_millis(0));
            iface.update_ip_addrs(|addrs| {
                addrs
                    .push(IpCidr::new(IpAddress::v4(127, 0, 0, 1), 8))
                    .unwrap();
            });

            let mut sockets = SocketSet::new(vec![]);
            let mut guest = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_SIZE]),
                tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_SIZE]),
            );
            guest.listen(TEST_GUEST_PORT).unwrap();
            let guest = sockets.add(guest);

            let (inbound_tx, inbound_rx) = mpsc::channel(1);
            let publisher = PortPublisher {
                inbound_rx,
                _inbound_tx: inbound_tx,
                connections: Vec::new(),
                guest_ip: Some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
                guest_ipv4: Some(Ipv4Addr::LOCALHOST),
                guest_ipv6: None,
                ephemeral_port: Arc::new(AtomicU16::new(UDP_EPHEMERAL_PORT_START)),
                max_inbound: 256,
                udp_routes: Arc::new(Mutex::new(HashMap::new())),
            };

            Self {
                device,
                iface,
                sockets,
                publisher,
                guest,
                shared: Arc::new(SharedState::new(4)),
                now: SmolInstant::from_millis(0),
            }
        }

        /// Queues a connection for the publisher and returns the host client end.
        async fn connect_host(&mut self) -> TcpStream {
            let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
                .await
                .unwrap();
            let client = TcpStream::connect(listener.local_addr().unwrap())
                .await
                .unwrap();
            let (stream, _) = listener.accept().await.unwrap();
            self.publisher
                ._inbound_tx
                .try_send(InboundConnection {
                    stream,
                    guest_port: TEST_GUEST_PORT,
                })
                .unwrap();
            client
        }

        /// One poll-loop pass, then give the relay tasks time to run.
        async fn step(&mut self) {
            self.now += SmolDuration::from_millis(STEP_MILLIS);
            self.iface
                .poll(self.now, &mut self.device, &mut self.sockets);
            self.publisher.accept_inbound(
                &mut self.iface,
                &mut self.sockets,
                &self.shared,
                &tokio::runtime::Handle::current(),
            );
            self.publisher.relay_data(&mut self.sockets);
            self.iface
                .poll(self.now, &mut self.device, &mut self.sockets);
            self.publisher.cleanup_closed(&mut self.sockets);
            tokio::time::sleep(Duration::from_millis(1)).await;
        }

        async fn run_until(
            &mut self,
            what: &str,
            max_steps: usize,
            mut done: impl FnMut(&mut Self) -> bool,
        ) {
            for _ in 0..max_steps {
                if done(self) {
                    return;
                }
                self.step().await;
            }
            panic!("timed out waiting for {what}");
        }

        fn guest(&mut self) -> &mut tcp::Socket<'static> {
            self.sockets.get_mut::<tcp::Socket>(self.guest)
        }

        fn guest_recv(&mut self, buf: &mut Vec<u8>) {
            let guest = self.guest();
            while guest.can_recv() {
                guest
                    .recv(|data| {
                        buf.extend_from_slice(data);
                        (data.len(), ())
                    })
                    .unwrap();
            }
        }

        async fn wait_for_guest_accept(&mut self) {
            self.run_until("guest to accept the connection", PROMPT_STEPS, |h| {
                !matches!(
                    h.guest().state(),
                    tcp::State::Listen | tcp::State::SynReceived
                )
            })
            .await;
        }

        async fn guest_recv_to_eof(&mut self) -> Vec<u8> {
            let mut buf = Vec::new();
            self.run_until("guest to receive EOF", PROMPT_STEPS, |h| {
                h.guest_recv(&mut buf);
                !h.guest().may_recv()
            })
            .await;
            buf
        }

        async fn assert_relays_cleaned_up(&mut self) {
            self.run_until("publisher to drop the relay", CLEANUP_STEPS, |h| {
                h.publisher.connections.is_empty()
            })
            .await;
            assert_eq!(
                self.sockets.iter().count(),
                1,
                "only the guest socket should remain"
            );
            // Each relay task holds a clone of the shared state; the count
            // drops back to one only once the task has returned.
            self.run_until("relay task to exit", PROMPT_STEPS, |h| {
                Arc::strong_count(&h.shared) == 1
            })
            .await;
        }
    }

    fn spawn_read_to_end(mut client: TcpStream) -> tokio::task::JoinHandle<Vec<u8>> {
        tokio::spawn(async move {
            let mut body = Vec::new();
            client.read_to_end(&mut body).await.unwrap();
            body
        })
    }

    #[tokio::test(start_paused = true)]
    async fn exited_host_relay_drains_slow_guest_and_times_out_only_when_stalled() {
        use crate::tcp::test_support::TestNetwork;

        for stalled in [false, true] {
            let mut network = TestNetwork::new(false);
            let mut publisher = PortPublisher::new(
                &[],
                TcpAcceptQueueSize::DEFAULT,
                Some(Ipv4Addr::new(10, 0, 0, 1)),
                None,
                Some(Ipv4Addr::new(10, 0, 0, 2)),
                None,
                [2, 0, 0, 0, 0, 1],
                [2, 0, 0, 0, 0, 2],
                Arc::new(NetworkPolicy::default()),
                Arc::new(SharedState::new(4)),
                &tokio::runtime::Handle::current(),
            );
            let mut socket = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; TCP_RX_BUF_SIZE]),
                tcp::SocketBuffer::new(vec![0; TCP_TX_BUF_SIZE]),
            );
            socket
                .connect(
                    network.iface.context(),
                    (smoltcp::wire::IpAddress::v4(10, 0, 0, 1), 12345),
                    (smoltcp::wire::IpAddress::v4(10, 0, 0, 2), 8099),
                )
                .unwrap();
            let handle = network.sockets.add(socket);
            let (to_host, from_guest) = mpsc::channel(CHANNEL_CAPACITY);
            let (from_host, to_guest) = mpsc::channel(CHANNEL_CAPACITY);
            publisher.connections.push(InboundRelay {
                handle,
                to_host: Some(to_host),
                read_buf: None,
                from_host: to_guest,
                write_buf: None,
                deferred_close: DeferredClose::default(),
            });
            for _ in 0..16 {
                network.poll();
            }
            assert_eq!(network.guest_state(), tcp::State::Established);

            let payload: Vec<u8> = (0..262144).map(|i| (i % 251) as u8).collect();
            for chunk in payload.chunks(16384) {
                from_host.try_send(Bytes::copy_from_slice(chunk)).unwrap();
            }
            drop(from_host);
            drop(from_guest);

            network
                .check_drain(|sockets| publisher.relay_data(sockets), &payload, stalled)
                .await;
        }
    }

    /// Regression for #1705: close-delimited HTTP must deliver EOF.
    #[tokio::test]
    async fn guest_close_delivers_eof_to_host_client() {
        let mut h = Harness::new();
        let client = h.connect_host().await;
        h.wait_for_guest_accept().await;

        let response = b"HTTP/1.0 200 OK\r\n\r\nhi";
        h.guest().send_slice(response).unwrap();
        h.guest().close();

        let reader = spawn_read_to_end(client);
        h.run_until("host client to see EOF", PROMPT_STEPS, |_| {
            reader.is_finished()
        })
        .await;
        assert_eq!(reader.await.unwrap(), response);

        h.assert_relays_cleaned_up().await;
    }

    #[tokio::test]
    async fn guest_close_keeps_host_to_guest_direction_open() {
        let mut h = Harness::new();
        let mut client = h.connect_host().await;
        h.wait_for_guest_accept().await;

        h.guest().send_slice(b"bye").unwrap();
        h.guest().close();

        let mut body = Vec::new();
        let mut eof = false;
        h.run_until(
            "host client to see guest data and EOF",
            PROMPT_STEPS,
            |_| {
                let mut chunk = [0u8; 64];
                loop {
                    match client.try_read(&mut chunk) {
                        Ok(0) => {
                            eof = true;
                            break;
                        }
                        Ok(n) => body.extend_from_slice(&chunk[..n]),
                        Err(_) => break,
                    }
                }
                eof
            },
        )
        .await;
        assert_eq!(body, b"bye");

        // The host can still send after the guest's FIN.
        client.write_all(b"late request").await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(h.guest_recv_to_eof().await, b"late request");

        drop(client);
        h.assert_relays_cleaned_up().await;
    }

    #[tokio::test]
    async fn host_half_close_keeps_guest_to_host_direction_open() {
        let mut h = Harness::new();
        let mut client = h.connect_host().await;
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();

        h.wait_for_guest_accept().await;
        assert_eq!(h.guest_recv_to_eof().await, b"request");
        assert_eq!(h.guest().state(), tcp::State::CloseWait);

        let reader = spawn_read_to_end(client);
        h.guest().send_slice(b"response").unwrap();
        h.guest().close();
        h.run_until("host client to see EOF", PROMPT_STEPS, |_| {
            reader.is_finished()
        })
        .await;
        assert_eq!(reader.await.unwrap(), b"response");

        h.assert_relays_cleaned_up().await;
    }

    #[tokio::test]
    async fn host_close_before_guest_accept_still_reaches_guest() {
        let mut h = Harness::new();
        let mut client = h.connect_host().await;
        // The relay task sees host EOF while the guest handshake is pending.
        client.shutdown().await.unwrap();

        h.wait_for_guest_accept().await;
        assert!(h.guest_recv_to_eof().await.is_empty());

        let reader = spawn_read_to_end(client);
        h.guest().send_slice(b"response").unwrap();
        h.guest().close();
        h.run_until("host client to see EOF", PROMPT_STEPS, |_| {
            reader.is_finished()
        })
        .await;
        assert_eq!(reader.await.unwrap(), b"response");

        h.assert_relays_cleaned_up().await;
    }

    #[tokio::test]
    async fn simultaneous_close_relays_both_directions() {
        let mut h = Harness::new();
        let mut client = h.connect_host().await;
        h.wait_for_guest_accept().await;

        // Both sides send and close before either has seen the other's FIN.
        client.write_all(b"request").await.unwrap();
        client.shutdown().await.unwrap();
        h.guest().send_slice(b"response").unwrap();
        h.guest().close();

        let reader = spawn_read_to_end(client);
        assert_eq!(h.guest_recv_to_eof().await, b"request");
        h.run_until("host client to see EOF", PROMPT_STEPS, |_| {
            reader.is_finished()
        })
        .await;
        assert_eq!(reader.await.unwrap(), b"response");

        h.assert_relays_cleaned_up().await;
    }

    #[tokio::test]
    async fn guest_reset_ends_relay_while_host_idle() {
        let mut h = Harness::new();
        let client = h.connect_host().await;
        h.wait_for_guest_accept().await;

        h.guest().abort();
        h.assert_relays_cleaned_up().await;
        drop(client);
    }

    #[tokio::test]
    async fn queue_inbound_connection_wakes_poll_loop() {
        let shared = SharedState::new(4);
        shared.proxy_wake.drain();

        let (tx, mut rx) = mpsc::channel(1);

        assert!(queue_inbound_connection(&tx, (), &shared).await);
        assert!(rx.try_recv().is_ok());
        assert!(shared.proxy_wake.wait_timeout(Duration::ZERO));
    }

    /// The listener hands `listen()` the configured depth, and the queue holds that many.
    ///
    /// The kernel clamps the request to `net.core.somaxconn`, so the expectation is
    /// `min(requested, somaxconn)` read from the host rather than a fixed number: on a host left
    /// at 128, a 128-deep queue is the correct result. `TCP_INFO` on a listening socket reports
    /// that effective depth in `tcpi_sacked`, which pins the value given to `listen()` exactly,
    /// including that `TcpAcceptQueueSize::MAX` does not wrap negative on its way to the C `int`.
    /// Filling the queue without accepting then shows the kernel honours it.
    ///
    /// Linux only: `tcpi_sacked` has this meaning only there, and macOS clamps to
    /// `kern.ipc.somaxconn` with no equivalent way to read the result back.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn published_listener_queues_the_configured_backlog() {
        let somaxconn: u32 = std::fs::read_to_string("/proc/sys/net/core/somaxconn")
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let loopback = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0);

        for requested in [
            1,
            300,
            TcpAcceptQueueSize::DEFAULT.get(),
            TcpAcceptQueueSize::MAX,
        ] {
            let backlog = TcpAcceptQueueSize::try_from(requested).unwrap();
            let listener = bind_listener(loopback, backlog).unwrap();
            assert_eq!(
                effective_backlog(&listener),
                requested.min(somaxconn),
                "requested {requested} with somaxconn {somaxconn}",
            );
        }

        let listener = bind_listener(loopback, TcpAcceptQueueSize::try_from(300).unwrap()).unwrap();
        let addr = listener.local_addr().unwrap();
        let depth = effective_backlog(&listener) as usize;

        // Deliberately never accept: what is under test is the queue, not the accept loop.
        let mut held = Vec::with_capacity(depth);
        for _ in 0..depth {
            match tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
                Ok(Ok(stream)) => held.push(stream),
                Ok(Err(e)) => panic!("refused after {} of {depth} connections: {e}", held.len()),
                Err(_) => panic!("timed out after {} of {depth} connections", held.len()),
            }
        }
    }

    /// Accept-queue depth the kernel actually applied to a listening socket.
    #[cfg(target_os = "linux")]
    fn effective_backlog(listener: &TcpListener) -> u32 {
        use std::os::fd::AsRawFd;

        // SAFETY: `tcp_info` is plain old data, so the all-zero pattern is a valid value.
        let mut info: libc::tcp_info = unsafe { std::mem::zeroed() };
        let mut len = std::mem::size_of::<libc::tcp_info>() as libc::socklen_t;
        // SAFETY: the descriptor is open for the listener's lifetime, and `info`/`len` describe a
        // writable buffer of exactly the size passed.
        let rc = unsafe {
            libc::getsockopt(
                listener.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_INFO,
                (&mut info as *mut libc::tcp_info).cast(),
                &mut len,
            )
        };
        assert_eq!(rc, 0, "TCP_INFO: {}", std::io::Error::last_os_error());
        // For a socket in LISTEN, Linux reports `sk_max_ack_backlog` here.
        info.tcpi_sacked
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
    fn full_host_channel_returns_guest_data_for_retry() {
        let (to_host, mut to_host_rx) = mpsc::channel(1);

        let occupied = Bytes::from_static(b"occupied");
        to_host.try_send(occupied.clone()).unwrap();

        let pending = Bytes::from_static(b"preserve me");
        let unsent = try_send_to_host_relay(&to_host, pending.clone()).unwrap_err();
        assert_eq!(unsent, pending);

        assert_eq!(to_host_rx.try_recv().unwrap(), occupied);
        try_send_to_host_relay(&to_host, unsent).unwrap();
        assert_eq!(
            to_host_rx.try_recv().unwrap(),
            Bytes::from_static(b"preserve me")
        );
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
