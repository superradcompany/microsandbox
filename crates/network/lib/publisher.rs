//! Published port handling: host-side listeners that forward connections
//! into the guest VM via smoltcp.
//!
//! For each configured [`PublishedPort`], a tokio TCP or UDP listener binds
//! on the host. When a connection arrives, the poll loop creates a smoltcp
//! socket that connects to the guest, and a relay task bridges the host
//! socket to the smoltcp socket via channels.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};
use std::time::Duration;

use bytes::Bytes;
use smoltcp::iface::{Interface, SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::IpEndpoint;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;

use crate::config::{PortProtocol, PublishedPort};
use crate::policy::{NetworkPolicy, Protocol};
use crate::shared::SharedState;

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
    /// Ephemeral port counter.
    ephemeral_port: Arc<AtomicU16>,
    /// Maximum inbound connections (prevents resource exhaustion from host-side floods).
    max_inbound: usize,
}

/// An accepted host-side connection waiting to be wired to the guest.
struct InboundConnection {
    /// The accepted host-side TCP stream.
    stream: TcpStream,
    /// Guest port to connect to.
    guest_port: u16,
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
    pub fn new(
        ports: &[PublishedPort],
        guest_ipv4: Option<Ipv4Addr>,
        guest_ipv6: Option<Ipv6Addr>,
        policy: Arc<NetworkPolicy>,
        shared: Arc<SharedState>,
        tokio_handle: &tokio::runtime::Handle,
    ) -> Self {
        let (inbound_tx, inbound_rx) = mpsc::channel(64);

        let guest_ip = guest_ipv4
            .map(IpAddr::V4)
            .or_else(|| guest_ipv6.map(IpAddr::V6));

        if guest_ip.is_some() {
            Self::spawn_listeners(ports, &inbound_tx, policy, shared, tokio_handle);
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
            ephemeral_port: Arc::new(AtomicU16::new(49152)),
            max_inbound: 256,
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
    }

    /// Spawn one tokio listener task per TCP published port.
    fn spawn_listeners(
        ports: &[PublishedPort],
        inbound_tx: &mpsc::Sender<InboundConnection>,
        policy: Arc<NetworkPolicy>,
        shared: Arc<SharedState>,
        tokio_handle: &tokio::runtime::Handle,
    ) {
        for port in ports {
            if port.protocol == PortProtocol::Tcp {
                let tx = inbound_tx.clone();
                let bind_addr = SocketAddr::new(port.host_bind, port.host_port);
                let guest_port = port.guest_port;
                let policy = policy.clone();
                let shared = shared.clone();
                tokio_handle.spawn(async move {
                    if let Err(e) =
                        tcp_listener_task(bind_addr, guest_port, tx, policy, shared).await
                    {
                        tracing::error!(
                            bind = %bind_addr,
                            error = %e,
                            "published port listener failed",
                        );
                    }
                });
            }
            // TODO: UDP published ports.
        }
    }

    fn alloc_ephemeral_port(&self) -> u16 {
        loop {
            let port = self.ephemeral_port.fetch_add(1, Ordering::Relaxed);
            // Wrap around in the ephemeral range.
            if port == 0 || port < 49152 {
                self.ephemeral_port.store(49152, Ordering::Relaxed);
                continue;
            }
            return port;
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
    tracing::debug!(bind = %bind_addr, guest_port, "published port listener started");

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
        if inbound_tx.send(conn).await.is_err() {
            break; // Publisher dropped.
        }
    }

    Ok(())
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
