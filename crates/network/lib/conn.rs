//! Connection tracker: manages smoltcp TCP sockets for the poll loop.
//!
//! Creates sockets on SYN detection, tracks connection lifecycle, relays data
//! between smoltcp sockets and proxy task channels, and cleans up closed
//! connections.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use bytes::Bytes;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::IpListenEndpoint;
use tokio::sync::mpsc;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// TCP socket receive buffer size (64 KiB).
const TCP_RX_BUF_SIZE: usize = 65536;

/// TCP socket transmit buffer size (64 KiB).
const TCP_TX_BUF_SIZE: usize = 65536;

/// Default max concurrent connections.
const DEFAULT_MAX_CONNECTIONS: usize = 256;

/// Capacity of the mpsc channels between the poll loop and proxy tasks.
const CHANNEL_CAPACITY: usize = 32;

/// Buffer size for reading from smoltcp sockets.
const RELAY_BUF_SIZE: usize = 16384;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Tracks TCP connections between guest and proxy tasks.
///
/// Each guest TCP connection maps to a smoltcp socket and a pair of channels
/// connecting it to a tokio proxy task. The tracker handles:
///
/// - **Socket creation** — on SYN detection, before smoltcp processes the frame.
/// - **Data relay** — shuttles bytes between smoltcp sockets and channels.
/// - **Lifecycle detection** — identifies newly-established connections for
///   proxy spawning.
/// - **Cleanup** — removes closed sockets from the socket set.
pub struct ConnectionTracker {
    /// Active connections keyed by smoltcp socket handle.
    connections: HashMap<SocketHandle, Connection>,
    /// Secondary index for O(1) duplicate-SYN detection by (src, dst) 4-tuple.
    connection_keys: HashSet<(SocketAddr, SocketAddr)>,
    /// Max concurrent connections (from NetworkConfig).
    max_connections: usize,
}

/// Maximum number of poll iterations to attempt flushing remaining data
/// after the proxy task has exited before force-aborting the socket.
const DEFERRED_CLOSE_LIMIT: u16 = 64;

/// Internal state for a single tracked TCP connection.
struct Connection {
    /// Guest source address (from the guest's SYN).
    src: SocketAddr,
    /// Original destination (from the guest's SYN).
    dst: SocketAddr,
    /// Sends data from smoltcp socket to proxy task (guest → server).
    to_proxy: mpsc::Sender<Bytes>,
    /// Receives data from proxy task to write to smoltcp socket (server → guest).
    from_proxy: mpsc::Receiver<Bytes>,
    /// Proxy-side channel ends, held until the connection is ESTABLISHED.
    /// Taken by [`ConnectionTracker::take_new_connections()`].
    proxy_channels: Option<ProxyChannels>,
    /// Whether a proxy task has been spawned for this connection.
    proxy_spawned: bool,
    /// Set `true` by the proxy task once its `TcpStream::connect` to
    /// the upstream succeeds. If the task exits with this still
    /// `false`, the smoltcp socket is aborted (RST) so the guest
    /// client gets ECONNREFUSED and happy-eyeballs clients fall back
    /// to another address family, instead of being stuck on a
    /// half-open connection that closed cleanly with FIN.
    upstream_connected: Arc<AtomicBool>,
    /// Partial data from proxy that couldn't be fully written to smoltcp socket.
    write_buf: Option<(Bytes, usize)>,
    /// Data read from smoltcp socket that couldn't be sent to proxy (channel full).
    /// Must be sent before reading more from the socket to preserve stream order.
    read_buf: Option<Bytes>,
    /// Counter for deferred close attempts (prevents stalling forever).
    close_attempts: u16,
}

/// Proxy-side channel ends, created at socket creation time and taken when
/// the connection becomes ESTABLISHED.
struct ProxyChannels {
    /// Receive data from smoltcp socket (guest → proxy task).
    from_smoltcp: mpsc::Receiver<Bytes>,
    /// Send data to smoltcp socket (proxy task → guest).
    to_smoltcp: mpsc::Sender<Bytes>,
}

/// Information for spawning a proxy task for a newly established connection.
///
/// Returned by [`ConnectionTracker::take_new_connections()`]. The poll loop
/// passes this to the proxy task spawner.
pub struct NewConnection {
    /// Original destination the guest was connecting to.
    pub dst: SocketAddr,
    /// Receive data from smoltcp socket (guest → proxy task).
    pub from_smoltcp: mpsc::Receiver<Bytes>,
    /// Send data to smoltcp socket (proxy task → guest).
    pub to_smoltcp: mpsc::Sender<Bytes>,
    /// Flag the proxy task flips to `true` after a successful upstream
    /// connect. Read by the connection tracker on proxy exit to decide
    /// between FIN (clean close) and RST (upstream never reached).
    pub upstream_connected: Arc<AtomicBool>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ConnectionTracker {
    /// Create a new tracker with the given connection limit.
    pub fn new(max_connections: Option<usize>) -> Self {
        Self {
            connections: HashMap::new(),
            connection_keys: HashSet::new(),
            max_connections: max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
        }
    }

    /// Returns `true` if a tracked socket already exists for this exact
    /// connection (same source AND destination). O(1) via HashSet lookup.
    pub fn has_socket_for(&self, src: &SocketAddr, dst: &SocketAddr) -> bool {
        self.connection_keys.contains(&(*src, *dst))
    }

    /// Create a smoltcp TCP socket for an incoming SYN and register it.
    ///
    /// The socket is put into LISTEN state on the destination IP + port so
    /// smoltcp will complete the three-way handshake when it processes the
    /// SYN frame. Binding to the specific destination IP (not just port)
    /// prevents socket dispatch ambiguity when multiple connections target
    /// different IPs on the same port.
    ///
    /// Returns `false` if at `max_connections` limit.
    pub fn create_tcp_socket(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        sockets: &mut SocketSet<'_>,
    ) -> bool {
        if self.connections.len() >= self.max_connections {
            return false;
        }

        // Create smoltcp TCP socket with buffers.
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_SIZE]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_SIZE]);
        let mut socket = tcp::Socket::new(rx_buf, tx_buf);

        // Listen on the specific destination IP + port. With any_ip mode,
        // binding to the IP ensures the correct socket accepts each SYN
        // when multiple connections target the same port on different IPs.
        let listen_endpoint = IpListenEndpoint {
            addr: Some(dst.ip().into()),
            port: dst.port(),
        };
        if socket.listen(listen_endpoint).is_err() {
            return false;
        }

        let handle = sockets.add(socket);

        // Create channel pairs for proxy task communication.
        //
        // smoltcp → proxy (guest sends data, proxy relays to server):
        let (to_proxy_tx, to_proxy_rx) = mpsc::channel(CHANNEL_CAPACITY);
        // proxy → smoltcp (server sends data, proxy relays to guest):
        let (from_proxy_tx, from_proxy_rx) = mpsc::channel(CHANNEL_CAPACITY);

        self.connection_keys.insert((src, dst));
        self.connections.insert(
            handle,
            Connection {
                src,
                dst,
                to_proxy: to_proxy_tx,
                from_proxy: from_proxy_rx,
                proxy_channels: Some(ProxyChannels {
                    from_smoltcp: to_proxy_rx,
                    to_smoltcp: from_proxy_tx,
                }),
                proxy_spawned: false,
                upstream_connected: Arc::new(AtomicBool::new(false)),
                write_buf: None,
                read_buf: None,
                close_attempts: 0,
            },
        );

        true
    }

    /// Relay data between smoltcp sockets and proxy task channels.
    ///
    /// For each connection with a spawned proxy:
    /// - Reads data from the smoltcp socket and sends it to the proxy channel.
    /// - Receives data from the proxy channel and writes it to the smoltcp socket.
    pub fn relay_data(&mut self, sockets: &mut SocketSet<'_>) {
        let mut relay_buf = [0u8; RELAY_BUF_SIZE];

        for (&handle, conn) in &mut self.connections {
            if !conn.proxy_spawned {
                continue;
            }

            let socket = sockets.get_mut::<tcp::Socket>(handle);

            // Already torn down (e.g. abort fired on a previous pass).
            // Leave it for `cleanup_closed` to evict.
            if matches!(socket.state(), tcp::State::Closed) {
                continue;
            }

            // Detect proxy task exit: when the proxy drops its channel
            // ends, close the smoltcp socket so the guest gets a FIN.
            //
            // If the proxy never successfully reached the upstream,
            // an RST via `abort()` is instead sent so happy-eyeballs
            // clients fall back to another family instead of committing
            // to this half-open connection.
            if conn.to_proxy.is_closed() {
                if !conn.upstream_connected.load(Ordering::Acquire) {
                    tracing::debug!(
                        src = %conn.src,
                        dst = %conn.dst,
                        "upstream never connected; aborting smoltcp socket (RST to guest)"
                    );
                    socket.abort();
                    continue;
                }
                write_proxy_data(socket, conn);
                if conn.write_buf.is_none() {
                    socket.close();
                } else {
                    // Abort if we've been trying to flush for too long
                    // (guest stopped reading, socket send buffer full).
                    conn.close_attempts += 1;
                    if conn.close_attempts >= DEFERRED_CLOSE_LIMIT {
                        socket.abort();
                    }
                }
                continue;
            }

            // smoltcp → proxy: flush read_buf first, then read from socket.
            if let Some(pending) = conn.read_buf.take()
                && let Err(e) = conn.to_proxy.try_send(pending)
            {
                conn.read_buf = Some(e.into_inner());
            }

            if conn.read_buf.is_none() {
                while socket.can_recv() {
                    match socket.recv_slice(&mut relay_buf) {
                        Ok(n) if n > 0 => {
                            let data = Bytes::copy_from_slice(&relay_buf[..n]);
                            if let Err(e) = conn.to_proxy.try_send(data) {
                                conn.read_buf = Some(e.into_inner());
                                break;
                            }
                        }
                        _ => break,
                    }
                }
            }

            // proxy → smoltcp: write pending data, then drain channel.
            write_proxy_data(socket, conn);
        }
    }

    /// Collect newly-established connections that need proxy tasks.
    ///
    /// Returns a list of [`NewConnection`] structs containing the channel ends
    /// for the proxy task. The poll loop is responsible for spawning the task.
    pub fn take_new_connections(&mut self, sockets: &mut SocketSet<'_>) -> Vec<NewConnection> {
        let mut new = Vec::new();

        for (&handle, conn) in &mut self.connections {
            if conn.proxy_spawned {
                continue;
            }

            let socket = sockets.get::<tcp::Socket>(handle);
            if socket.state() == tcp::State::Established {
                conn.proxy_spawned = true;

                if let Some(channels) = conn.proxy_channels.take() {
                    new.push(NewConnection {
                        dst: conn.dst,
                        from_smoltcp: channels.from_smoltcp,
                        to_smoltcp: channels.to_smoltcp,
                        upstream_connected: conn.upstream_connected.clone(),
                    });
                }
            }
        }

        new
    }

    /// Remove closed connections and their sockets.
    ///
    /// Only removes sockets in the `Closed` state. Sockets in `TimeWait`
    /// are left for smoltcp to handle naturally (2*MSL timer), preventing
    /// delayed duplicate segments from being accepted by a reused port.
    pub fn cleanup_closed(&mut self, sockets: &mut SocketSet<'_>) {
        let keys = &mut self.connection_keys;
        self.connections.retain(|&handle, conn| {
            let socket = sockets.get::<tcp::Socket>(handle);
            if matches!(socket.state(), tcp::State::Closed) {
                keys.remove(&(conn.src, conn.dst));
                sockets.remove(handle);
                false
            } else {
                true
            }
        });
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Try to write proxy data to the smoltcp socket.
fn write_proxy_data(socket: &mut tcp::Socket<'_>, conn: &mut Connection) {
    // First, try to finish writing any pending partial data.
    if let Some((data, offset)) = &mut conn.write_buf {
        if socket.can_send() {
            match socket.send_slice(&data[*offset..]) {
                Ok(written) => {
                    *offset += written;
                    if *offset >= data.len() {
                        conn.write_buf = None;
                    }
                }
                Err(_) => return,
            }
        } else {
            return;
        }
    }

    // Then drain the channel.
    while conn.write_buf.is_none() {
        match conn.from_proxy.try_recv() {
            Ok(data) => {
                if socket.can_send() {
                    match socket.send_slice(&data) {
                        Ok(written) if written < data.len() => {
                            conn.write_buf = Some((data, written));
                        }
                        Err(_) => {
                            conn.write_buf = Some((data, 0));
                        }
                        _ => {}
                    }
                } else {
                    conn.write_buf = Some((data, 0));
                }
            }
            Err(_) => break,
        }
    }
}
