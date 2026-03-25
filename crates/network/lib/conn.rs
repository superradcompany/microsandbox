//! Connection tracker: manages smoltcp TCP sockets for the poll loop.
//!
//! Creates sockets on SYN detection, tracks connection lifecycle, relays data
//! between smoltcp sockets and proxy task channels, and cleans up closed
//! connections.

use std::collections::HashMap;
use std::net::SocketAddr;

use bytes::Bytes;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
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
    /// Max concurrent connections (from NetworkConfig).
    max_connections: usize,
}

/// Internal state for a single tracked TCP connection.
struct Connection {
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
    /// Partial data from proxy that couldn't be fully written to smoltcp socket.
    write_buf: Option<(Bytes, usize)>,
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
    /// Socket handle (for logging/debugging).
    pub handle: SocketHandle,
    /// Original destination the guest was connecting to.
    pub dst: SocketAddr,
    /// Receive data from smoltcp socket (guest → proxy task).
    pub from_smoltcp: mpsc::Receiver<Bytes>,
    /// Send data to smoltcp socket (proxy task → guest).
    pub to_smoltcp: mpsc::Sender<Bytes>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ConnectionTracker {
    /// Create a new tracker with the given connection limit.
    pub fn new(max_connections: Option<usize>) -> Self {
        Self {
            connections: HashMap::new(),
            max_connections: max_connections.unwrap_or(DEFAULT_MAX_CONNECTIONS),
        }
    }

    /// Returns `true` if a tracked socket already exists for this destination.
    pub fn has_socket_for(&self, dst: &SocketAddr) -> bool {
        self.connections.values().any(|c| c.dst == *dst)
    }

    /// Create a smoltcp TCP socket for an incoming SYN and register it.
    ///
    /// The socket is put into LISTEN state on the destination port so smoltcp
    /// will complete the three-way handshake when it processes the SYN frame.
    ///
    /// Returns `false` if at `max_connections` limit.
    pub fn create_tcp_socket(&mut self, dst: SocketAddr, sockets: &mut SocketSet<'_>) -> bool {
        if self.connections.len() >= self.max_connections {
            return false;
        }

        // Create smoltcp TCP socket with buffers.
        let rx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_RX_BUF_SIZE]);
        let tx_buf = tcp::SocketBuffer::new(vec![0u8; TCP_TX_BUF_SIZE]);
        let mut socket = tcp::Socket::new(rx_buf, tx_buf);

        // Listen on the destination port. With any_ip mode, smoltcp will
        // accept the SYN regardless of destination IP.
        if socket.listen(dst.port()).is_err() {
            return false;
        }

        let handle = sockets.add(socket);

        // Create channel pairs for proxy task communication.
        //
        // smoltcp → proxy (guest sends data, proxy relays to server):
        let (to_proxy_tx, to_proxy_rx) = mpsc::channel(CHANNEL_CAPACITY);
        // proxy → smoltcp (server sends data, proxy relays to guest):
        let (from_proxy_tx, from_proxy_rx) = mpsc::channel(CHANNEL_CAPACITY);

        self.connections.insert(
            handle,
            Connection {
                dst,
                to_proxy: to_proxy_tx,
                from_proxy: from_proxy_rx,
                proxy_channels: Some(ProxyChannels {
                    from_smoltcp: to_proxy_rx,
                    to_smoltcp: from_proxy_tx,
                }),
                proxy_spawned: false,
                write_buf: None,
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

            // Detect proxy task exit: when the proxy drops its channel
            // ends, close the smoltcp socket so the guest gets a FIN.
            if conn.to_proxy.is_closed() {
                write_proxy_data(socket, conn);
                if conn.write_buf.is_none() {
                    socket.close();
                }
                continue;
            }

            // smoltcp → proxy: read from socket, send via channel.
            while socket.can_recv() {
                match socket.recv_slice(&mut relay_buf) {
                    Ok(n) if n > 0 => {
                        let data = Bytes::copy_from_slice(&relay_buf[..n]);
                        if conn.to_proxy.try_send(data).is_err() {
                            break;
                        }
                    }
                    _ => break,
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
                        handle,
                        dst: conn.dst,
                        from_smoltcp: channels.from_smoltcp,
                        to_smoltcp: channels.to_smoltcp,
                    });
                }
            }
        }

        new
    }

    /// Remove closed connections and their sockets.
    pub fn cleanup_closed(&mut self, sockets: &mut SocketSet<'_>) {
        let closed: Vec<SocketHandle> = self
            .connections
            .keys()
            .filter(|&&handle| {
                let socket = sockets.get::<tcp::Socket>(handle);
                matches!(socket.state(), tcp::State::Closed | tcp::State::TimeWait)
            })
            .copied()
            .collect();

        for handle in closed {
            self.connections.remove(&handle);
            sockets.remove(handle);
        }
    }

    /// Number of active connections.
    pub fn len(&self) -> usize {
        self.connections.len()
    }

    /// Returns `true` if no connections are tracked.
    pub fn is_empty(&self) -> bool {
        self.connections.is_empty()
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
