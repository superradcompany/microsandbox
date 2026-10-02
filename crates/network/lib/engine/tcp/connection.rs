//! Connection tracker: manages smoltcp TCP sockets for the poll loop.
//!
//! Creates sockets on SYN detection, tracks connection lifecycle, relays data
//! between smoltcp sockets and proxy task channels, and cleans up closed
//! connections.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};

use bytes::Bytes;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::tcp;
use smoltcp::wire::IpListenEndpoint;
use tokio::sync::mpsc;

use crate::tcp::deferred_close::DeferredClose;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Log target for opt-in profiling events.
const PROFILING_TARGET: &str = "microsandbox::profiling";

/// TCP socket receive buffer size (64 KiB).
const TCP_RX_BUF_SIZE: usize = 65536;

/// TCP socket transmit buffer size (64 KiB).
const TCP_TX_BUF_SIZE: usize = 65536;

/// Capacity of the mpsc channels between the poll loop and proxy tasks.
const CHANNEL_CAPACITY: usize = 32;

/// Buffer size for reading from smoltcp sockets.
const RELAY_BUF_SIZE: usize = 16384;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Terminal connection status reported by an outbound proxy task.
#[repr(u8)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProxyConnectStatus {
    /// No final proxy connection status has been reported yet.
    Pending = 0,
    /// The proxy connected to the upstream.
    Connected = 1,
    /// The proxy denied the connection before dialing upstream.
    PolicyDenied = 2,
    /// The proxy attempted to dial upstream and the connect failed.
    UpstreamConnectFailed = 3,
}

/// Shared status for an outbound proxy task.
///
/// The smoltcp poll loop reads this when the proxy task exits to decide
/// whether the guest should see a clean close or a TCP reset.
pub struct ProxyConnectState {
    status: AtomicU8,
}

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
pub struct TcpConnectionTracker {
    /// Active connections keyed by smoltcp socket handle.
    connections: HashMap<SocketHandle, Connection>,
    /// Secondary index for O(1) duplicate-SYN detection by (src, dst) 4-tuple.
    connection_keys: HashSet<(SocketAddr, SocketAddr)>,
    /// Max concurrent connections (from NetworkConfig).
    max_tcp_connections: Option<NonZeroUsize>,
    rejected_connections: u64,
}

/// Deprecated name for [`TcpConnectionTracker`].
#[deprecated(note = "use TcpConnectionTracker instead")]
pub type ConnectionTracker = TcpConnectionTracker;

/// Internal state for a single tracked TCP connection.
struct Connection {
    /// Guest source address (from the guest's SYN).
    src: SocketAddr,
    /// Original destination (from the guest's SYN).
    dst: SocketAddr,
    /// Sends data from smoltcp socket to proxy task (guest → server).
    ///
    /// Set to `None` once the guest half-closes (FIN) and all its data has
    /// been relayed: dropping the sender makes the proxy task's
    /// `from_smoltcp.recv()` return `None`, propagating the half-close
    /// upstream while the server → guest direction stays open.
    to_proxy: Option<mpsc::Sender<Bytes>>,
    /// Receives data from proxy task to write to smoltcp socket (server → guest).
    from_proxy: mpsc::Receiver<Bytes>,
    /// Proxy-side channel ends, held until the connection is ESTABLISHED.
    /// Taken by [`TcpConnectionTracker::take_new_connections()`].
    proxy_channels: Option<ProxyChannels>,
    /// Whether a proxy task has been spawned for this connection.
    proxy_spawned: bool,
    /// Status reported by the proxy task before it exits.
    proxy_connect: Arc<ProxyConnectState>,
    /// Partial data from proxy that couldn't be fully written to smoltcp socket.
    write_buf: Option<(Bytes, usize)>,
    /// Data read from smoltcp socket that couldn't be sent to proxy (channel full).
    /// Must be sent before reading more from the socket to preserve stream order.
    read_buf: Option<Bytes>,
    /// Progress deadline while draining after the host task exits.
    deferred_close: DeferredClose,
    /// Egress policy already denied this flow at SYN time; the connection
    /// was accepted only so an HTTP/HTTPS client can be answered with 403.
    policy_denied: bool,
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
/// Returned by [`TcpConnectionTracker::take_new_connections()`]. The poll loop
/// passes this to the proxy task spawner.
pub struct NewConnection {
    /// Original destination the guest was connecting to.
    pub dst: SocketAddr,
    /// Receive data from smoltcp socket (guest → proxy task).
    pub from_smoltcp: mpsc::Receiver<Bytes>,
    /// Send data to smoltcp socket (proxy task → guest).
    pub to_smoltcp: mpsc::Sender<Bytes>,
    /// Status the proxy task updates before it exits.
    pub proxy_connect: Arc<ProxyConnectState>,
    /// Egress policy already denied this flow at SYN time. The dispatcher
    /// must answer it (HTTP 403) and never dial upstream.
    pub policy_denied: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ProxyConnectStatus {
    fn as_u8(self) -> u8 {
        self as u8
    }

    fn from_u8(value: u8) -> Self {
        match value {
            value if value == Self::Connected as u8 => Self::Connected,
            value if value == Self::PolicyDenied as u8 => Self::PolicyDenied,
            value if value == Self::UpstreamConnectFailed as u8 => Self::UpstreamConnectFailed,
            _ => Self::Pending,
        }
    }
}

impl ProxyConnectState {
    /// Create a new pending proxy connection status.
    pub fn new() -> Self {
        Self {
            status: AtomicU8::new(ProxyConnectStatus::Pending.as_u8()),
        }
    }

    /// Mark the proxy as successfully connected to upstream.
    pub fn mark_connected(&self) {
        self.store(ProxyConnectStatus::Connected);
    }

    /// Mark the proxy as denied by egress policy before dialing upstream.
    pub fn mark_policy_denied(&self) {
        self.store(ProxyConnectStatus::PolicyDenied);
    }

    /// Mark the proxy as failed while dialing upstream.
    pub fn mark_upstream_connect_failed(&self) {
        self.store(ProxyConnectStatus::UpstreamConnectFailed);
    }

    /// Load the latest proxy connection status.
    pub fn status(&self) -> ProxyConnectStatus {
        ProxyConnectStatus::from_u8(self.status.load(Ordering::Acquire))
    }

    fn store(&self, status: ProxyConnectStatus) {
        self.status.store(status.as_u8(), Ordering::Release);
    }
}

impl Default for ProxyConnectState {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpConnectionTracker {
    /// Create a new tracker with the given connection limit.
    pub fn new(max_tcp_connections: Option<NonZeroUsize>) -> Self {
        Self {
            connections: HashMap::new(),
            connection_keys: HashSet::new(),
            max_tcp_connections,
            rejected_connections: 0,
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
    /// Returns `false` if at `max_tcp_connections` limit.
    pub fn create_tcp_socket(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        sockets: &mut SocketSet<'_>,
    ) -> bool {
        self.insert_tcp_socket(src, dst, sockets, false)
    }

    /// Like [`Self::create_tcp_socket`], for a flow egress policy has
    /// already denied. The handshake completes so the guest's HTTP/HTTPS
    /// client can be answered with `403 Forbidden`; the dispatcher never
    /// dials upstream for it.
    pub fn create_policy_denied_tcp_socket(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        sockets: &mut SocketSet<'_>,
    ) -> bool {
        self.insert_tcp_socket(src, dst, sockets, true)
    }

    fn insert_tcp_socket(
        &mut self,
        src: SocketAddr,
        dst: SocketAddr,
        sockets: &mut SocketSet<'_>,
        policy_denied: bool,
    ) -> bool {
        if self
            .max_tcp_connections
            .is_some_and(|max| self.connections.len() >= max.get())
        {
            // Reclaim completed flows before rejecting a burst. Existing
            // listeners have already consumed their SYN in the poll loop;
            // an idle listener here is an invalid or reset handshake.
            self.cleanup_closed(sockets);
            if self
                .max_tcp_connections
                .is_some_and(|max| self.connections.len() >= max.get())
            {
                self.rejected_connections = self.rejected_connections.saturating_add(1);
                return false;
            }
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
                to_proxy: Some(to_proxy_tx),
                from_proxy: from_proxy_rx,
                proxy_channels: Some(ProxyChannels {
                    from_smoltcp: to_proxy_rx,
                    to_smoltcp: from_proxy_tx,
                }),
                proxy_spawned: false,
                proxy_connect: Arc::new(ProxyConnectState::new()),
                write_buf: None,
                read_buf: None,
                deferred_close: DeferredClose::default(),
                policy_denied,
            },
        );

        true
    }

    /// Earliest pending drain deadline for the network poll loop.
    pub(crate) fn deferred_close_delay(&self) -> Option<std::time::Duration> {
        self.connections
            .values()
            .filter_map(|conn| conn.deferred_close.poll_delay())
            .min()
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
                conn.deferred_close = DeferredClose::default();
                continue;
            }

            // Detect proxy task exit: when the proxy drops its channel
            // ends, close the smoltcp socket so the guest gets a FIN.
            //
            // If the proxy attempted and failed to reach upstream,
            // an RST via `abort()` is instead sent so happy-eyeballs
            // clients fall back to another family instead of committing
            // to this half-open connection.
            let proxy_exited = match &conn.to_proxy {
                Some(to_proxy) => to_proxy.is_closed(),
                // The guest already half-closed (sender dropped below), so
                // proxy exit is detected on the other channel instead: the
                // proxy drops its `to_smoltcp` sender when it returns.
                None => conn.from_proxy.is_closed(),
            };
            if proxy_exited {
                if matches!(
                    conn.proxy_connect.status(),
                    ProxyConnectStatus::UpstreamConnectFailed
                ) {
                    tracing::debug!(
                        src = %conn.src,
                        dst = %conn.dst,
                        "upstream connect failed; aborting smoltcp socket (RST to guest)"
                    );
                    socket.abort();
                    continue;
                }
                let queued_before = socket.send_queue();
                write_proxy_data(socket, conn);
                let written = socket.send_queue() - queued_before;
                conn.deferred_close
                    .finish(socket, conn.write_buf.is_some(), written);
                continue;
            }

            // smoltcp → proxy: flush read_buf first, then read from socket.
            if let Some(to_proxy) = &conn.to_proxy {
                if let Some(pending) = conn.read_buf.take()
                    && let Err(e) = to_proxy.try_send(pending)
                {
                    conn.read_buf = Some(e.into_inner());
                }

                if conn.read_buf.is_none() {
                    while socket.can_recv() {
                        match socket.recv_slice(&mut relay_buf) {
                            Ok(n) if n > 0 => {
                                let data = Bytes::copy_from_slice(&relay_buf[..n]);
                                if let Err(e) = to_proxy.try_send(data) {
                                    conn.read_buf = Some(e.into_inner());
                                    break;
                                }
                            }
                            _ => break,
                        }
                    }
                }

                // Guest half-close: the guest sent a FIN (CLOSE_WAIT) and
                // everything it sent has been relayed. Drop the sender so
                // the proxy task sees EOF and can shut down the guest →
                // server direction upstream. The server → guest direction
                // stays open; the socket is closed once the proxy task
                // exits (see `proxy_exited` above).
                if matches!(socket.state(), tcp::State::CloseWait)
                    && conn.read_buf.is_none()
                    && !socket.can_recv()
                {
                    conn.to_proxy = None;
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
            if matches!(
                socket.state(),
                tcp::State::Established | tcp::State::CloseWait
            ) {
                conn.proxy_spawned = true;

                if let Some(channels) = conn.proxy_channels.take() {
                    new.push(NewConnection {
                        dst: conn.dst,
                        from_smoltcp: channels.from_smoltcp,
                        to_smoltcp: channels.to_smoltcp,
                        proxy_connect: conn.proxy_connect.clone(),
                        policy_denied: conn.policy_denied,
                    });
                }
            }
        }

        new
    }

    /// Record bounded-cardinality diagnostics once per maintenance interval.
    pub fn trace_stats(&self, sockets: &SocketSet<'_>) {
        if !tracing::enabled!(target: PROFILING_TARGET, tracing::Level::TRACE) {
            return;
        }
        let closing = self
            .connections
            .keys()
            .filter(|&&handle| {
                matches!(
                    sockets.get::<tcp::Socket>(handle).state(),
                    tcp::State::CloseWait
                        | tcp::State::FinWait1
                        | tcp::State::FinWait2
                        | tcp::State::Closing
                        | tcp::State::LastAck
                        | tcp::State::TimeWait
                )
            })
            .count();
        tracing::trace!(
            target: PROFILING_TARGET,
            limit = ?self.max_tcp_connections,
            tracked = self.connections.len(),
            closing,
            rejected_total = self.rejected_connections,
            socket_buffer_bytes = self.connections.len() * (TCP_RX_BUF_SIZE + TCP_TX_BUF_SIZE),
            "TCP connection budget"
        );
    }

    /// Remove closed connections and their sockets.
    ///
    /// Idle listeners represent failed/reset SYNs: this tracker never owns
    /// persistent listening sockets. Closed sockets with a remote endpoint
    /// still owe the guest an RST and must survive until smoltcp emits it.
    /// TIME_WAIT remains intact to reject delayed duplicate segments.
    pub fn cleanup_closed(&mut self, sockets: &mut SocketSet<'_>) {
        let keys = &mut self.connection_keys;
        self.connections.retain(|&handle, conn| {
            let socket = sockets.get::<tcp::Socket>(handle);
            if matches!(socket.state(), tcp::State::Closed | tcp::State::Listen)
                && socket.remote_endpoint().is_none()
            {
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn exited_proxy_drains_slow_guest_and_times_out_only_when_stalled() {
        use crate::tcp::test_support::TestNetwork;

        for stalled in [false, true] {
            let mut network = TestNetwork::new(true);
            let mut tracker = TcpConnectionTracker::new(None);
            assert!(tracker.create_tcp_socket(
                "10.0.0.1:12345".parse().unwrap(),
                "10.0.0.2:8099".parse().unwrap(),
                &mut network.sockets,
            ));
            for _ in 0..16 {
                network.poll();
            }
            let mut connections = tracker.take_new_connections(&mut network.sockets);
            assert_eq!(connections.len(), 1);
            let conn = connections.remove(0);
            conn.proxy_connect.mark_connected();
            let payload: Vec<u8> = (0..262144).map(|i| (i % 251) as u8).collect();
            for chunk in payload.chunks(16384) {
                conn.to_smoltcp
                    .try_send(Bytes::copy_from_slice(chunk))
                    .unwrap();
            }
            drop(conn);

            network
                .check_drain(|sockets| tracker.relay_data(sockets), &payload, stalled)
                .await;
        }
    }

    #[test]
    fn omitted_limit_tracks_more_than_the_previous_default() {
        let mut tracker = TcpConnectionTracker::new(None);
        let mut sockets = SocketSet::new(Vec::new());
        let dst = "198.51.100.1:443".parse().unwrap();
        for port in 10000..10300 {
            let src = SocketAddr::from(([192, 0, 2, 1], port));
            assert!(tracker.create_tcp_socket(src, dst, &mut sockets));
        }
        assert_eq!(tracker.connections.len(), 300);
    }
}
