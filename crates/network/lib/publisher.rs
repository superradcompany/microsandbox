//! Published port management.
//!
//! Binds host-side TCP/UDP listeners and proxies traffic to guest ports
//! through regular kernel sockets. The existing frame relay handles L2
//! transport automatically — the publisher operates at the application layer.

use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::{Duration, Instant},
};

use tokio::{
    net::{TcpListener, TcpStream, UdpSocket},
    sync::Mutex,
};

use crate::config::{PortProtocol, PublishedPort};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// UDP session idle timeout.
const UDP_SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Maximum concurrent UDP sessions per published port.
const MAX_UDP_SESSIONS: usize = 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Manages all published port listeners for a sandbox.
pub struct PortPublisher {
    /// Handles to spawned listener tasks (kept alive via JoinHandle).
    _handles: Vec<tokio::task::JoinHandle<()>>,
}

/// Resolved guest addresses used by published-port listeners.
pub struct GuestAddresses {
    pub ipv4: Option<Ipv4Addr>,
    pub ipv6: Option<Ipv6Addr>,
}

/// A single UDP session mapping an external peer to a guest-facing socket.
struct UdpSession {
    /// Socket connected to the guest for this peer (shared with response relay task).
    guest_socket: Arc<UdpSocket>,

    /// Last time this session was active.
    last_active: Instant,
}

/// A bound but not yet active listener, ready to be passed to [`PortPublisher::start_from`].
pub enum PendingListener {
    /// A bound TCP listener.
    Tcp {
        /// The bound TCP listener.
        listener: TcpListener,
        /// Guest address to proxy to.
        guest_addr: SocketAddr,
    },
    /// A bound UDP socket.
    Udp {
        /// The bound UDP socket.
        socket: UdpSocket,
        /// Guest address to relay to.
        guest_addr: SocketAddr,
    },
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PortPublisher {
    /// Binds host-side listeners for all published ports.
    ///
    /// This performs the privileged `bind()` syscalls but does not spawn relay
    /// tasks. Call [`start_from`] after dropping privileges to begin relaying.
    pub async fn bind(
        ports: &[PublishedPort],
        guest_ipv4: Option<Ipv4Addr>,
        guest_ipv6: Option<Ipv6Addr>,
    ) -> std::io::Result<Vec<PendingListener>> {
        let mut pending = Vec::with_capacity(ports.len());
        let guest_addresses = GuestAddresses {
            ipv4: guest_ipv4,
            ipv6: guest_ipv6,
        };

        for port in ports {
            let guest_ip = resolve_guest_ip(port.host_bind, &guest_addresses)?;
            let host_bind = SocketAddr::new(port.host_bind, port.host_port);
            let guest_addr = SocketAddr::new(guest_ip, port.guest_port);

            match port.protocol {
                PortProtocol::Tcp => {
                    let listener = TcpListener::bind(host_bind).await?;
                    tracing::info!(%host_bind, %guest_addr, "published TCP port");
                    pending.push(PendingListener::Tcp {
                        listener,
                        guest_addr,
                    });
                }
                PortProtocol::Udp => {
                    let socket = UdpSocket::bind(host_bind).await?;
                    tracing::info!(%host_bind, %guest_addr, "published UDP port");
                    pending.push(PendingListener::Udp { socket, guest_addr });
                }
            }
        }

        Ok(pending)
    }

    /// Spawns relay tasks from pre-bound listeners.
    ///
    /// Each listener gets its own tokio task:
    /// - TCP: one `TcpListener`, spawns a sub-task per accepted connection.
    /// - UDP: one `UdpSocket`, maintains a session map for peer tracking.
    pub fn start_from(pending: Vec<PendingListener>) -> Self {
        let mut handles = Vec::with_capacity(pending.len());

        for listener in pending {
            let handle = match listener {
                PendingListener::Tcp {
                    listener,
                    guest_addr,
                } => tokio::spawn(async move {
                    tcp_listener_loop(listener, guest_addr).await;
                }),
                PendingListener::Udp { socket, guest_addr } => tokio::spawn(async move {
                    udp_relay_loop(socket, guest_addr).await;
                }),
            };
            handles.push(handle);
        }

        Self { _handles: handles }
    }

    /// Binds and starts listeners in one call (convenience for unprivileged use).
    pub async fn start(
        ports: &[PublishedPort],
        guest_ipv4: Option<Ipv4Addr>,
        guest_ipv6: Option<Ipv6Addr>,
    ) -> std::io::Result<Self> {
        let pending = Self::bind(ports, guest_ipv4, guest_ipv6).await?;
        Ok(Self::start_from(pending))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: TCP
//--------------------------------------------------------------------------------------------------

/// Accepts TCP connections and spawns a proxy task for each.
async fn tcp_listener_loop(listener: TcpListener, guest_addr: SocketAddr) {
    loop {
        let (client_stream, peer_addr) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                tracing::warn!("TCP accept error: {e}");
                continue;
            }
        };

        tracing::debug!(%peer_addr, %guest_addr, "TCP connection accepted");

        tokio::spawn(async move {
            if let Err(e) = tcp_proxy(client_stream, guest_addr).await {
                tracing::debug!(%peer_addr, %guest_addr, "TCP proxy ended: {e}");
            }
        });
    }
}

/// Proxies bytes bidirectionally between a client and the guest.
async fn tcp_proxy(mut client: TcpStream, guest_addr: SocketAddr) -> std::io::Result<()> {
    let mut guest = TcpStream::connect(guest_addr).await?;
    tokio::io::copy_bidirectional(&mut client, &mut guest).await?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: UDP
//--------------------------------------------------------------------------------------------------

/// Relays UDP datagrams between external peers and the guest.
async fn udp_relay_loop(host_socket: UdpSocket, guest_addr: SocketAddr) {
    let host_socket = Arc::new(host_socket);
    let sessions: Arc<Mutex<HashMap<SocketAddr, UdpSession>>> =
        Arc::new(Mutex::new(HashMap::new()));

    let mut buf = [0u8; 65535];

    loop {
        let (n, peer_addr) = match host_socket.recv_from(&mut buf).await {
            Ok(result) => result,
            Err(e) => {
                tracing::warn!("UDP recv error: {e}");
                continue;
            }
        };

        let data = &buf[..n];

        // Look up or create a session. Clone the socket Arc, then drop
        // the lock before any await to avoid holding it across send_to.
        let guest_socket = {
            let mut map = sessions.lock().await;

            if let Some(session) = map.get_mut(&peer_addr) {
                session.last_active = Instant::now();
                Some(Arc::clone(&session.guest_socket))
            } else {
                None
            }
        };

        if let Some(socket) = guest_socket {
            if let Err(e) = socket.send_to(data, guest_addr).await {
                tracing::debug!(%peer_addr, "UDP send to guest failed: {e}");
            }
            continue;
        }

        // Enforce session cap to prevent fd exhaustion under attack.
        if sessions.lock().await.len() >= MAX_UDP_SESSIONS {
            tracing::warn!(%peer_addr, "UDP session limit reached, dropping datagram");
            continue;
        }

        // New session: create a guest-facing UDP socket.
        let bind_addr = if guest_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let guest_socket = match UdpSocket::bind(bind_addr).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                tracing::warn!(%peer_addr, "failed to bind guest UDP socket: {e}");
                continue;
            }
        };

        // Send the first datagram.
        if let Err(e) = guest_socket.send_to(data, guest_addr).await {
            tracing::debug!(%peer_addr, "UDP send to guest failed: {e}");
            continue;
        }

        // Register the new session.
        sessions.lock().await.insert(
            peer_addr,
            UdpSession {
                guest_socket: Arc::clone(&guest_socket),
                last_active: Instant::now(),
            },
        );

        // Spawn a task to relay responses from guest back to this peer.
        let host_socket_clone = Arc::clone(&host_socket);
        let sessions_clone = Arc::clone(&sessions);

        tokio::spawn(async move {
            let mut resp_buf = [0u8; 65535];
            loop {
                let recv_result = tokio::time::timeout(
                    UDP_SESSION_TIMEOUT,
                    guest_socket.recv_from(&mut resp_buf),
                )
                .await;

                match recv_result {
                    Ok(Ok((n, _from))) => {
                        if let Err(e) = host_socket_clone.send_to(&resp_buf[..n], peer_addr).await {
                            tracing::debug!(%peer_addr, "UDP send to peer failed: {e}");
                            break;
                        }
                        if let Some(session) = sessions_clone.lock().await.get_mut(&peer_addr) {
                            session.last_active = Instant::now();
                        }
                    }
                    Ok(Err(e)) => {
                        tracing::debug!(%peer_addr, "UDP recv from guest failed: {e}");
                        break;
                    }
                    Err(_timeout) => {
                        tracing::debug!(%peer_addr, "UDP session timed out");
                        sessions_clone.lock().await.remove(&peer_addr);
                        break;
                    }
                }
            }

            sessions_clone.lock().await.remove(&peer_addr);
        });
    }
}

fn resolve_guest_ip(
    host_bind: IpAddr,
    guest_addresses: &GuestAddresses,
) -> std::io::Result<IpAddr> {
    match host_bind {
        IpAddr::V4(_) => guest_addresses
            .ipv4
            .map(IpAddr::V4)
            .or_else(|| guest_addresses.ipv6.map(IpAddr::V6)),
        IpAddr::V6(_) => guest_addresses
            .ipv6
            .map(IpAddr::V6)
            .or_else(|| guest_addresses.ipv4.map(IpAddr::V4)),
    }
    .ok_or_else(|| {
        std::io::Error::other(format!(
            "no guest address available for published port bind family {host_bind}"
        ))
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::TcpListener as StdTcpListener;

    use super::*;

    #[tokio::test]
    async fn test_start_does_not_leak_earlier_listener_on_later_bind_failure() {
        let reserved = StdTcpListener::bind(("127.0.0.1", 0)).unwrap();
        let reserved_port = reserved.local_addr().unwrap().port();
        let first = StdTcpListener::bind(("127.0.0.1", 0)).unwrap();
        let first_port = first.local_addr().unwrap().port();
        drop(first);

        let ports = vec![
            PublishedPort {
                host_port: first_port,
                guest_port: 8080,
                protocol: PortProtocol::Tcp,
                host_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
            PublishedPort {
                host_port: reserved_port,
                guest_port: 8081,
                protocol: PortProtocol::Tcp,
                host_bind: IpAddr::V4(Ipv4Addr::LOCALHOST),
            },
        ];

        assert!(
            PortPublisher::start(&ports, Some(Ipv4Addr::new(100, 96, 0, 2)), None)
                .await
                .is_err()
        );

        StdTcpListener::bind(("127.0.0.1", first_port)).unwrap();
    }
}
