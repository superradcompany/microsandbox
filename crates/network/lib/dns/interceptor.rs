//! DNS query interception: the smoltcp ↔ channel bridge.
//!
//! [`DnsInterceptor`] owns the smoltcp UDP socket bound to `gateway:53`
//! and a pair of channels to the async forwarder task spawned on the
//! tokio runtime. Each poll-loop iteration, [`DnsInterceptor::process`]
//! reads pending queries off the smoltcp socket and hands them to the
//! forwarder, then writes any forwarded responses back to the socket.
//!
//! The DNS wire protocol, upstream client, block-list, and rebind-
//! protection logic all live under sibling modules and are reached via
//! the forwarder task.

use std::sync::Arc;

use bytes::Bytes;
use smoltcp::iface::SocketSet;
use smoltcp::socket::udp;
use smoltcp::storage::PacketMetadata;
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};
use tokio::sync::mpsc;

use super::forwarder::{self, NormalizedDnsConfig};
use crate::config::DnsConfig;
use crate::shared::SharedState;

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
pub struct DnsInterceptor {
    /// Handle to the smoltcp UDP socket bound to gateway:53.
    socket_handle: smoltcp::iface::SocketHandle,
    /// Sends queries to the background forwarder task.
    query_tx: mpsc::Sender<DnsQuery>,
    /// Receives responses from the background forwarder task.
    response_rx: mpsc::Receiver<DnsResponse>,
}

/// A DNS query extracted from the smoltcp socket.
pub(super) struct DnsQuery {
    /// Raw DNS message bytes.
    pub(super) data: Bytes,
    /// Source endpoint (guest IP:port) for routing the response back.
    pub(super) source: IpEndpoint,
}

/// A forwarded DNS response ready to send back to the guest.
pub(super) struct DnsResponse {
    /// Raw DNS response bytes.
    pub(super) data: Bytes,
    /// Destination endpoint (guest IP:port).
    pub(super) dest: IpEndpoint,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DnsInterceptor {
    /// Create the DNS interceptor.
    ///
    /// Binds a smoltcp UDP socket to port 53, creates the channel pair, and
    /// spawns the background forwarder task.
    pub fn new(
        sockets: &mut SocketSet<'_>,
        dns_config: DnsConfig,
        shared: Arc<SharedState>,
        tokio_handle: &tokio::runtime::Handle,
    ) -> Self {
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

        forwarder::spawn(tokio_handle, query_rx, response_tx, normalized, shared);

        Self {
            socket_handle,
            query_tx,
            response_rx,
        }
    }

    /// Process DNS queries and responses.
    ///
    /// Called by the poll loop each iteration:
    /// 1. Reads queries from the smoltcp socket → sends to forwarder task.
    /// 2. Reads responses from the forwarder → writes to smoltcp socket.
    pub fn process(&mut self, sockets: &mut SocketSet<'_>) {
        let socket = sockets.get_mut::<udp::Socket>(self.socket_handle);

        // Read queries from the smoltcp socket.
        let mut buf = [0u8; DNS_MAX_SIZE];
        while socket.can_recv() {
            match socket.recv_slice(&mut buf) {
                Ok((n, meta)) => {
                    let query = DnsQuery {
                        data: Bytes::copy_from_slice(&buf[..n]),
                        source: meta.endpoint,
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
                    let _ = socket.send_slice(&response.data, response.dest);
                }
                Err(_) => break,
            }
        }
    }
}
