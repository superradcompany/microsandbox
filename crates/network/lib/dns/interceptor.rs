//! DNS query interception, filtering, and resolution.
//!
//! The [`DnsInterceptor`] bridges the smoltcp UDP socket (bound to gateway:53)
//! and the host DNS resolvers. Queries are read from the socket, checked
//! against the domain block list, forwarded to hickory-resolver for
//! resolution, and responses are sent back through the socket.
//!
//! Because resolution is async and the poll loop is sync, queries are sent to
//! a background tokio task via a channel. Responses come back through another
//! channel and are written to the smoltcp socket on the next poll iteration.

use std::sync::Arc;

use bytes::Bytes;
use smoltcp::iface::{SocketHandle, SocketSet};
use smoltcp::socket::udp;
use smoltcp::storage::PacketMetadata;
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};
use tokio::sync::mpsc;

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
/// Owns the smoltcp UDP socket handle and channels to the async resolver
/// task. The poll loop calls [`process()`] each iteration to:
///
/// 1. Read pending queries from the smoltcp socket → send to resolver task.
/// 2. Read resolved responses from the channel → write to smoltcp socket.
///
/// [`process()`]: DnsInterceptor::process
pub struct DnsInterceptor {
    /// Handle to the smoltcp UDP socket bound to gateway:53.
    socket_handle: SocketHandle,
    /// Sends queries to the background resolver task.
    query_tx: mpsc::Sender<DnsQuery>,
    /// Receives responses from the background resolver task.
    response_rx: mpsc::Receiver<DnsResponse>,
}

/// A DNS query extracted from the smoltcp socket.
struct DnsQuery {
    /// Raw DNS message bytes.
    data: Bytes,
    /// Source endpoint (guest IP:port) for routing the response back.
    source: IpEndpoint,
}

/// A resolved DNS response ready to send back to the guest.
struct DnsResponse {
    /// Raw DNS response bytes.
    data: Bytes,
    /// Destination endpoint (guest IP:port).
    dest: IpEndpoint,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DnsInterceptor {
    /// Create the DNS interceptor.
    ///
    /// Binds a smoltcp UDP socket to port 53, creates the channel pair, and
    /// spawns the background resolver task.
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

        // Spawn background resolver task.
        tokio_handle.spawn(dns_resolver_task(query_rx, response_tx, dns_config, shared));

        Self {
            socket_handle,
            query_tx,
            response_rx,
        }
    }

    /// Process DNS queries and responses.
    ///
    /// Called by the poll loop each iteration:
    /// 1. Reads queries from the smoltcp socket → sends to resolver task.
    /// 2. Reads responses from the resolver → writes to smoltcp socket.
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
        while let Ok(response) = self.response_rx.try_recv() {
            if socket.can_send() {
                let _ = socket.send_slice(&response.data, response.dest);
            }
        }
    }

    /// Return the socket handle (for external use if needed).
    pub fn socket_handle(&self) -> SocketHandle {
        self.socket_handle
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Background task that resolves DNS queries using the host's resolvers.
///
/// Reads queries from the channel, applies domain filtering, resolves via
/// hickory-resolver, and sends responses back.
async fn dns_resolver_task(
    mut query_rx: mpsc::Receiver<DnsQuery>,
    response_tx: mpsc::Sender<DnsResponse>,
    dns_config: DnsConfig,
    shared: Arc<SharedState>,
) {
    // Create a system resolver that uses the host's /etc/resolv.conf.
    let resolver = match hickory_resolver::Resolver::builder_tokio().map(|b| b.build()) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!(error = %e, "failed to create DNS resolver");
            return;
        }
    };

    while let Some(query) = query_rx.recv().await {
        let response_tx = response_tx.clone();
        let dns_config = dns_config.clone();
        let shared = shared.clone();
        let resolver = resolver.clone();

        // Spawn a task per query for concurrency.
        tokio::spawn(async move {
            let result = resolve_query(&query.data, &dns_config, &resolver).await;
            match result {
                Some(response_data) => {
                    let response = DnsResponse {
                        data: response_data,
                        dest: query.source,
                    };
                    if response_tx.send(response).await.is_ok() {
                        shared.proxy_wake.wake();
                    }
                }
                None => {
                    // Query was blocked or failed — send SERVFAIL.
                    if let Some(servfail) = build_servfail(&query.data) {
                        let response = DnsResponse {
                            data: servfail,
                            dest: query.source,
                        };
                        if response_tx.send(response).await.is_ok() {
                            shared.proxy_wake.wake();
                        }
                    }
                }
            }
        });
    }
}

/// Resolve a single DNS query. Returns `None` if the domain is blocked.
async fn resolve_query(
    raw_query: &[u8],
    dns_config: &DnsConfig,
    resolver: &hickory_resolver::TokioResolver,
) -> Option<Bytes> {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::BinDecodable;

    // Parse the DNS query.
    let query_msg = Message::from_bytes(raw_query).ok()?;
    let query_id = query_msg.id();

    // Extract the queried domain name.
    let question = query_msg.queries().first()?;
    let domain = question.name().to_string();
    let domain = domain.trim_end_matches('.');

    // Check domain block lists.
    if is_domain_blocked(domain, dns_config) {
        tracing::debug!(domain = %domain, "DNS query blocked");
        return None;
    }

    // Forward the raw query to the host resolver by performing a lookup.
    // We use the parsed question to do a proper lookup via hickory-resolver.
    let record_type = question.query_type();

    let lookup = resolver
        .lookup(question.name().clone(), record_type)
        .await
        .ok()?;

    // Build a DNS response message from the lookup result.
    let mut response_msg = query_msg.clone();
    response_msg.set_id(query_id);
    response_msg.set_message_type(hickory_proto::op::MessageType::Response);
    response_msg.set_response_code(hickory_proto::op::ResponseCode::NoError);
    response_msg.set_recursion_available(true);

    // Add answer records.
    let answers: Vec<_> = lookup.records().to_vec();
    response_msg.insert_answers(answers);

    // Serialize the response.
    use hickory_proto::serialize::binary::BinEncodable;
    let response_bytes = response_msg.to_bytes().ok()?;

    Some(Bytes::from(response_bytes))
}

/// Check if a domain is blocked by the DNS config.
fn is_domain_blocked(domain: &str, config: &DnsConfig) -> bool {
    let domain_lower = domain.to_lowercase();

    // Check exact domain matches.
    if config
        .blocked_domains
        .iter()
        .any(|d| d.to_lowercase() == domain_lower)
    {
        return true;
    }

    // Check suffix matches.
    if config.blocked_suffixes.iter().any(|suffix| {
        let suffix_lower = suffix.to_lowercase();
        let suffix_lower = suffix_lower.trim_start_matches('.');
        domain_lower == suffix_lower || domain_lower.ends_with(&format!(".{suffix_lower}"))
    }) {
        return true;
    }

    false
}

/// Build a SERVFAIL response for a query that was blocked or failed.
fn build_servfail(raw_query: &[u8]) -> Option<Bytes> {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

    let query_msg = Message::from_bytes(raw_query).ok()?;
    let mut response = query_msg.clone();
    response.set_message_type(hickory_proto::op::MessageType::Response);
    response.set_response_code(hickory_proto::op::ResponseCode::ServFail);
    response.set_recursion_available(true);

    let bytes = response.to_bytes().ok()?;
    Some(Bytes::from(bytes))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_domain_blocked() {
        let config = DnsConfig {
            blocked_domains: vec!["evil.com".to_string()],
            blocked_suffixes: vec![],
            rebind_protection: false,
        };
        assert!(is_domain_blocked("evil.com", &config));
        assert!(is_domain_blocked("Evil.COM", &config));
        assert!(!is_domain_blocked("not-evil.com", &config));
        assert!(!is_domain_blocked("sub.evil.com", &config));
    }

    #[test]
    fn test_suffix_domain_blocked() {
        let config = DnsConfig {
            blocked_domains: vec![],
            blocked_suffixes: vec![".evil.com".to_string()],
            rebind_protection: false,
        };
        assert!(is_domain_blocked("sub.evil.com", &config));
        assert!(is_domain_blocked("deep.sub.evil.com", &config));
        assert!(is_domain_blocked("evil.com", &config));
        assert!(!is_domain_blocked("notevil.com", &config));
    }

    #[test]
    fn test_no_blocks_nothing_blocked() {
        let config = DnsConfig::default();
        assert!(!is_domain_blocked("anything.com", &config));
    }
}
