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

use std::collections::HashSet;
use std::sync::Arc;

use bytes::Bytes;
use smoltcp::iface::SocketSet;
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
    socket_handle: smoltcp::iface::SocketHandle,
    /// Sends queries to the background resolver task.
    query_tx: mpsc::Sender<DnsQuery>,
    /// Receives responses from the background resolver task.
    response_rx: mpsc::Receiver<DnsResponse>,
}

/// Pre-processed DNS config with lowercased block lists (avoids per-query allocations).
struct NormalizedDnsConfig {
    /// O(1) exact-match lookup for blocked domains.
    blocked_domains: HashSet<String>,
    /// Lowercased suffixes WITHOUT leading dot (for exact match against the suffix itself).
    blocked_suffixes: Vec<String>,
    /// Dot-prefixed lowercased suffixes (for `ends_with` matching without per-query `format!`).
    blocked_suffixes_dotted: Vec<String>,
    rebind_protection: bool,
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

        // Pre-lowercase block lists once to avoid per-query allocations.
        let suffixes: Vec<String> = dns_config
            .blocked_suffixes
            .iter()
            .map(|s| s.to_lowercase().trim_start_matches('.').to_string())
            .collect();
        let suffixes_dotted: Vec<String> = suffixes.iter().map(|s| format!(".{s}")).collect();
        let normalized = Arc::new(NormalizedDnsConfig {
            blocked_domains: dns_config
                .blocked_domains
                .iter()
                .map(|d| d.to_lowercase())
                .collect(),
            blocked_suffixes: suffixes,
            blocked_suffixes_dotted: suffixes_dotted,
            rebind_protection: dns_config.rebind_protection,
        });

        // Spawn background resolver task.
        tokio_handle.spawn(dns_resolver_task(query_rx, response_tx, normalized, shared));

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
    dns_config: Arc<NormalizedDnsConfig>,
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
                    // Query was blocked or failed — send REFUSED.
                    if let Some(servfail) = build_refused(&query.data) {
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

/// Resolve a single DNS query. Returns `None` if the domain is blocked
/// or contains rebind-protected addresses.
async fn resolve_query(
    raw_query: &[u8],
    dns_config: &NormalizedDnsConfig,
    resolver: &hickory_resolver::TokioResolver,
) -> Option<Bytes> {
    use hickory_proto::op::Message;
    use hickory_proto::rr::RData;
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

    // DNS rebind protection: reject responses containing private/reserved IPs.
    if dns_config.rebind_protection {
        for record in lookup.records() {
            let is_private = match record.data() {
                RData::A(a) => is_private_ipv4((*a).into()),
                RData::AAAA(aaaa) => is_private_ipv6((*aaaa).into()),
                _ => false,
            };
            if is_private {
                tracing::debug!(
                    domain = %domain,
                    "DNS rebind protection: response contains private IP"
                );
                return None;
            }
        }
    }

    // Build a fresh DNS response (avoids cloning the entire query message).
    let mut response_msg = Message::new();
    response_msg.set_id(query_id);
    response_msg.set_message_type(hickory_proto::op::MessageType::Response);
    response_msg.set_op_code(query_msg.op_code());
    response_msg.set_response_code(hickory_proto::op::ResponseCode::NoError);
    response_msg.set_recursion_desired(query_msg.recursion_desired());
    response_msg.set_recursion_available(true);
    response_msg.add_query(question.clone());

    // Add answer records.
    let answers: Vec<_> = lookup.records().to_vec();
    response_msg.insert_answers(answers);

    // Serialize the response.
    use hickory_proto::serialize::binary::BinEncodable;
    let response_bytes = response_msg.to_bytes().ok()?;

    Some(Bytes::from(response_bytes))
}

/// Check if an IPv4 address is in a private/reserved range (for rebind protection).
fn is_private_ipv4(addr: std::net::Ipv4Addr) -> bool {
    let octets = addr.octets();
    addr.is_loopback()                                        // 127.0.0.0/8
        || octets[0] == 10                                    // 10.0.0.0/8
        || (octets[0] == 172 && (octets[1] & 0xf0) == 16)    // 172.16.0.0/12
        || (octets[0] == 192 && octets[1] == 168)             // 192.168.0.0/16
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64)    // 100.64.0.0/10 (CGNAT)
        || (octets[0] == 169 && octets[1] == 254)             // 169.254.0.0/16 (link-local)
        || addr.is_unspecified() // 0.0.0.0
}

/// Check if an IPv6 address is in a private/reserved range (for rebind protection).
fn is_private_ipv6(addr: std::net::Ipv6Addr) -> bool {
    let segments = addr.segments();
    addr.is_loopback()                       // ::1
        || (segments[0] & 0xfe00) == 0xfc00  // fc00::/7 (ULA)
        || (segments[0] & 0xffc0) == 0xfe80  // fe80::/10 (link-local)
        || addr.is_unspecified() // ::
}

/// Check if a domain is blocked by the DNS config.
///
/// Block lists are pre-lowercased in [`NormalizedDnsConfig`], so only the
/// queried domain needs lowercasing (once per query instead of per entry).
fn is_domain_blocked(domain: &str, config: &NormalizedDnsConfig) -> bool {
    let domain_lower = domain.to_lowercase();

    // Check exact domain matches — O(1) via HashSet.
    if config.blocked_domains.contains(&domain_lower) {
        return true;
    }

    // Check suffix matches (already lowercased with pre-computed dot-prefixed forms).
    for (suffix, dotted) in config
        .blocked_suffixes
        .iter()
        .zip(config.blocked_suffixes_dotted.iter())
    {
        if domain_lower == *suffix || domain_lower.ends_with(dotted.as_str()) {
            return true;
        }
    }

    false
}

/// Build a REFUSED response for a query that was blocked by policy.
///
/// Uses REFUSED (RCODE 5) instead of SERVFAIL (RCODE 2) because the
/// refusal is a policy decision, not a server failure. Most stub resolvers
/// do not retry REFUSED, avoiding unnecessary latency.
fn build_refused(raw_query: &[u8]) -> Option<Bytes> {
    use hickory_proto::op::Message;
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};

    let query_msg = Message::from_bytes(raw_query).ok()?;
    let mut response = Message::new();
    response.set_id(query_msg.id());
    for q in query_msg.queries() {
        response.add_query(q.clone());
    }
    response.set_message_type(hickory_proto::op::MessageType::Response);
    response.set_response_code(hickory_proto::op::ResponseCode::Refused);
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

    fn normalized(domains: Vec<&str>, suffixes: Vec<&str>) -> NormalizedDnsConfig {
        let blocked_suffixes: Vec<String> = suffixes
            .iter()
            .map(|s| s.to_lowercase().trim_start_matches('.').to_string())
            .collect();
        let blocked_suffixes_dotted = blocked_suffixes.iter().map(|s| format!(".{s}")).collect();
        NormalizedDnsConfig {
            blocked_domains: domains
                .iter()
                .map(|d| d.to_lowercase())
                .collect::<HashSet<_>>(),
            blocked_suffixes,
            blocked_suffixes_dotted,
            rebind_protection: false,
        }
    }

    #[test]
    fn test_exact_domain_blocked() {
        let config = normalized(vec!["evil.com"], vec![]);
        assert!(is_domain_blocked("evil.com", &config));
        assert!(is_domain_blocked("Evil.COM", &config));
        assert!(!is_domain_blocked("not-evil.com", &config));
        assert!(!is_domain_blocked("sub.evil.com", &config));
    }

    #[test]
    fn test_suffix_domain_blocked() {
        let config = normalized(vec![], vec![".evil.com"]);
        assert!(is_domain_blocked("sub.evil.com", &config));
        assert!(is_domain_blocked("deep.sub.evil.com", &config));
        assert!(is_domain_blocked("evil.com", &config));
        assert!(!is_domain_blocked("notevil.com", &config));
    }

    #[test]
    fn test_no_blocks_nothing_blocked() {
        let config = normalized(vec![], vec![]);
        assert!(!is_domain_blocked("anything.com", &config));
    }
}
