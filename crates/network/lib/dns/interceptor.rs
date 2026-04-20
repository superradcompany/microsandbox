//! DNS query interception, filtering, and forwarding.
//!
//! The [`DnsInterceptor`] bridges the smoltcp UDP socket (bound to
//! gateway:53) and the host's upstream DNS servers via [`hickory_client`].
//!
//! Design: the interceptor is a **forwarder**, not a stub resolver. The
//! guest's OS already has its own stub (musl, glibc NSS, systemd-resolved)
//! running its own retry/cache/parallel-A+AAAA logic. This code's job is
//! to speak DNS on the wire and get out of the way. Queries are forwarded
//! verbatim upstream; responses are echoed back with their original RCODE,
//! authority section, EDNS OPT records, and answer records intact. Only
//! the local-policy cases (block list, rebind protection) synthesize a
//! response locally (REFUSED); transport failures synthesize SERVFAIL.
//!
//! Because resolution is async and the smoltcp poll loop is sync, queries
//! are sent to a background tokio task via a channel. Responses come back
//! through another channel and are written to the smoltcp socket on the
//! next poll iteration.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use hickory_client::client::Client;
use hickory_client::proto::op::{Message, MessageType, ResponseCode};
use hickory_client::proto::rr::RData;
use hickory_client::proto::runtime::TokioRuntimeProvider;
use hickory_client::proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_client::proto::udp::UdpClientStream;
use hickory_client::proto::xfer::{DnsHandle, DnsRequest};
use resolv_conf::Config as ResolvConfig;
use smoltcp::iface::SocketSet;
use smoltcp::socket::udp;
use smoltcp::storage::PacketMetadata;
use smoltcp::wire::{IpEndpoint, IpListenEndpoint};
use tokio::sync::mpsc;

use crate::config::DnsConfig;
use crate::dns::parse::NameserverSpec;
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

/// Path to the host resolver configuration. Used as a fallback when
/// [`DnsConfig::nameservers`] is empty.
const RESOLV_CONF_PATH: &str = "/etc/resolv.conf";

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

/// Pre-processed DNS config with lowercased block lists (avoids per-query allocations).
struct NormalizedDnsConfig {
    /// O(1) exact-match lookup for blocked domains.
    blocked_domains: HashSet<String>,
    /// Lowercased suffixes WITHOUT leading dot (for exact match against the suffix itself).
    blocked_suffixes: Vec<String>,
    /// Dot-prefixed lowercased suffixes (for `ends_with` matching without per-query `format!`).
    blocked_suffixes_dotted: Vec<String>,
    rebind_protection: bool,
    /// Explicit nameservers (unresolved specs). Empty means fall back to
    /// the host's `/etc/resolv.conf`. Hostnames are resolved once at
    /// forwarder-task startup via the host's own resolver.
    nameservers: Vec<NameserverSpec>,
    /// Per-query timeout.
    query_timeout: Duration,
}

/// A DNS query extracted from the smoltcp socket.
struct DnsQuery {
    /// Raw DNS message bytes.
    data: Bytes,
    /// Source endpoint (guest IP:port) for routing the response back.
    source: IpEndpoint,
}

/// A forwarded DNS response ready to send back to the guest.
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
            nameservers: dns_config.nameservers.clone(),
            query_timeout: Duration::from_millis(dns_config.query_timeout_ms),
        });

        // Spawn background forwarder task.
        tokio_handle.spawn(dns_forwarder_task(
            query_rx,
            response_tx,
            normalized,
            shared,
        ));

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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Background task that forwards DNS queries to the host's upstream
/// resolver and sends responses back to the guest.
///
/// Sets up a single [`Client`] connected to the first configured upstream.
/// `Client` is cheaply cloneable (it's a handle to a shared multiplexer),
/// so each incoming query is handled in its own task for concurrency.
async fn dns_forwarder_task(
    mut query_rx: mpsc::Receiver<DnsQuery>,
    response_tx: mpsc::Sender<DnsResponse>,
    dns_config: Arc<NormalizedDnsConfig>,
    shared: Arc<SharedState>,
) {
    let upstreams = if !dns_config.nameservers.is_empty() {
        match resolve_specs(&dns_config.nameservers).await {
            Ok(s) if !s.is_empty() => s,
            Ok(_) => {
                tracing::error!("no configured nameservers resolved to an address");
                return;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to resolve configured nameservers");
                return;
            }
        }
    } else {
        match read_host_dns_servers().await {
            Ok(s) if !s.is_empty() => s,
            Ok(_) => {
                tracing::error!("no upstream DNS servers discovered from host");
                return;
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to read host DNS configuration");
                return;
            }
        }
    };

    // Use the first upstream. If it's unhealthy the guest's stub will
    // observe SERVFAIL and fall through to its own next nameserver.
    let upstream = upstreams[0];
    let stream =
        UdpClientStream::<TokioRuntimeProvider>::builder(upstream, TokioRuntimeProvider::new())
            .with_timeout(Some(dns_config.query_timeout))
            .build();
    let (client, bg) = match Client::connect(stream).await {
        Ok(pair) => pair,
        Err(e) => {
            tracing::error!(upstream = %upstream, error = %e, "failed to connect to upstream DNS");
            return;
        }
    };
    tokio::spawn(bg);

    while let Some(query) = query_rx.recv().await {
        let response_tx = response_tx.clone();
        let dns_config = dns_config.clone();
        let shared = shared.clone();
        let client = client.clone();

        // Spawn a task per query for concurrency.
        tokio::spawn(async move {
            if let Some(data) = handle_query(&query.data, &dns_config, &client).await {
                let response = DnsResponse {
                    data,
                    dest: query.source,
                };
                if response_tx.send(response).await.is_ok() {
                    shared.proxy_wake.wake();
                }
            }
        });
    }
}

/// Handle a single DNS query: parse, apply local policy, forward upstream,
/// and build the wire response. Returns `None` only when even synthesising
/// a local error response fails (malformed query bytes).
async fn handle_query(
    raw_query: &[u8],
    dns_config: &NormalizedDnsConfig,
    client: &Client,
) -> Option<Bytes> {
    let query_msg = Message::from_bytes(raw_query).ok()?;
    let guest_id = query_msg.id();

    let question = query_msg.queries().first()?;
    let domain = question.name().to_string();
    let domain = domain.trim_end_matches('.').to_owned();

    // Local policy: block list → synthesize REFUSED.
    if is_domain_blocked(&domain, dns_config) {
        tracing::debug!(domain = %domain, "DNS query blocked by policy");
        return build_status_response(&query_msg, ResponseCode::Refused);
    }

    // Forward upstream. hickory-client's multiplexer assigns its own
    // transaction id; we rewrite the response id back to the guest's
    // below.
    let mut send = client.send(DnsRequest::from(query_msg.clone()));
    let response = match send.next().await {
        Some(Ok(resp)) => resp,
        Some(Err(e)) => {
            tracing::warn!(domain = %domain, error = %e, "upstream DNS send failed");
            return build_status_response(&query_msg, ResponseCode::ServFail);
        }
        None => {
            tracing::warn!(domain = %domain, "upstream DNS closed stream without a response");
            return build_status_response(&query_msg, ResponseCode::ServFail);
        }
    };
    let mut response_msg: Message = response.into();

    // Rebind protection: reject responses containing private/reserved IPs.
    if dns_config.rebind_protection {
        for record in response_msg.answers() {
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
                return build_status_response(&query_msg, ResponseCode::Refused);
            }
        }
    }

    // Preserve the guest's transaction id.
    response_msg.set_id(guest_id);

    response_msg.to_bytes().ok().map(Bytes::from)
}

/// Build a status-only response (no answers, no authority) with the given
/// RCODE. Used for locally-synthesized REFUSED (policy) and SERVFAIL
/// (upstream unreachable). The guest's transaction id, OPCODE and RD bit
/// are echoed.
fn build_status_response(query: &Message, rcode: ResponseCode) -> Option<Bytes> {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_op_code(query.op_code());
    response.set_recursion_desired(query.recursion_desired());
    response.set_message_type(MessageType::Response);
    response.set_response_code(rcode);
    response.set_recursion_available(true);
    if let Some(q) = query.queries().first() {
        response.add_query(q.clone());
    }
    response.to_bytes().ok().map(Bytes::from)
}

/// Read the host's configured DNS servers as `SocketAddr`s on port 53.
///
/// On macOS the authoritative source is `SystemConfiguration.framework`
/// (the dynamic store `configd` maintains), not `/etc/resolv.conf` —
/// VPN + split-DNS setups leave the file either stale or pointing at
/// only one leg of the resolver table. We query
/// `State:/Network/Global/DNS` first and only fall back to the file if
/// the dynamic store is unavailable or reports no servers.
///
/// On Linux the file is authoritative.
async fn read_host_dns_servers() -> std::io::Result<Vec<SocketAddr>> {
    #[cfg(target_os = "macos")]
    {
        match super::scdynamicstore::read_dns_servers() {
            Ok(servers) if !servers.is_empty() => {
                tracing::debug!(
                    count = servers.len(),
                    "loaded nameservers from SCDynamicStore"
                );
                return Ok(servers);
            }
            Ok(_) => {
                tracing::debug!(
                    "SCDynamicStore returned no nameservers; falling back to /etc/resolv.conf"
                );
            }
            Err(e) => {
                tracing::debug!(
                    error = %e,
                    "SCDynamicStore lookup failed; falling back to /etc/resolv.conf"
                );
            }
        }
    }
    read_resolv_conf(Path::new(RESOLV_CONF_PATH)).await
}

/// Parse a `resolv.conf`-format file and return the `nameserver` entries
/// as `SocketAddr`s on port 53. Uses the same parser as hickory-resolver
/// does internally (`resolv-conf` crate), but without pulling hickory's
/// stub-resolver machinery along with it.
async fn read_resolv_conf(path: &Path) -> std::io::Result<Vec<SocketAddr>> {
    let bytes = tokio::fs::read(path).await?;
    let cfg = ResolvConfig::parse(&bytes)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
    Ok(cfg
        .nameservers
        .into_iter()
        .map(|ns| SocketAddr::new(IpAddr::from(ns), DNS_PORT))
        .collect())
}

/// Resolve a list of [`NameserverSpec`]s to concrete `SocketAddr`s.
///
/// Hostnames are looked up via the host's OS resolver (via
/// [`tokio::net::lookup_host`]), never via this interceptor. this
/// bootstrap path must not depend on us being already running.
/// Individual lookup failures are logged and skipped; the whole
/// operation errors only if every entry fails.
async fn resolve_specs(specs: &[NameserverSpec]) -> std::io::Result<Vec<SocketAddr>> {
    let mut out = Vec::with_capacity(specs.len());
    let mut last_err: Option<std::io::Error> = None;
    for spec in specs {
        match spec.resolve().await {
            Ok(sa) => out.push(sa),
            Err(e) => {
                tracing::warn!(spec = %spec, error = %e, "failed to resolve nameserver spec");
                last_err = Some(e);
            }
        }
    }
    if out.is_empty()
        && let Some(e) = last_err
    {
        return Err(e);
    }
    Ok(out)
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_client::proto::op::{MessageType, OpCode, Query};
    use hickory_client::proto::rr::{DNSClass, Name, RecordType};

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
            nameservers: Vec::<NameserverSpec>::new(),
            query_timeout: Duration::from_millis(5000),
        }
    }

    fn make_query(name: &str, qtype: RecordType) -> Message {
        let mut msg = Message::new();
        msg.set_id(0x4242);
        msg.set_message_type(MessageType::Query);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        let parsed = Name::from_ascii(name).expect("valid dns name");
        let mut q = Query::new();
        q.set_name(parsed);
        q.set_query_type(qtype);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);
        msg
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

    #[test]
    fn build_status_response_preserves_header_and_question() {
        let query = make_query("slack.com.", RecordType::AAAA);
        let bytes = build_status_response(&query, ResponseCode::Refused).expect("built");
        let msg = Message::from_bytes(&bytes).expect("parse response");
        assert_eq!(msg.id(), 0x4242);
        assert_eq!(msg.response_code(), ResponseCode::Refused);
        assert_eq!(msg.message_type(), MessageType::Response);
        assert_eq!(msg.op_code(), OpCode::Query);
        assert!(msg.recursion_desired());
        assert!(msg.recursion_available());
        assert_eq!(msg.queries().len(), 1);
        assert_eq!(msg.queries()[0].query_type(), RecordType::AAAA);
        assert_eq!(msg.answers().len(), 0);
    }

    #[test]
    fn build_status_response_servfail_variant() {
        let query = make_query("example.com.", RecordType::A);
        let bytes = build_status_response(&query, ResponseCode::ServFail).expect("built");
        let msg = Message::from_bytes(&bytes).expect("parse response");
        assert_eq!(msg.response_code(), ResponseCode::ServFail);
        assert_eq!(msg.answers().len(), 0);
    }

    #[tokio::test]
    async fn read_resolv_conf_parses_nameservers() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("msb-resolv-{}.conf", std::process::id()));
        std::fs::write(
            &path,
            "# comment line\n\
             nameserver 1.1.1.1\n\
             nameserver 8.8.8.8  # inline comment\n\
             search example.com\n\
             options ndots:5\n\
             nameserver 2606:4700:4700::1111\n\
             \n",
        )
        .unwrap();

        let servers = read_resolv_conf(&path).await.expect("read ok");
        std::fs::remove_file(&path).ok();

        assert_eq!(servers.len(), 3);
        assert_eq!(servers[0], "1.1.1.1:53".parse().unwrap());
        assert_eq!(servers[1], "8.8.8.8:53".parse().unwrap());
        assert_eq!(servers[2], "[2606:4700:4700::1111]:53".parse().unwrap());
    }

    #[tokio::test]
    async fn read_resolv_conf_missing_file_errs() {
        assert!(
            read_resolv_conf(Path::new("/nonexistent/path/to/resolv.conf"))
                .await
                .is_err()
        );
    }
}
