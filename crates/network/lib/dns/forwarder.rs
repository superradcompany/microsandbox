//! Async DNS forwarder: per-query handling against an upstream resolver.
//!
//! The forwarder is the middle of the data flow: the [`DnsInterceptor`]
//! feeds raw query bytes in via a channel, the forwarder talks to an
//! upstream resolver over UDP, and the response bytes go back out
//! through another channel to be written to the smoltcp socket.
//!
//! The forwarder is a **forwarder**, not a stub resolver: the guest's OS
//! already runs its own stub. Queries are forwarded verbatim; upstream
//! responses are echoed back with their original RCODE, authority
//! section, EDNS OPT records, and answer records intact. Only the
//! local-policy cases (block list, rebind protection) synthesize a
//! response locally (REFUSED); transport failures synthesize SERVFAIL.
//!
//! [`DnsInterceptor`]: super::interceptor::DnsInterceptor

use std::collections::HashSet;
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
use tokio::sync::mpsc;

use super::filter::{is_domain_blocked, is_private_ipv4, is_private_ipv6};
use super::interceptor::{DnsQuery, DnsResponse};
use super::parse::Nameserver;
use super::upstream::{read_host_dns_servers, resolve_nameservers};
use crate::config::DnsConfig;
use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Pre-processed DNS config with lowercased block lists (avoids per-query allocations).
///
/// Fields are `pub(super)` so sibling modules (filter, tests) can read
/// them directly; construction should go through [`Self::from_config`].
pub(super) struct NormalizedDnsConfig {
    /// O(1) exact-match lookup for blocked domains.
    pub(super) blocked_domains: HashSet<String>,
    /// Lowercased suffixes WITHOUT leading dot (for exact match against the suffix itself).
    pub(super) blocked_suffixes: Vec<String>,
    /// Dot-prefixed lowercased suffixes (for `ends_with` matching without per-query `format!`).
    pub(super) blocked_suffixes_dotted: Vec<String>,
    pub(super) rebind_protection: bool,
    /// Explicit nameservers (unresolved specs). Empty means fall back to
    /// the host's configured resolvers. Hostnames are resolved once at
    /// forwarder-task startup via the host's own resolver.
    pub(super) nameservers: Vec<Nameserver>,
    /// Per-query timeout.
    pub(super) query_timeout: Duration,
}

impl NormalizedDnsConfig {
    /// Build a normalized config from a raw [`DnsConfig`]. Lowercases and
    /// dot-prefixes the block lists once, up-front, so the query path
    /// doesn't allocate per match.
    pub(super) fn from_config(config: DnsConfig) -> Self {
        let blocked_suffixes: Vec<String> = config
            .blocked_suffixes
            .iter()
            .map(|s| s.to_lowercase().trim_start_matches('.').to_string())
            .collect();
        let blocked_suffixes_dotted: Vec<String> =
            blocked_suffixes.iter().map(|s| format!(".{s}")).collect();
        Self {
            blocked_domains: config
                .blocked_domains
                .into_iter()
                .map(|d| d.to_lowercase())
                .collect(),
            blocked_suffixes,
            blocked_suffixes_dotted,
            rebind_protection: config.rebind_protection,
            nameservers: config.nameservers,
            query_timeout: Duration::from_millis(config.query_timeout_ms),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn the forwarder task on the given tokio runtime. Takes ownership
/// of the query receiver and response sender used by the interceptor.
pub(super) fn spawn(
    handle: &tokio::runtime::Handle,
    query_rx: mpsc::Receiver<DnsQuery>,
    response_tx: mpsc::Sender<DnsResponse>,
    config: Arc<NormalizedDnsConfig>,
    shared: Arc<SharedState>,
) {
    handle.spawn(dns_forwarder_task(query_rx, response_tx, config, shared));
}

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
        match resolve_nameservers(&dns_config.nameservers).await {
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_client::proto::op::{MessageType, OpCode, Query};
    use hickory_client::proto::rr::{DNSClass, Name, RecordType};

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
}
