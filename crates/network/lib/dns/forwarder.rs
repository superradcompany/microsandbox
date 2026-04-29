//! Async DNS forwarder: per-query handling with policy-gated upstream.
//!
//! The forwarder is the middle of the data flow: the three proxies
//! ([`super::proxies::udp::UdpProxy`],
//! [`super::proxies::tcp::TcpProxy`],
//! [`super::proxies::dot::DotProxy`]) feed raw query bytes in, the
//! forwarder parses them, applies the configured block list, decides
//! which upstream resolver to use, talks to that upstream, and returns
//! the wire response bytes for the caller to send back to the guest.
//!
//! Upstream selection per query:
//! - If the guest aimed at the sandbox gateway IP (the implicit
//!   "use whatever resolver this network gave me" case), forward via
//!   the operator-configured upstream.
//! - Otherwise the guest explicitly chose a resolver via `@target`.
//!   Consult the network egress policy: if the resolver IP is allowed,
//!   forward there directly; if denied, return REFUSED.
//!
//! Block list and rebind protection apply to every query/response
//! regardless of which path was taken — the host always sees the
//! traffic in the clear and can refuse it. UDP responses that exceed
//! the guest's advertised EDNS buffer are truncated (TC=1) so the stub
//! retries over TCP through the same forwarder.
//!
//! [`DnsInterceptor`]: super::interceptor::DnsInterceptor

use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use hickory_client::client::Client;
use hickory_client::proto::op::{Message, MessageType, ResponseCode};
use hickory_client::proto::rr::rdata::{A, AAAA};
use hickory_client::proto::rr::{RData, Record, RecordType};
use hickory_client::proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_client::proto::xfer::{DnsHandle, DnsRequest};
use tokio::sync::{OnceCell, watch};

use super::client::{build_direct_client, build_tcp_client, build_udp_client};
use super::common::config::NormalizedDnsConfig;
use super::common::filter::{is_private_ipv4, is_private_ipv6};
use super::common::transport::Transport;
use super::nameserver::{read_host_dns_servers, resolve_nameservers};
use crate::policy::{DomainName, NetworkPolicy};
use crate::shared::{ResolvedHostnameFamily, SharedState};
use crate::stack::GatewayIps;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Policy grace floor for DNS-derived resolved hostnames.
///
/// This is intentionally **not** DNS semantics. Resolved-hostname
/// lifetimes normally follow the upstream response TTL, but when that
/// TTL is zero we keep the entry alive for a very short window so an
/// immediate connect following a successful DNS lookup does not fail
/// closed before the guest can use the answer.
const RESOLVED_HOSTNAME_MIN_TTL_SECS: u32 = 1;

/// TTL for locally-synthesized `host.microsandbox.internal` answers. Short
/// enough that the guest re-resolves often, long enough to avoid hammering
/// the forwarder on each connection.
const HOST_ALIAS_TTL_SECS: u32 = 60;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Shared handle to the DNS forwarder, populated once the configured
/// upstream connection succeeds. Both the UDP interceptor's per-query
/// tasks and the TCP/53 proxy clone this handle and `await` the
/// forwarder before serving any query.
///
/// Stays at `None` if upstream init fails; consumers observe that as
/// "drop the query" (UDP) or "close the connection" (TCP).
pub(crate) type DnsForwarderHandle = watch::Receiver<Option<Arc<DnsForwarder>>>;

/// Owns the operator-configured upstream client(s), gateway IP set,
/// network policy, and normalized DNS config. Cheaply cloneable via
/// `Arc`.
pub(crate) struct DnsForwarder {
    /// Configured UDP upstream (operator-set nameserver or the host's
    /// resolver). Used when the guest queried the gateway IP.
    configured_udp: Client,
    /// Lazy configured TCP upstream. Built on first TCP query aimed at
    /// the gateway; many sandboxes never use TCP DNS at all, so we
    /// don't pay the handshake cost up front.
    configured_tcp: OnceCell<Client>,
    /// SocketAddr of the configured upstream — needed to build
    /// `configured_tcp` on demand and for diagnostic logging.
    configured_upstream: SocketAddr,
    /// Set of gateway IPs (v4 + v6). Queries to these IPs go through
    /// the configured upstream; queries to other IPs go through the
    /// direct path subject to network egress policy.
    gateway_ips: Arc<HashSet<IpAddr>>,
    /// Network policy. Direct-path queries consult this for outbound
    /// permission to the chosen `@target` resolver IP.
    network_policy: Arc<NetworkPolicy>,
    /// Cross-thread network state. Used both for policy evaluation on
    /// the direct-upstream path (Domain rules may match the resolver IP
    /// if the guest resolved it) and for caching the resolved addresses
    /// from upstream answers so Domain rules can match on subsequent
    /// guest connects.
    shared: Arc<SharedState>,
    /// Gateway IPs returned as A / AAAA answers when the guest asks for
    /// `host.microsandbox.internal`.
    gateway: GatewayIps,
    /// Whether the host can route external IPv6 traffic.
    host_ipv6_egress: bool,
    config: Arc<NormalizedDnsConfig>,
}

/// Outcome of upstream selection. The query may be forwarded through a
/// [`Client`], synthesized as REFUSED (policy denied the resolver IP),
/// or synthesized as SERVFAIL (couldn't reach upstream).
enum UpstreamChoice {
    Client(Client),
    Refused,
    ServFail,
}

/// Pure routing decision: where should this query go, given the guest's
/// chosen target and the policy. Extracted from [`DnsForwarder`] so the
/// rule logic is testable without spinning up a real upstream client.
#[derive(Debug, PartialEq, Eq)]
enum UpstreamDecision {
    /// Use the operator-configured upstream.
    Configured,
    /// Forward directly to this resolver IP over the matching transport.
    Direct(SocketAddr),
    /// Network policy denied egress to the chosen resolver — synthesize
    /// REFUSED.
    Refused,
}

impl DnsForwarder {
    /// Process a single raw DNS query: parse, apply block list, select
    /// upstream, forward, apply rebind protection, optionally truncate
    /// for UDP, and return the wire response. Returns `None` only when
    /// even synthesising a local error response fails (malformed bytes
    /// the parser couldn't recover anything from).
    /// `sni` is only consulted on the `Transport::Dot` direct path —
    /// it's threaded into the upstream TLS client as the server name
    /// for certificate verification. `None` falls back to the target
    /// IP as a string. UDP and plain TCP callers pass `None`.
    pub(crate) async fn forward(
        &self,
        raw_query: &[u8],
        original_dst: Option<IpAddr>,
        transport: Transport,
        sni: Option<&str>,
    ) -> Option<Bytes> {
        let query_msg = Message::from_bytes(raw_query).ok()?;
        let guest_id = query_msg.id();

        let question = query_msg.queries().first()?;
        let query_type = question.query_type();
        let domain = question.name().to_string();
        let domain = domain.trim_end_matches('.').to_owned();

        // Refuse queries denied by the network policy.
        if let Ok(canonical) = domain.parse::<DomainName>()
            && self.network_policy.dns_query_denied(&canonical)
        {
            tracing::debug!(domain = %domain, "DNS query refused by network policy");
            return build_status_response(&query_msg, ResponseCode::Refused);
        }

        // Locally synthesize answers for the host alias; MX / TXT / etc.
        // fall through to upstream.
        if is_host_alias_query(&domain)
            && let Some(response) =
                synthesize_host_alias_response(&query_msg, self.gateway, query_type)
        {
            return Some(response);
        }

        if should_suppress_aaaa(&domain, query_type, self.host_ipv6_egress) {
            tracing::debug!(
                domain = %domain,
                "suppressing external AAAA response because host IPv6 egress is unavailable"
            );
            self.shared
                .clear_resolved_hostname(&domain, ResolvedHostnameFamily::Ipv6);
            return build_empty_noerror_response(&query_msg);
        }

        // Pick upstream client based on where the guest aimed and the
        // network policy.
        let client = match self.select_upstream(original_dst, transport, sni).await {
            UpstreamChoice::Client(c) => c,
            UpstreamChoice::Refused => {
                tracing::debug!(
                    domain = %domain,
                    ?original_dst,
                    "DNS resolver denied by network policy"
                );
                return build_status_response(&query_msg, ResponseCode::Refused);
            }
            UpstreamChoice::ServFail => {
                return build_status_response(&query_msg, ResponseCode::ServFail);
            }
        };

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
        if self.config.rebind_protection {
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

        // Cache the resolved addresses so policy `Domain` /
        // `DomainSuffix` rules can later match when the guest connects
        // to one of them.
        if let Some(family) = family_for_query_type(query_type) {
            if let Some((addrs, ttl)) = extract_addrs_and_ttl(&response_msg, family) {
                self.shared
                    .cache_resolved_hostname(&domain, family, addrs, ttl);
            } else {
                self.shared.clear_resolved_hostname(&domain, family);
            }
        }

        // Preserve the guest's transaction id.
        response_msg.set_id(guest_id);
        let response_bytes = response_msg.to_bytes().ok()?;

        // UDP truncation: if the wire response exceeds the buffer the
        // guest advertised via EDNS (default 512 if no OPT), reply with
        // a header-only response carrying TC=1 and the original
        // question; the stub retries over TCP, which we also intercept.
        if transport == Transport::Udp {
            let max_size = query_msg.max_payload() as usize;
            if response_bytes.len() > max_size {
                tracing::debug!(
                    domain = %domain,
                    response_size = response_bytes.len(),
                    advertised = max_size,
                    "DNS response exceeds guest UDP buffer; setting TC=1"
                );
                return build_truncated_response(&query_msg).map(Bytes::from);
            }
        }

        Some(Bytes::from(response_bytes))
    }

    /// Resolve a routing decision into a concrete upstream client.
    /// Per-query client build for the direct path. UDP socket bind is
    /// cheap; TCP pays a handshake. Pooling is a deliberate v1 omission
    /// — add an LRU keyed by (ip, transport) if profiling shows it
    /// matters.
    async fn select_upstream(
        &self,
        original_dst: Option<IpAddr>,
        transport: Transport,
        sni: Option<&str>,
    ) -> UpstreamChoice {
        match decide_upstream(
            &self.gateway_ips,
            &self.network_policy,
            &self.shared,
            original_dst,
            transport,
        ) {
            UpstreamDecision::Configured => self.configured_client(transport).await,
            UpstreamDecision::Refused => UpstreamChoice::Refused,
            UpstreamDecision::Direct(addr) => {
                match build_direct_client(addr, transport, sni, self.config.query_timeout).await {
                    Some(client) => UpstreamChoice::Client(client),
                    None => UpstreamChoice::ServFail,
                }
            }
        }
    }

    /// Get the configured upstream client for `transport`. UDP is
    /// shared (pre-connected at startup); TCP is built on first use
    /// and cached. DoT guests reuse the TCP client — the configured
    /// upstream is typically on the host's loopback or internal
    /// network and serves plain DNS, so re-TLSing there is overkill.
    async fn configured_client(&self, transport: Transport) -> UpstreamChoice {
        match transport {
            Transport::Udp => UpstreamChoice::Client(self.configured_udp.clone()),
            Transport::Tcp | Transport::Dot => {
                let timeout = self.config.query_timeout;
                let upstream = self.configured_upstream;
                let result = self
                    .configured_tcp
                    .get_or_try_init(|| async move {
                        build_tcp_client(upstream, timeout).await.ok_or(())
                    })
                    .await;
                match result {
                    Ok(c) => UpstreamChoice::Client(c.clone()),
                    Err(()) => UpstreamChoice::ServFail,
                }
            }
        }
    }

    /// Spawn the forwarder init task on the given tokio runtime.
    /// Connects to the configured upstream asynchronously and publishes
    /// the resulting [`DnsForwarder`] on the returned
    /// [`DnsForwarderHandle`].
    ///
    /// Both the UDP proxy ([`super::proxies::udp::UdpProxy`]) and the
    /// TCP/53 proxy ([`super::proxies::tcp::TcpProxy`]) clone the
    /// handle and [`Self::wait`] before serving any query, so they
    /// share one configured upstream + policy across transports.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn spawn(
        handle: &tokio::runtime::Handle,
        config: Arc<NormalizedDnsConfig>,
        gateway_ips: Arc<HashSet<IpAddr>>,
        network_policy: Arc<NetworkPolicy>,
        shared: Arc<SharedState>,
        gateway: GatewayIps,
    ) -> DnsForwarderHandle {
        let (forwarder_tx, forwarder_rx) = watch::channel(None);
        handle.spawn(async move {
            let Some(forwarder) =
                Self::build(config, gateway_ips, network_policy, shared, gateway).await
            else {
                // Drop forwarder_tx by returning; waiters observe init
                // failure as `Self::wait().await == None`.
                return;
            };
            let _ = forwarder_tx.send(Some(forwarder));
        });
        forwarder_rx
    }

    /// Build the forwarder with its configured upstream connected.
    /// Returns `None` and logs on any failure (no nameservers, none
    /// resolvable, connect error).
    async fn build(
        config: Arc<NormalizedDnsConfig>,
        gateway_ips: Arc<HashSet<IpAddr>>,
        network_policy: Arc<NetworkPolicy>,
        shared: Arc<SharedState>,
        gateway: GatewayIps,
    ) -> Option<Arc<Self>> {
        let upstreams = if !config.nameservers.is_empty() {
            match resolve_nameservers(&config.nameservers).await {
                Ok(s) if !s.is_empty() => s,
                Ok(_) => {
                    tracing::error!("no configured nameservers resolved to an address");
                    return None;
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to resolve configured nameservers");
                    return None;
                }
            }
        } else {
            match read_host_dns_servers().await {
                Ok(s) if !s.is_empty() => s,
                Ok(_) => {
                    tracing::error!("no upstream DNS servers discovered from host");
                    return None;
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to read host DNS configuration");
                    return None;
                }
            }
        };

        // Use the first upstream. If it's unhealthy the guest's stub
        // will observe SERVFAIL and fall through to its own next
        // nameserver.
        let upstream = upstreams[0];
        let configured_udp = build_udp_client(upstream, config.query_timeout).await?;
        let host_ipv6_egress = host_has_ipv6_egress();
        tracing::debug!(host_ipv6_egress, "detected host IPv6 egress capability");

        Some(Arc::new(Self {
            configured_udp,
            configured_tcp: OnceCell::new(),
            configured_upstream: upstream,
            gateway_ips,
            network_policy,
            shared,
            gateway,
            host_ipv6_egress,
            config,
        }))
    }

    /// Wait until the forwarder cell is populated, then return a
    /// handle. Returns `None` if the upstream init task exited without
    /// populating the cell (i.e. configured upstream connection
    /// failed). Called by each proxy task before it starts serving
    /// queries.
    pub(crate) async fn wait(mut handle: DnsForwarderHandle) -> Option<Arc<Self>> {
        if let Some(f) = handle.borrow().clone() {
            return Some(f);
        }
        // changed() returns Err only if the sender dropped, which
        // happens when the init task exited without sending — treat as
        // init failure.
        handle.changed().await.ok()?;
        handle.borrow().clone()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Decide where a query goes based on the guest-chosen `original_dst`,
/// the gateway IP set, and the network policy. Pure function — no
/// upstream connection happens here. Lifted out of [`DnsForwarder`] so
/// the rule logic is testable without a real upstream client.
fn decide_upstream(
    gateway_ips: &HashSet<IpAddr>,
    policy: &NetworkPolicy,
    shared: &SharedState,
    original_dst: Option<IpAddr>,
    transport: Transport,
) -> UpstreamDecision {
    // No `original_dst` recorded — fall back to the configured upstream
    // (safe default; happens only if smoltcp didn't populate metadata).
    let Some(dst) = original_dst else {
        return UpstreamDecision::Configured;
    };
    if gateway_ips.contains(&dst) {
        return UpstreamDecision::Configured;
    }
    // Direct path: the guest aimed at a non-gateway resolver. Consult
    // the egress policy for that resolver IP over the transport's
    // corresponding port and protocol.
    let policy_dst = SocketAddr::new(dst, transport.upstream_port());
    if policy
        .evaluate_egress(policy_dst, transport.policy_protocol(), shared)
        .is_deny()
    {
        return UpstreamDecision::Refused;
    }
    UpstreamDecision::Direct(policy_dst)
}

/// Build a status-only response (no answers, no authority) with the given
/// RCODE. Used for locally-synthesized REFUSED (block list / policy) and
/// SERVFAIL (upstream unreachable). The guest's transaction id, OPCODE
/// and RD bit are echoed.
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

/// Build a NoError response with the original question but no answers.
fn build_empty_noerror_response(query: &Message) -> Option<Bytes> {
    build_status_response(query, ResponseCode::NoError)
}

/// Map a DNS query type to a [`ResolvedHostnameFamily`] for policy caching.
fn family_for_query_type(query_type: RecordType) -> Option<ResolvedHostnameFamily> {
    match query_type {
        RecordType::A => Some(ResolvedHostnameFamily::Ipv4),
        RecordType::AAAA => Some(ResolvedHostnameFamily::Ipv6),
        _ => None,
    }
}

/// Extract resolved IP addresses and the minimum TTL across answers of
/// the requested family. Zero-TTL answers are floored to
/// [`RESOLVED_HOSTNAME_MIN_TTL_SECS`] so an immediate connect following
/// a successful lookup does not fail closed.
fn extract_addrs_and_ttl(
    response: &Message,
    family: ResolvedHostnameFamily,
) -> Option<(Vec<IpAddr>, Duration)> {
    let mut addrs = Vec::new();
    let mut ttl: Option<Duration> = None;

    for record in response.answers() {
        let addr = match (family, record.data()) {
            (ResolvedHostnameFamily::Ipv4, RData::A(a)) => IpAddr::V4((*a).into()),
            (ResolvedHostnameFamily::Ipv6, RData::AAAA(aaaa)) => IpAddr::V6((*aaaa).into()),
            _ => continue,
        };
        addrs.push(addr);
        let record_ttl =
            Duration::from_secs(u64::from(record.ttl().max(RESOLVED_HOSTNAME_MIN_TTL_SECS)));
        ttl = Some(ttl.map_or(record_ttl, |current| current.min(record_ttl)));
    }

    ttl.map(|ttl| (addrs, ttl))
}

/// Case-insensitive match against [`crate::HOST_ALIAS`] with trailing-dot tolerance.
fn is_host_alias_query(query_name: &str) -> bool {
    query_name
        .trim_end_matches('.')
        .eq_ignore_ascii_case(crate::HOST_ALIAS)
}

/// Returns true when an external AAAA query should be hidden from the guest.
fn should_suppress_aaaa(domain: &str, query_type: RecordType, host_ipv6_egress: bool) -> bool {
    query_type == RecordType::AAAA && !host_ipv6_egress && !is_host_alias_query(domain)
}

/// Probe whether the host has an external IPv6 route.
fn host_has_ipv6_egress() -> bool {
    let probe_addr = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    TcpStream::connect_timeout(
        &SocketAddr::new(IpAddr::V6(probe_addr), 443),
        Duration::from_millis(250),
    )
    .is_ok()
}

/// Synthesize an A/AAAA response for `host.microsandbox.internal`. Returns
/// `None` for non-A/AAAA queries so the caller keeps forwarding upstream.
fn synthesize_host_alias_response(
    query: &Message,
    gateway: GatewayIps,
    qtype: RecordType,
) -> Option<Bytes> {
    let question = query.queries().first()?;
    let name = question.name().clone();

    let rdata = match qtype {
        RecordType::A => RData::A(A::from(gateway.ipv4)),
        RecordType::AAAA => RData::AAAA(AAAA::from(gateway.ipv6)),
        _ => return None,
    };

    let mut response = Message::new();
    response.set_id(query.id());
    response.set_op_code(query.op_code());
    response.set_recursion_desired(query.recursion_desired());
    response.set_message_type(MessageType::Response);
    response.set_response_code(ResponseCode::NoError);
    response.set_recursion_available(true);
    response.set_authoritative(true);
    response.add_query(question.clone());
    response.add_answer(Record::from_rdata(name, HOST_ALIAS_TTL_SECS, rdata));

    response.to_bytes().ok().map(Bytes::from)
}

/// Build a header-only NoError response with TC=1. RFC 5966 §3 requires
/// servers to set TC when truncating; the guest's stub then retries the
/// query over TCP per RFC 7766.
fn build_truncated_response(query: &Message) -> Option<Vec<u8>> {
    let mut response = Message::new();
    response.set_id(query.id());
    response.set_op_code(query.op_code());
    response.set_recursion_desired(query.recursion_desired());
    response.set_message_type(MessageType::Response);
    response.set_response_code(ResponseCode::NoError);
    response.set_recursion_available(true);
    response.set_truncated(true);
    if let Some(q) = query.queries().first() {
        response.add_query(q.clone());
    }
    response.to_bytes().ok()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::Protocol;
    use hickory_client::proto::op::{Edns, MessageType, OpCode, Query};
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

    fn parse_response(bytes: Bytes) -> Message {
        Message::from_bytes(&bytes).expect("parse response")
    }

    #[test]
    fn build_status_response_preserves_header_and_question() {
        let query = make_query("slack.com.", RecordType::AAAA);
        let bytes = build_status_response(&query, ResponseCode::Refused).expect("built");
        let msg = parse_response(bytes);
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
        let msg = parse_response(bytes);
        assert_eq!(msg.response_code(), ResponseCode::ServFail);
        assert_eq!(msg.answers().len(), 0);
    }

    #[test]
    fn build_empty_noerror_response_preserves_question_without_answers() {
        let query = make_query("openrouter.ai.", RecordType::AAAA);
        let bytes = build_empty_noerror_response(&query).expect("built");
        let msg = parse_response(bytes);

        assert_eq!(msg.id(), 0x4242);
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.message_type(), MessageType::Response);
        assert_eq!(msg.op_code(), OpCode::Query);
        assert!(msg.recursion_desired());
        assert!(msg.recursion_available());
        assert_eq!(msg.queries().len(), 1);
        assert_eq!(msg.queries()[0].query_type(), RecordType::AAAA);
        assert!(msg.answers().is_empty());
    }

    #[test]
    fn build_truncated_response_sets_tc_and_keeps_question() {
        let query = make_query("example.com.", RecordType::TXT);
        let bytes = build_truncated_response(&query).expect("built");
        let msg = Message::from_bytes(&bytes).expect("parse response");
        assert_eq!(msg.id(), 0x4242);
        assert_eq!(msg.message_type(), MessageType::Response);
        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert!(msg.truncated(), "TC bit should be set");
        assert_eq!(msg.queries().len(), 1);
        assert_eq!(msg.queries()[0].query_type(), RecordType::TXT);
        assert!(msg.answers().is_empty());
    }

    /// EDNS OPT pass-through (#2): a query parsed back from wire bytes
    /// must still expose the OPT record so the guest's advertised UDP
    /// buffer size + DO bit reach upstream.
    #[test]
    fn edns_opt_round_trips_through_wire() {
        let mut query = make_query("example.com.", RecordType::A);
        let mut edns = Edns::new();
        edns.set_max_payload(4096);
        edns.set_dnssec_ok(true);
        edns.set_version(0);
        *query.extensions_mut() = Some(edns);

        let bytes = query.to_bytes().expect("serialize");
        let parsed = Message::from_bytes(&bytes).expect("parse");

        let opt = parsed.extensions().as_ref().expect("OPT preserved");
        assert_eq!(opt.max_payload(), 4096);
        assert!(opt.flags().dnssec_ok, "DO bit preserved");
        // Message::max_payload returns OPT value (clamped to 512 floor).
        assert_eq!(parsed.max_payload(), 4096);
    }

    /// Without EDNS OPT, the guest's advertised buffer defaults to 512
    /// (RFC 1035), which gates the truncation logic.
    #[test]
    fn max_payload_defaults_to_512_without_opt() {
        let query = make_query("example.com.", RecordType::A);
        assert!(query.extensions().is_none());
        assert_eq!(query.max_payload(), 512);
    }

    #[test]
    fn should_suppress_external_aaaa_when_host_ipv6_unavailable() {
        assert!(should_suppress_aaaa(
            "openrouter.ai",
            RecordType::AAAA,
            false
        ));
    }

    #[test]
    fn should_not_suppress_a_records_when_host_ipv6_unavailable() {
        assert!(!should_suppress_aaaa("openrouter.ai", RecordType::A, false));
    }

    #[test]
    fn should_not_suppress_external_aaaa_when_host_ipv6_available() {
        assert!(!should_suppress_aaaa(
            "openrouter.ai",
            RecordType::AAAA,
            true
        ));
    }

    #[test]
    fn should_not_suppress_host_alias_aaaa() {
        assert!(!should_suppress_aaaa(
            crate::HOST_ALIAS,
            RecordType::AAAA,
            false
        ));
    }

    #[test]
    fn host_ipv6_egress_probe_returns_a_boolean() {
        let _ = host_has_ipv6_egress();
    }

    #[test]
    fn suppressed_external_aaaa_returns_nodata_shape() {
        let query = make_query("openrouter.ai.", RecordType::AAAA);
        assert!(should_suppress_aaaa(
            "openrouter.ai",
            RecordType::AAAA,
            false
        ));

        let msg = parse_response(build_empty_noerror_response(&query).expect("built"));

        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.queries()[0].query_type(), RecordType::AAAA);
        assert!(msg.answers().is_empty());
    }

    #[test]
    fn host_alias_aaaa_is_not_suppressed_without_host_ipv6_egress() {
        let query = make_query(crate::HOST_ALIAS, RecordType::AAAA);
        assert!(!should_suppress_aaaa(
            crate::HOST_ALIAS,
            RecordType::AAAA,
            false
        ));

        let gateway = GatewayIps {
            ipv4: std::net::Ipv4Addr::new(100, 96, 0, 1),
            ipv6: "fd42:6d73:62::1".parse().unwrap(),
        };
        let bytes =
            synthesize_host_alias_response(&query, gateway, RecordType::AAAA).expect("built");
        let msg = parse_response(bytes);

        assert_eq!(msg.response_code(), ResponseCode::NoError);
        assert_eq!(msg.answers().len(), 1);
    }

    fn gateway_set() -> HashSet<IpAddr> {
        HashSet::from([
            IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
        ])
    }

    #[test]
    fn decide_upstream_configured_when_dst_is_gateway_v4() {
        let gw = gateway_set();
        let shared = SharedState::new(4);
        let policy = NetworkPolicy::allow_all();
        let dst = Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, dst, Transport::Udp),
            UpstreamDecision::Configured
        );
    }

    #[test]
    fn decide_upstream_configured_when_dst_is_gateway_v6() {
        let gw = gateway_set();
        let shared = SharedState::new(4);
        let policy = NetworkPolicy::allow_all();
        let dst = Some(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST));
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, dst, Transport::Tcp),
            UpstreamDecision::Configured
        );
    }

    #[test]
    fn decide_upstream_configured_when_dst_unknown() {
        // smoltcp may fail to populate local_address; safe default is
        // to fall back to the configured upstream, never accidentally
        // forward to whoever the guest happens to be aiming at.
        let gw = gateway_set();
        let shared = SharedState::new(4);
        let policy = NetworkPolicy::allow_all();
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, None, Transport::Udp),
            UpstreamDecision::Configured
        );
    }

    #[test]
    fn decide_upstream_direct_when_dst_external_and_policy_allows() {
        let gw = gateway_set();
        let shared = SharedState::new(4);
        let policy = NetworkPolicy::allow_all();
        let dst = Some(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, dst, Transport::Udp),
            UpstreamDecision::Direct(SocketAddr::from(([1, 1, 1, 1], 53)))
        );
    }

    #[test]
    fn decide_upstream_refused_when_policy_denies_resolver() {
        // public_only policy denies private addresses — guest aiming at
        // a private resolver should get REFUSED rather than silently
        // hitting the configured upstream instead.
        let gw = gateway_set();
        let shared = SharedState::new(4);
        let policy = NetworkPolicy::public_only();
        let dst = Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 53)));
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, dst, Transport::Udp),
            UpstreamDecision::Refused
        );
    }

    #[test]
    fn decide_upstream_refused_when_policy_denies_all() {
        // none() denies everything; only queries to the gateway can
        // still reach the configured upstream. Direct queries get
        // REFUSED.
        let gw = gateway_set();
        let shared = SharedState::new(4);
        let policy = NetworkPolicy::none();
        let dst = Some(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, dst, Transport::Tcp),
            UpstreamDecision::Refused
        );
        // But aiming at the gateway still works.
        let gw_dst = Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, gw_dst, Transport::Tcp),
            UpstreamDecision::Configured
        );
    }

    #[test]
    fn decide_upstream_uses_correct_transport_protocol() {
        // Build a policy that allows UDP but denies TCP to a specific
        // resolver — verifies the decision threads the transport
        // through to the policy evaluator.
        use crate::policy::{Action, Destination, Direction, Rule};
        let gw = gateway_set();
        let shared = SharedState::new(4);
        let dst_ip = std::net::Ipv4Addr::new(8, 8, 8, 8);
        let policy = NetworkPolicy {
            default_egress: Action::Allow,
            default_ingress: Action::Allow,
            rules: vec![Rule {
                direction: Direction::Egress,
                destination: Destination::Cidr("8.8.8.8/32".parse().unwrap()),
                protocols: vec![Protocol::Tcp],
                ports: vec![],
                action: Action::Deny,
            }],
        };
        let dst = Some(IpAddr::V4(dst_ip));
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, dst, Transport::Udp),
            UpstreamDecision::Direct(SocketAddr::from(([8, 8, 8, 8], 53)))
        );
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, dst, Transport::Tcp),
            UpstreamDecision::Refused
        );
    }

    #[test]
    fn decide_upstream_dot_configured_when_dst_is_gateway() {
        let gw = gateway_set();
        let shared = SharedState::new(4);
        let policy = NetworkPolicy::allow_all();
        let dst = Some(IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, dst, Transport::Dot),
            UpstreamDecision::Configured
        );
    }

    #[test]
    fn decide_upstream_dot_direct_targets_port_853() {
        let gw = gateway_set();
        let shared = SharedState::new(4);
        let policy = NetworkPolicy::allow_all();
        let dst = Some(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, dst, Transport::Dot),
            UpstreamDecision::Direct(SocketAddr::from(([1, 1, 1, 1], 853))),
        );
    }

    #[test]
    fn decide_upstream_dot_refused_when_policy_denies_853() {
        // A policy that denies TCP to 1.1.1.1 blocks DoT upstream
        // regardless of port, since DoT rides TCP.
        use crate::policy::{Action, Destination, Direction, Rule};
        let gw = gateway_set();
        let shared = SharedState::new(4);
        let policy = NetworkPolicy {
            default_egress: Action::Allow,
            default_ingress: Action::Allow,
            rules: vec![Rule {
                direction: Direction::Egress,
                destination: Destination::Cidr("1.1.1.1/32".parse().unwrap()),
                protocols: vec![Protocol::Tcp],
                ports: vec![],
                action: Action::Deny,
            }],
        };
        let dst = Some(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, dst, Transport::Dot),
            UpstreamDecision::Refused
        );
    }
}
