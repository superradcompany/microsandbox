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
//!   forward there directly; if denied, synthesize NXDOMAIN.
//!
//! Block list and rebind protection apply to every query/response
//! regardless of which path was taken — the host always sees the
//! traffic in the clear and can refuse it. UDP responses that exceed
//! the guest's advertised EDNS buffer are truncated (TC=1) so the stub
//! retries over TCP through the same forwarder.
//!
//! [`DnsInterceptor`]: super::interceptor::DnsInterceptor

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use futures::StreamExt;
use hickory_net::proto::op::{DnsRequest, Message, ResponseCode};
use hickory_net::proto::rr::rdata::{A, AAAA};
use hickory_net::proto::rr::{RData, Record, RecordType};
use hickory_net::proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_net::xfer::DnsHandle;
use tokio::sync::{OnceCell, watch};

use super::client::{Client, build_direct_client, build_tcp_client, build_udp_client};
use super::common::config::NormalizedDnsConfig;
use super::common::filter::{is_private_ipv4, is_private_ipv6};
use super::common::transport::Transport;
use super::nameserver::{read_host_dns_servers, resolve_nameservers};
use crate::policy::{Action, DomainName, NetworkPolicy};
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
    config: Arc<NormalizedDnsConfig>,
}

/// Outcome of upstream selection. The query may be forwarded through a
/// [`Client`], synthesized as NXDOMAIN (policy denied the resolver IP),
/// or synthesized as SERVFAIL (couldn't reach upstream).
enum UpstreamChoice {
    Client(Client),
    PolicyDenied,
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
    /// an NXDOMAIN denial.
    PolicyDenied,
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
        let guest_id = query_msg.metadata.id;

        let question = query_msg.queries.first()?;
        let query_type = question.query_type();
        let domain = question.name().to_string();
        let domain = domain.trim_end_matches('.').to_owned();

        // Refuse queries denied by the network policy. DNS is evaluated
        // as egress over the guest-facing DNS transport, so deny-by-
        // default policies fail closed unless a rule allows the name or
        // the DNS protocol/port.
        if decide_dns_action(&self.network_policy, &domain, transport).is_deny() {
            tracing::debug!(domain = %domain, "DNS query denied by network policy");
            // NXDOMAIN, not REFUSED: stub resolvers (e.g. glibc) don't
            // fail-fast on REFUSED, so a denied lookup hangs the guest in a
            // deny-by-default sandbox. NXDOMAIN is a synthetic negative that
            // fails the lookup immediately — the convention DNS blockers
            // (Pi-hole et al.) use for filtered names.
            return build_status_response(&query_msg, ResponseCode::NXDomain);
        }

        if let Some(family) = inactive_query_family(query_type, self.gateway) {
            tracing::debug!(
                domain = %domain,
                ?family,
                "DNS query family is inactive for this sandbox",
            );
            self.shared.clear_resolved_hostname(&domain, family);
            return build_status_response(&query_msg, ResponseCode::NoError);
        }

        // Locally synthesize answers for the host alias; MX / TXT / etc.
        // fall through to upstream.
        if is_host_alias_query(&domain)
            && let Some(response) =
                synthesize_host_alias_response(&query_msg, self.gateway, query_type)
        {
            return Some(response);
        }

        // Pick upstream client based on where the guest aimed and the
        // network policy.
        let client = match self.select_upstream(original_dst, transport, sni).await {
            UpstreamChoice::Client(c) => c,
            UpstreamChoice::PolicyDenied => {
                tracing::debug!(
                    domain = %domain,
                    ?original_dst,
                    "DNS resolver denied by network policy"
                );
                return build_status_response(&query_msg, ResponseCode::NXDomain);
            }
            UpstreamChoice::ServFail => {
                return build_status_response(&query_msg, ResponseCode::ServFail);
            }
        };

        // Forward upstream. hickory's multiplexer assigns its own
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
            for record in &response_msg.answers {
                let private_addr = match &record.data {
                    RData::A(a) => {
                        let addr = IpAddr::V4((*a).into());
                        is_private_ipv4((*a).into()).then_some(addr)
                    }
                    RData::AAAA(aaaa) => {
                        let addr = IpAddr::V6((*aaaa).into());
                        is_private_ipv6((*aaaa).into()).then_some(addr)
                    }
                    _ => None,
                };
                if private_addr.is_some_and(|addr| {
                    !policy_allows_rebind_address(&self.network_policy, &self.shared, addr)
                }) {
                    tracing::debug!(
                        domain = %domain,
                        "DNS rebind protection: response contains private IP"
                    );
                    return build_status_response(&query_msg, ResponseCode::NXDomain);
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
        response_msg.metadata.id = guest_id;
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
    /// cheap; TCP pays a handshake. Pooling is intentionally omitted —
    /// add an LRU keyed by (ip, transport) if profiling shows it
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
            UpstreamDecision::PolicyDenied => UpstreamChoice::PolicyDenied,
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

        Some(Arc::new(Self {
            configured_udp,
            configured_tcp: OnceCell::new(),
            configured_upstream: upstream,
            gateway_ips,
            network_policy,
            shared,
            gateway,
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

/// Return whether a private/reserved DNS answer was explicitly made reachable.
///
/// Rebind protection remains fail-closed unless an address-only TCP or UDP
/// policy evaluation allows the answer. Port-scoped rules do not qualify here;
/// they cannot be evaluated safely before the guest chooses a connection port.
fn policy_allows_rebind_address(
    policy: &NetworkPolicy,
    shared: &SharedState,
    addr: IpAddr,
) -> bool {
    [crate::policy::Protocol::Tcp, crate::policy::Protocol::Udp]
        .into_iter()
        .any(|protocol| {
            policy.evaluate_explicit_egress_ip(addr, protocol, shared) == Some(Action::Allow)
        })
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
        return UpstreamDecision::PolicyDenied;
    }
    UpstreamDecision::Direct(policy_dst)
}

/// Evaluate a guest-issued DNS query against the network policy. Pure
/// function — no I/O — so the denial logic is testable without a real
/// upstream client. Names that don't parse as a [`DomainName`] take the
/// nameless path, where only `Any` rules can match.
fn decide_dns_action(policy: &NetworkPolicy, domain: &str, transport: Transport) -> Action {
    match domain.parse::<DomainName>() {
        Ok(canonical) => policy.evaluate_dns_query(
            &canonical,
            transport.policy_protocol(),
            transport.upstream_port(),
        ),
        Err(_) => policy.evaluate_dns_query_without_name(
            transport.policy_protocol(),
            transport.upstream_port(),
        ),
    }
}

/// Build a status-only response (no answers, no authority) with the given
/// RCODE. Used for locally-synthesized NXDOMAIN (block list / policy deny /
/// rebind rejection) and SERVFAIL (upstream unreachable). The guest's
/// transaction id, OPCODE and RD bit are echoed.
fn build_status_response(query: &Message, rcode: ResponseCode) -> Option<Bytes> {
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.response_code = rcode;
    response.metadata.recursion_available = true;
    if let Some(q) = query.queries.first() {
        response.add_query(q.clone());
    }
    response.to_bytes().ok().map(Bytes::from)
}

/// Map a DNS query type to a [`ResolvedHostnameFamily`] for policy caching.
fn family_for_query_type(query_type: RecordType) -> Option<ResolvedHostnameFamily> {
    match query_type {
        RecordType::A => Some(ResolvedHostnameFamily::Ipv4),
        RecordType::AAAA => Some(ResolvedHostnameFamily::Ipv6),
        _ => None,
    }
}

/// Return the queried address family when the sandbox has no gateway for it.
fn inactive_query_family(
    query_type: RecordType,
    gateway: GatewayIps,
) -> Option<ResolvedHostnameFamily> {
    match query_type {
        RecordType::A if gateway.ipv4.is_none() => Some(ResolvedHostnameFamily::Ipv4),
        RecordType::AAAA if gateway.ipv6.is_none() => Some(ResolvedHostnameFamily::Ipv6),
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

    for record in &response.answers {
        let addr = match (family, &record.data) {
            (ResolvedHostnameFamily::Ipv4, RData::A(a)) => IpAddr::V4((*a).into()),
            (ResolvedHostnameFamily::Ipv6, RData::AAAA(aaaa)) => IpAddr::V6((*aaaa).into()),
            _ => continue,
        };
        addrs.push(addr);
        let record_ttl =
            Duration::from_secs(u64::from(record.ttl.max(RESOLVED_HOSTNAME_MIN_TTL_SECS)));
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

/// Synthesize an A/AAAA response for `host.microsandbox.internal`. Returns
/// `None` for non-A/AAAA queries so the caller keeps forwarding upstream.
fn synthesize_host_alias_response(
    query: &Message,
    gateway: GatewayIps,
    qtype: RecordType,
) -> Option<Bytes> {
    let question = query.queries.first()?;
    let name = question.name().clone();

    let rdata = match qtype {
        RecordType::A => RData::A(A::from(gateway.ipv4?)),
        RecordType::AAAA => RData::AAAA(AAAA::from(gateway.ipv6?)),
        _ => return None,
    };

    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.response_code = ResponseCode::NoError;
    response.metadata.recursion_available = true;
    response.metadata.authoritative = true;
    response.add_query(question.clone());
    response.add_answer(Record::from_rdata(name, HOST_ALIAS_TTL_SECS, rdata));

    response.to_bytes().ok().map(Bytes::from)
}

/// Build a header-only NoError response with TC=1. RFC 5966 §3 requires
/// servers to set TC when truncating; the guest's stub then retries the
/// query over TCP per RFC 7766.
fn build_truncated_response(query: &Message) -> Option<Vec<u8>> {
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.response_code = ResponseCode::NoError;
    response.metadata.recursion_available = true;
    response.metadata.truncation = true;
    if let Some(q) = query.queries.first() {
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
    use crate::policy::{Action, Destination, NetworkProfile, Protocol, Rule};
    use hickory_net::proto::op::{Edns, MessageType, OpCode, Query};
    use hickory_net::proto::rr::{DNSClass, Name, RecordType};

    fn make_query(name: &str, qtype: RecordType) -> Message {
        let mut msg = Message::new(0x4242, MessageType::Query, OpCode::Query);
        msg.metadata.recursion_desired = true;
        let parsed = Name::from_ascii(name).expect("valid dns name");
        let mut q = Query::new();
        q.set_name(parsed);
        q.set_query_type(qtype);
        q.set_query_class(DNSClass::IN);
        msg.add_query(q);
        msg
    }

    #[test]
    fn rebind_filter_allows_private_answers_for_private_profile() {
        let policy = NetworkPolicy::from_profiles([NetworkProfile::Private]);
        let shared = SharedState::new(4);
        assert!(policy_allows_rebind_address(
            &policy,
            &shared,
            "10.20.30.40".parse().unwrap()
        ));
    }

    #[test]
    fn rebind_filter_rejects_private_answers_for_public_profile() {
        let policy = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let shared = SharedState::new(4);
        assert!(!policy_allows_rebind_address(
            &policy,
            &shared,
            "10.20.30.40".parse().unwrap()
        ));
    }

    #[test]
    fn rebind_filter_rejects_unspecified_answers_for_public_profile() {
        let policy = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let shared = SharedState::new(4);
        for addr in ["0.0.0.0", "::"] {
            assert!(
                !policy_allows_rebind_address(&policy, &shared, addr.parse().unwrap()),
                "expected {addr} to remain blocked by rebind protection"
            );
        }
    }

    #[test]
    fn rebind_filter_remains_enabled_for_allow_all_default() {
        let policy = NetworkPolicy::allow_all();
        let shared = SharedState::new(4);
        assert!(!policy_allows_rebind_address(
            &policy,
            &shared,
            "10.20.30.40".parse().unwrap()
        ));
    }

    #[test]
    fn rebind_filter_does_not_treat_explicit_any_as_private_intent() {
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule::allow_egress(Destination::Any)],
        };
        let shared = SharedState::new(4);
        assert!(!policy_allows_rebind_address(
            &policy,
            &shared,
            "10.20.30.40".parse().unwrap()
        ));
    }

    #[test]
    fn rebind_filter_honors_ordered_deny_before_private_allow() {
        let mut policy = NetworkPolicy::from_profiles([NetworkProfile::Private]);
        policy.rules.insert(
            0,
            Rule {
                direction: crate::policy::Direction::Egress,
                destination: Destination::Cidr("10.20.30.40/32".parse().unwrap()),
                protocols: Vec::new(),
                ports: Vec::new(),
                action: Action::Deny,
            },
        );
        let shared = SharedState::new(4);
        assert!(!policy_allows_rebind_address(
            &policy,
            &shared,
            "10.20.30.40".parse().unwrap()
        ));
    }

    #[test]
    fn build_status_response_preserves_header_and_question() {
        let query = make_query("slack.com.", RecordType::AAAA);
        let bytes = build_status_response(&query, ResponseCode::Refused).expect("built");
        let msg = Message::from_bytes(&bytes).expect("parse response");
        assert_eq!(msg.metadata.id, 0x4242);
        assert_eq!(msg.metadata.response_code, ResponseCode::Refused);
        assert_eq!(msg.metadata.message_type, MessageType::Response);
        assert_eq!(msg.metadata.op_code, OpCode::Query);
        assert!(msg.metadata.recursion_desired);
        assert!(msg.metadata.recursion_available);
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.queries[0].query_type(), RecordType::AAAA);
        assert_eq!(msg.answers.len(), 0);
    }

    #[test]
    fn build_status_response_servfail_variant() {
        let query = make_query("example.com.", RecordType::A);
        let bytes = build_status_response(&query, ResponseCode::ServFail).expect("built");
        let msg = Message::from_bytes(&bytes).expect("parse response");
        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(msg.answers.len(), 0);
    }

    /// Policy denials synthesize NXDOMAIN (not REFUSED) so stub resolvers
    /// fail closed immediately instead of falling back to an unreachable
    /// next nameserver under deny-by-default egress.
    #[test]
    fn build_status_response_nxdomain_variant() {
        let query = make_query("example.com.", RecordType::A);
        let bytes = build_status_response(&query, ResponseCode::NXDomain).expect("built");
        let msg = Message::from_bytes(&bytes).expect("parse response");
        assert_eq!(msg.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(msg.answers.len(), 0);
        assert_eq!(msg.queries.len(), 1);
    }

    #[test]
    fn build_status_response_noerror_variant_is_nodata() {
        let query = make_query("example.com.", RecordType::AAAA);
        let bytes = build_status_response(&query, ResponseCode::NoError).expect("built");
        let msg = Message::from_bytes(&bytes).expect("parse response");
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert_eq!(msg.answers.len(), 0);
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.queries[0].query_type(), RecordType::AAAA);
    }

    #[test]
    fn build_truncated_response_sets_tc_and_keeps_question() {
        let query = make_query("example.com.", RecordType::TXT);
        let bytes = build_truncated_response(&query).expect("built");
        let msg = Message::from_bytes(&bytes).expect("parse response");
        assert_eq!(msg.metadata.id, 0x4242);
        assert_eq!(msg.metadata.message_type, MessageType::Response);
        assert_eq!(msg.metadata.response_code, ResponseCode::NoError);
        assert!(msg.metadata.truncation, "TC bit should be set");
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.queries[0].query_type(), RecordType::TXT);
        assert!(msg.answers.is_empty());
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
        query.edns = Some(edns);

        let bytes = query.to_bytes().expect("serialize");
        let parsed = Message::from_bytes(&bytes).expect("parse");

        let opt = parsed.edns.as_ref().expect("OPT preserved");
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
        assert!(query.edns.is_none());
        assert_eq!(query.max_payload(), 512);
    }

    #[test]
    fn inactive_query_family_detects_missing_ipv6_gateway() {
        let gateway = GatewayIps {
            ipv4: Some(std::net::Ipv4Addr::new(172, 16, 0, 1)),
            ipv6: None,
        };

        assert_eq!(
            inactive_query_family(RecordType::AAAA, gateway),
            Some(ResolvedHostnameFamily::Ipv6)
        );
        assert_eq!(inactive_query_family(RecordType::A, gateway), None);
    }

    #[test]
    fn inactive_query_family_detects_missing_ipv4_gateway() {
        let gateway = GatewayIps {
            ipv4: None,
            ipv6: Some("fd42:6d73:62::1".parse().unwrap()),
        };

        assert_eq!(
            inactive_query_family(RecordType::A, gateway),
            Some(ResolvedHostnameFamily::Ipv4)
        );
        assert_eq!(inactive_query_family(RecordType::AAAA, gateway), None);
    }

    #[test]
    fn inactive_query_family_ignores_non_address_queries() {
        let gateway = GatewayIps {
            ipv4: None,
            ipv6: None,
        };

        assert_eq!(inactive_query_family(RecordType::MX, gateway), None);
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
    fn decide_upstream_policy_denied_when_policy_denies_resolver() {
        // The public profile denies private addresses — guest aiming at
        // a private resolver should be routed to the denial path (a
        // synthesized NXDOMAIN) rather than silently hitting the configured
        // upstream instead.
        let gw = gateway_set();
        let shared = SharedState::new(4);
        let policy = NetworkPolicy::default();
        let dst = Some(IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 53)));
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, dst, Transport::Udp),
            UpstreamDecision::PolicyDenied
        );
    }

    #[test]
    fn decide_upstream_policy_denied_when_policy_denies_all() {
        // none() denies everything; only queries to the gateway can
        // still reach the configured upstream. Direct queries are routed
        // to the denial path (synthesized NXDOMAIN).
        let gw = gateway_set();
        let shared = SharedState::new(4);
        let policy = NetworkPolicy::none();
        let dst = Some(IpAddr::V4(std::net::Ipv4Addr::new(1, 1, 1, 1)));
        assert_eq!(
            decide_upstream(&gw, &policy, &shared, dst, Transport::Tcp),
            UpstreamDecision::PolicyDenied
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
            UpstreamDecision::PolicyDenied
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
    fn decide_upstream_dot_policy_denied_when_policy_denies_853() {
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
            UpstreamDecision::PolicyDenied
        );
    }

    //----------------------------------------------------------------------------------------------
    // decide_dns_action
    //----------------------------------------------------------------------------------------------

    #[test]
    fn decide_dns_action_allows_under_default_allow() {
        let policy = NetworkPolicy::allow_all();
        assert_eq!(
            decide_dns_action(&policy, "example.com", Transport::Udp),
            Action::Allow
        );
    }

    #[test]
    fn decide_dns_action_denies_under_deny_by_default() {
        // Deny-by-default with no rule that grants the DNS transport must
        // deny the query — this is the regression the wider DNS-as-
        // egress evaluation was added for.
        let policy = NetworkPolicy::none();
        assert_eq!(
            decide_dns_action(&policy, "example.com", Transport::Udp),
            Action::Deny
        );
        assert_eq!(
            decide_dns_action(&policy, "example.com", Transport::Tcp),
            Action::Deny
        );
        assert_eq!(
            decide_dns_action(&policy, "example.com", Transport::Dot),
            Action::Deny
        );
    }

    #[test]
    fn decide_dns_action_any_rule_grants_dns_when_protocol_and_port_match() {
        // `Any udp/53` is the operator-friendly way to open DNS under a
        // deny-by-default policy. Same rule must NOT grant TCP DNS.
        use crate::policy::{Destination, Direction, PortRange, Rule};
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule {
                direction: Direction::Egress,
                destination: Destination::Any,
                protocols: vec![Protocol::Udp],
                ports: vec![PortRange::single(53)],
                action: Action::Allow,
            }],
        };
        assert_eq!(
            decide_dns_action(&policy, "example.com", Transport::Udp),
            Action::Allow
        );
        assert_eq!(
            decide_dns_action(&policy, "example.com", Transport::Tcp),
            Action::Deny
        );
    }

    #[test]
    fn decide_dns_action_dot_uses_tcp_and_port_853() {
        // DoT rides TCP; an `Any tcp/853` rule must grant it, while a
        // narrower `Any tcp/53` rule must NOT.
        use crate::policy::{Destination, Direction, PortRange, Rule};
        let policy_853 = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule {
                direction: Direction::Egress,
                destination: Destination::Any,
                protocols: vec![Protocol::Tcp],
                ports: vec![PortRange::single(853)],
                action: Action::Allow,
            }],
        };
        assert_eq!(
            decide_dns_action(&policy_853, "example.com", Transport::Dot),
            Action::Allow
        );

        let policy_53 = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule {
                direction: Direction::Egress,
                destination: Destination::Any,
                protocols: vec![Protocol::Tcp],
                ports: vec![PortRange::single(53)],
                action: Action::Allow,
            }],
        };
        assert_eq!(
            decide_dns_action(&policy_53, "example.com", Transport::Dot),
            Action::Deny
        );
    }

    #[test]
    fn decide_dns_action_unparseable_name_takes_nameless_path() {
        // An empty label or otherwise invalid name fails DomainName
        // parsing; only Any rules can match. A domain-targeted allow
        // rule must NOT grant such queries.
        let policy = NetworkPolicy::allow_all()
            .deny_domain("evil.com")
            .expect("valid name");
        // "..something" has only empty labels after trim — DomainName
        // parsing rejects it; the nameless path falls through to the
        // default (allow_all → Allow).
        assert_eq!(
            decide_dns_action(&policy, "", Transport::Udp),
            Action::Allow
        );

        // Under deny-by-default, an unparseable name with no Any rule is
        // denied.
        let deny = NetworkPolicy::none();
        assert_eq!(decide_dns_action(&deny, "", Transport::Udp), Action::Deny);
    }

    #[test]
    fn decide_dns_action_domain_rule_denies_specific_name() {
        let policy = NetworkPolicy::allow_all()
            .deny_domain("evil.com")
            .expect("valid name");
        assert_eq!(
            decide_dns_action(&policy, "evil.com", Transport::Udp),
            Action::Deny
        );
        assert_eq!(
            decide_dns_action(&policy, "good.com", Transport::Udp),
            Action::Allow
        );
    }
}
