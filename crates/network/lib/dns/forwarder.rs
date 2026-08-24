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
use hickory_net::proto::op::{DnsRequest, Message, Query, ResponseCode};
use hickory_net::proto::rr::rdata::{A, AAAA, CNAME};
use hickory_net::proto::rr::{RData, Record, RecordType};
use hickory_net::proto::serialize::binary::{BinDecodable, BinEncodable};
use hickory_net::xfer::DnsHandle;
use tokio::sync::{OnceCell, watch};

use super::client::{Client, build_direct_client, build_tcp_client, build_udp_client};
use super::common::config::NormalizedDnsConfig;
use super::common::filter::{is_private_ipv4, is_private_ipv6};
use super::common::transport::Transport;
#[cfg(not(windows))]
use super::nameserver::read_host_dns_servers;
use super::nameserver::resolve_nameservers;
#[cfg(windows)]
use super::windows_resolver::WindowsSystemResolver;
use crate::netstack::{
    poll::GatewayIps,
    shared::{ResolvedHostnameFamily, SharedState},
};
use crate::policy::{Action, DomainName, NetworkPolicy};

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
    /// Resolver used when the guest queries the gateway IP. Explicitly configured nameservers use
    /// direct clients; on Windows, host-default queries use the system DNS Client so interface,
    /// VPN, NRPT and resolver-health policy remains owned by the operating system.
    configured: ConfiguredResolver,
    /// Set of gateway IPs (v4 + v6). Queries to these IPs go through
    /// the configured upstream; queries to other IPs go through the
    /// direct path subject to network egress policy.
    gateway_ips: Arc<HashSet<IpAddr>>,
    /// Network policy. Direct-path queries consult this for outbound
    /// permission to the chosen `@target` resolver IP.
    network_policy: Arc<NetworkPolicy>,
    /// Optional host-owned policy floor. Direct resolvers and private DNS
    /// answers must pass this policy in addition to the tenant policy.
    platform_policy: Option<Arc<NetworkPolicy>>,
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

/// One configured upstream and its per-transport clients.
struct ConfiguredUpstream {
    /// SocketAddr of this upstream — needed to build `tcp` on demand
    /// and for diagnostic logging.
    addr: SocketAddr,
    /// UDP client, connected at startup. Cheap to build for every
    /// upstream: since hickory 0.26 the constructor only wraps a
    /// request sender, so socket errors surface per-query instead.
    udp: Client,
    /// Lazy TCP client. Built on first TCP query that reaches this
    /// upstream; many sandboxes never use TCP DNS at all, so we don't
    /// pay the handshake cost up front.
    tcp: OnceCell<Client>,
}

/// Backend for queries addressed to the sandbox gateway.
enum ConfiguredResolver {
    /// Direct upstreams, tried in order. This covers operator-configured nameservers on every host
    /// and host-discovered nameservers on Unix.
    Direct(Vec<ConfiguredUpstream>),
    /// Native Windows DNS Client used only when no nameserver was explicitly configured.
    #[cfg(windows)]
    WindowsSystem(WindowsSystemResolver),
}

/// Outcome of upstream selection. The query may be forwarded through
/// the configured upstreams or one guest-chosen resolver, synthesized
/// as NXDOMAIN (policy denied the resolver IP), or synthesized as
/// SERVFAIL (couldn't reach upstream).
enum UpstreamChoice {
    /// Walk the configured upstreams in order, falling over on timeout
    /// or transport failure.
    Configured,
    /// Forward to the single resolver the guest aimed at. Not subject
    /// to failover: substituting a different server would silently
    /// redirect a query the guest addressed deliberately.
    Direct(Client),
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

        let question = match single_question(&query_msg) {
            Ok(question) => question,
            Err(rcode) => return build_status_response(&query_msg, rcode),
        };
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

        // Pick upstream based on where the guest aimed and the network
        // policy, then forward. On the configured path, walk the
        // upstreams in order so a timeout or transport failure falls
        // over to the next one; the guest was handed the gateway as its
        // only nameserver, so it cannot retry elsewhere itself.
        let response = match self.select_upstream(original_dst, transport, sni).await {
            UpstreamChoice::PolicyDenied => {
                tracing::debug!(
                    domain = %domain,
                    ?original_dst,
                    "DNS resolver denied by network policy"
                );
                return build_status_response(&query_msg, ResponseCode::NXDomain);
            }
            UpstreamChoice::ServFail => None,
            UpstreamChoice::Direct(client) => self.send_query(&client, &query_msg, &domain).await,
            UpstreamChoice::Configured => {
                self.forward_to_configured(raw_query, &query_msg, &domain, transport)
                    .await
            }
        };
        let Some(mut response_msg) = response else {
            return build_status_response(&query_msg, ResponseCode::ServFail);
        };

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
                    !policies_allow_rebind_address(
                        &self.network_policy,
                        self.platform_policy.as_deref(),
                        &self.shared,
                        addr,
                    )
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
            if let Some((addrs, ttl)) = extract_addrs_and_ttl(&response_msg, family, &domain) {
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
        match decide_upstream_with_platform(
            &self.gateway_ips,
            &self.network_policy,
            self.platform_policy.as_deref(),
            &self.shared,
            original_dst,
            transport,
        ) {
            UpstreamDecision::Configured => UpstreamChoice::Configured,
            UpstreamDecision::PolicyDenied => UpstreamChoice::PolicyDenied,
            UpstreamDecision::Direct(addr) => {
                match build_direct_client(addr, transport, sni, self.config.query_timeout).await {
                    Some(client) => UpstreamChoice::Direct(client),
                    None => UpstreamChoice::ServFail,
                }
            }
        }
    }

    /// Forward a query to the configured upstreams, in order, stopping
    /// at the first that answers. Falls over on per-query timeout or
    /// transport failure, which is the whole point: the guest holds the
    /// gateway as its only nameserver and cannot try the rest itself.
    /// `None` when every upstream is unusable.
    async fn forward_to_configured(
        &self,
        _raw_query: &[u8],
        query_msg: &Message,
        domain: &str,
        transport: Transport,
    ) -> Option<Message> {
        match &self.configured {
            ConfiguredResolver::Direct(upstreams) => {
                let total = upstreams.len();
                for (index, upstream) in upstreams.iter().enumerate() {
                    let Some(client) = self.client_for(upstream, transport).await else {
                        continue;
                    };
                    if let Some(response) = self.send_query(&client, query_msg, domain).await {
                        return Some(response);
                    }
                    if index + 1 < total {
                        tracing::debug!(
                            domain = %domain,
                            upstream = %upstream.addr,
                            "upstream DNS unusable, trying next configured nameserver",
                        );
                    }
                }
                None
            }
            #[cfg(windows)]
            ConfiguredResolver::WindowsSystem(resolver) => {
                match resolver.query(_raw_query, transport).await {
                    Ok(response) => match Message::from_bytes(&response) {
                        Ok(response) => Some(response),
                        Err(error) => {
                            tracing::warn!(
                                domain = %domain,
                                error = %error,
                                "Windows system DNS returned an invalid response",
                            );
                            None
                        }
                    },
                    Err(error) => {
                        tracing::warn!(
                            domain = %domain,
                            error = %error,
                            "Windows system DNS query failed",
                        );
                        None
                    }
                }
            }
        }
    }

    /// Send one query to one upstream. `None` means this upstream did
    /// not produce a usable answer, which is what makes the caller fall
    /// over to the next one: a per-query timeout and a transport error
    /// both arrive as `Some(Err)`, and a closed stream as `None`.
    ///
    /// A response that *arrives* is returned as-is even when it carries
    /// SERVFAIL or REFUSED. That is an answer from a working resolver,
    /// not an unusable server, and re-asking the next one would change
    /// what the sandbox resolves rather than just repairing reachability.
    async fn send_query(
        &self,
        client: &Client,
        query_msg: &Message,
        domain: &str,
    ) -> Option<Message> {
        let mut send = client.send(DnsRequest::from(query_msg.clone()));
        match send.next().await {
            Some(Ok(resp)) => Some(resp.into()),
            Some(Err(e)) => {
                tracing::warn!(domain = %domain, error = %e, "upstream DNS send failed");
                None
            }
            None => {
                tracing::warn!(domain = %domain, "upstream DNS closed stream without a response");
                None
            }
        }
    }

    /// Get the client for one configured upstream on `transport`. UDP
    /// is shared (pre-connected at startup); TCP is built on first use
    /// and cached per upstream. DoT guests reuse the TCP client — the
    /// configured upstream is typically on the host's loopback or
    /// internal network and serves plain DNS, so re-TLSing there is
    /// overkill.
    ///
    /// Called per upstream as the query walks the list, so an upstream
    /// that is never reached never pays for a TCP handshake.
    async fn client_for(
        &self,
        upstream: &ConfiguredUpstream,
        transport: Transport,
    ) -> Option<Client> {
        match transport {
            Transport::Udp => Some(upstream.udp.clone()),
            Transport::Tcp | Transport::Dot => {
                let timeout = self.config.query_timeout;
                let addr = upstream.addr;
                upstream
                    .tcp
                    .get_or_try_init(
                        || async move { build_tcp_client(addr, timeout).await.ok_or(()) },
                    )
                    .await
                    .ok()
                    .cloned()
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
        platform_policy: Option<Arc<NetworkPolicy>>,
        shared: Arc<SharedState>,
        gateway: GatewayIps,
    ) -> DnsForwarderHandle {
        let (forwarder_tx, forwarder_rx) = watch::channel(None);
        handle.spawn(async move {
            let Some(forwarder) = Self::build(
                config,
                gateway_ips,
                network_policy,
                platform_policy,
                shared,
                gateway,
            )
            .await
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
        platform_policy: Option<Arc<NetworkPolicy>>,
        shared: Arc<SharedState>,
        gateway: GatewayIps,
    ) -> Option<Arc<Self>> {
        let configured = if !config.nameservers.is_empty() {
            match resolve_nameservers(&config.nameservers).await {
                Ok(upstreams) if !upstreams.is_empty() => ConfiguredResolver::Direct(
                    Self::build_direct_upstreams(upstreams, config.query_timeout).await?,
                ),
                Ok(_) => {
                    tracing::error!("no configured nameservers resolved to an address");
                    return None;
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to resolve configured nameservers");
                    return None;
                }
            }
        } else if cfg!(windows) {
            #[cfg(windows)]
            {
                ConfiguredResolver::WindowsSystem(WindowsSystemResolver::new(config.query_timeout))
            }
            #[cfg(not(windows))]
            unreachable!()
        } else {
            #[cfg(not(windows))]
            match read_host_dns_servers().await {
                Ok(upstreams) if !upstreams.is_empty() => ConfiguredResolver::Direct(
                    Self::build_direct_upstreams(upstreams, config.query_timeout).await?,
                ),
                Ok(_) => {
                    tracing::error!("no upstream DNS servers discovered from host");
                    return None;
                }
                Err(e) => {
                    tracing::error!(error = %e, "failed to read host DNS configuration");
                    return None;
                }
            }
            #[cfg(windows)]
            unreachable!()
        };

        Some(Arc::new(Self {
            configured,
            gateway_ips,
            network_policy,
            platform_policy,
            shared,
            gateway,
            config,
        }))
    }

    /// Build every direct upstream so the gateway path can fall over when one is unreachable.
    async fn build_direct_upstreams(
        upstreams: Vec<SocketAddr>,
        query_timeout: Duration,
    ) -> Option<Vec<ConfiguredUpstream>> {
        let mut configured = Vec::with_capacity(upstreams.len());
        for addr in upstreams {
            let Some(udp) = build_udp_client(addr, query_timeout).await else {
                tracing::warn!(upstream = %addr, "skipping upstream: failed to build UDP client");
                continue;
            };
            configured.push(ConfiguredUpstream {
                addr,
                udp,
                tcp: OnceCell::new(),
            });
        }
        if configured.is_empty() {
            tracing::error!("no upstream DNS client could be built");
            return None;
        }
        Some(configured)
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

    /// Build a forwarder for proxy tests whose queries are handled locally.
    #[cfg(test)]
    pub(crate) async fn for_proxy_test(shared: Arc<SharedState>, gateway: GatewayIps) -> Arc<Self> {
        let config = Arc::new(NormalizedDnsConfig::from_config(
            crate::config::DnsConfig::default(),
        ));
        let upstream = SocketAddr::from(([127, 0, 0, 1], 9));
        let udp = build_udp_client(upstream, config.query_timeout)
            .await
            .expect("test UDP client should initialize");
        let gateway_ips = Arc::new(
            gateway
                .ipv4
                .map(IpAddr::V4)
                .into_iter()
                .chain(gateway.ipv6.map(IpAddr::V6))
                .collect(),
        );

        Arc::new(Self {
            configured: ConfiguredResolver::Direct(vec![ConfiguredUpstream {
                addr: upstream,
                udp,
                tcp: OnceCell::new(),
            }]),
            gateway_ips,
            network_policy: Arc::new(NetworkPolicy::allow_all()),
            platform_policy: None,
            shared,
            gateway,
            config,
        })
    }
}

/// Return whether a private/reserved DNS answer was explicitly made reachable.
///
/// Rebind protection remains fail-closed unless an address-only TCP or UDP
/// policy evaluation allows the answer. Port-scoped rules do not qualify here;
/// they cannot be evaluated safely before the guest chooses a connection port.
#[cfg(test)]
fn policy_allows_rebind_address(
    policy: &NetworkPolicy,
    shared: &SharedState,
    addr: IpAddr,
) -> bool {
    policies_allow_rebind_address(policy, None, shared, addr)
}

/// Return whether both the platform floor and tenant policy admit a private answer.
fn policies_allow_rebind_address(
    policy: &NetworkPolicy,
    platform_policy: Option<&NetworkPolicy>,
    shared: &SharedState,
    addr: IpAddr,
) -> bool {
    [crate::policy::Protocol::Tcp, crate::policy::Protocol::Udp]
        .into_iter()
        .any(|protocol| {
            let platform_allows = platform_policy.is_none_or(|platform| {
                platform
                    .evaluate_egress_ip(addr, protocol, shared)
                    .is_allow()
            });
            platform_allows
                && policy.evaluate_explicit_egress_ip(addr, protocol, shared) == Some(Action::Allow)
        })
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Decide where a query goes based on the guest-chosen `original_dst`,
/// the gateway IP set, and the network policy. Pure function — no
/// upstream connection happens here. Lifted out of [`DnsForwarder`] so
/// the rule logic is testable without a real upstream client.
#[cfg(test)]
fn decide_upstream(
    gateway_ips: &HashSet<IpAddr>,
    policy: &NetworkPolicy,
    shared: &SharedState,
    original_dst: Option<IpAddr>,
    transport: Transport,
) -> UpstreamDecision {
    decide_upstream_with_platform(gateway_ips, policy, None, shared, original_dst, transport)
}

fn decide_upstream_with_platform(
    gateway_ips: &HashSet<IpAddr>,
    policy: &NetworkPolicy,
    platform_policy: Option<&NetworkPolicy>,
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
    if platform_policy.is_some_and(|platform| {
        platform
            .evaluate_egress(policy_dst, transport.policy_protocol(), shared)
            .is_deny()
    }) || policy
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

/// Return the single DNS question this forwarder is willing to policy-check.
fn single_question(query: &Message) -> Result<&Query, ResponseCode> {
    if query.queries.len() == 1 {
        return Ok(&query.queries[0]);
    }

    Err(ResponseCode::FormErr)
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
    query_name: &str,
) -> Option<(Vec<IpAddr>, Duration)> {
    if response.metadata.response_code != ResponseCode::NoError {
        return None;
    }

    let mut eligible_names = HashSet::from([normalize_dns_name(query_name)]);
    let mut ttl: Option<Duration> = None;

    // CNAME answers are allowed only when they start from the queried owner.
    // Iterate to support ordinary alias chains without trusting unrelated RRs.
    let mut changed = true;
    while changed {
        changed = false;
        for record in &response.answers {
            let owner = normalize_dns_name(&record.name.to_string());
            if !eligible_names.contains(&owner) {
                continue;
            }

            if let RData::CNAME(CNAME(canonical)) = &record.data {
                let record_ttl = dns_record_ttl(record.ttl);
                ttl = Some(ttl.map_or(record_ttl, |current| current.min(record_ttl)));
                changed |= eligible_names.insert(normalize_dns_name(&canonical.to_string()));
            }
        }
    }

    let mut addrs = Vec::new();

    for record in &response.answers {
        if !eligible_names.contains(&normalize_dns_name(&record.name.to_string())) {
            continue;
        }

        let addr = match (family, &record.data) {
            (ResolvedHostnameFamily::Ipv4, RData::A(a)) => IpAddr::V4((*a).into()),
            (ResolvedHostnameFamily::Ipv6, RData::AAAA(aaaa)) => IpAddr::V6((*aaaa).into()),
            _ => continue,
        };
        addrs.push(addr);
        let record_ttl = dns_record_ttl(record.ttl);
        ttl = Some(ttl.map_or(record_ttl, |current| current.min(record_ttl)));
    }

    if addrs.is_empty() {
        None
    } else {
        ttl.map(|ttl| (addrs, ttl))
    }
}

fn dns_record_ttl(ttl: u32) -> Duration {
    Duration::from_secs(u64::from(ttl.max(RESOLVED_HOSTNAME_MIN_TTL_SECS)))
}

fn normalize_dns_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
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
    use std::net::Ipv4Addr;
    use std::sync::atomic::{AtomicUsize, Ordering};

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

    /// Black-hole UDP server: recv the query, never send a reply, so the
    /// client hits its per-query timeout. Mirrors `dns::client::tests`.
    async fn blackhole_udp() -> SocketAddr {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let _ = sock.recv_from(&mut buf).await;
            }
        });
        addr
    }

    /// UDP server that answers every query with `answer_ip`, and reports
    /// how many queries it received so a test can prove an upstream was
    /// never consulted.
    async fn responding_udp(answer_ip: Ipv4Addr) -> (SocketAddr, Arc<AtomicUsize>) {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let hits = Arc::new(AtomicUsize::new(0));
        let seen = Arc::clone(&hits);
        tokio::spawn(async move {
            let mut buf = [0u8; 4096];
            loop {
                let Ok((len, from)) = sock.recv_from(&mut buf).await else {
                    continue;
                };
                seen.fetch_add(1, Ordering::SeqCst);
                let Ok(query) = Message::from_bytes(&buf[..len]) else {
                    continue;
                };
                let mut resp =
                    Message::new(query.metadata.id, MessageType::Response, OpCode::Query);
                resp.metadata.recursion_desired = query.metadata.recursion_desired;
                resp.metadata.recursion_available = true;
                if let Some(q) = query.queries.first() {
                    resp.add_query(q.clone());
                    resp.answers.push(Record::from_rdata(
                        q.name().clone(),
                        60,
                        RData::A(A::from(answer_ip)),
                    ));
                }
                if let Ok(bytes) = resp.to_bytes() {
                    let _ = sock.send_to(&bytes, from).await;
                }
            }
        });
        (addr, hits)
    }

    /// Build a forwarder over `upstreams` with a short query timeout, as
    /// the gateway path uses it. No microVM or host resolver involved.
    async fn forwarder_over(upstreams: &[SocketAddr]) -> Arc<DnsForwarder> {
        let config = Arc::new(NormalizedDnsConfig {
            rebind_protection: false,
            nameservers: Vec::new(),
            query_timeout: Duration::from_millis(300),
        });
        let mut configured = Vec::new();
        for addr in upstreams {
            configured.push(ConfiguredUpstream {
                addr: *addr,
                udp: build_udp_client(*addr, config.query_timeout)
                    .await
                    .expect("udp client"),
                tcp: OnceCell::new(),
            });
        }
        let gateway_ip: IpAddr = "10.0.0.1".parse().unwrap();
        Arc::new(DnsForwarder {
            configured: ConfiguredResolver::Direct(configured),
            gateway_ips: Arc::new(HashSet::from([gateway_ip])),
            network_policy: Arc::new(NetworkPolicy::from_profiles([NetworkProfile::Public])),
            platform_policy: None,
            shared: Arc::new(SharedState::new(4)),
            gateway: GatewayIps {
                ipv4: Some("10.0.0.1".parse().unwrap()),
                ipv6: None,
            },
            config,
        })
    }

    /// Resolve `example.com` through the gateway path and return the
    /// first A answer, or `None` if the forwarder synthesized a failure.
    async fn resolve_via_gateway(forwarder: &DnsForwarder) -> Option<Ipv4Addr> {
        let query = make_query("example.com.", RecordType::A);
        let raw = query.to_bytes().expect("encode query");
        let gateway: IpAddr = "10.0.0.1".parse().unwrap();
        let bytes = forwarder
            .forward(&raw, Some(gateway), Transport::Udp, None)
            .await?;
        let msg = Message::from_bytes(&bytes).expect("parse response");
        if msg.metadata.response_code != ResponseCode::NoError {
            return None;
        }
        msg.answers.iter().find_map(|r| match &r.data {
            RData::A(a) => Some(Ipv4Addr::from(*a)),
            _ => None,
        })
    }

    /// The reported bug: only the first upstream was ever tried, so an
    /// unusable first nameserver made every lookup fail even though a
    /// later one worked. The guest is handed the gateway as its only
    /// nameserver, so it cannot try the rest itself.
    #[tokio::test]
    async fn configured_upstream_falls_over_to_the_next_on_timeout() {
        let dead = blackhole_udp().await;
        let (live, live_hits) = responding_udp(Ipv4Addr::new(93, 184, 216, 34)).await;

        let forwarder = forwarder_over(&[dead, live]).await;

        assert_eq!(
            resolve_via_gateway(&forwarder).await,
            Some(Ipv4Addr::new(93, 184, 216, 34)),
            "a stalled first upstream must fall over to the next one"
        );
        assert_eq!(
            live_hits.load(Ordering::SeqCst),
            1,
            "the working upstream should have been queried exactly once"
        );
    }

    /// The other half of the reported reproduction: with the order
    /// reversed the lookup already worked. It must keep working, and a
    /// query the first upstream answers must not be sent to the rest.
    ///
    /// The second upstream answers too (with a different address) rather
    /// than being a black hole, so this fails if the forwarder fans out.
    /// With a silent second server the fan-out is invisible: the reply
    /// never arrives, so the answer and the first server's hit count are
    /// identical either way.
    #[tokio::test]
    async fn first_usable_upstream_answers_without_consulting_the_rest() {
        let (first, first_hits) = responding_udp(Ipv4Addr::new(198, 51, 100, 7)).await;
        let (second, second_hits) = responding_udp(Ipv4Addr::new(198, 51, 100, 8)).await;

        let forwarder = forwarder_over(&[first, second]).await;

        assert_eq!(
            resolve_via_gateway(&forwarder).await,
            Some(Ipv4Addr::new(198, 51, 100, 7)),
            "the answer must come from the first upstream"
        );
        assert_eq!(
            first_hits.load(Ordering::SeqCst),
            1,
            "a query answered by the first upstream must not be re-sent"
        );
        assert_eq!(
            second_hits.load(Ordering::SeqCst),
            0,
            "later upstreams must not be consulted once one answers"
        );
    }

    /// Failover walks the whole list, not just one extra server.
    #[tokio::test]
    async fn configured_upstreams_fall_over_past_several_dead_servers() {
        let first = blackhole_udp().await;
        let second = blackhole_udp().await;
        let (live, _) = responding_udp(Ipv4Addr::new(203, 0, 113, 5)).await;

        let forwarder = forwarder_over(&[first, second, live]).await;

        assert_eq!(
            resolve_via_gateway(&forwarder).await,
            Some(Ipv4Addr::new(203, 0, 113, 5))
        );
    }

    /// When every upstream is unusable the guest still gets a definite
    /// failure rather than a hang.
    #[tokio::test]
    async fn all_upstreams_unusable_yields_servfail() {
        let first = blackhole_udp().await;
        let second = blackhole_udp().await;

        let forwarder = forwarder_over(&[first, second]).await;

        let query = make_query("example.com.", RecordType::A);
        let raw = query.to_bytes().expect("encode query");
        let gateway: IpAddr = "10.0.0.1".parse().unwrap();
        let bytes = forwarder
            .forward(&raw, Some(gateway), Transport::Udp, None)
            .await
            .expect("a synthesized response");
        let msg = Message::from_bytes(&bytes).expect("parse response");
        assert_eq!(msg.metadata.response_code, ResponseCode::ServFail);
        assert_eq!(msg.metadata.id, 0x4242, "guest transaction id is preserved");
    }

    fn make_response(query: &Message) -> Message {
        let mut response = Message::response(query.metadata.id, query.metadata.op_code);
        response.metadata.response_code = ResponseCode::NoError;
        response.metadata.recursion_available = true;
        response.add_query(query.queries[0].clone());
        response
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
    fn platform_public_floor_rejects_tenant_allowed_private_dns_answer() {
        let tenant = NetworkPolicy::from_profiles([NetworkProfile::Private]);
        let platform = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let shared = SharedState::new(4);

        assert!(!policies_allow_rebind_address(
            &tenant,
            Some(&platform),
            &shared,
            "10.0.0.7".parse().unwrap(),
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

    #[test]
    fn single_question_rejects_multi_question_packets() {
        let mut query = make_query("example.com.", RecordType::A);
        let mut extra = Query::new();
        extra.set_name(Name::from_ascii("other.example.").unwrap());
        extra.set_query_type(RecordType::AAAA);
        extra.set_query_class(DNSClass::IN);
        query.add_query(extra);

        assert!(matches!(
            single_question(&query),
            Err(ResponseCode::FormErr)
        ));

        let bytes = build_status_response(&query, ResponseCode::FormErr).expect("built");
        let msg = Message::from_bytes(&bytes).expect("parse response");
        assert_eq!(msg.metadata.response_code, ResponseCode::FormErr);
        assert_eq!(msg.queries.len(), 1);
        assert_eq!(msg.queries[0].query_type(), RecordType::A);
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

    #[test]
    fn extract_addrs_and_ttl_ignores_unrelated_answers() {
        let query = make_query("example.com.", RecordType::A);
        let mut response = make_response(&query);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            30,
            RData::A(A::from(std::net::Ipv4Addr::new(93, 184, 216, 34))),
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("unrelated.example.").unwrap(),
            10,
            RData::A(A::from(std::net::Ipv4Addr::new(198, 51, 100, 7))),
        ));

        let (addrs, ttl) =
            extract_addrs_and_ttl(&response, ResolvedHostnameFamily::Ipv4, "example.com").unwrap();

        assert_eq!(
            addrs,
            vec![IpAddr::V4(std::net::Ipv4Addr::new(93, 184, 216, 34))]
        );
        assert_eq!(ttl, Duration::from_secs(30));
    }

    #[test]
    fn extract_addrs_and_ttl_follows_cname_chain() {
        let query = make_query("example.com.", RecordType::A);
        let mut response = make_response(&query);
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            20,
            RData::CNAME(CNAME(Name::from_ascii("cdn.example.net.").unwrap())),
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("cdn.example.net.").unwrap(),
            40,
            RData::A(A::from(std::net::Ipv4Addr::new(203, 0, 113, 10))),
        ));
        response.add_answer(Record::from_rdata(
            Name::from_ascii("other.example.net.").unwrap(),
            1,
            RData::A(A::from(std::net::Ipv4Addr::new(203, 0, 113, 11))),
        ));

        let (addrs, ttl) =
            extract_addrs_and_ttl(&response, ResolvedHostnameFamily::Ipv4, "example.com").unwrap();

        assert_eq!(
            addrs,
            vec![IpAddr::V4(std::net::Ipv4Addr::new(203, 0, 113, 10))]
        );
        assert_eq!(ttl, Duration::from_secs(20));
    }

    #[test]
    fn extract_addrs_and_ttl_ignores_error_responses() {
        let query = make_query("example.com.", RecordType::A);
        let mut response = make_response(&query);
        response.metadata.response_code = ResponseCode::NXDomain;
        response.add_answer(Record::from_rdata(
            Name::from_ascii("example.com.").unwrap(),
            30,
            RData::A(A::from(std::net::Ipv4Addr::new(93, 184, 216, 34))),
        ));

        assert!(
            extract_addrs_and_ttl(&response, ResolvedHostnameFamily::Ipv4, "example.com").is_none()
        );
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
    fn platform_public_floor_denies_private_direct_resolver() {
        let gateways = gateway_set();
        let shared = SharedState::new(4);
        let tenant = NetworkPolicy::allow_all();
        let platform = NetworkPolicy::from_profiles([NetworkProfile::Public]);
        let dst = Some(IpAddr::V4("10.0.0.53".parse().unwrap()));

        assert_eq!(
            decide_upstream_with_platform(
                &gateways,
                &tenant,
                Some(&platform),
                &shared,
                dst,
                Transport::Udp,
            ),
            UpstreamDecision::PolicyDenied
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
