//! Policy types: rules, actions, destinations, and protocol matching.
//!
//! A [`NetworkPolicy`] is a single ordered rule list plus two direction-
//! specific default actions. Each rule carries its direction
//! ([`Direction`]) — `Egress`, `Ingress`, or `Both` — which determines
//! which evaluator considers it. Rule lookup is first-match-wins per
//! direction; if no rule of the right direction matches, the direction-
//! specific default applies.
//!
//! The `Rule::destination` field is direction-dependent in interpretation.
//! In an egress rule it matches the destination the guest is reaching;
//! in an ingress rule it matches the source (peer) of the incoming
//! connection. `Rule::ports` always refers to the guest-side port
//! (destination for egress, listening port for ingress) — ingress does
//! not filter by peer source port.
//!
//! [`Rule::protocols`] and [`Rule::ports`] are sets (Vecs); a rule
//! matches if the packet's protocol is in `protocols` or `protocols` is
//! empty (any-protocol), and likewise for ports. This compresses common
//! cases like "TCP-or-UDP on 80-or-443 to Public" into a single rule.

use std::net::{IpAddr, SocketAddr};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::shared::SharedState;

use super::destination::{matches_cidr, matches_group};
use super::name::DomainName;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Network policy: single ordered rule list plus per-direction default actions.
///
/// Rules carry a [`Direction`] field that determines which evaluator
/// considers them. Egress evaluation iterates rules where
/// `direction ∈ {Egress, Both}`; ingress evaluation iterates rules where
/// `direction ∈ {Ingress, Both}`. First-match-wins within a direction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Default action for egress traffic not matching any rule.
    #[serde(default = "Action::deny")]
    pub default_egress: Action,

    /// Default action for ingress traffic not matching any rule.
    #[serde(default = "Action::allow")]
    pub default_ingress: Action,

    /// Ordered list of rules, evaluated first-match-wins per direction.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Action to take on matched traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Allow the traffic.
    Allow,

    /// Silently drop.
    Deny,
}

/// A single network rule.
///
/// The `destination` field is direction-dependent: in an egress-direction
/// rule, `destination` is what the guest is reaching; in an ingress-
/// direction rule, `destination` is the source (peer) of the incoming
/// connection. `Both`-direction rules apply in either path with the
/// destination interpreted appropriately for each.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Direction this rule applies to: outbound, inbound, or either.
    pub direction: Direction,

    /// Destination filter. Direction-dependent interpretation.
    pub destination: Destination,

    /// Protocol set (empty = any protocol). The rule matches if the
    /// packet's protocol is in this set.
    #[serde(default)]
    pub protocols: Vec<Protocol>,

    /// Port-range set (empty = any port). Always the guest-side port:
    /// destination port for egress, listening port for ingress.
    #[serde(default)]
    pub ports: Vec<PortRange>,

    /// Action to take.
    pub action: Action,
}

/// Direction a rule applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Outbound: guest → remote. Evaluated by `evaluate_egress`.
    Egress,

    /// Inbound: peer → guest. Evaluated by `evaluate_ingress`.
    Ingress,

    /// Either direction. The rule is matched by both evaluators
    /// (egress and ingress).
    Any,
}

/// Traffic destination specification.
///
/// `Domain` and `DomainSuffix` values carry a validated [`DomainName`],
/// whose construction enforces the canonical form (lowercase ASCII,
/// leading/trailing dots stripped) once at parse time. Matching code
/// can then rely on byte equality against the DNS cache's own
/// canonical entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    /// Match any remote.
    Any,

    /// IP address or CIDR block.
    Cidr(IpNetwork),

    /// Exact domain name. Matches only when a cached hostname for the
    /// remote IP equals this name.
    Domain(DomainName),

    /// Domain suffix. Matches the apex domain itself and any subdomain
    /// of it (e.g. suffix `example.com` matches `example.com` and
    /// `foo.example.com` but not `evilexample.com`).
    DomainSuffix(DomainName),

    /// Pre-defined destination group.
    Group(DestinationGroup),
}

/// Pre-defined destination groups.
///
/// Categories are disjoint with one exception: `Metadata` is a single IP
/// (`169.254.169.254`) that also falls inside the `LinkLocal` range.
/// Membership order in [`matches_group`](super::destination::matches_group)
/// gives `Metadata` precedence over `LinkLocal` for that IP. All other
/// categories are disjoint; [`Public`](Self::Public) is defined as the
/// complement of the other five.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationGroup {
    /// Public internet — any address not in one of the other categories.
    Public,

    /// Loopback addresses (`127.0.0.0/8`, `::1`).
    Loopback,

    /// Private IP ranges (RFC 1918 + RFC 4193 ULA + CGN).
    Private,

    /// Link-local addresses (`169.254.0.0/16`, `fe80::/10`), excluding
    /// the metadata IP which is categorized as [`Metadata`](Self::Metadata).
    LinkLocal,

    /// Cloud metadata endpoints (`169.254.169.254`).
    Metadata,

    /// Multicast addresses (`224.0.0.0/4`, `ff00::/8`).
    Multicast,

    /// The sandbox host itself, reachable via the gateway IP and
    /// `host.microsandbox.internal`. Matches against the per-sandbox
    /// gateway IPs stored on [`SharedState`].
    Host,
}

/// Protocol filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// TCP.
    Tcp,

    /// UDP.
    Udp,

    /// ICMPv4.
    Icmpv4,

    /// ICMPv6.
    Icmpv6,
}

/// Port range for matching.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct PortRange {
    /// Start port (inclusive).
    pub start: u16,

    /// End port (inclusive).
    pub end: u16,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NetworkPolicy {
    /// No network access — deny everything in both directions.
    pub fn none() -> Self {
        Self {
            default_egress: Action::Deny,
            default_ingress: Action::Deny,
            rules: vec![],
        }
    }

    /// Unrestricted network access — allow everything in both directions.
    pub fn allow_all() -> Self {
        Self {
            default_egress: Action::Allow,
            default_ingress: Action::Allow,
            rules: vec![],
        }
    }

    /// Public internet only — allow egress to public IPs, deny private,
    /// loopback, link-local, and metadata. Ingress defaults to allow
    /// (preserves today's unfiltered published-port behavior).
    pub fn public_only() -> Self {
        Self {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule::allow_egress(Destination::Group(
                DestinationGroup::Public,
            ))],
        }
    }

    /// Non-local network access — allow public internet and private/LAN
    /// egress; deny loopback, link-local, and metadata. Ingress defaults
    /// to allow.
    pub fn non_local() -> Self {
        Self {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![
                Rule::allow_egress(Destination::Group(DestinationGroup::Public)),
                Rule::allow_egress(Destination::Group(DestinationGroup::Private)),
            ],
        }
    }

    /// Evaluate an outbound connection against the rule list.
    ///
    /// Iterates rules in order, considering only rules where
    /// `direction ∈ {Egress, Any}`. Returns the action from the first
    /// matching rule, or `default_egress` if no rule matches.
    pub fn evaluate_egress(
        &self,
        dst: SocketAddr,
        protocol: Protocol,
        shared: &SharedState,
    ) -> Action {
        for rule in &self.rules {
            if !matches!(rule.direction, Direction::Egress | Direction::Any) {
                continue;
            }
            if !rule_matches(rule, dst.ip(), Some(dst.port()), protocol, shared) {
                continue;
            }
            return rule.action;
        }
        self.default_egress
    }

    /// Evaluate an outbound ICMP packet against the rule list.
    ///
    /// Same as [`Self::evaluate_egress`] but without port matching —
    /// ICMP has no ports. Rules with a non-empty `ports` filter are
    /// skipped since applying a port range to a portless protocol would
    /// be semantically incorrect.
    pub fn evaluate_egress_ip(
        &self,
        dst: IpAddr,
        protocol: Protocol,
        shared: &SharedState,
    ) -> Action {
        for rule in &self.rules {
            if !matches!(rule.direction, Direction::Egress | Direction::Any) {
                continue;
            }
            if !rule.ports.is_empty() {
                continue;
            }
            if !rule_matches(rule, dst, None, protocol, shared) {
                continue;
            }
            return rule.action;
        }
        self.default_egress
    }

    /// Evaluate an inbound connection against the rule list.
    ///
    /// Iterates rules in order, considering only rules where
    /// `direction ∈ {Ingress, Any}`. `peer` is the source of the
    /// incoming connection (peer IP and source port — only the IP is
    /// matched). `guest_port` is the guest-side listening port; rules'
    /// `ports` filter is matched against `guest_port`, not the peer's
    /// port.
    pub fn evaluate_ingress(
        &self,
        peer: SocketAddr,
        guest_port: u16,
        protocol: Protocol,
        shared: &SharedState,
    ) -> Action {
        for rule in &self.rules {
            if !matches!(rule.direction, Direction::Ingress | Direction::Any) {
                continue;
            }
            if !rule_matches(rule, peer.ip(), Some(guest_port), protocol, shared) {
                continue;
            }
            return rule.action;
        }
        self.default_ingress
    }
}

impl Action {
    /// Returns `true` if this action allows the traffic.
    pub fn is_allow(self) -> bool {
        matches!(self, Action::Allow)
    }

    /// Returns `true` if this action denies the traffic.
    pub fn is_deny(self) -> bool {
        matches!(self, Action::Deny)
    }

    /// Helper for `#[serde(default)]` — returns [`Action::Allow`].
    pub fn allow() -> Self {
        Action::Allow
    }

    /// Helper for `#[serde(default)]` — returns [`Action::Deny`].
    pub fn deny() -> Self {
        Action::Deny
    }
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self::public_only()
    }
}

impl Rule {
    /// Convenience: allow rule for egress, any protocol, any port.
    pub fn allow_egress(destination: Destination) -> Self {
        Self::new(Direction::Egress, destination, Action::Allow)
    }

    /// Convenience: deny rule for egress, any protocol, any port.
    pub fn deny_egress(destination: Destination) -> Self {
        Self::new(Direction::Egress, destination, Action::Deny)
    }

    /// Convenience: allow rule for ingress, any protocol, any port.
    pub fn allow_ingress(destination: Destination) -> Self {
        Self::new(Direction::Ingress, destination, Action::Allow)
    }

    /// Convenience: deny rule for ingress, any protocol, any port.
    pub fn deny_ingress(destination: Destination) -> Self {
        Self::new(Direction::Ingress, destination, Action::Deny)
    }

    /// Convenience: allow rule for either direction, any protocol, any port.
    pub fn allow_any(destination: Destination) -> Self {
        Self::new(Direction::Any, destination, Action::Allow)
    }

    /// Convenience: deny rule for either direction, any protocol, any port.
    pub fn deny_any(destination: Destination) -> Self {
        Self::new(Direction::Any, destination, Action::Deny)
    }

    fn new(direction: Direction, destination: Destination, action: Action) -> Self {
        Self {
            direction,
            destination,
            protocols: Vec::new(),
            ports: Vec::new(),
            action,
        }
    }
}

impl PortRange {
    /// Match a single port.
    pub fn single(port: u16) -> Self {
        Self {
            start: port,
            end: port,
        }
    }

    /// Match a range of ports (inclusive).
    pub fn range(start: u16, end: u16) -> Self {
        Self { start, end }
    }

    /// Returns `true` if the port falls within this range.
    pub fn contains(&self, port: u16) -> bool {
        port >= self.start && port <= self.end
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Internal helper: does this rule match a flow's address/port/protocol?
///
/// The direction filter is applied by the caller (`evaluate_egress` /
/// `evaluate_ingress`). This function checks only protocol set, port
/// set, and destination match.
fn rule_matches(
    rule: &Rule,
    addr: IpAddr,
    port: Option<u16>,
    protocol: Protocol,
    shared: &SharedState,
) -> bool {
    if !rule.protocols.is_empty() && !rule.protocols.contains(&protocol) {
        return false;
    }
    if !rule.ports.is_empty() {
        let Some(p) = port else {
            // Caller doesn't have a port (ICMP path). Skip rules that
            // require a port match.
            return false;
        };
        if !rule.ports.iter().any(|range| range.contains(p)) {
            return false;
        }
    }
    matches_destination(&rule.destination, addr, shared)
}

/// Check if an IP address matches a destination specification.
fn matches_destination(dest: &Destination, addr: IpAddr, shared: &SharedState) -> bool {
    match dest {
        Destination::Any => true,
        Destination::Cidr(network) => matches_cidr(network, addr),
        Destination::Group(DestinationGroup::Host) => matches_host(addr, shared),
        Destination::Group(group) => matches_group(*group, addr),
        Destination::Domain(domain) => {
            shared.any_resolved_hostname(addr, |hostname| hostname == domain.as_str())
        }
        Destination::DomainSuffix(suffix) => {
            shared.any_resolved_hostname(addr, |hostname| matches_suffix(hostname, suffix.as_str()))
        }
    }
}

/// Matches the per-sandbox gateway IPs carried by [`SharedState`]. Returns
/// `false` when gateway IPs haven't been set (e.g. isolated unit tests
/// that don't exercise Host rules).
fn matches_host(addr: IpAddr, shared: &SharedState) -> bool {
    match addr {
        IpAddr::V4(v4) => shared.gateway_ipv4().is_some_and(|gw| gw == v4),
        IpAddr::V6(v6) => shared.gateway_ipv6().is_some_and(|gw| gw == v6),
    }
}

/// Label-aware suffix match on pre-canonicalized strings.
///
/// `hostname` is the lowercased-no-trailing-dot form the DNS cache
/// stores; `suffix` is a [`DomainName`]'s inner string, which shares
/// the same canonical form. Matches either the apex domain itself or
/// any subdomain (label-aligned, so `evilexample.com` does not match
/// suffix `example.com`). A plain `==` would miss the apex-vs-subdomain
/// asymmetry, which is why this helper still exists.
fn matches_suffix(hostname: &str, suffix: &str) -> bool {
    if hostname == suffix {
        return true;
    }
    if hostname.len() > suffix.len() + 1 {
        let (prefix, tail) = hostname.split_at(hostname.len() - suffix.len());
        return prefix.ends_with('.') && tail == suffix;
    }
    false
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::time::Duration;

    use super::*;
    use crate::shared::ResolvedHostnameFamily;

    const PYPI_V4: &str = "151.101.0.223";
    const FILES_V4: &str = "151.101.64.223";
    const CLOUDFLARE_V6: &str = "2606:4700:4700::1111";

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn sock(ip_str: &str, port: u16) -> SocketAddr {
        SocketAddr::new(ip(ip_str), port)
    }

    /// Insert a resolved hostname into the cache.
    fn cache(shared: &SharedState, host: &str, family: ResolvedHostnameFamily, ip_str: &str) {
        shared.cache_resolved_hostname(host, family, [ip(ip_str)], Duration::from_secs(60));
    }

    /// Build a shared state that has one IPv4 resolved hostname cached.
    fn shared_with_host(host: &str, ip_str: &str) -> SharedState {
        let shared = SharedState::new(4);
        cache(&shared, host, ResolvedHostnameFamily::Ipv4, ip_str);
        shared
    }

    /// Build a shared state with gateway IPs set, for `Group::Host` tests.
    fn shared_with_gateway() -> (SharedState, Ipv4Addr, Ipv6Addr) {
        let shared = SharedState::new(4);
        let v4 = Ipv4Addr::new(100, 96, 0, 1);
        let v6 = Ipv6Addr::new(0xfd42, 0x6d73, 0x62, 0, 0, 0, 0, 1);
        shared.set_gateway_ips(v4, v6);
        (shared, v4, v6)
    }

    fn egress_tcp(policy: &NetworkPolicy, ip_str: &str, shared: &SharedState) -> Action {
        policy.evaluate_egress(sock(ip_str, 443), Protocol::Tcp, shared)
    }

    fn allow_rule(dest: Destination) -> NetworkPolicy {
        NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule::allow_egress(dest)],
        }
    }

    /// Outbound TCP/443 allow rule pinned to a specific hostname,
    /// used by the multi-rule default-deny scenarios below.
    fn allow_domain_tcp_443(domain: &str) -> Rule {
        Rule {
            direction: Direction::Egress,
            destination: Destination::Domain(domain.parse().unwrap()),
            protocols: vec![Protocol::Tcp],
            ports: vec![PortRange::single(443)],
            action: Action::Allow,
        }
    }

    #[test]
    fn exact_domain_rules_match_resolved_hostnames() {
        let shared = shared_with_host("pypi.org", PYPI_V4);
        let policy = allow_rule(Destination::Domain("pypi.org".parse().unwrap()));
        assert!(egress_tcp(&policy, PYPI_V4, &shared).is_allow());
    }

    #[test]
    fn exact_domain_rules_normalize_user_input() {
        let shared = shared_with_host("pypi.org", PYPI_V4);
        let policy = allow_rule(Destination::Domain("PyPI.Org.".parse().unwrap()));
        assert!(egress_tcp(&policy, PYPI_V4, &shared).is_allow());
    }

    #[test]
    fn suffix_rules_match_resolved_hostnames() {
        let shared = shared_with_host("files.pythonhosted.org", FILES_V4);
        let policy = allow_rule(Destination::DomainSuffix(
            ".pythonhosted.org".parse().unwrap(),
        ));
        assert!(egress_tcp(&policy, FILES_V4, &shared).is_allow());
    }

    #[test]
    fn suffix_rules_normalize_user_input() {
        let shared = shared_with_host("files.pythonhosted.org", FILES_V4);
        let policy = allow_rule(Destination::DomainSuffix(
            ".PythonHosted.Org.".parse().unwrap(),
        ));
        assert!(egress_tcp(&policy, FILES_V4, &shared).is_allow());
    }

    #[test]
    fn unresolved_domain_rules_do_not_match_by_ip_alone() {
        let shared = SharedState::new(4);
        let policy = allow_rule(Destination::Domain("pypi.org".parse().unwrap()));
        assert!(egress_tcp(&policy, PYPI_V4, &shared).is_deny());
    }

    #[test]
    fn exact_domain_rules_match_resolved_hostnames_for_icmp() {
        let shared = shared_with_host("pypi.org", PYPI_V4);
        let policy = allow_rule(Destination::Domain("pypi.org".parse().unwrap()));
        assert!(
            policy
                .evaluate_egress_ip(ip(PYPI_V4), Protocol::Icmpv4, &shared)
                .is_allow()
        );
    }

    #[test]
    fn deserialized_policies_normalize_domain_values() {
        let shared = shared_with_host("pypi.org", PYPI_V4);
        let policy: NetworkPolicy = serde_json::from_str(
            r#"{
                "default_egress": "deny",
                "default_ingress": "allow",
                "rules": [
                    {
                        "direction": "egress",
                        "destination": { "domain": "PyPI.Org." },
                        "action": "allow"
                    }
                ]
            }"#,
        )
        .unwrap();
        assert!(egress_tcp(&policy, PYPI_V4, &shared).is_allow());
    }

    /// Default-deny policy with explicit allow rules for multiple
    /// hostnames on TCP/443. Both hostnames resolve via DNS first,
    /// populating the cache, and the subsequent connects must be
    /// allowed through the Domain rules.
    #[test]
    fn default_deny_allows_multiple_domain_rules_after_dns() {
        let shared = SharedState::new(4);
        cache(&shared, "pypi.org", ResolvedHostnameFamily::Ipv4, PYPI_V4);
        cache(
            &shared,
            "files.pythonhosted.org",
            ResolvedHostnameFamily::Ipv4,
            FILES_V4,
        );

        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![
                allow_domain_tcp_443("pypi.org"),
                allow_domain_tcp_443("files.pythonhosted.org"),
            ],
        };

        assert!(
            policy
                .evaluate_egress(sock(PYPI_V4, 443), Protocol::Tcp, &shared)
                .is_allow(),
            "pypi.org:443 should be allowed after DNS resolution"
        );
        assert!(
            policy
                .evaluate_egress(sock(FILES_V4, 443), Protocol::Tcp, &shared)
                .is_allow(),
            "files.pythonhosted.org:443 should be allowed after DNS resolution"
        );
    }

    /// Cache has `pypi.org` -> IP, but the policy only allows
    /// `example.com`. A connection to `pypi.org`'s IP must not be
    /// allowed through the unrelated rule.
    #[test]
    fn domain_rule_does_not_match_other_cached_hostnames() {
        let shared = shared_with_host("pypi.org", PYPI_V4);
        let policy = allow_rule(Destination::Domain("example.com".parse().unwrap()));
        assert!(egress_tcp(&policy, PYPI_V4, &shared).is_deny());
    }

    /// A suffix `.pythonhosted.org` must also match the apex domain
    /// `pythonhosted.org` itself (a common source of confusion with
    /// naive suffix matching that checks only `.ends_with`).
    #[test]
    fn suffix_rule_matches_apex_domain_itself() {
        let shared = shared_with_host("pythonhosted.org", FILES_V4);
        let policy = allow_rule(Destination::DomainSuffix(
            ".pythonhosted.org".parse().unwrap(),
        ));
        assert!(egress_tcp(&policy, FILES_V4, &shared).is_allow());
    }

    /// `.pythonhosted.org` must not match `evilpythonhosted.org`: a
    /// naive `ends_with` check would pass, but the label-boundary
    /// guard (dot before the suffix) must reject it.
    #[test]
    fn suffix_rule_does_not_false_match_adjacent_domain() {
        let shared = shared_with_host("evilpythonhosted.org", FILES_V4);
        let policy = allow_rule(Destination::DomainSuffix(
            ".pythonhosted.org".parse().unwrap(),
        ));
        assert!(egress_tcp(&policy, FILES_V4, &shared).is_deny());
    }

    /// Shared-IP mitigation via rule ordering: a specific allow-Domain
    /// rule listed before a broad deny-Cidr rule must win under
    /// first-match-wins semantics, even when both would match the
    /// destination.
    #[test]
    fn allow_rule_before_deny_wins_on_shared_ip() {
        let shared = shared_with_host("pypi.org", PYPI_V4);
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![
                Rule::allow_egress(Destination::Domain("pypi.org".parse().unwrap())),
                Rule {
                    direction: Direction::Egress,
                    destination: Destination::Cidr("151.101.0.0/16".parse().unwrap()),
                    protocols: Vec::new(),
                    ports: Vec::new(),
                    action: Action::Deny,
                },
            ],
        };
        assert!(egress_tcp(&policy, PYPI_V4, &shared).is_allow());
    }

    /// UDP traffic (e.g., QUIC over port 443) must match Domain rules
    /// the same way TCP does, since both go through `evaluate_egress`.
    #[test]
    fn udp_egress_consults_domain_cache() {
        let shared = shared_with_host("pypi.org", PYPI_V4);
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule {
                direction: Direction::Egress,
                destination: Destination::Domain("pypi.org".parse().unwrap()),
                protocols: vec![Protocol::Udp],
                ports: vec![PortRange::single(443)],
                action: Action::Allow,
            }],
        };
        assert!(
            policy
                .evaluate_egress(sock(PYPI_V4, 443), Protocol::Udp, &shared)
                .is_allow()
        );
    }

    /// Resolving only A (IPv4) must not grant access over IPv6, and
    /// vice versa. The family partition in the cache key guarantees
    /// independent refresh/expiry per address family.
    #[test]
    fn ipv4_and_ipv6_caches_are_independent() {
        let shared = shared_with_host("pypi.org", PYPI_V4);
        let policy = allow_rule(Destination::Domain("pypi.org".parse().unwrap()));
        assert!(
            egress_tcp(&policy, PYPI_V4, &shared).is_allow(),
            "cached IPv4 address should match"
        );
        assert!(
            egress_tcp(&policy, CLOUDFLARE_V6, &shared).is_deny(),
            "uncached IPv6 address must not match through an IPv4-only cache entry"
        );
    }

    // -- Group::Host -------------------------------------------------------

    #[test]
    fn group_host_matches_gateway_v4() {
        let (shared, gw4, _) = shared_with_gateway();
        let policy = NetworkPolicy {
            default_egress: Action::Allow,
            default_ingress: Action::Allow,
            rules: vec![Rule::deny_egress(Destination::Group(
                DestinationGroup::Host,
            ))],
        };
        let dst = SocketAddr::new(IpAddr::V4(gw4), 80);
        assert_eq!(
            policy.evaluate_egress(dst, Protocol::Tcp, &shared),
            Action::Deny
        );
    }

    #[test]
    fn group_host_matches_gateway_v6() {
        let (shared, _, gw6) = shared_with_gateway();
        let policy = NetworkPolicy {
            default_egress: Action::Allow,
            default_ingress: Action::Allow,
            rules: vec![Rule::deny_egress(Destination::Group(
                DestinationGroup::Host,
            ))],
        };
        let dst = SocketAddr::new(IpAddr::V6(gw6), 80);
        assert_eq!(
            policy.evaluate_egress(dst, Protocol::Tcp, &shared),
            Action::Deny
        );
    }

    #[test]
    fn group_host_does_not_match_other_ips() {
        let (shared, _, _) = shared_with_gateway();
        let policy = NetworkPolicy {
            default_egress: Action::Allow,
            default_ingress: Action::Allow,
            rules: vec![Rule::deny_egress(Destination::Group(
                DestinationGroup::Host,
            ))],
        };
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80);
        assert_eq!(
            policy.evaluate_egress(dst, Protocol::Tcp, &shared),
            Action::Allow
        );
    }

    #[test]
    fn public_only_preset_denies_host_gateway() {
        let (shared, gw4, gw6) = shared_with_gateway();
        let policy = NetworkPolicy::public_only();

        let v4 = SocketAddr::new(IpAddr::V4(gw4), 80);
        assert_eq!(
            policy.evaluate_egress(v4, Protocol::Tcp, &shared),
            Action::Deny,
            "default policy should deny host via IPv4 gateway"
        );

        let v6 = SocketAddr::new(IpAddr::V6(gw6), 80);
        assert_eq!(
            policy.evaluate_egress(v6, Protocol::Tcp, &shared),
            Action::Deny,
            "default policy should deny host via IPv6 gateway (ULA fd42::/8)"
        );
    }

    #[test]
    fn allow_all_preset_permits_host_gateway() {
        let (shared, gw4, _) = shared_with_gateway();
        let policy = NetworkPolicy::allow_all();
        let v4 = SocketAddr::new(IpAddr::V4(gw4), 80);
        assert_eq!(
            policy.evaluate_egress(v4, Protocol::Tcp, &shared),
            Action::Allow
        );
    }

    #[test]
    fn group_host_allow_overrides_private_deny_when_ordered_first() {
        let (shared, gw4, _) = shared_with_gateway();
        let mut policy = NetworkPolicy::public_only();
        policy.rules.insert(
            0,
            Rule::allow_egress(Destination::Group(DestinationGroup::Host)),
        );

        let v4 = SocketAddr::new(IpAddr::V4(gw4), 80);
        assert_eq!(
            policy.evaluate_egress(v4, Protocol::Tcp, &shared),
            Action::Allow
        );

        let other_private = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 80);
        assert_eq!(
            policy.evaluate_egress(other_private, Protocol::Tcp, &shared),
            Action::Deny,
            "non-host private destinations should still be blocked"
        );
    }

    /// Ingress default is Allow; empty ingress-applicable rules means
    /// all inbound traffic is permitted (today's unfiltered published-
    /// port behavior).
    #[test]
    fn default_ingress_allows_unfiltered_with_no_rules() {
        let shared = SharedState::new(4);
        let policy = NetworkPolicy::default();
        let peer = sock("198.51.100.10", 54321);
        assert!(
            policy
                .evaluate_ingress(peer, 8080, Protocol::Tcp, &shared)
                .is_allow()
        );
    }

    /// Single rule with `direction: Ingress` only fires for ingress
    /// evaluation, never for egress.
    #[test]
    fn ingress_rule_does_not_fire_on_egress() {
        let shared = SharedState::new(4);
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Deny,
            rules: vec![Rule::allow_ingress(Destination::Group(
                DestinationGroup::Private,
            ))],
        };
        // Egress to a private IP: ingress rule doesn't apply, falls to default_egress = Deny.
        assert!(
            policy
                .evaluate_egress(sock("10.0.0.5", 443), Protocol::Tcp, &shared)
                .is_deny()
        );
        // Ingress from a private peer: rule fires, allowed.
        assert!(
            policy
                .evaluate_ingress(sock("10.0.0.5", 54321), 8080, Protocol::Tcp, &shared)
                .is_allow()
        );
    }

    /// `Direction::Any` rule fires for evaluation in either direction.
    #[test]
    fn any_direction_rule_matches_egress_and_ingress() {
        let shared = SharedState::new(4);
        let policy = NetworkPolicy {
            default_egress: Action::Allow,
            default_ingress: Action::Allow,
            rules: vec![Rule::deny_any(Destination::Cidr(
                "1.2.3.4/32".parse().unwrap(),
            ))],
        };
        // Egress to 1.2.3.4: Any rule fires.
        assert!(
            policy
                .evaluate_egress(sock("1.2.3.4", 443), Protocol::Tcp, &shared)
                .is_deny()
        );
        // Ingress from 1.2.3.4: Any rule fires.
        assert!(
            policy
                .evaluate_ingress(sock("1.2.3.4", 54321), 8080, Protocol::Tcp, &shared)
                .is_deny()
        );
        // Egress to a different IP: rule doesn't match, falls to default_egress = Allow.
        assert!(
            policy
                .evaluate_egress(sock("8.8.8.8", 443), Protocol::Tcp, &shared)
                .is_allow()
        );
    }

    /// Wire-format casing: every field name and enum tag must serialize
    /// in snake_case, and the serializer's output must round-trip back to
    /// an equivalent value.
    #[test]
    fn serde_round_trip_uses_snake_case() {
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![
                Rule {
                    direction: Direction::Egress,
                    destination: Destination::Group(DestinationGroup::LinkLocal),
                    protocols: vec![Protocol::Tcp, Protocol::Icmpv4],
                    ports: vec![],
                    action: Action::Allow,
                },
                Rule {
                    direction: Direction::Any,
                    destination: Destination::DomainSuffix(".example.com".parse().unwrap()),
                    protocols: vec![],
                    ports: vec![],
                    action: Action::Deny,
                },
            ],
        };
        let json = serde_json::to_string(&policy).unwrap();

        // Field names: snake_case directly from Rust source (no rename needed).
        assert!(json.contains("\"default_egress\""), "JSON: {json}");
        assert!(json.contains("\"default_ingress\""), "JSON: {json}");
        // Enum tags: snake_case via rename_all on each enum.
        assert!(json.contains("\"egress\""), "JSON: {json}");
        assert!(json.contains("\"any\""), "JSON: {json}");
        assert!(json.contains("\"allow\""), "JSON: {json}");
        assert!(json.contains("\"deny\""), "JSON: {json}");
        assert!(json.contains("\"link_local\""), "JSON: {json}");
        assert!(json.contains("\"domain_suffix\""), "JSON: {json}");
        assert!(json.contains("\"icmpv4\""), "JSON: {json}");
        assert!(json.contains("\"tcp\""), "JSON: {json}");
        // No PascalCase residue.
        assert!(!json.contains("\"Egress\""), "JSON: {json}");
        assert!(!json.contains("\"Allow\""), "JSON: {json}");
        assert!(!json.contains("\"LinkLocal\""), "JSON: {json}");
        assert!(!json.contains("\"DomainSuffix\""), "JSON: {json}");
        // No camelCase residue.
        assert!(!json.contains("\"linkLocal\""), "JSON: {json}");
        assert!(!json.contains("\"domainSuffix\""), "JSON: {json}");
        assert!(!json.contains("\"defaultEgress\""), "JSON: {json}");

        // Round-trip back: must parse and produce a structurally equivalent value.
        let back: NetworkPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(back.rules.len(), policy.rules.len());
        assert!(matches!(back.default_egress, Action::Deny));
        assert!(matches!(back.default_ingress, Action::Allow));
        assert!(matches!(back.rules[0].direction, Direction::Egress));
        assert!(matches!(back.rules[1].direction, Direction::Any));
    }

    /// Multi-protocol rule: TCP-or-UDP both match.
    #[test]
    fn multi_protocol_rule_matches_any_listed() {
        let shared = SharedState::new(4);
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule {
                direction: Direction::Egress,
                destination: Destination::Group(DestinationGroup::Public),
                protocols: vec![Protocol::Tcp, Protocol::Udp],
                ports: vec![PortRange::single(443)],
                action: Action::Allow,
            }],
        };
        assert!(
            policy
                .evaluate_egress(sock("8.8.8.8", 443), Protocol::Tcp, &shared)
                .is_allow()
        );
        assert!(
            policy
                .evaluate_egress(sock("8.8.8.8", 443), Protocol::Udp, &shared)
                .is_allow()
        );
        // Different protocol — doesn't match, falls to default_egress.
        assert!(
            policy
                .evaluate_egress(sock("8.8.8.8", 443), Protocol::Icmpv4, &shared)
                .is_deny()
        );
    }

    /// Multi-port rule: 80 OR 443 both match.
    #[test]
    fn multi_port_rule_matches_any_listed() {
        let shared = SharedState::new(4);
        let policy = NetworkPolicy {
            default_egress: Action::Deny,
            default_ingress: Action::Allow,
            rules: vec![Rule {
                direction: Direction::Egress,
                destination: Destination::Group(DestinationGroup::Public),
                protocols: vec![Protocol::Tcp],
                ports: vec![PortRange::single(80), PortRange::single(443)],
                action: Action::Allow,
            }],
        };
        assert!(
            policy
                .evaluate_egress(sock("8.8.8.8", 80), Protocol::Tcp, &shared)
                .is_allow()
        );
        assert!(
            policy
                .evaluate_egress(sock("8.8.8.8", 443), Protocol::Tcp, &shared)
                .is_allow()
        );
        // Different port — doesn't match, falls to default_egress.
        assert!(
            policy
                .evaluate_egress(sock("8.8.8.8", 8080), Protocol::Tcp, &shared)
                .is_deny()
        );
    }

    /// The `Public` group matches IPs that are not in any of the other
    /// categories.
    #[test]
    fn public_group_matches_complement_of_other_categories() {
        let shared = SharedState::new(4);
        let policy = allow_rule(Destination::Group(DestinationGroup::Public));

        // Public IPs (8.8.8.8, an arbitrary non-private routable) are allowed.
        assert!(egress_tcp(&policy, "8.8.8.8", &shared).is_allow());
        // Private IPs are not in Public.
        assert!(egress_tcp(&policy, "10.0.0.5", &shared).is_deny());
        // Loopback is not in Public.
        assert!(egress_tcp(&policy, "127.0.0.1", &shared).is_deny());
        // Metadata is not in Public.
        assert!(egress_tcp(&policy, "169.254.169.254", &shared).is_deny());
    }
}
