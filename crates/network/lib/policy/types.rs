//! Policy types: rules, actions, destinations, and protocol matching.

use std::net::{IpAddr, SocketAddr};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

use crate::shared::SharedState;

use super::destination::{matches_cidr, matches_group};
use super::name::DomainName;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Network policy with ordered rules.
///
/// Rules are evaluated in first-match-wins order. If no rule matches,
/// the default action is applied.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPolicy {
    /// Default action for traffic not matching any rule.
    #[serde(default)]
    pub default_action: Action,

    /// Ordered list of rules (first match wins).
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Action to take on matched traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum Action {
    /// Allow the traffic.
    #[default]
    Allow,

    /// Silently drop.
    Deny,
}

/// A single network rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    /// Traffic direction.
    pub direction: Direction,

    /// Destination filter.
    pub destination: Destination,

    /// Protocol filter (None = any protocol).
    #[serde(default)]
    pub protocol: Option<Protocol>,

    /// Port filter (None = any port).
    #[serde(default)]
    pub ports: Option<PortRange>,

    /// Action to take.
    pub action: Action,
}

/// Traffic direction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// Outbound (guest → internet).
    Outbound,

    /// Inbound (internet → guest).
    Inbound,
}

/// Traffic destination specification.
///
/// `Domain` and `DomainSuffix` values carry a validated [`DomainName`],
/// whose construction enforces the canonical form (lowercase ASCII,
/// leading/trailing dots stripped) once at parse time. Matching code
/// can then rely on byte equality against the DNS cache's own
/// canonical entries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Destination {
    /// Match any destination.
    Any,

    /// IP address or CIDR block.
    Cidr(IpNetwork),

    /// Exact domain name. Matches only when a cached hostname for the
    /// destination IP equals this name.
    Domain(DomainName),

    /// Domain suffix. Matches the apex domain itself and any subdomain
    /// of it (e.g. suffix `example.com` matches `example.com` and
    /// `foo.example.com` but not `evilexample.com`).
    DomainSuffix(DomainName),

    /// Pre-defined destination group.
    Group(DestinationGroup),
}

/// Pre-defined destination groups.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum DestinationGroup {
    /// Loopback addresses (`127.0.0.0/8`, `::1`).
    Loopback,

    /// Private IP ranges (RFC 1918 + RFC 4193 ULA).
    Private,

    /// Link-local addresses (`169.254.0.0/16`, `fe80::/10`).
    LinkLocal,

    /// Cloud metadata endpoints (`169.254.169.254`).
    Metadata,

    /// Multicast addresses (`224.0.0.0/4`, `ff00::/8`).
    Multicast,
}

/// Protocol filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
    /// No network access — deny everything.
    pub fn none() -> Self {
        Self {
            default_action: Action::Deny,
            rules: vec![],
        }
    }

    /// Unrestricted network access — allow everything.
    pub fn allow_all() -> Self {
        Self {
            default_action: Action::Allow,
            rules: vec![],
        }
    }

    /// Public internet only — deny loopback, private, link-local, and
    /// cloud metadata addresses.
    pub fn public_only() -> Self {
        Self {
            default_action: Action::Allow,
            rules: vec![
                Rule::deny_outbound(Destination::Group(DestinationGroup::Loopback)),
                Rule::deny_outbound(Destination::Group(DestinationGroup::Private)),
                Rule::deny_outbound(Destination::Group(DestinationGroup::LinkLocal)),
                Rule::deny_outbound(Destination::Group(DestinationGroup::Metadata)),
            ],
        }
    }

    /// Non-local network access — allow public internet and private/LAN addresses,
    /// but deny loopback, link-local, and cloud metadata addresses.
    pub fn non_local() -> Self {
        Self {
            default_action: Action::Allow,
            rules: vec![
                Rule::deny_outbound(Destination::Group(DestinationGroup::Loopback)),
                Rule::deny_outbound(Destination::Group(DestinationGroup::LinkLocal)),
                Rule::deny_outbound(Destination::Group(DestinationGroup::Metadata)),
            ],
        }
    }

    /// Evaluate an outbound connection against the policy.
    ///
    /// Returns the action from the first matching rule, or the default
    /// action if no rule matches.
    pub fn evaluate_egress(
        &self,
        dst: SocketAddr,
        protocol: Protocol,
        shared: &SharedState,
    ) -> Action {
        for rule in &self.rules {
            if rule.direction != Direction::Outbound {
                continue;
            }
            if let Some(ref rule_proto) = rule.protocol
                && *rule_proto != protocol
            {
                continue;
            }
            if let Some(ref ports) = rule.ports
                && !ports.contains(dst.port())
            {
                continue;
            }
            if !matches_destination(&rule.destination, dst.ip(), shared) {
                continue;
            }
            return rule.action;
        }
        self.default_action
    }

    /// Evaluate an outbound ICMP packet against the policy.
    ///
    /// Same first-match-wins logic as [`Self::evaluate_egress`] but without port
    /// matching — ICMP has no ports. Rules with a `ports` filter are
    /// skipped since applying a port range to a portless protocol would
    /// be semantically incorrect.
    pub fn evaluate_egress_ip(
        &self,
        dst: IpAddr,
        protocol: Protocol,
        shared: &SharedState,
    ) -> Action {
        for rule in &self.rules {
            if rule.direction != Direction::Outbound {
                continue;
            }
            if let Some(ref rule_proto) = rule.protocol
                && *rule_proto != protocol
            {
                continue;
            }
            if rule.ports.is_some() {
                continue;
            }
            if !matches_destination(&rule.destination, dst, shared) {
                continue;
            }
            return rule.action;
        }
        self.default_action
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
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self::public_only()
    }
}

impl Rule {
    /// Convenience: allow outbound to a destination.
    pub fn allow_outbound(destination: Destination) -> Self {
        Self::outbound(destination, Action::Allow)
    }

    /// Convenience: deny outbound to a destination.
    pub fn deny_outbound(destination: Destination) -> Self {
        Self::outbound(destination, Action::Deny)
    }

    fn outbound(destination: Destination, action: Action) -> Self {
        Self {
            direction: Direction::Outbound,
            destination,
            protocol: None,
            ports: None,
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

/// Check if an IP address matches a destination specification.
fn matches_destination(dest: &Destination, addr: IpAddr, shared: &SharedState) -> bool {
    match dest {
        Destination::Any => true,
        Destination::Cidr(network) => matches_cidr(network, addr),
        Destination::Group(group) => matches_group(*group, addr),
        Destination::Domain(domain) => {
            shared.any_resolved_hostname(addr, |hostname| hostname == domain.as_str())
        }
        Destination::DomainSuffix(suffix) => {
            shared.any_resolved_hostname(addr, |hostname| matches_suffix(hostname, suffix.as_str()))
        }
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

    fn egress_tcp(policy: &NetworkPolicy, ip_str: &str, shared: &SharedState) -> Action {
        policy.evaluate_egress(sock(ip_str, 443), Protocol::Tcp, shared)
    }

    fn allow_rule(dest: Destination) -> NetworkPolicy {
        NetworkPolicy {
            default_action: Action::Deny,
            rules: vec![Rule::allow_outbound(dest)],
        }
    }

    /// Outbound TCP/443 allow rule pinned to a specific hostname,
    /// used by the multi-rule default-deny scenarios below.
    fn allow_domain_tcp_443(domain: &str) -> Rule {
        Rule {
            direction: Direction::Outbound,
            destination: Destination::Domain(domain.parse().unwrap()),
            protocol: Some(Protocol::Tcp),
            ports: Some(PortRange::single(443)),
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
                "default_action": "Deny",
                "rules": [
                    {
                        "direction": "Outbound",
                        "destination": { "Domain": "PyPI.Org." },
                        "action": "Allow"
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
            default_action: Action::Deny,
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
            default_action: Action::Deny,
            rules: vec![
                Rule::allow_outbound(Destination::Domain("pypi.org".parse().unwrap())),
                Rule {
                    direction: Direction::Outbound,
                    destination: Destination::Cidr("151.101.0.0/16".parse().unwrap()),
                    protocol: None,
                    ports: None,
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
            default_action: Action::Deny,
            rules: vec![Rule {
                direction: Direction::Outbound,
                destination: Destination::Domain("pypi.org".parse().unwrap()),
                protocol: Some(Protocol::Udp),
                ports: Some(PortRange::single(443)),
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
}
