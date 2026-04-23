//! Policy types: rules, actions, destinations, and protocol matching.

use std::net::{IpAddr, SocketAddr};

use ipnetwork::IpNetwork;
use serde::{Deserialize, Deserializer, Serialize};

use crate::shared::{SharedState, normalize_hostname};

use super::destination::{matches_cidr, matches_group};

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
/// Deserialization normalizes `Domain` and `DomainSuffix` values
/// (lowercased, trailing/leading dots stripped) so comparisons against
/// resolved hostnames are canonical.
#[derive(Debug, Clone, Serialize)]
pub enum Destination {
    /// Match any destination.
    Any,

    /// IP address or CIDR block.
    Cidr(IpNetwork),

    /// Domain name (resolved and matched via DNS pin set).
    Domain(String),

    /// Domain suffix (e.g. `".example.com"`).
    DomainSuffix(String),

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

    fn outbound(mut destination: Destination, action: Action) -> Self {
        destination.normalize_mut();
        Self {
            direction: Direction::Outbound,
            destination,
            protocol: None,
            ports: None,
            action,
        }
    }
}

impl Destination {
    fn normalize_mut(&mut self) {
        match self {
            Destination::Domain(s) => *s = normalize_hostname(s),
            Destination::DomainSuffix(s) => *s = normalize_suffix(s),
            Destination::Any | Destination::Cidr(_) | Destination::Group(_) => {}
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

impl<'de> Deserialize<'de> for Destination {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        enum Repr {
            Any,
            Cidr(IpNetwork),
            Domain(String),
            DomainSuffix(String),
            Group(DestinationGroup),
        }

        Ok(match Repr::deserialize(deserializer)? {
            Repr::Any => Destination::Any,
            Repr::Cidr(network) => Destination::Cidr(network),
            Repr::Domain(s) => Destination::Domain(normalize_hostname(&s)),
            Repr::DomainSuffix(s) => Destination::DomainSuffix(normalize_suffix(&s)),
            Repr::Group(g) => Destination::Group(g),
        })
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
            shared.any_resolved_hostname(addr, |hostname| hostname == domain)
        }
        Destination::DomainSuffix(suffix) => {
            shared.any_resolved_hostname(addr, |hostname| matches_suffix(hostname, suffix))
        }
    }
}

fn matches_suffix(hostname: &str, suffix: &str) -> bool {
    hostname == suffix
        || hostname
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

fn normalize_suffix(suffix: &str) -> String {
    normalize_hostname(suffix)
        .trim_start_matches('.')
        .to_string()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;
    use crate::shared::ResolvedHostnameFamily;

    const PYPI_V4: &str = "151.101.0.223";
    const FILES_V4: &str = "151.101.64.223";

    /// Build a shared state that has one resolved hostname cached.
    fn shared_with_host(host: &str, ip_str: &str) -> SharedState {
        let shared = SharedState::new(4);
        shared.cache_resolved_hostname(
            host,
            ResolvedHostnameFamily::Ipv4,
            [ip_str.parse::<IpAddr>().unwrap()],
            Duration::from_secs(30),
        );
        shared
    }

    fn egress_tcp(policy: &NetworkPolicy, ip_str: &str, shared: &SharedState) -> Action {
        let addr = SocketAddr::new(ip_str.parse().unwrap(), 443);
        policy.evaluate_egress(addr, Protocol::Tcp, shared)
    }

    fn allow_rule(dest: Destination) -> NetworkPolicy {
        NetworkPolicy {
            default_action: Action::Deny,
            rules: vec![Rule::allow_outbound(dest)],
        }
    }

    #[test]
    fn exact_domain_rules_match_resolved_hostnames() {
        let shared = shared_with_host("pypi.org", PYPI_V4);
        let policy = allow_rule(Destination::Domain("pypi.org".into()));
        assert!(egress_tcp(&policy, PYPI_V4, &shared).is_allow());
    }

    #[test]
    fn exact_domain_rules_normalize_user_input() {
        let shared = shared_with_host("pypi.org", PYPI_V4);
        let policy = allow_rule(Destination::Domain("PyPI.Org.".into()));
        assert!(egress_tcp(&policy, PYPI_V4, &shared).is_allow());
    }

    #[test]
    fn suffix_rules_match_resolved_hostnames() {
        let shared = shared_with_host("files.pythonhosted.org", FILES_V4);
        let policy = allow_rule(Destination::DomainSuffix(".pythonhosted.org".into()));
        assert!(egress_tcp(&policy, FILES_V4, &shared).is_allow());
    }

    #[test]
    fn suffix_rules_normalize_user_input() {
        let shared = shared_with_host("files.pythonhosted.org", FILES_V4);
        let policy = allow_rule(Destination::DomainSuffix(".PythonHosted.Org.".into()));
        assert!(egress_tcp(&policy, FILES_V4, &shared).is_allow());
    }

    #[test]
    fn unresolved_domain_rules_do_not_match_by_ip_alone() {
        let shared = SharedState::new(4);
        let policy = allow_rule(Destination::Domain("pypi.org".into()));
        assert!(egress_tcp(&policy, PYPI_V4, &shared).is_deny());
    }

    #[test]
    fn exact_domain_rules_match_resolved_hostnames_for_icmp() {
        let shared = shared_with_host("pypi.org", PYPI_V4);
        let policy = allow_rule(Destination::Domain("pypi.org".into()));
        let ip: IpAddr = PYPI_V4.parse().unwrap();
        assert!(
            policy
                .evaluate_egress_ip(ip, Protocol::Icmpv4, &shared)
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
}
