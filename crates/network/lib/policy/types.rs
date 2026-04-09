//! Policy types: rules, actions, destinations, and protocol matching.

use std::net::SocketAddr;

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

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
#[derive(Debug, Clone, Serialize, Deserialize)]
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
    pub fn evaluate_egress(&self, dst: SocketAddr, protocol: Protocol) -> Action {
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
            if !matches_destination(&rule.destination, dst.ip()) {
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
    pub fn evaluate_egress_ip(&self, dst: std::net::IpAddr, protocol: Protocol) -> Action {
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
            if !matches_destination(&rule.destination, dst) {
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
        Self {
            direction: Direction::Outbound,
            destination,
            protocol: None,
            ports: None,
            action: Action::Allow,
        }
    }

    /// Convenience: deny outbound to a destination.
    pub fn deny_outbound(destination: Destination) -> Self {
        Self {
            direction: Direction::Outbound,
            destination,
            protocol: None,
            ports: None,
            action: Action::Deny,
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
fn matches_destination(dest: &Destination, addr: std::net::IpAddr) -> bool {
    match dest {
        Destination::Any => true,
        Destination::Cidr(network) => matches_cidr(network, addr),
        Destination::Group(group) => matches_group(*group, addr),
        // Domain and DomainSuffix require a DNS pin set for IP→domain
        // reverse lookup. Without pins, they don't match by IP alone.
        Destination::Domain(_) | Destination::DomainSuffix(_) => false,
    }
}
