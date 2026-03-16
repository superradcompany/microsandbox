//! Policy types: rules, actions, destinations, and protocol matching.

use ipnetwork::IpNetwork;
use serde::{Deserialize, Serialize};

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
}

impl Default for NetworkPolicy {
    fn default() -> Self {
        Self::allow_all()
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
