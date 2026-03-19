//! Policy evaluation engine.
//!
//! Evaluates rules against parsed packet headers using first-match-wins semantics.
//! Domain-based rules are resolved via the DNS pin set.

use std::{
    collections::{HashMap, HashSet},
    net::IpAddr,
    sync::{Arc, RwLock},
};

use crate::packet::{IpProtocol, ParsedFrame};

use super::{
    destination::{matches_cidr, matches_group},
    types::{Action, Destination, Direction, NetworkPolicy, Protocol},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Maps resolved IP addresses back to domain names.
///
/// Populated by the DNS interceptor when it resolves A/AAAA records.
/// Used by the policy engine to match domain-based rules against destination IPs.
pub struct DnsPinSet {
    /// IP → set of domain names that resolved to it.
    ip_to_domains: HashMap<IpAddr, HashSet<String>>,
}

/// Policy evaluation engine.
///
/// Evaluates `NetworkPolicy` rules against parsed frames, using first-match-wins
/// semantics. Domain-based rules check the `DnsPinSet` to see if the destination
/// IP was resolved from a matching domain.
pub struct PolicyEngine {
    policy: NetworkPolicy,
    pin_set: Arc<RwLock<DnsPinSet>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DnsPinSet {
    /// Creates an empty pin set.
    pub fn new() -> Self {
        Self {
            ip_to_domains: HashMap::new(),
        }
    }

    /// Records that `domain` resolved to `ip`.
    pub fn pin(&mut self, domain: &str, ip: IpAddr) {
        self.ip_to_domains
            .entry(ip)
            .or_default()
            .insert(domain.to_lowercase());
    }

    /// Returns the set of domains that resolved to `ip`, if any.
    pub fn lookup(&self, ip: IpAddr) -> Option<&HashSet<String>> {
        self.ip_to_domains.get(&ip)
    }

    /// Removes all entries for an IP.
    pub fn remove_ip(&mut self, ip: &IpAddr) {
        self.ip_to_domains.remove(ip);
    }
}

impl Default for DnsPinSet {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    /// Creates a new policy engine with the given policy and pin set.
    pub fn new(policy: NetworkPolicy, pin_set: Arc<RwLock<DnsPinSet>>) -> Self {
        Self { policy, pin_set }
    }

    /// Evaluates a parsed frame against the policy.
    ///
    /// Returns the action to take (Allow or Deny). Uses first-match-wins:
    /// the first rule whose direction, destination, protocol, and ports all
    /// match determines the action. If no rule matches, the default action
    /// is returned.
    pub fn evaluate(&self, frame: &ParsedFrame<'_>, direction: Direction) -> Action {
        let dst_ip = match frame.dst_ip() {
            Some(ip) => ip,
            None => return self.policy.default_action,
        };

        let protocol = frame.protocol();
        let dst_port = frame.dst_port();

        for rule in &self.policy.rules {
            if rule.direction != direction {
                continue;
            }

            if !self.matches_destination(&rule.destination, dst_ip) {
                continue;
            }

            if let Some(ref rule_proto) = rule.protocol
                && !matches_protocol(rule_proto, protocol)
            {
                continue;
            }

            if let Some(ref port_range) = rule.ports {
                match dst_port {
                    Some(port) if port_range.contains(port) => {}
                    _ => continue,
                }
            }

            return rule.action;
        }

        self.policy.default_action
    }

    /// Checks if a destination IP matches a rule's destination spec.
    fn matches_destination(&self, destination: &Destination, ip: IpAddr) -> bool {
        match destination {
            Destination::Any => true,
            Destination::Cidr(network) => matches_cidr(network, ip),
            Destination::Group(group) => matches_group(*group, ip),
            Destination::Domain(domain) => self.ip_matches_domain(ip, domain),
            Destination::DomainSuffix(suffix) => self.ip_matches_domain_suffix(ip, suffix),
        }
    }

    /// Checks if an IP was resolved from the given domain via intercepted DNS.
    fn ip_matches_domain(&self, ip: IpAddr, domain: &str) -> bool {
        let pin_set = match self.pin_set.read() {
            Ok(ps) => ps,
            Err(_) => return false,
        };
        match pin_set.lookup(ip) {
            Some(domains) => domains.contains(&domain.to_lowercase()),
            None => false,
        }
    }

    /// Checks if an IP was resolved from a domain matching the suffix.
    fn ip_matches_domain_suffix(&self, ip: IpAddr, suffix: &str) -> bool {
        let pin_set = match self.pin_set.read() {
            Ok(ps) => ps,
            Err(_) => return false,
        };
        let suffix_lower = suffix.to_lowercase();
        match pin_set.lookup(ip) {
            Some(domains) => domains.iter().any(|d| d.ends_with(&suffix_lower)),
            None => false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Checks if a parsed protocol matches a rule's protocol filter.
fn matches_protocol(rule_proto: &Protocol, frame_proto: Option<IpProtocol>) -> bool {
    let frame_proto = match frame_proto {
        Some(p) => p,
        None => return false,
    };

    matches!(
        (rule_proto, frame_proto),
        (Protocol::Tcp, IpProtocol::Tcp)
            | (Protocol::Udp, IpProtocol::Udp)
            | (Protocol::Icmpv4, IpProtocol::Icmpv4)
            | (Protocol::Icmpv6, IpProtocol::Icmpv6)
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::policy::{DestinationGroup, PortRange, Rule};

    fn build_udp_frame(dst_ip: [u8; 4], dst_port: u16) -> Vec<u8> {
        use etherparse::PacketBuilder;
        let builder = PacketBuilder::ethernet2(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        )
        .ipv4([10, 0, 0, 1], dst_ip, 64)
        .udp(50000, dst_port);
        let mut buf = Vec::new();
        builder.write(&mut buf, &[]).unwrap();
        buf
    }

    fn build_tcp_frame(dst_ip: [u8; 4], dst_port: u16) -> Vec<u8> {
        use etherparse::PacketBuilder;
        let builder = PacketBuilder::ethernet2(
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x01],
            [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
        )
        .ipv4([10, 0, 0, 1], dst_ip, 64)
        .tcp(50000, dst_port, 0, 65535);
        let mut buf = Vec::new();
        builder.write(&mut buf, &[]).unwrap();
        buf
    }

    fn make_engine(policy: NetworkPolicy) -> PolicyEngine {
        PolicyEngine::new(policy, Arc::new(RwLock::new(DnsPinSet::new())))
    }

    #[test]
    fn test_allow_all() {
        let engine = make_engine(NetworkPolicy::allow_all());
        let frame_data = build_tcp_frame([93, 184, 216, 34], 443);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Allow);
    }

    #[test]
    fn test_deny_all() {
        let engine = make_engine(NetworkPolicy::none());
        let frame_data = build_tcp_frame([93, 184, 216, 34], 443);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Deny);
    }

    #[test]
    fn test_deny_private_networks() {
        let policy = NetworkPolicy {
            default_action: Action::Allow,
            rules: vec![Rule::deny_outbound(Destination::Group(
                DestinationGroup::Private,
            ))],
        };
        let engine = make_engine(policy);

        // Private → denied.
        let frame_data = build_tcp_frame([10, 0, 0, 1], 80);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Deny);

        // Public → allowed (default).
        let frame_data = build_tcp_frame([93, 184, 216, 34], 443);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Allow);
    }

    #[test]
    fn test_cidr_rule() {
        let policy = NetworkPolicy {
            default_action: Action::Deny,
            rules: vec![Rule::allow_outbound(Destination::Cidr(
                "93.184.216.0/24".parse().unwrap(),
            ))],
        };
        let engine = make_engine(policy);

        let frame_data = build_tcp_frame([93, 184, 216, 34], 443);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Allow);

        let frame_data = build_tcp_frame([8, 8, 8, 8], 53);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Deny);
    }

    #[test]
    fn test_port_range() {
        let policy = NetworkPolicy {
            default_action: Action::Deny,
            rules: vec![Rule {
                direction: Direction::Outbound,
                destination: Destination::Any,
                protocol: Some(Protocol::Tcp),
                ports: Some(PortRange::range(80, 443)),
                action: Action::Allow,
            }],
        };
        let engine = make_engine(policy);

        let frame_data = build_tcp_frame([8, 8, 8, 8], 443);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Allow);

        let frame_data = build_tcp_frame([8, 8, 8, 8], 22);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Deny);
    }

    #[test]
    fn test_protocol_filter() {
        let policy = NetworkPolicy {
            default_action: Action::Deny,
            rules: vec![Rule {
                direction: Direction::Outbound,
                destination: Destination::Any,
                protocol: Some(Protocol::Tcp),
                ports: None,
                action: Action::Allow,
            }],
        };
        let engine = make_engine(policy);

        // TCP → allowed.
        let frame_data = build_tcp_frame([8, 8, 8, 8], 443);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Allow);

        // UDP → denied (protocol mismatch).
        let frame_data = build_udp_frame([8, 8, 8, 8], 53);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Deny);
    }

    #[test]
    fn test_direction_filter() {
        let policy = NetworkPolicy {
            default_action: Action::Allow,
            rules: vec![Rule::deny_outbound(Destination::Group(
                DestinationGroup::Loopback,
            ))],
        };
        let engine = make_engine(policy);

        let frame_data = build_tcp_frame([127, 0, 0, 1], 80);
        let frame = ParsedFrame::parse(&frame_data).unwrap();

        // Outbound → denied.
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Deny);

        // Inbound → allowed (rule is outbound-only).
        assert_eq!(engine.evaluate(&frame, Direction::Inbound), Action::Allow);
    }

    #[test]
    fn test_domain_rule_with_pin_set() {
        let pin_set = Arc::new(RwLock::new(DnsPinSet::new()));
        pin_set
            .write()
            .unwrap()
            .pin("example.com", IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));

        let policy = NetworkPolicy {
            default_action: Action::Deny,
            rules: vec![Rule::allow_outbound(Destination::Domain(
                "example.com".to_string(),
            ))],
        };
        let engine = PolicyEngine::new(policy, pin_set);

        // Pinned IP → allowed.
        let frame_data = build_tcp_frame([93, 184, 216, 34], 443);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Allow);

        // Unpinned IP → denied.
        let frame_data = build_tcp_frame([8, 8, 8, 8], 443);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Deny);
    }

    #[test]
    fn test_first_match_wins() {
        let policy = NetworkPolicy {
            default_action: Action::Deny,
            rules: vec![
                // First rule: allow port 443 to anywhere.
                Rule {
                    direction: Direction::Outbound,
                    destination: Destination::Any,
                    protocol: Some(Protocol::Tcp),
                    ports: Some(PortRange::single(443)),
                    action: Action::Allow,
                },
                // Second rule: deny all TCP (should not be reached for port 443).
                Rule {
                    direction: Direction::Outbound,
                    destination: Destination::Any,
                    protocol: Some(Protocol::Tcp),
                    ports: None,
                    action: Action::Deny,
                },
            ],
        };
        let engine = make_engine(policy);

        let frame_data = build_tcp_frame([8, 8, 8, 8], 443);
        let frame = ParsedFrame::parse(&frame_data).unwrap();
        assert_eq!(engine.evaluate(&frame, Direction::Outbound), Action::Allow);
    }
}
