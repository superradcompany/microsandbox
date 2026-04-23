//! Runtime policy evaluator.
//!
//! Binds a [`NetworkPolicy`] to the per-sandbox gateway IPs needed to resolve
//! [`DestinationGroup::Host`] rules. Keeping this separate from `NetworkPolicy`
//! lets the policy stay pure serialisable config.

use std::net::{IpAddr, SocketAddr};

use super::destination::{matches_cidr, matches_group};
use super::types::{Action, Destination, DestinationGroup, Direction, NetworkPolicy, Protocol};
use crate::stack::GatewayIps;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Per-sandbox policy evaluator.
///
/// Wraps a [`NetworkPolicy`] plus the gateway IPs that [`DestinationGroup::Host`] resolves to.
#[derive(Debug, Clone)]
pub struct PolicyEvaluator {
    policy: NetworkPolicy,
    gateway: GatewayIps,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PolicyEvaluator {
    /// Build an evaluator from a user-provided policy and the sandbox's gateway IPs.
    ///
    /// # Arguments
    ///
    /// * `policy` - The declarative rules the user authored.
    /// * `gateway` - Per-sandbox gateway addresses (v4 + v6);
    ///   `DestinationGroup::Host` rules match either family.
    pub fn new(policy: NetworkPolicy, gateway: GatewayIps) -> Self {
        Self { policy, gateway }
    }

    /// Borrow the underlying declarative policy.
    pub fn policy(&self) -> &NetworkPolicy {
        &self.policy
    }

    /// Default action returned when no rule matches an outbound packet.
    pub fn default_action(&self) -> Action {
        self.policy.default_action
    }

    /// Evaluate an outbound TCP/UDP connection against the policy.
    ///
    /// Returns the action from the first matching rule, or the default action if no rule matches.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination socket address (IP + port) of the outbound connection.
    /// * `protocol` - Transport protocol; rules with a `protocol` filter only match when
    ///   it equals this value.
    pub fn evaluate_egress(&self, dst: SocketAddr, protocol: Protocol) -> Action {
        for rule in &self.policy.rules {
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
            if !self.matches_destination(&rule.destination, dst.ip()) {
                continue;
            }
            return rule.action;
        }
        self.policy.default_action
    }

    /// Evaluate an outbound ICMP packet against the policy.
    ///
    /// Same first-match-wins logic as [`Self::evaluate_egress`] but without port
    /// matching — ICMP has no ports. Rules with a `ports` filter are skipped since
    /// applying a port range to a portless protocol would be semantically incorrect.
    ///
    /// # Arguments
    ///
    /// * `dst` - Destination IP.
    /// * `protocol` - Either [`Protocol::Icmpv4`] or [`Protocol::Icmpv6`].
    pub fn evaluate_egress_ip(&self, dst: IpAddr, protocol: Protocol) -> Action {
        for rule in &self.policy.rules {
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
            if !self.matches_destination(&rule.destination, dst) {
                continue;
            }
            return rule.action;
        }
        self.policy.default_action
    }

    /// Check whether `addr` matches `dest`, resolving [`DestinationGroup::Host`]
    /// against the evaluator's gateway IPs.
    fn matches_destination(&self, dest: &Destination, addr: IpAddr) -> bool {
        match dest {
            Destination::Any => true,
            Destination::Cidr(network) => matches_cidr(network, addr),
            Destination::Group(DestinationGroup::Host) => match addr {
                IpAddr::V4(v4) => v4 == self.gateway.ipv4,
                IpAddr::V6(v6) => v6 == self.gateway.ipv6,
            },
            Destination::Group(group) => matches_group(*group, addr),
            // Domain and DomainSuffix require a DNS pin set for IP→domain
            // reverse lookup. Without pins, they don't match by IP alone.
            Destination::Domain(_) | Destination::DomainSuffix(_) => false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::policy::Rule;

    fn test_gateway() -> GatewayIps {
        GatewayIps {
            ipv4: Ipv4Addr::new(100, 96, 0, 1),
            ipv6: Ipv6Addr::new(0xfd42, 0x6d73, 0x62, 0, 0, 0, 0, 1),
        }
    }

    fn host_rule() -> Rule {
        Rule::deny_outbound(Destination::Group(DestinationGroup::Host))
    }

    #[test]
    fn group_host_matches_gateway_v4() {
        let policy = NetworkPolicy {
            default_action: Action::Allow,
            rules: vec![host_rule()],
        };
        let gw = test_gateway();
        let evaluator = PolicyEvaluator::new(policy, gw);

        let dst = SocketAddr::new(IpAddr::V4(gw.ipv4), 80);
        assert_eq!(evaluator.evaluate_egress(dst, Protocol::Tcp), Action::Deny);
    }

    #[test]
    fn group_host_matches_gateway_v6() {
        let policy = NetworkPolicy {
            default_action: Action::Allow,
            rules: vec![host_rule()],
        };
        let gw = test_gateway();
        let evaluator = PolicyEvaluator::new(policy, gw);

        let dst = SocketAddr::new(IpAddr::V6(gw.ipv6), 80);
        assert_eq!(evaluator.evaluate_egress(dst, Protocol::Tcp), Action::Deny);
    }

    #[test]
    fn group_host_does_not_match_other_ips() {
        let policy = NetworkPolicy {
            default_action: Action::Allow,
            rules: vec![host_rule()],
        };
        let evaluator = PolicyEvaluator::new(policy, test_gateway());

        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)), 80);
        assert_eq!(evaluator.evaluate_egress(dst, Protocol::Tcp), Action::Allow);
    }

    #[test]
    fn public_only_preset_denies_host_gateway() {
        // `public_only` is the default policy. Users who don't configure a
        // policy cannot reach `host.microsandbox.internal` — the gateway
        // sits inside CGNAT (100.64/10), which `DestinationGroup::Private`
        // covers. Changing this (e.g. adding a `Host` allow rule to the
        // preset) must be a deliberate decision; this test pins it.
        let evaluator = PolicyEvaluator::new(NetworkPolicy::public_only(), test_gateway());
        let gw = test_gateway();

        let v4 = SocketAddr::new(IpAddr::V4(gw.ipv4), 80);
        assert_eq!(
            evaluator.evaluate_egress(v4, Protocol::Tcp),
            Action::Deny,
            "default policy should deny host via IPv4 gateway"
        );

        let v6 = SocketAddr::new(IpAddr::V6(gw.ipv6), 80);
        assert_eq!(
            evaluator.evaluate_egress(v6, Protocol::Tcp),
            Action::Deny,
            "default policy should deny host via IPv6 gateway (ULA fd42::/8)"
        );
    }

    #[test]
    fn allow_all_preset_permits_host_gateway() {
        let evaluator = PolicyEvaluator::new(NetworkPolicy::allow_all(), test_gateway());
        let gw = test_gateway();

        let v4 = SocketAddr::new(IpAddr::V4(gw.ipv4), 80);
        assert_eq!(evaluator.evaluate_egress(v4, Protocol::Tcp), Action::Allow);
    }

    #[test]
    fn group_host_allow_overrides_private_deny_when_ordered_first() {
        // Practical recipe for users who want public_only semantics plus
        // host access: prepend a `Group(Host) → Allow` rule. First-match-
        // wins means the host request hits the allow before the Private
        // deny fires.
        let mut policy = NetworkPolicy::public_only();
        policy.rules.insert(
            0,
            Rule::allow_outbound(Destination::Group(DestinationGroup::Host)),
        );
        let evaluator = PolicyEvaluator::new(policy, test_gateway());
        let gw = test_gateway();

        let v4 = SocketAddr::new(IpAddr::V4(gw.ipv4), 80);
        assert_eq!(evaluator.evaluate_egress(v4, Protocol::Tcp), Action::Allow);

        // Non-gateway private IPs are still denied by the Private rule.
        let other_private = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 80);
        assert_eq!(
            evaluator.evaluate_egress(other_private, Protocol::Tcp),
            Action::Deny,
            "non-host private destinations should still be blocked"
        );
    }

    #[test]
    fn default_action_returned_when_no_rule_matches() {
        let policy = NetworkPolicy::allow_all();
        let evaluator = PolicyEvaluator::new(policy, test_gateway());
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 443);
        assert_eq!(evaluator.evaluate_egress(dst, Protocol::Tcp), Action::Allow);
    }

    #[test]
    fn evaluate_egress_ip_skips_port_filtered_rules() {
        let policy = NetworkPolicy {
            default_action: Action::Allow,
            rules: vec![Rule {
                direction: Direction::Outbound,
                destination: Destination::Any,
                protocol: Some(Protocol::Icmpv4),
                ports: Some(super::super::PortRange::single(0)),
                action: Action::Deny,
            }],
        };
        let evaluator = PolicyEvaluator::new(policy, test_gateway());
        let dst = IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8));
        assert_eq!(
            evaluator.evaluate_egress_ip(dst, Protocol::Icmpv4),
            Action::Allow
        );
    }
}
