//! Integration tests for Domain/DomainSuffix policy rules backed by the
//! DNS-derived resolved-hostname cache.
//!
//! These tests exercise the fix for issue 603 through the public crate API:
//! the guest resolves a hostname via the in-process DNS interceptor (here
//! simulated by calling `cache_resolved_hostname` directly), and a
//! subsequent egress decision must match the cached hostname against
//! Domain/DomainSuffix rules.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use microsandbox_network::policy::{
    Action, Destination, Direction, NetworkPolicy, PortRange, Protocol, Rule,
};
use microsandbox_network::shared::{ResolvedHostnameFamily, SharedState};

const PYPI_V4: &str = "151.101.0.223";
const FILES_V4: &str = "151.101.64.223";
const CLOUDFLARE_V6: &str = "2606:4700:4700::1111";

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

fn sock(ip_str: &str, port: u16) -> SocketAddr {
    SocketAddr::new(ip(ip_str), port)
}

fn cache(shared: &SharedState, host: &str, family: ResolvedHostnameFamily, ip_str: &str) {
    shared.cache_resolved_hostname(host, family, [ip(ip_str)], Duration::from_secs(60));
}

fn allow_domain_443(domain: &str) -> Rule {
    Rule {
        direction: Direction::Outbound,
        destination: Destination::Domain(domain.into()),
        protocol: Some(Protocol::Tcp),
        ports: Some(PortRange::single(443)),
        action: Action::Allow,
    }
}

#[test]
fn issue_603_reproduction_allow_pypi_after_dns() {
    // Mirrors the reporter's failing config: deny by default, allow
    // pypi.org and files.pythonhosted.org on 443. DNS succeeds inside the
    // sandbox, so the cache is populated before the guest connects.
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
            allow_domain_443("pypi.org"),
            allow_domain_443("files.pythonhosted.org"),
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

#[test]
fn default_deny_rejects_unresolved_destination() {
    // Same policy, no DNS lookup — the cache is empty, so the IP cannot
    // be tied back to an allowed domain and falls through to default-deny.
    let shared = SharedState::new(4);
    let policy = NetworkPolicy {
        default_action: Action::Deny,
        rules: vec![allow_domain_443("pypi.org")],
    };

    assert!(
        policy
            .evaluate_egress(sock(PYPI_V4, 443), Protocol::Tcp, &shared)
            .is_deny()
    );
}

#[test]
fn domain_rule_does_not_match_other_cached_hostnames() {
    // Cache has pypi.org -> IP, but the policy only allows example.com.
    // A connection to pypi.org's IP must not be allowed through the
    // example.com rule.
    let shared = SharedState::new(4);
    cache(&shared, "pypi.org", ResolvedHostnameFamily::Ipv4, PYPI_V4);

    let policy = NetworkPolicy {
        default_action: Action::Deny,
        rules: vec![allow_domain_443("example.com")],
    };

    assert!(
        policy
            .evaluate_egress(sock(PYPI_V4, 443), Protocol::Tcp, &shared)
            .is_deny()
    );
}

#[test]
fn suffix_rule_matches_subdomain_of_resolved_host() {
    let shared = SharedState::new(4);
    cache(
        &shared,
        "files.pythonhosted.org",
        ResolvedHostnameFamily::Ipv4,
        FILES_V4,
    );

    let policy = NetworkPolicy {
        default_action: Action::Deny,
        rules: vec![Rule::allow_outbound(Destination::DomainSuffix(
            ".pythonhosted.org".into(),
        ))],
    };

    assert!(
        policy
            .evaluate_egress(sock(FILES_V4, 443), Protocol::Tcp, &shared)
            .is_allow()
    );
}

#[test]
fn suffix_rule_matches_apex_domain_itself() {
    // A suffix ".pythonhosted.org" should also match the apex
    // "pythonhosted.org" (a common source of confusion with naive
    // suffix matching).
    let shared = SharedState::new(4);
    cache(
        &shared,
        "pythonhosted.org",
        ResolvedHostnameFamily::Ipv4,
        FILES_V4,
    );

    let policy = NetworkPolicy {
        default_action: Action::Deny,
        rules: vec![Rule::allow_outbound(Destination::DomainSuffix(
            ".pythonhosted.org".into(),
        ))],
    };

    assert!(
        policy
            .evaluate_egress(sock(FILES_V4, 443), Protocol::Tcp, &shared)
            .is_allow()
    );
}

#[test]
fn suffix_rule_does_not_false_match_adjacent_domain() {
    // A suffix ".pythonhosted.org" must not match "evilpythonhosted.org"
    // (no dot boundary before the suffix).
    let shared = SharedState::new(4);
    cache(
        &shared,
        "evilpythonhosted.org",
        ResolvedHostnameFamily::Ipv4,
        FILES_V4,
    );

    let policy = NetworkPolicy {
        default_action: Action::Deny,
        rules: vec![Rule::allow_outbound(Destination::DomainSuffix(
            ".pythonhosted.org".into(),
        ))],
    };

    assert!(
        policy
            .evaluate_egress(sock(FILES_V4, 443), Protocol::Tcp, &shared)
            .is_deny()
    );
}

#[test]
fn allow_rule_before_deny_wins_on_shared_ip() {
    // Shared-IP mitigation via rule ordering: a specific allow-Domain
    // rule listed before a broad deny-Cidr rule must win under
    // first-match-wins semantics, even when both would match the
    // destination.
    let shared = SharedState::new(4);
    cache(&shared, "pypi.org", ResolvedHostnameFamily::Ipv4, PYPI_V4);

    let policy = NetworkPolicy {
        default_action: Action::Deny,
        rules: vec![
            Rule::allow_outbound(Destination::Domain("pypi.org".into())),
            Rule {
                direction: Direction::Outbound,
                destination: Destination::Cidr("151.101.0.0/16".parse().unwrap()),
                protocol: None,
                ports: None,
                action: Action::Deny,
            },
        ],
    };

    assert!(
        policy
            .evaluate_egress(sock(PYPI_V4, 443), Protocol::Tcp, &shared)
            .is_allow()
    );
}

#[test]
fn icmp_egress_consults_domain_cache() {
    // evaluate_egress_ip (ICMP path) must also consult the resolved
    // hostname cache so Domain rules apply to pings.
    let shared = SharedState::new(4);
    cache(&shared, "pypi.org", ResolvedHostnameFamily::Ipv4, PYPI_V4);

    let policy = NetworkPolicy {
        default_action: Action::Deny,
        rules: vec![Rule::allow_outbound(Destination::Domain("pypi.org".into()))],
    };

    assert!(
        policy
            .evaluate_egress_ip(ip(PYPI_V4), Protocol::Icmpv4, &shared)
            .is_allow()
    );
}

#[test]
fn udp_egress_consults_domain_cache() {
    // UDP traffic (e.g., QUIC over port 443) must match Domain rules
    // the same way TCP does, since both go through evaluate_egress.
    let shared = SharedState::new(4);
    cache(&shared, "pypi.org", ResolvedHostnameFamily::Ipv4, PYPI_V4);

    let policy = NetworkPolicy {
        default_action: Action::Deny,
        rules: vec![Rule {
            direction: Direction::Outbound,
            destination: Destination::Domain("pypi.org".into()),
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

#[test]
fn ipv4_and_ipv6_caches_are_independent() {
    // Resolving only A (IPv4) must not grant access over IPv6, and
    // vice versa. The family partition in the cache key guarantees
    // independent refresh/expiry per address family.
    let shared = SharedState::new(4);
    cache(&shared, "pypi.org", ResolvedHostnameFamily::Ipv4, PYPI_V4);

    let policy = NetworkPolicy {
        default_action: Action::Deny,
        rules: vec![Rule::allow_outbound(Destination::Domain("pypi.org".into()))],
    };

    assert!(
        policy
            .evaluate_egress(sock(PYPI_V4, 443), Protocol::Tcp, &shared)
            .is_allow(),
        "cached IPv4 address should match"
    );
    assert!(
        policy
            .evaluate_egress(sock(CLOUDFLARE_V6, 443), Protocol::Tcp, &shared)
            .is_deny(),
        "uncached IPv6 address must not match through an IPv4-only cache entry"
    );
}

#[test]
fn policy_from_json_normalizes_domain_inputs() {
    // End-to-end config path: a user-authored JSON policy with uppercase
    // and trailing-dot domain values must be canonicalized on
    // deserialization and match the lowercased cache entry populated by
    // the DNS interceptor.
    let shared = SharedState::new(4);
    cache(&shared, "pypi.org", ResolvedHostnameFamily::Ipv4, PYPI_V4);

    let policy: NetworkPolicy = serde_json::from_str(
        r#"{
            "default_action": "Deny",
            "rules": [
                {
                    "direction": "Outbound",
                    "destination": { "Domain": "PyPI.Org." },
                    "protocol": "Tcp",
                    "ports": { "start": 443, "end": 443 },
                    "action": "Allow"
                }
            ]
        }"#,
    )
    .unwrap();

    assert!(
        policy
            .evaluate_egress(sock(PYPI_V4, 443), Protocol::Tcp, &shared)
            .is_allow()
    );
}
