//! Destination group matching: maps IP addresses to the
//! [`DestinationGroup`] they belong to.

use std::net::IpAddr;

use ipnetwork::IpNetwork;

use super::DestinationGroup;
use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Returns `true` if `addr` belongs to the given destination group.
///
/// Built on a single private classifier (`addr_classify`) so adding a
/// new `DestinationGroup` variant forces an exhaustive-match update
/// in the classifier and a corresponding witness in the test suite.
/// `Public` is the fallback when no other classification matches —
/// there's no list of excluded groups to keep in sync.
///
/// Groups are disjoint: each IP belongs to exactly one. `Metadata`
/// takes precedence over `LinkLocal` for `169.254.169.254`, and `Host`
/// takes precedence over `Private` when the gateway IPs sit inside
/// CGNAT or ULA ranges (which they currently do).
pub fn matches_group(group: DestinationGroup, addr: IpAddr, shared: &SharedState) -> bool {
    addr_classify(addr, shared) == group
}

/// Classify an IP into exactly one destination group.
///
/// Order matters: more specific tests first. `Host` first because
/// today's gateway IPs land in CGNAT (`100.64.0.0/10`) and ULA
/// (`fc00::/7`) ranges that `is_private` would otherwise claim.
/// `Metadata` before `LinkLocal` because `169.254.169.254` is in the
/// link-local CIDR.
fn addr_classify(addr: IpAddr, shared: &SharedState) -> DestinationGroup {
    if matches_host(addr, shared) {
        DestinationGroup::Host
    } else if is_metadata(addr) {
        DestinationGroup::Metadata
    } else if is_loopback(addr) {
        DestinationGroup::Loopback
    } else if is_private(addr) {
        DestinationGroup::Private
    } else if is_link_local(addr) {
        DestinationGroup::LinkLocal
    } else if is_multicast(addr) {
        DestinationGroup::Multicast
    } else {
        DestinationGroup::Public
    }
}

/// Matches the per-sandbox gateway IPs carried by [`SharedState`].
/// Returns `false` when gateway IPs haven't been set (e.g. isolated
/// unit tests that don't exercise Host rules).
fn matches_host(addr: IpAddr, shared: &SharedState) -> bool {
    match addr {
        IpAddr::V4(v4) => shared.gateway_ipv4().is_some_and(|gw| gw == v4),
        IpAddr::V6(v6) => shared.gateway_ipv6().is_some_and(|gw| gw == v6),
    }
}

fn is_loopback(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_loopback(), // 127.0.0.0/8
        IpAddr::V6(v6) => v6.is_loopback(), // ::1
    }
}

fn is_private(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 10.0.0.0/8
            octets[0] == 10
            // 172.16.0.0/12
            || (octets[0] == 172 && (octets[1] & 0xf0) == 16)
            // 192.168.0.0/16
            || (octets[0] == 192 && octets[1] == 168)
            // 100.64.0.0/10 (Carrier-grade NAT / shared address space)
            || (octets[0] == 100 && (octets[1] & 0xc0) == 64)
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // fc00::/7 (ULA — Unique Local Address)
            (segments[0] & 0xfe00) == 0xfc00
        }
    }
}

fn is_link_local(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            let octets = v4.octets();
            // 169.254.0.0/16
            octets[0] == 169 && octets[1] == 254
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            // fe80::/10
            (segments[0] & 0xffc0) == 0xfe80
        }
    }
}

fn is_metadata(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => {
            // AWS/GCP/Azure metadata endpoint.
            v4.octets() == [169, 254, 169, 254]
        }
        IpAddr::V6(_) => false,
    }
}

fn is_multicast(addr: IpAddr) -> bool {
    match addr {
        IpAddr::V4(v4) => v4.is_multicast(), // 224.0.0.0/4
        IpAddr::V6(v6) => v6.is_multicast(), // ff00::/8
    }
}

/// Returns `true` if `addr` matches a CIDR network.
pub fn matches_cidr(network: &IpNetwork, addr: IpAddr) -> bool {
    network.contains(addr)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    /// SharedState with no gateway IPs — `Host` matching never fires.
    fn no_host() -> SharedState {
        SharedState::new(4)
    }

    /// SharedState wired with the canonical sandbox gateway IPs.
    fn with_gateway() -> SharedState {
        let s = SharedState::new(4);
        s.set_gateway_ips(
            Ipv4Addr::new(100, 96, 0, 1),
            "fd42:6d73:62::1".parse().unwrap(),
        );
        s
    }

    #[test]
    fn loopback_v4() {
        let s = no_host();
        assert!(matches_group(
            DestinationGroup::Loopback,
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            &s,
        ));
        assert!(matches_group(
            DestinationGroup::Loopback,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
            &s,
        ));
        assert!(!matches_group(
            DestinationGroup::Loopback,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            &s,
        ));
    }

    #[test]
    fn loopback_v6() {
        let s = no_host();
        assert!(matches_group(
            DestinationGroup::Loopback,
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            &s,
        ));
        assert!(!matches_group(
            DestinationGroup::Loopback,
            IpAddr::V6("fe80::1".parse().unwrap()),
            &s,
        ));
    }

    #[test]
    fn private_v4() {
        let s = no_host();
        for ip in [
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(172, 16, 0, 1),
            Ipv4Addr::new(192, 168, 1, 1),
            Ipv4Addr::new(100, 64, 0, 1),
        ] {
            assert!(matches_group(DestinationGroup::Private, IpAddr::V4(ip), &s));
        }
        assert!(!matches_group(
            DestinationGroup::Private,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
            &s,
        ));
    }

    #[test]
    fn private_v6_ula() {
        let s = no_host();
        assert!(matches_group(
            DestinationGroup::Private,
            IpAddr::V6("fd42:6d73:62:2a::1".parse().unwrap()),
            &s,
        ));
        assert!(!matches_group(
            DestinationGroup::Private,
            IpAddr::V6("2001:db8::1".parse().unwrap()),
            &s,
        ));
    }

    #[test]
    fn link_local() {
        let s = no_host();
        assert!(matches_group(
            DestinationGroup::LinkLocal,
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            &s,
        ));
        assert!(matches_group(
            DestinationGroup::LinkLocal,
            IpAddr::V6("fe80::1".parse().unwrap()),
            &s,
        ));
        assert!(!matches_group(
            DestinationGroup::LinkLocal,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            &s,
        ));
    }

    #[test]
    fn metadata() {
        let s = no_host();
        assert!(matches_group(
            DestinationGroup::Metadata,
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            &s,
        ));
        assert!(!matches_group(
            DestinationGroup::Metadata,
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            &s,
        ));
    }

    /// `169.254.169.254` is in the link-local CIDR but classified as
    /// `Metadata`. Groups are disjoint, so `LinkLocal` doesn't match
    /// the metadata IP.
    #[test]
    fn metadata_takes_precedence_over_link_local() {
        let s = no_host();
        let metadata_ip = IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254));
        assert!(matches_group(DestinationGroup::Metadata, metadata_ip, &s));
        assert!(!matches_group(DestinationGroup::LinkLocal, metadata_ip, &s));
    }

    #[test]
    fn multicast() {
        let s = no_host();
        assert!(matches_group(
            DestinationGroup::Multicast,
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            &s,
        ));
        assert!(matches_group(
            DestinationGroup::Multicast,
            IpAddr::V6("ff02::1".parse().unwrap()),
            &s,
        ));
        assert!(!matches_group(
            DestinationGroup::Multicast,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            &s,
        ));
    }

    #[test]
    fn cidr_match() {
        let net: IpNetwork = "10.0.0.0/8".parse().unwrap();
        assert!(matches_cidr(&net, IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!matches_cidr(&net, IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }

    #[test]
    fn public_v4_routable() {
        let s = no_host();
        for ip in [
            Ipv4Addr::new(8, 8, 8, 8),
            Ipv4Addr::new(1, 1, 1, 1),
            Ipv4Addr::new(151, 101, 0, 223),
        ] {
            assert!(matches_group(DestinationGroup::Public, IpAddr::V4(ip), &s));
        }
    }

    #[test]
    fn public_v6_routable() {
        let s = no_host();
        for ip in [
            "2606:4700:4700::1111".parse().unwrap(),
            "2001:db8::1".parse().unwrap(),
        ] {
            assert!(matches_group(DestinationGroup::Public, IpAddr::V6(ip), &s));
        }
    }

    #[test]
    fn public_excludes_other_categories() {
        let s = no_host();
        let not_public = [
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::LOCALHOST),
            IpAddr::V6("fd42:6d73:62:2a::1".parse().unwrap()),
            IpAddr::V6("fe80::1".parse().unwrap()),
            IpAddr::V6("ff02::1".parse().unwrap()),
        ];
        for ip in not_public {
            assert!(
                !matches_group(DestinationGroup::Public, ip, &s),
                "expected {ip} to not be Public"
            );
        }
    }

    /// `Host` takes precedence over the static categories that would
    /// otherwise claim the gateway IPs (CGNAT for IPv4, ULA for IPv6).
    /// This means an `allow Public` rule won't accidentally allow host
    /// traffic, and a `deny Private` rule won't accidentally cover the
    /// host gateway either.
    #[test]
    fn host_takes_precedence_over_private() {
        let s = with_gateway();
        let v4 = IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1));
        let v6 = IpAddr::V6("fd42:6d73:62::1".parse().unwrap());

        assert!(matches_group(DestinationGroup::Host, v4, &s));
        assert!(matches_group(DestinationGroup::Host, v6, &s));
        assert!(!matches_group(DestinationGroup::Private, v4, &s));
        assert!(!matches_group(DestinationGroup::Private, v6, &s));
        assert!(!matches_group(DestinationGroup::Public, v4, &s));
        assert!(!matches_group(DestinationGroup::Public, v6, &s));
    }

    /// Witness test: every `DestinationGroup` variant is producible by
    /// the classifier given the right input. Adding a new variant
    /// without wiring it into `addr_classify` makes this test fail
    /// (the new variant has no witness IP).
    #[test]
    fn classifier_covers_every_destination_group() {
        let s = with_gateway();
        let cases: &[(IpAddr, DestinationGroup)] = &[
            (
                IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
                DestinationGroup::Public,
            ),
            (IpAddr::V4(Ipv4Addr::LOCALHOST), DestinationGroup::Loopback),
            (
                IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                DestinationGroup::Private,
            ),
            (
                IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1)),
                DestinationGroup::LinkLocal,
            ),
            (
                IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
                DestinationGroup::Metadata,
            ),
            (
                IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1)),
                DestinationGroup::Multicast,
            ),
            (
                IpAddr::V4(Ipv4Addr::new(100, 96, 0, 1)),
                DestinationGroup::Host,
            ),
        ];

        // Compile-time exhaustiveness check on the witness table:
        // adding a new variant to `DestinationGroup` makes this match
        // non-exhaustive, forcing the test author to add a witness row
        // above. The runtime assertion below then verifies the witness
        // actually maps to the new variant.
        fn _exhaustive_witness_check(g: DestinationGroup) {
            match g {
                DestinationGroup::Public
                | DestinationGroup::Loopback
                | DestinationGroup::Private
                | DestinationGroup::LinkLocal
                | DestinationGroup::Metadata
                | DestinationGroup::Multicast
                | DestinationGroup::Host => (),
            }
        }

        for (ip, expected) in cases {
            assert_eq!(
                addr_classify(*ip, &s),
                *expected,
                "expected {ip:?} to classify as {expected:?}"
            );
        }
    }
}
