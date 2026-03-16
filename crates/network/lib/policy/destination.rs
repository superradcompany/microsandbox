//! Destination group matching: maps `DestinationGroup` variants to concrete
//! IP ranges for loopback, private, link-local, metadata, and multicast.

use std::net::IpAddr;

use ipnetwork::IpNetwork;

use super::DestinationGroup;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Returns `true` if `addr` belongs to the given destination group.
pub fn matches_group(group: DestinationGroup, addr: IpAddr) -> bool {
    match group {
        DestinationGroup::Loopback => is_loopback(addr),
        DestinationGroup::Private => is_private(addr),
        DestinationGroup::LinkLocal => is_link_local(addr),
        DestinationGroup::Metadata => is_metadata(addr),
        DestinationGroup::Multicast => is_multicast(addr),
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

    #[test]
    fn test_loopback_v4() {
        assert!(matches_group(
            DestinationGroup::Loopback,
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        ));
        assert!(matches_group(
            DestinationGroup::Loopback,
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2))
        ));
        assert!(!matches_group(
            DestinationGroup::Loopback,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        ));
    }

    #[test]
    fn test_loopback_v6() {
        assert!(matches_group(
            DestinationGroup::Loopback,
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        ));
        assert!(!matches_group(
            DestinationGroup::Loopback,
            IpAddr::V6("fe80::1".parse().unwrap())
        ));
    }

    #[test]
    fn test_private_v4() {
        assert!(matches_group(
            DestinationGroup::Private,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        ));
        assert!(matches_group(
            DestinationGroup::Private,
            IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))
        ));
        assert!(matches_group(
            DestinationGroup::Private,
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))
        ));
        assert!(matches_group(
            DestinationGroup::Private,
            IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))
        ));
        assert!(!matches_group(
            DestinationGroup::Private,
            IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))
        ));
    }

    #[test]
    fn test_private_v6_ula() {
        assert!(matches_group(
            DestinationGroup::Private,
            IpAddr::V6("fd42:6d73:62:2a::1".parse().unwrap())
        ));
        assert!(!matches_group(
            DestinationGroup::Private,
            IpAddr::V6("2001:db8::1".parse().unwrap())
        ));
    }

    #[test]
    fn test_link_local() {
        assert!(matches_group(
            DestinationGroup::LinkLocal,
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))
        ));
        assert!(matches_group(
            DestinationGroup::LinkLocal,
            IpAddr::V6("fe80::1".parse().unwrap())
        ));
        assert!(!matches_group(
            DestinationGroup::LinkLocal,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        ));
    }

    #[test]
    fn test_metadata() {
        assert!(matches_group(
            DestinationGroup::Metadata,
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))
        ));
        assert!(!matches_group(
            DestinationGroup::Metadata,
            IpAddr::V4(Ipv4Addr::new(169, 254, 1, 1))
        ));
    }

    #[test]
    fn test_multicast() {
        assert!(matches_group(
            DestinationGroup::Multicast,
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))
        ));
        assert!(matches_group(
            DestinationGroup::Multicast,
            IpAddr::V6("ff02::1".parse().unwrap())
        ));
        assert!(!matches_group(
            DestinationGroup::Multicast,
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))
        ));
    }

    #[test]
    fn test_cidr_match() {
        let net: IpNetwork = "10.0.0.0/8".parse().unwrap();
        assert!(matches_cidr(&net, IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))));
        assert!(!matches_cidr(&net, IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
    }
}
