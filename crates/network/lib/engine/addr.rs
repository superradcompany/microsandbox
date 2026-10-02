//! IP address helpers shared by network policy and DNS code.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ipnetwork::Ipv6Network;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Collapse IPv4-mapped IPv6 addresses into their embedded IPv4 address.
///
/// Some runtimes and resolvers can represent an IPv4 endpoint as `::ffff:a.b.c.d`.
/// Normalizing keeps policy classification, CIDR checks, DNS rebind protection, and
/// resolved-hostname cache lookups aligned with the actual IPv4 endpoint.
pub(crate) fn normalize_ip_addr(addr: IpAddr) -> IpAddr {
    match addr {
        IpAddr::V4(_) => addr,
        IpAddr::V6(v6) => v6
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(v6)),
    }
}

/// Extract the embedded IPv4 destination from a NAT64 `/96` prefix.
///
/// This is a policy projection, not general address normalization: the IPv6
/// address remains the transport destination, but policy also evaluates the
/// IPv4 address encoded in the low 32 bits.
pub(crate) fn nat64_embedded_ipv4_addr(
    addr: Ipv6Addr,
    prefixes: &[Ipv6Network],
) -> Option<Ipv4Addr> {
    prefixes
        .iter()
        .any(|prefix| prefix.prefix() == 96 && prefix.contains(addr))
        .then(|| Ipv4Addr::from((u128::from(addr) & u128::from(u32::MAX)) as u32))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use super::*;

    #[test]
    fn normalize_ip_addr_unwraps_ipv4_mapped_ipv6() {
        assert_eq!(
            normalize_ip_addr(IpAddr::V6("::ffff:169.254.169.254".parse().unwrap())),
            IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
        );
    }

    #[test]
    fn normalize_ip_addr_keeps_native_ipv6() {
        let addr = IpAddr::V6("2606:4700:4700::1111".parse().unwrap());

        assert_eq!(normalize_ip_addr(addr), addr);
    }

    #[test]
    fn normalize_ip_addr_keeps_ipv4() {
        let addr = IpAddr::V4(Ipv4Addr::LOCALHOST);

        assert_eq!(normalize_ip_addr(addr), addr);
    }

    #[test]
    fn nat64_embedded_ipv4_addr_uses_configured_prefixes() {
        let prefixes = ["64:ff9b::/96".parse().unwrap()];

        assert_eq!(
            nat64_embedded_ipv4_addr("64:ff9b::a9fe:a9fe".parse().unwrap(), &prefixes),
            Some(Ipv4Addr::new(169, 254, 169, 254)),
        );
    }

    #[test]
    fn nat64_embedded_ipv4_addr_requires_configured_prefix() {
        let prefixes = ["2001:db8:64::/96".parse().unwrap()];

        assert_eq!(
            nat64_embedded_ipv4_addr("64:ff9b::a9fe:a9fe".parse().unwrap(), &prefixes),
            None,
        );
        assert_eq!(
            nat64_embedded_ipv4_addr("2002:0a00:0001::1".parse().unwrap(), &prefixes),
            None,
        );
        assert_eq!(
            nat64_embedded_ipv4_addr(
                "2001:0000:4136:e378:8000:63bf:80ff:fffe".parse().unwrap(),
                &prefixes,
            ),
            None,
        );
    }
}
