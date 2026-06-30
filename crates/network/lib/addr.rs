//! IP address helpers shared by network policy and DNS code.

use std::net::IpAddr;

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
}
