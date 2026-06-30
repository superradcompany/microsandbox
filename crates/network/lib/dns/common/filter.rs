//! DNS filter predicates: private-IP detection for rebind protection.
//!
//! Pure, synchronous helpers used by the forwarder to decide whether a
//! response contains addresses that trip rebind protection.

use std::net::{Ipv4Addr, Ipv6Addr};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Check if an IPv4 address is in a private/reserved range (for rebind protection).
pub(in crate::dns) fn is_private_ipv4(addr: Ipv4Addr) -> bool {
    let octets = addr.octets();
    addr.is_loopback()                                        // 127.0.0.0/8
        || octets[0] == 10                                    // 10.0.0.0/8
        || (octets[0] == 172 && (octets[1] & 0xf0) == 16)    // 172.16.0.0/12
        || (octets[0] == 192 && octets[1] == 168)             // 192.168.0.0/16
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64)    // 100.64.0.0/10 (CGNAT)
        || (octets[0] == 169 && octets[1] == 254)             // 169.254.0.0/16 (link-local)
        || addr.is_unspecified() // 0.0.0.0
}

/// Check if an IPv6 address is in a private/reserved range (for rebind protection).
pub(in crate::dns) fn is_private_ipv6(addr: Ipv6Addr) -> bool {
    if let Some(addr) = addr.to_ipv4_mapped() {
        return is_private_ipv4(addr);
    }

    let segments = addr.segments();
    addr.is_loopback()                       // ::1
        || (segments[0] & 0xfe00) == 0xfc00  // fc00::/7 (ULA)
        || (segments[0] & 0xffc0) == 0xfe80  // fe80::/10 (link-local)
        || addr.is_unspecified() // ::
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ipv6_rejects_ipv4_mapped_private_ranges() {
        for addr in [
            "::ffff:127.0.0.1",
            "::ffff:10.0.0.1",
            "::ffff:172.16.0.1",
            "::ffff:192.168.1.10",
            "::ffff:100.64.0.1",
            "::ffff:169.254.169.254",
            "::ffff:0.0.0.0",
        ] {
            assert!(
                is_private_ipv6(addr.parse().unwrap()),
                "expected {addr} to trip rebind protection"
            );
        }
    }

    #[test]
    fn private_ipv6_allows_ipv4_mapped_public_addresses() {
        assert!(!is_private_ipv6("::ffff:8.8.8.8".parse().unwrap()));
    }
}
