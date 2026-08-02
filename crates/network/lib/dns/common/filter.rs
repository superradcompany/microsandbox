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
    octets[0] == 0 // 0.0.0.0/8, including the unspecified address
        || addr.is_loopback() // 127.0.0.0/8
        || octets[0] == 10 // 10.0.0.0/8
        || (octets[0] == 172 && (octets[1] & 0xf0) == 16) // 172.16.0.0/12
        || (octets[0] == 192 && octets[1] == 168) // 192.168.0.0/16
        || (octets[0] == 100 && (octets[1] & 0xc0) == 64) // 100.64.0.0/10 (CGNAT)
        || (octets[0] == 169 && octets[1] == 254) // 169.254.0.0/16 (link-local)
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 0) // 192.0.0.0/24
        || (octets[0] == 192 && octets[1] == 0 && octets[2] == 2) // 192.0.2.0/24
        || (octets[0] == 192 && octets[1] == 88 && octets[2] == 99) // 192.88.99.0/24
        || (octets[0] == 198 && octets[1] == 18) // 198.18.0.0/15
        || (octets[0] == 198 && octets[1] == 19) // 198.18.0.0/15
        || (octets[0] == 198 && octets[1] == 51 && octets[2] == 100) // 198.51.100.0/24
        || (octets[0] == 203 && octets[1] == 0 && octets[2] == 113) // 203.0.113.0/24
        || (224..=239).contains(&octets[0]) // 224.0.0.0/4 (multicast)
        || octets[0] >= 240 // 240.0.0.0/4, including broadcast
}

/// Check if an IPv6 address is in a private/reserved range (for rebind protection).
pub(in crate::dns) fn is_private_ipv6(addr: Ipv6Addr) -> bool {
    if let Some(addr) = addr.to_ipv4_mapped() {
        return is_private_ipv4(addr);
    }

    let segments = addr.segments();
    addr.is_loopback() // ::1
        || addr.is_unspecified() // ::
        || addr.is_multicast() // ff00::/8
        || (segments[0] & 0xfe00) == 0xfc00 // fc00::/7 (ULA)
        || (segments[0] & 0xffc0) == 0xfe80 // fe80::/10 (link-local)
        || (segments[0] & 0xffc0) == 0xfec0 // fec0::/10 (site-local)
        || (segments[0] == 0x0100
            && segments[1] == 0
            && segments[2] == 0
            && segments[3] == 0) // 100::/64 (discard-only)
        || (segments[0] == 0x0064 && segments[1] == 0xff9b && segments[2] == 0x0001) // 64:ff9b:1::/48
        || (segments[0] == 0x2001 && segments[1] == 0x0db8) // 2001:db8::/32
        || (segments[0] == 0x3fff && (segments[1] & 0xf000) == 0) // 3fff::/20
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn private_ipv4_rejects_reserved_ranges() {
        for addr in [
            "0.1.2.3",
            "192.0.0.8",
            "192.0.2.1",
            "192.88.99.1",
            "198.18.0.1",
            "198.51.100.7",
            "203.0.113.10",
            "224.0.0.1",
            "255.255.255.255",
        ] {
            assert!(
                is_private_ipv4(addr.parse().unwrap()),
                "expected {addr} to trip rebind protection"
            );
        }
    }

    #[test]
    fn private_ipv4_allows_public_addresses() {
        for addr in ["1.1.1.1", "8.8.8.8", "93.184.216.34"] {
            assert!(
                !is_private_ipv4(addr.parse().unwrap()),
                "expected {addr} to remain public"
            );
        }
    }

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

    #[test]
    fn private_ipv6_rejects_reserved_ranges() {
        for addr in [
            "ff02::1",
            "fec0::1",
            "100::1",
            "64:ff9b:1::1",
            "2001:db8::1",
            "3fff::1",
        ] {
            assert!(
                is_private_ipv6(addr.parse().unwrap()),
                "expected {addr} to trip rebind protection"
            );
        }
    }

    #[test]
    fn private_ipv6_allows_public_addresses() {
        for addr in ["2606:4700:4700::1111", "2001:4860:4860::8888"] {
            assert!(
                !is_private_ipv6(addr.parse().unwrap()),
                "expected {addr} to remain public"
            );
        }
    }
}
