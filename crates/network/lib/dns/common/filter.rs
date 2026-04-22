//! DNS filter predicates: block-list matching and private-IP detection.
//!
//! Pure, synchronous helpers used by the forwarder to decide whether a
//! query should be refused locally (block list) or whether a response
//! contains addresses that trip rebind protection.

use std::net::{Ipv4Addr, Ipv6Addr};

use super::config::NormalizedDnsConfig;

/// Check if a domain is blocked by the DNS config.
///
/// Block lists are pre-lowercased in [`NormalizedDnsConfig`], so only the
/// queried domain needs lowercasing (once per query instead of per entry).
pub(in crate::dns) fn is_domain_blocked(domain: &str, config: &NormalizedDnsConfig) -> bool {
    let domain_lower = domain.to_lowercase();

    // Check exact domain matches — O(1) via HashSet.
    if config.blocked_domains.contains(&domain_lower) {
        return true;
    }

    // Check suffix matches (already lowercased with pre-computed dot-prefixed forms).
    for (suffix, dotted) in config
        .blocked_suffixes
        .iter()
        .zip(config.blocked_suffixes_dotted.iter())
    {
        if domain_lower == *suffix || domain_lower.ends_with(dotted.as_str()) {
            return true;
        }
    }

    false
}

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
    use std::collections::HashSet;
    use std::time::Duration;

    use super::*;
    use crate::dns::nameserver::Nameserver;

    fn normalized(domains: Vec<&str>, suffixes: Vec<&str>) -> NormalizedDnsConfig {
        let blocked_suffixes: Vec<String> = suffixes
            .iter()
            .map(|s| s.to_lowercase().trim_start_matches('.').to_string())
            .collect();

        let blocked_suffixes_dotted = blocked_suffixes.iter().map(|s| format!(".{s}")).collect();

        NormalizedDnsConfig {
            blocked_domains: domains
                .iter()
                .map(|d| d.to_lowercase())
                .collect::<HashSet<_>>(),
            blocked_suffixes,
            blocked_suffixes_dotted,
            rebind_protection: false,
            nameservers: Vec::<Nameserver>::new(),
            query_timeout: Duration::from_millis(5000),
        }
    }

    #[test]
    fn test_exact_domain_blocked() {
        let config = normalized(vec!["evil.com"], vec![]);
        assert!(is_domain_blocked("evil.com", &config));
        assert!(is_domain_blocked("Evil.COM", &config));
        assert!(!is_domain_blocked("not-evil.com", &config));
        assert!(!is_domain_blocked("sub.evil.com", &config));
    }

    #[test]
    fn test_suffix_domain_blocked() {
        let config = normalized(vec![], vec![".evil.com"]);
        assert!(is_domain_blocked("sub.evil.com", &config));
        assert!(is_domain_blocked("deep.sub.evil.com", &config));
        assert!(is_domain_blocked("evil.com", &config));
        assert!(!is_domain_blocked("notevil.com", &config));
    }

    #[test]
    fn test_no_blocks_nothing_blocked() {
        let config = normalized(vec![], vec![]);
        assert!(!is_domain_blocked("anything.com", &config));
    }
}
