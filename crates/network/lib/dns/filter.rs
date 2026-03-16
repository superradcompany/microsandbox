//! DNS domain filtering and rebind protection.

use std::net::IpAddr;

use crate::policy::DestinationGroup;
use crate::policy::destination::matches_group;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// DNS query filter configuration.
///
/// Domain names and suffixes are stored pre-lowercased for O(1)-per-entry
/// comparison without per-query allocation.
#[derive(Debug, Clone, Default)]
pub struct DnsFilter {
    /// Blocked domain names (exact match, pre-lowercased).
    blocked_domains: Vec<String>,

    /// Blocked domain suffixes (e.g. `.evil.com`, pre-lowercased).
    blocked_suffixes: Vec<String>,

    /// Whether rebind protection is enabled.
    pub rebind_protection: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DnsFilter {
    /// Creates a new DNS filter, normalizing all domain strings to lowercase.
    pub fn new(
        blocked_domains: Vec<String>,
        blocked_suffixes: Vec<String>,
        rebind_protection: bool,
    ) -> Self {
        Self {
            blocked_domains: blocked_domains
                .into_iter()
                .map(|d| d.to_lowercase())
                .collect(),
            blocked_suffixes: blocked_suffixes
                .into_iter()
                .map(|s| s.to_lowercase())
                .collect(),
            rebind_protection,
        }
    }

    /// Returns `true` if the domain is blocked by exact match or suffix.
    pub fn is_domain_blocked(&self, domain: &str) -> bool {
        let domain_lower = domain.to_lowercase();

        for blocked in &self.blocked_domains {
            if domain_lower == *blocked {
                return true;
            }
        }

        for suffix in &self.blocked_suffixes {
            if domain_lower.ends_with(suffix.as_str()) {
                return true;
            }
        }

        false
    }

    /// Returns `true` if the resolved IP should be blocked by rebind protection.
    ///
    /// Blocks DNS answers that resolve to loopback, private, link-local,
    /// or multicast addresses — preventing DNS rebinding attacks.
    pub fn is_rebind_blocked(&self, ip: IpAddr) -> bool {
        if !self.rebind_protection {
            return false;
        }

        matches_group(DestinationGroup::Loopback, ip)
            || matches_group(DestinationGroup::Private, ip)
            || matches_group(DestinationGroup::LinkLocal, ip)
            || matches_group(DestinationGroup::Multicast, ip)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn test_exact_domain_block() {
        let filter = DnsFilter::new(vec!["evil.com".to_string()], vec![], false);
        assert!(filter.is_domain_blocked("evil.com"));
        assert!(filter.is_domain_blocked("Evil.Com"));
        assert!(!filter.is_domain_blocked("good.com"));
        assert!(!filter.is_domain_blocked("sub.evil.com"));
    }

    #[test]
    fn test_suffix_domain_block() {
        let filter = DnsFilter::new(vec![], vec![".evil.com".to_string()], false);
        assert!(filter.is_domain_blocked("sub.evil.com"));
        assert!(filter.is_domain_blocked("deep.sub.evil.com"));
        assert!(!filter.is_domain_blocked("evil.com")); // no leading dot
        assert!(!filter.is_domain_blocked("good.com"));
    }

    #[test]
    fn test_rebind_protection_off() {
        let filter = DnsFilter::new(vec![], vec![], false);
        assert!(!filter.is_rebind_blocked(IpAddr::V4(Ipv4Addr::LOCALHOST)));
    }

    #[test]
    fn test_rebind_protection_blocks_private() {
        let filter = DnsFilter::new(vec![], vec![], true);
        assert!(filter.is_rebind_blocked(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(filter.is_rebind_blocked(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(filter.is_rebind_blocked(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        assert!(!filter.is_rebind_blocked(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
    }
}
