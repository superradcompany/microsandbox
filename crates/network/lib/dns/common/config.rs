//! Normalized DNS config: pre-processed operator input that the
//! per-query path can consult without re-allocating on every match.
//!
//! [`crate::dns::forwarder::DnsForwarder`] holds an
//! `Arc<NormalizedDnsConfig>` built once at startup. Block lists are
//! lowercased and `.suffix`-dotted up-front so [`super::filter`]
//! doesn't have to `format!` on every query; the raw-millisecond
//! timeout is converted once to a [`Duration`] for hickory.

use std::collections::HashSet;
use std::time::Duration;

use crate::config::DnsConfig;
use crate::dns::nameserver::Nameserver;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Pre-processed DNS config with lowercased block lists (avoids
/// per-query allocations).
///
/// Fields are visible across the `dns` module so the forwarder and the
/// filter predicates can read them directly; construction goes through
/// [`Self::from_config`].
pub(in crate::dns) struct NormalizedDnsConfig {
    /// O(1) exact-match lookup for blocked domains.
    pub(in crate::dns) blocked_domains: HashSet<String>,
    /// Lowercased suffixes WITHOUT leading dot (for exact match against the suffix itself).
    pub(in crate::dns) blocked_suffixes: Vec<String>,
    /// Dot-prefixed lowercased suffixes (for `ends_with` matching without per-query `format!`).
    pub(in crate::dns) blocked_suffixes_dotted: Vec<String>,
    pub(in crate::dns) rebind_protection: bool,
    /// Explicit nameservers (unresolved specs). Empty means fall back
    /// to the host's configured resolvers. Hostnames are resolved once
    /// at forwarder-task startup via the host's own resolver.
    pub(in crate::dns) nameservers: Vec<Nameserver>,
    /// Per-query timeout.
    pub(in crate::dns) query_timeout: Duration,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NormalizedDnsConfig {
    /// Build a normalized config from a raw [`DnsConfig`]. Lowercases
    /// and dot-prefixes the block lists once, up-front, so the query
    /// path doesn't allocate per match.
    pub(in crate::dns) fn from_config(config: DnsConfig) -> Self {
        let blocked_suffixes: Vec<String> = config
            .blocked_suffixes
            .iter()
            .map(|s| s.to_lowercase().trim_start_matches('.').to_string())
            .collect();
        let blocked_suffixes_dotted: Vec<String> =
            blocked_suffixes.iter().map(|s| format!(".{s}")).collect();
        Self {
            blocked_domains: config
                .blocked_domains
                .into_iter()
                .map(|d| d.to_lowercase())
                .collect(),
            blocked_suffixes,
            blocked_suffixes_dotted,
            rebind_protection: config.rebind_protection,
            nameservers: config.nameservers,
            query_timeout: Duration::from_millis(config.query_timeout_ms),
        }
    }
}
