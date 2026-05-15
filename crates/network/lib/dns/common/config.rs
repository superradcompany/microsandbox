//! Normalized DNS config: pre-processed operator input that the
//! per-query path can consult without re-allocating on every match.
//!
//! [`crate::dns::forwarder::DnsForwarder`] holds an
//! `Arc<NormalizedDnsConfig>` built once at startup. The raw-millisecond
//! timeout is converted once to a [`Duration`] for hickory.

use std::time::Duration;

use crate::config::DnsConfig;
use crate::dns::nameserver::Nameserver;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Pre-processed DNS config (avoids per-query allocations).
///
/// Fields are visible across the `dns` module so the forwarder and the
/// filter predicates can read them directly; construction goes through
/// [`Self::from_config`].
pub(in crate::dns) struct NormalizedDnsConfig {
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
    /// Build a normalized config from a raw [`DnsConfig`].
    pub(in crate::dns) fn from_config(config: DnsConfig) -> Self {
        Self {
            rebind_protection: config.rebind_protection,
            nameservers: config.nameservers,
            query_timeout: Duration::from_millis(config.query_timeout_ms),
        }
    }
}
