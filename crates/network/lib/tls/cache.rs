//! In-memory LRU certificate cache with TTL eviction.

use std::{
    io,
    num::NonZeroUsize,
    sync::{Arc, RwLock},
    time::{Duration, Instant},
};

use lru::LruCache;
use rustls::sign::CertifiedKey;

use super::{CaKeyPair, CertCacheConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Thread-safe LRU cache for per-domain TLS certificates.
///
/// On cache miss, generates a new certificate signed by the CA. Expired
/// entries are evicted on access. The cache is bounded by `max_entries`.
pub struct CertCache {
    inner: RwLock<LruCache<String, CacheEntry>>,
    ca: CaKeyPair,
    ttl: Duration,
}

/// A cached certificate with its creation timestamp.
struct CacheEntry {
    key: Arc<CertifiedKey>,
    created: Instant,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CertCache {
    /// Creates a new certificate cache.
    pub fn new(ca: CaKeyPair, config: &CertCacheConfig) -> Self {
        let capacity = NonZeroUsize::new(config.max_entries).unwrap_or(NonZeroUsize::MIN);
        Self {
            inner: RwLock::new(LruCache::new(capacity)),
            ca,
            ttl: Duration::from_secs(config.ttl_secs),
        }
    }

    /// Returns a cached `CertifiedKey` for the domain, generating one if
    /// absent or expired.
    pub fn get_or_generate(&self, domain: &str) -> io::Result<Arc<CertifiedKey>> {
        let lower = domain.to_ascii_lowercase();

        // Fast path: read lock. Use unwrap_or_else to recover from poisoned
        // locks (a previous holder panicked) rather than cascading the panic.
        {
            let cache = self.inner.read().unwrap_or_else(|e| e.into_inner());
            if let Some(entry) = cache.peek(&lower)
                && entry.created.elapsed() < self.ttl
            {
                return Ok(Arc::clone(&entry.key));
            }
        }

        // Slow path: write lock, generate.
        let mut cache = self.inner.write().unwrap_or_else(|e| e.into_inner());

        // Double-check after acquiring write lock.
        if let Some(entry) = cache.get(&lower)
            && entry.created.elapsed() < self.ttl
        {
            return Ok(Arc::clone(&entry.key));
        }

        // Generate.
        let cert = super::certgen::generate_cert(&lower, &self.ca)?;
        let certified = super::certgen::to_certified_key(&cert)?;

        cache.put(
            lower,
            CacheEntry {
                key: Arc::clone(&certified),
                created: Instant::now(),
            },
        );

        Ok(certified)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ca;

    fn make_cache() -> CertCache {
        let ca_config = crate::tls::CaConfig::default();
        let ca_kp = ca::generate_ca(&ca_config).unwrap();
        let cache_config = CertCacheConfig {
            max_entries: 10,
            ttl_secs: 3600,
        };
        CertCache::new(ca_kp, &cache_config)
    }

    #[test]
    fn test_cache_miss_generates() {
        let cache = make_cache();
        let cert = cache.get_or_generate("example.com").unwrap();
        assert_eq!(cert.cert.len(), 2);
    }

    #[test]
    fn test_cache_hit_returns_same() {
        let cache = make_cache();
        let cert1 = cache.get_or_generate("example.com").unwrap();
        let cert2 = cache.get_or_generate("example.com").unwrap();
        // Same Arc pointer.
        assert!(Arc::ptr_eq(&cert1, &cert2));
    }

    #[test]
    fn test_different_domains() {
        let cache = make_cache();
        let cert1 = cache.get_or_generate("a.com").unwrap();
        let cert2 = cache.get_or_generate("b.com").unwrap();
        assert!(!Arc::ptr_eq(&cert1, &cert2));
    }
}
