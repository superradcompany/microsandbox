//! Shared TLS state: CA, certificate cache, and upstream connector.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;
use tokio_rustls::TlsConnector;

use super::ca::CertAuthority;
use super::certgen::{self, DomainCert};
use super::config::TlsConfig;
use crate::secrets::config::SecretsConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Shared TLS interception state.
///
/// Holds the CA, per-domain certificate cache, upstream TLS connector,
/// and configuration. Shared across all TLS proxy tasks via `Arc`.
pub struct TlsState {
    /// Certificate authority for signing per-domain certs.
    pub ca: CertAuthority,
    /// LRU cache of generated domain certificates.
    cert_cache: Mutex<LruCache<String, Arc<DomainCert>>>,
    /// TLS connector for upstream (real server) connections.
    pub connector: TlsConnector,
    /// TLS configuration.
    pub config: TlsConfig,
    /// Secrets configuration for placeholder substitution.
    pub secrets: SecretsConfig,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TlsState {
    /// Create TLS state from configuration.
    pub fn new(config: TlsConfig, secrets: SecretsConfig) -> Self {
        let ca = CertAuthority::generate();

        let capacity =
            NonZeroUsize::new(config.cache.capacity).unwrap_or(NonZeroUsize::new(1000).unwrap());
        let cert_cache = Mutex::new(LruCache::new(capacity));

        // Build upstream TLS connector.
        let mut root_store = rustls::RootCertStore::empty();
        if config.verify_upstream {
            let certs = rustls_native_certs::load_native_certs();
            for cert in certs.certs {
                let _ = root_store.add(cert);
            }
        }

        let client_config = rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client_config));

        Self {
            ca,
            cert_cache,
            connector,
            config,
            secrets,
        }
    }

    /// Get or generate a certificate for the given domain.
    pub fn get_or_generate_cert(&self, domain: &str) -> Arc<DomainCert> {
        let mut cache = self.cert_cache.lock().unwrap();
        if let Some(cert) = cache.get(domain) {
            return cert.clone();
        }

        let cert = Arc::new(certgen::generate_domain_cert(
            domain,
            &self.ca,
            self.config.cache.validity_hours,
        ));
        cache.put(domain.to_string(), cert.clone());
        cert
    }

    /// Check if a domain should bypass TLS interception.
    pub fn should_bypass(&self, sni: &str) -> bool {
        let sni_lower = sni.to_lowercase();
        self.config.bypass.iter().any(|pattern| {
            let pattern_lower = pattern.to_lowercase();
            if let Some(suffix) = pattern_lower.strip_prefix("*.") {
                sni_lower == suffix || sni_lower.ends_with(&format!(".{suffix}"))
            } else {
                sni_lower == pattern_lower
            }
        })
    }

    /// Get the CA certificate PEM bytes for guest installation.
    pub fn ca_cert_pem(&self) -> Vec<u8> {
        self.ca.cert_pem()
    }
}
