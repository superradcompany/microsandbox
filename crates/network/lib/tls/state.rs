//! Shared TLS state: CA, certificate cache, and upstream connector.

use std::num::NonZeroUsize;
use std::sync::{Arc, Mutex};

use lru::LruCache;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
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
    /// Pre-computed lowercased bypass patterns for efficient matching.
    bypass_patterns: Vec<BypassPattern>,
}

/// A pre-processed bypass pattern (avoids per-connection allocations).
enum BypassPattern {
    /// Exact domain match (lowercased).
    Exact(String),
    /// Wildcard suffix match. `suffix` is the bare suffix, `dotted` is `.suffix`
    /// (pre-computed to avoid per-connection `format!` allocations).
    Wildcard { suffix: String, dotted: String },
}

/// A [`ServerCertVerifier`] that accepts all server certificates without
/// validation. Used when `verify_upstream` is `false`.
#[derive(Debug)]
struct NoVerify;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TlsState {
    /// Create TLS state from configuration.
    ///
    /// CA resolution order:
    /// 1. User-provided paths (`config.ca.cert_path` + `config.ca.key_path`)
    /// 2. Default persistence path (`~/.microsandbox/tls/ca.{crt,key}`)
    /// 3. Auto-generate and persist to default path
    pub fn new(config: TlsConfig, secrets: SecretsConfig) -> Self {
        let ca = load_or_generate_ca(&config);

        let capacity =
            NonZeroUsize::new(config.cache.capacity).unwrap_or(NonZeroUsize::new(1000).unwrap());
        let cert_cache = Mutex::new(LruCache::new(capacity));

        let connector = build_upstream_connector(&config);

        // Pre-compute lowercased bypass patterns to avoid per-connection allocations.
        let bypass_patterns = config
            .bypass
            .iter()
            .map(|pattern| {
                let lower = pattern.to_lowercase();
                if let Some(suffix) = lower.strip_prefix("*.") {
                    let dotted = format!(".{suffix}");
                    BypassPattern::Wildcard {
                        suffix: suffix.to_string(),
                        dotted,
                    }
                } else {
                    BypassPattern::Exact(lower)
                }
            })
            .collect();

        Self {
            ca,
            cert_cache,
            connector,
            config,
            secrets,
            bypass_patterns,
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
        self.bypass_patterns.iter().any(|pattern| match pattern {
            BypassPattern::Exact(exact) => sni_lower == *exact,
            BypassPattern::Wildcard { suffix, dotted } => {
                sni_lower == *suffix || sni_lower.ends_with(dotted.as_str())
            }
        })
    }

    /// Get the CA certificate PEM bytes for guest installation.
    pub fn ca_cert_pem(&self) -> Vec<u8> {
        self.ca.cert_pem()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        static SCHEMES: std::sync::OnceLock<Vec<rustls::SignatureScheme>> =
            std::sync::OnceLock::new();
        SCHEMES
            .get_or_init(|| {
                rustls::crypto::ring::default_provider()
                    .signature_verification_algorithms
                    .supported_schemes()
            })
            .clone()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build the upstream TLS connector based on configuration.
///
/// When `verify_upstream` is true, loads the system's native root certificates.
/// When false, uses a permissive verifier that accepts all server certificates.
fn build_upstream_connector(config: &TlsConfig) -> TlsConnector {
    let client_config = if config.verify_upstream {
        let mut root_store = rustls::RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs();
        if !certs.errors.is_empty() {
            tracing::warn!(
                count = certs.errors.len(),
                "errors loading native certificates"
            );
        }
        let mut added = 0usize;
        for cert in certs.certs {
            if root_store.add(cert).is_ok() {
                added += 1;
            }
        }
        if added == 0 {
            tracing::error!("no native root certificates loaded — all upstream TLS will fail");
        }
        rustls::ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    };

    TlsConnector::from(Arc::new(client_config))
}

/// Load or generate a CA based on the TLS configuration.
///
/// Resolution order:
/// 1. User-provided paths (`cert_path` + `key_path`)
/// 2. Default persistence path (`~/.microsandbox/tls/ca.{crt,key}`)
/// 3. Auto-generate and persist to default path
fn load_or_generate_ca(config: &TlsConfig) -> CertAuthority {
    // Warn if only one of cert_path/key_path is set (likely a config error).
    if config.ca.cert_path.is_some() != config.ca.key_path.is_some() {
        tracing::warn!(
            "incomplete CA config: both cert_path and key_path must be set together, ignoring"
        );
    }

    // 1. Try user-provided paths.
    if let (Some(cert_path), Some(key_path)) = (&config.ca.cert_path, &config.ca.key_path) {
        match (std::fs::read(cert_path), std::fs::read(key_path)) {
            (Ok(cert_pem), Ok(key_pem)) => match CertAuthority::load(&cert_pem, &key_pem) {
                Ok(ca) => {
                    tracing::info!("loaded user-provided CA from {:?}", cert_path);
                    return ca;
                }
                Err(e) => {
                    tracing::error!(
                        error = %e,
                        "failed to load user-provided CA, falling back to auto-generate"
                    );
                }
            },
            _ => {
                tracing::error!(
                    "failed to read CA files from {:?} / {:?}, falling back to auto-generate",
                    cert_path,
                    key_path,
                );
            }
        }
    }

    // 2. Try default persistence path.
    if let Some(default_dir) = default_ca_dir() {
        let cert_path = default_dir.join("ca.crt");
        let key_path = default_dir.join("ca.key");

        if cert_path.exists()
            && key_path.exists()
            && let (Ok(cert_pem), Ok(key_pem)) =
                (std::fs::read(&cert_path), std::fs::read(&key_path))
            && let Ok(ca) = CertAuthority::load(&cert_pem, &key_pem)
        {
            tracing::debug!("loaded persisted CA from {:?}", cert_path);
            return ca;
        }

        // 3. Auto-generate and persist.
        let ca = CertAuthority::generate();
        if let Err(e) = std::fs::create_dir_all(&default_dir) {
            tracing::warn!(error = %e, "failed to create CA directory, CA will not persist");
        } else {
            if let Err(e) = std::fs::write(&cert_path, ca.cert_pem()) {
                tracing::warn!(error = %e, "failed to persist CA certificate");
            }
            if let Err(e) = write_key_file(&key_path, &ca.key_pem()) {
                tracing::warn!(error = %e, "failed to persist CA key");
            } else {
                tracing::info!("generated and persisted CA to {:?}", default_dir);
            }
        }
        return ca;
    }

    // Fallback: generate without persistence.
    tracing::warn!("could not determine CA persistence path, generating ephemeral CA");
    CertAuthority::generate()
}

/// Default CA persistence directory: `~/.microsandbox/tls/`.
fn default_ca_dir() -> Option<std::path::PathBuf> {
    dirs::home_dir().map(|h| h.join(".microsandbox").join("tls"))
}

/// Write a private key file with restricted permissions (0o600) from creation.
///
/// Uses `OpenOptions` with mode set at creation time to avoid the TOCTOU race
/// of write-then-chmod where the file is briefly world-readable.
fn write_key_file(path: &std::path::Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)?;
    }
    Ok(())
}
