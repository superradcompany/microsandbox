//! Shared TLS state: CA, certificate cache, and upstream connectors.

use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use lru::LruCache;
use microsandbox_utils::TLS_SUBDIR;
use rustls::DigitallySignedStruct;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime, pem::PemObject};
use time::{Duration, OffsetDateTime};
use tokio_rustls::TlsConnector;

use super::ca::CertAuthority;
use super::certgen::{self, DomainCert, DomainCertError};
use crate::secrets::handle::SecretsHandle;
use microsandbox_types::TlsConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Shared TLS interception state.
///
/// Holds the CA, per-domain certificate cache, upstream TLS connectors,
/// and configuration. Shared across all TLS proxy tasks via `Arc`.
pub struct TlsState {
    /// Interception CA for signing per-domain certs presented to the guest.
    pub intercept_ca: CertAuthority,
    /// LRU cache of generated domain certificates.
    cert_cache: Mutex<LruCache<String, Arc<DomainCert>>>,
    /// Default TLS connector for upstream (real server) connections.
    pub connector: TlsConnector,
    /// Host-scoped TLS connectors for upstream connections.
    scoped_upstream_connectors: Vec<ScopedUpstreamConnector>,
    /// TLS configuration.
    pub config: TlsConfig,
    /// Live-swappable secrets configuration for placeholder substitution.
    /// Loaded per connection so live secret updates apply to future traffic.
    pub secrets: SecretsHandle,
    /// Pre-computed lowercased bypass patterns for efficient matching.
    bypass_patterns: Vec<DomainPattern>,
}

/// Errors that prevent TLS interception state from being initialized safely.
#[derive(Debug, thiserror::Error)]
pub enum TlsStateError {
    /// The host TLS verifier could not be initialized.
    #[error("failed to initialize upstream TLS verification: {0}")]
    UpstreamVerifier(#[from] rustls::Error),

    /// Exactly one of the intercept CA certificate/key paths was configured.
    #[error("intercept CA config is incomplete; set both cert_path and key_path")]
    IncompleteInterceptCaConfig,

    /// The configured intercept CA certificate could not be read.
    #[error("failed to read intercept CA certificate `{path}`: {source}")]
    ReadInterceptCaCert {
        /// Certificate path that failed to read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The configured intercept CA private key could not be read.
    #[error("failed to read intercept CA key `{path}`: {source}")]
    ReadInterceptCaKey {
        /// Private-key path that failed to read.
        path: PathBuf,
        /// Underlying I/O error.
        #[source]
        source: std::io::Error,
    },

    /// The configured intercept CA files were readable but did not form a usable CA.
    #[error("failed to load intercept CA `{cert_path}` / `{key_path}`: {reason}")]
    InvalidInterceptCa {
        /// Certificate path that was loaded.
        cert_path: PathBuf,
        /// Private-key path that was loaded.
        key_path: PathBuf,
        /// Validation or parsing failure from the CA loader.
        reason: String,
    },
}

/// A pre-processed domain pattern (avoids per-connection allocations).
enum DomainPattern {
    /// Exact domain match (lowercased).
    Exact(String),
    /// Wildcard suffix match. `suffix` is the bare suffix, `dotted` is `.suffix`
    /// (pre-computed to avoid per-connection `format!` allocations).
    Wildcard { suffix: String, dotted: String },
}

/// An upstream connector selected only for matching server names.
struct ScopedUpstreamConnector {
    pattern: DomainPattern,
    connector: TlsConnector,
}

/// Effective upstream TLS settings for one host pattern.
struct ScopedUpstreamSettings {
    pattern: String,
    ca_cert: Vec<PathBuf>,
    verify_upstream: Option<bool>,
}

impl ScopedUpstreamSettings {
    fn new(pattern: &str) -> Self {
        Self {
            pattern: pattern.to_string(),
            ca_cert: Vec::new(),
            verify_upstream: None,
        }
    }
}

/// A [`ServerCertVerifier`] that accepts all server certificates without
/// validation. Used when `verify_upstream` is `false`.
#[derive(Debug)]
struct NoVerify;

/// Refresh cached leaf certs shortly before expiry so long-lived sandboxes
/// do not start serving an already-expired intercept certificate.
const CERT_REFRESH_WINDOW: Duration = Duration::minutes(5);

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TlsState {
    /// Create TLS state from configuration.
    ///
    /// CA resolution order:
    /// 1. User-provided paths (`config.intercept_ca.cert_path` + `config.intercept_ca.key_path`)
    /// 2. Microsandbox home TLS path (`$MSB_HOME/tls` or `~/.microsandbox/tls`)
    /// 3. Auto-generate and persist to the microsandbox home TLS path
    pub fn new(config: TlsConfig, secrets: SecretsHandle) -> Result<Self, TlsStateError> {
        let ca = load_or_generate_ca(&config)?;

        let capacity =
            NonZeroUsize::new(config.cache.capacity).unwrap_or(NonZeroUsize::new(1000).unwrap());
        let cert_cache = Mutex::new(LruCache::new(capacity));

        let connector = build_upstream_connector(&config, config.verify_upstream, &[])?;
        let scoped_upstream_connectors = build_scoped_upstream_connectors(&config)?;

        // Pre-compute lowercased bypass patterns to avoid per-connection allocations.
        let bypass_patterns = config
            .bypass
            .iter()
            .map(|pattern| DomainPattern::new(pattern))
            .collect();

        Ok(Self {
            intercept_ca: ca,
            cert_cache,
            connector,
            scoped_upstream_connectors,
            config,
            secrets,
            bypass_patterns,
        })
    }

    /// Get or generate a certificate for the given domain.
    pub fn get_or_generate_cert(&self, domain: &str) -> Result<Arc<DomainCert>, DomainCertError> {
        let mut cache = match self.cert_cache.lock() {
            Ok(cache) => cache,
            Err(poisoned) => {
                tracing::warn!("TLS certificate cache was poisoned; recovering");
                poisoned.into_inner()
            }
        };
        if let Some(cert) = cache.get(domain)
            && cert.expires_at > OffsetDateTime::now_utc() + CERT_REFRESH_WINDOW
        {
            return Ok(cert.clone());
        }

        let cert = Arc::new(certgen::generate_domain_cert(
            domain,
            &self.intercept_ca,
            self.config.cache.validity_hours,
        )?);
        cache.put(domain.to_string(), cert.clone());
        Ok(cert)
    }

    /// Check if a domain should bypass TLS interception.
    pub fn should_bypass(&self, sni: &str) -> bool {
        let sni_lower = normalize_domain(sni);
        self.bypass_patterns
            .iter()
            .any(|pattern| pattern.matches_normalized(&sni_lower))
    }

    /// Select the upstream connector for the given server name.
    ///
    /// Falls back to the default connector when no host-scoped connector
    /// matches; when several match, the most specific pattern wins.
    pub fn upstream_connector_for(&self, sni: &str) -> &TlsConnector {
        self.scoped_upstream_connector_for(sni)
            .map_or(&self.connector, |scoped| &scoped.connector)
    }

    /// Find the most specific host-scoped upstream connector for `sni`, if any.
    fn scoped_upstream_connector_for(&self, sni: &str) -> Option<&ScopedUpstreamConnector> {
        let sni_lower = normalize_domain(sni);
        self.scoped_upstream_connectors
            .iter()
            .filter(|scoped| scoped.pattern.matches_normalized(&sni_lower))
            .max_by_key(|scoped| scoped.pattern.specificity())
    }

    /// Get the CA certificate PEM bytes for guest installation.
    pub fn ca_cert_pem(&self) -> Vec<u8> {
        self.intercept_ca.cert_pem()
    }
}

impl DomainPattern {
    fn new(pattern: &str) -> Self {
        let lower = normalize_domain(pattern);
        if let Some(suffix) = lower.strip_prefix("*.") {
            let dotted = format!(".{suffix}");
            DomainPattern::Wildcard {
                suffix: suffix.to_string(),
                dotted,
            }
        } else {
            DomainPattern::Exact(lower)
        }
    }

    fn matches_normalized(&self, sni_lower: &str) -> bool {
        match self {
            DomainPattern::Exact(exact) => sni_lower == exact,
            DomainPattern::Wildcard { suffix, dotted } => {
                sni_lower == suffix || sni_lower.ends_with(dotted.as_str())
            }
        }
    }

    fn specificity(&self) -> usize {
        match self {
            DomainPattern::Exact(exact) => exact.len() + 1,
            DomainPattern::Wildcard { suffix, .. } => suffix.len(),
        }
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
/// Verified Windows and macOS connections use native platform certificate
/// validation; other platforms load native roots. When false, uses a
/// permissive verifier that accepts all server certificates.
fn build_upstream_connector(
    config: &TlsConfig,
    verify_upstream: bool,
    scoped_ca_cert: &[PathBuf],
) -> Result<TlsConnector, TlsStateError> {
    let client_config = if verify_upstream {
        #[cfg(any(windows, target_os = "macos"))]
        let verified = {
            let mut extra_roots = Vec::new();
            let mut parsed_roots = rustls::RootCertStore::empty();
            let mut add_root = |cert: CertificateDer<'static>| {
                // Preserve the existing handling of malformed DER in user CA bundles.
                if parsed_roots.add(cert.clone()).is_err() {
                    return false;
                }
                extra_roots.push(cert);
                true
            };
            load_upstream_ca_certificates(&config.upstream_ca_cert, &mut add_root);
            load_upstream_ca_certificates(scoped_ca_cert, &mut add_root);
            let builder = rustls::ClientConfig::builder();
            let provider = Arc::clone(builder.crypto_provider());
            // Native verification follows host trust policy (including Keychain
            // intermediates, AIA fetching, and explicit distrust overrides on
            // macOS, and automatic trusted-root retrieval on Windows). Extra CAs
            // belong only to this connector, never to the host trust store.
            let verifier = if extra_roots.is_empty() {
                rustls_platform_verifier::Verifier::new(provider)?
            } else {
                rustls_platform_verifier::Verifier::new_with_extra_roots(extra_roots, provider)?
            };
            builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(verifier))
                .with_no_client_auth()
        };
        #[cfg(not(any(windows, target_os = "macos")))]
        let verified = {
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

            load_upstream_ca_certificates(&config.upstream_ca_cert, |cert| {
                root_store.add(cert).is_ok()
            });
            load_upstream_ca_certificates(scoped_ca_cert, |cert| root_store.add(cert).is_ok());

            rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth()
        };
        verified
    } else {
        rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth()
    };

    Ok(TlsConnector::from(Arc::new(client_config)))
}

/// Build host-scoped upstream TLS connectors from grouped scoped settings.
fn build_scoped_upstream_connectors(
    config: &TlsConfig,
) -> Result<Vec<ScopedUpstreamConnector>, TlsStateError> {
    let mut connectors = Vec::new();
    for settings in grouped_scoped_upstream_settings(config) {
        let verify_upstream = settings.verify_upstream.unwrap_or(config.verify_upstream);
        if verify_upstream == config.verify_upstream && settings.ca_cert.is_empty() {
            continue;
        }
        connectors.push(ScopedUpstreamConnector {
            pattern: DomainPattern::new(&settings.pattern),
            connector: build_upstream_connector(config, verify_upstream, &settings.ca_cert)?,
        });
    }
    Ok(connectors)
}

/// Group repeated scoped upstream settings by host pattern.
///
/// Grouping order is irrelevant: [`TlsState::upstream_connector_for`] selects
/// by pattern specificity, not declaration order.
fn grouped_scoped_upstream_settings(config: &TlsConfig) -> Vec<ScopedUpstreamSettings> {
    let mut grouped = HashMap::<String, ScopedUpstreamSettings>::new();

    for scoped in &config.scoped_upstream_ca_cert {
        grouped
            .entry(normalize_domain(&scoped.pattern))
            .or_insert_with(|| ScopedUpstreamSettings::new(&scoped.pattern))
            .ca_cert
            .push(scoped.path.clone());
    }

    for scoped in &config.scoped_verify_upstream {
        grouped
            .entry(normalize_domain(&scoped.pattern))
            .or_insert_with(|| ScopedUpstreamSettings::new(&scoped.pattern))
            .verify_upstream = Some(scoped.verify);
    }

    grouped.into_values().collect()
}

/// Load extra upstream CA certificates, preserving caller-specific trust-store handling.
fn load_upstream_ca_certificates(
    paths: &[PathBuf],
    mut add: impl FnMut(CertificateDer<'static>) -> bool,
) {
    for path in paths {
        match std::fs::read(path) {
            Ok(pem_data) => {
                let mut extra_added = 0usize;
                for cert in CertificateDer::pem_slice_iter(&pem_data).flatten() {
                    if add(cert) {
                        extra_added += 1;
                    }
                }
                tracing::info!(
                    path = %path.display(),
                    count = extra_added,
                    "loaded upstream CA certificates"
                );
            }
            Err(e) => {
                tracing::error!(
                    path = %path.display(),
                    error = %e,
                    "failed to read upstream CA certificate file"
                );
            }
        }
    }
}

/// Normalize host patterns and SNI names for matching.
fn normalize_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_ascii_lowercase()
}

/// Load or generate a CA based on the TLS configuration.
///
/// Resolution order:
/// 1. User-provided paths (`cert_path` + `key_path`)
/// 2. Microsandbox home TLS path (`$MSB_HOME/tls` or `~/.microsandbox/tls`)
/// 3. Auto-generate and persist to the microsandbox home TLS path
fn load_or_generate_ca(config: &TlsConfig) -> Result<CertAuthority, TlsStateError> {
    match (
        &config.intercept_ca.cert_path,
        &config.intercept_ca.key_path,
    ) {
        (Some(cert_path), Some(key_path)) => {
            let cert_pem =
                std::fs::read(cert_path).map_err(|source| TlsStateError::ReadInterceptCaCert {
                    path: cert_path.clone(),
                    source,
                })?;
            let key_pem =
                std::fs::read(key_path).map_err(|source| TlsStateError::ReadInterceptCaKey {
                    path: key_path.clone(),
                    source,
                })?;
            let ca = CertAuthority::load(&cert_pem, &key_pem)
                .and_then(|ca| {
                    ca.verify_signing_key()?;
                    Ok(ca)
                })
                .map_err(|err| TlsStateError::InvalidInterceptCa {
                    cert_path: cert_path.clone(),
                    key_path: key_path.clone(),
                    reason: err.to_string(),
                })?;
            tracing::info!("loaded user-provided CA from {:?}", cert_path);
            return Ok(ca);
        }
        (Some(_), None) | (None, Some(_)) => {
            return Err(TlsStateError::IncompleteInterceptCaConfig);
        }
        (None, None) => {}
    }

    // 2. Try the same microsandbox home root used by cache/db/logs/metrics.
    let default_dir = default_ca_dir();
    let cert_path = default_dir.join("ca.crt");
    let key_path = default_dir.join("ca.key");

    if cert_path.exists()
        && key_path.exists()
        && let (Ok(cert_pem), Ok(key_pem)) = (std::fs::read(&cert_path), std::fs::read(&key_path))
        && let Ok(ca) = CertAuthority::load(&cert_pem, &key_pem)
    {
        tracing::debug!("loaded persisted CA from {:?}", cert_path);
        return Ok(ca);
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
    Ok(ca)
}

/// Default CA persistence directory under the resolved microsandbox home.
fn default_ca_dir() -> PathBuf {
    default_ca_dir_from_home(microsandbox_utils::resolve_home())
}

/// Build the CA directory from a known microsandbox home.
fn default_ca_dir_from_home(home: impl AsRef<Path>) -> PathBuf {
    home.as_ref().join(TLS_SUBDIR)
}

/// Write a private key file with restricted permissions (0o600) from creation.
///
/// Uses `OpenOptions` with mode set at creation time to avoid the TOCTOU race
/// of write-then-chmod where the file is briefly world-readable.
fn write_key_file(path: &Path, data: &[u8]) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use microsandbox_types::{ScopedUpstreamCaCert, ScopedVerifyUpstream};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

    use super::*;
    use crate::secrets::config::SecretsConfig;
    use crate::secrets::handle::SecretsHandle;

    /// Drive a real certificate handshake entirely in memory. No fixture root is installed
    /// in the host store, so each connector must enforce its own configured trust scope.
    fn verify_fixture(
        connector: &TlsConnector,
        cert: &DomainCert,
        name: &str,
    ) -> Result<(), rustls::Error> {
        let mut client = rustls::ClientConnection::new(
            Arc::clone(connector.config()),
            ServerName::try_from(name.to_owned()).unwrap(),
        )?;
        let mut server = rustls::ServerConnection::new(Arc::clone(&cert.server_config))?;
        for _ in 0..8 {
            let mut wire = Vec::new();
            client.write_tls(&mut wire).unwrap();
            server.read_tls(&mut std::io::Cursor::new(wire)).unwrap();
            server.process_new_packets()?;
            let mut wire = Vec::new();
            server.write_tls(&mut wire).unwrap();
            client.read_tls(&mut std::io::Cursor::new(wire)).unwrap();
            client.process_new_packets()?;
            if !client.is_handshaking() {
                return Ok(());
            }
        }
        panic!("fixture TLS handshake did not complete");
    }

    #[test]
    fn upstream_verification_preserves_extra_roots_names_and_scope() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let ca = CertAuthority::generate();
        let cert = certgen::generate_domain_cert("api.internal", &ca, 24).unwrap();
        let other = certgen::generate_domain_cert("other.internal", &ca, 24).unwrap();
        let path =
            std::env::temp_dir().join(format!("msb-upstream-scope-{}.pem", std::process::id()));
        std::fs::write(&path, ca.cert_pem()).unwrap();

        let mut config = TlsConfig::default();
        let strict = build_upstream_connector(&config, true, &[]).unwrap();
        assert!(verify_fixture(&strict, &cert, "api.internal").is_err());

        config.upstream_ca_cert.push(path.clone());
        let trusted = build_upstream_connector(&config, true, &[]).unwrap();
        assert!(verify_fixture(&trusted, &cert, "api.internal").is_ok());
        assert!(verify_fixture(&trusted, &cert, "wrong.internal").is_err());

        config.upstream_ca_cert.clear();
        config.scoped_upstream_ca_cert.push(ScopedUpstreamCaCert {
            pattern: "api.internal".to_owned(),
            path: path.clone(),
        });
        let state =
            TlsState::new(config.clone(), SecretsHandle::new(SecretsConfig::default())).unwrap();
        assert!(
            verify_fixture(
                state.upstream_connector_for("api.internal"),
                &cert,
                "api.internal"
            )
            .is_ok()
        );
        assert!(
            verify_fixture(
                state.upstream_connector_for("other.internal"),
                &other,
                "other.internal"
            )
            .is_err()
        );

        config.scoped_upstream_ca_cert.clear();
        config.scoped_verify_upstream.push(ScopedVerifyUpstream {
            pattern: "api.internal".to_owned(),
            verify: false,
        });
        let state = TlsState::new(config, SecretsHandle::new(SecretsConfig::default())).unwrap();
        assert!(
            verify_fixture(
                state.upstream_connector_for("api.internal"),
                &cert,
                "api.internal"
            )
            .is_ok()
        );
        assert!(
            verify_fixture(
                state.upstream_connector_for("other.internal"),
                &other,
                "other.internal"
            )
            .is_err()
        );
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn regenerates_cached_domain_cert_when_near_expiry() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let state = TlsState::new(
            TlsConfig::default(),
            SecretsHandle::new(SecretsConfig::default()),
        )
        .unwrap();
        let first = state.get_or_generate_cert("openrouter.ai").unwrap();
        let original_expires_at = first.expires_at;

        {
            let mut cache = state.cert_cache.lock().unwrap();
            let stale = Arc::new(DomainCert {
                chain: first.chain.clone(),
                key: first.key.clone_key(),
                expires_at: OffsetDateTime::now_utc() + Duration::seconds(30),
                server_config: first.server_config.clone(),
            });
            cache.put("openrouter.ai".to_string(), stale);
        }

        let refreshed = state.get_or_generate_cert("openrouter.ai").unwrap();
        assert!(refreshed.expires_at > OffsetDateTime::now_utc() + Duration::hours(23));
        assert!(refreshed.expires_at > original_expires_at - Duration::minutes(10));
    }

    #[test]
    fn invalid_domain_cert_request_does_not_poison_cache() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let state = TlsState::new(
            TlsConfig::default(),
            SecretsHandle::new(SecretsConfig::default()),
        )
        .unwrap();

        assert!(state.get_or_generate_cert("snowman.☃").is_err());
        assert!(state.get_or_generate_cert("openrouter.ai").is_ok());
    }

    #[test]
    fn default_ca_dir_uses_microsandbox_home_tls_subdir() {
        let home = PathBuf::from("isolated-msb-home");

        assert_eq!(
            default_ca_dir_from_home(&home),
            home.join(microsandbox_utils::TLS_SUBDIR)
        );
    }

    #[test]
    fn tls_state_rejects_incomplete_intercept_ca_config() {
        let mut config = TlsConfig::default();
        config.intercept_ca.cert_path = Some(PathBuf::from("/tmp/ca.crt"));

        let err = match TlsState::new(config, SecretsHandle::new(SecretsConfig::default())) {
            Ok(_) => panic!("incomplete CA config should fail"),
            Err(err) => err,
        };

        assert!(matches!(err, TlsStateError::IncompleteInterceptCaConfig));
    }

    #[test]
    fn tls_state_rejects_invalid_intercept_ca_pair() {
        let dir = std::env::temp_dir().join(format!(
            "microsandbox-invalid-intercept-ca-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let cert_path = dir.join("ca.crt");
        let key_path = dir.join("ca.key");
        std::fs::write(&cert_path, b"not a cert").unwrap();
        std::fs::write(&key_path, b"not a key").unwrap();

        let mut config = TlsConfig::default();
        config.intercept_ca.cert_path = Some(cert_path);
        config.intercept_ca.key_path = Some(key_path);

        let err = match TlsState::new(config, SecretsHandle::new(SecretsConfig::default())) {
            Ok(_) => panic!("invalid CA config should fail"),
            Err(err) => err,
        };
        let _ = std::fs::remove_dir_all(&dir);

        assert!(matches!(err, TlsStateError::InvalidInterceptCa { .. }));
    }

    #[test]
    fn domain_patterns_match_exact_and_wildcard_hosts() {
        let exact = DomainPattern::new("api.internal.");
        assert!(exact.matches_normalized("api.internal"));
        assert!(!exact.matches_normalized("other.api.internal"));

        let wildcard = DomainPattern::new("*.internal");
        assert!(wildcard.matches_normalized("internal"));
        assert!(wildcard.matches_normalized("api.internal"));
        assert!(!wildcard.matches_normalized("notinternal"));
    }

    #[test]
    fn domain_patterns_score_exact_as_more_specific() {
        let exact = DomainPattern::new("api.internal");
        let wildcard = DomainPattern::new("*.internal");

        assert!(exact.specificity() > wildcard.specificity());
    }

    #[test]
    fn scoped_upstream_settings_group_ca_and_verify_by_pattern() {
        let mut config = TlsConfig::default();
        config.scoped_upstream_ca_cert.push(ScopedUpstreamCaCert {
            pattern: "*.internal".to_string(),
            path: PathBuf::from("/tmp/one.pem"),
        });
        config.scoped_upstream_ca_cert.push(ScopedUpstreamCaCert {
            pattern: "*.internal.".to_string(),
            path: PathBuf::from("/tmp/two.pem"),
        });
        config.scoped_verify_upstream.push(ScopedVerifyUpstream {
            pattern: "*.internal".to_string(),
            verify: false,
        });

        let settings = grouped_scoped_upstream_settings(&config);

        assert_eq!(settings.len(), 1);
        assert_eq!(settings[0].pattern, "*.internal");
        assert_eq!(
            settings[0].ca_cert,
            vec![PathBuf::from("/tmp/one.pem"), PathBuf::from("/tmp/two.pem")]
        );
        assert_eq!(settings[0].verify_upstream, Some(false));
    }

    #[test]
    fn upstream_connector_for_selects_scoped_connector_for_matching_host() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut config = TlsConfig::default();
        config.scoped_verify_upstream.push(ScopedVerifyUpstream {
            pattern: "*.internal".to_string(),
            verify: false,
        });
        let state = TlsState::new(config, SecretsHandle::new(SecretsConfig::default())).unwrap();

        assert!(
            state
                .scoped_upstream_connector_for("api.internal")
                .is_some()
        );
        assert!(
            state
                .scoped_upstream_connector_for("api.example.com")
                .is_none()
        );
    }

    #[test]
    fn load_upstream_ca_certificates_keeps_certs_and_skips_other_sections() {
        let ca = crate::engine::tls::ca::CertAuthority::generate();
        let path =
            std::env::temp_dir().join(format!("msb-upstream-ca-test-{}.pem", std::process::id()));
        // Bundle a private key and stray text around the certificate: only the
        // certificate section must end up in the root store.
        let mut bundle = ca.key_pem();
        bundle.extend_from_slice(b"stray text between sections\n");
        bundle.extend_from_slice(&ca.cert_pem());
        std::fs::write(&path, &bundle).expect("write CA bundle");

        let mut root_store = rustls::RootCertStore::empty();
        load_upstream_ca_certificates(
            &[path.clone(), PathBuf::from("/nonexistent/upstream-ca.pem")],
            |cert| root_store.add(cert).is_ok(),
        );
        std::fs::remove_file(&path).ok();

        assert_eq!(root_store.len(), 1);
    }

    fn write_temp_pem(label: &str, pem: &[u8]) -> PathBuf {
        static NEXT_FILE: AtomicUsize = AtomicUsize::new(0);
        let id = NEXT_FILE.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("msb-{label}-{}-{id}.pem", std::process::id()));
        std::fs::write(&path, pem).expect("write temporary PEM");
        path
    }

    fn verify_chain_fixture(
        connector: &TlsConnector,
        chain: Vec<CertificateDer<'static>>,
        key: PrivateKeyDer<'static>,
        server_name: ServerName<'static>,
    ) -> Result<(), rustls::Error> {
        let server_config = Arc::new(
            rustls::ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(chain, key)
                .unwrap(),
        );
        let mut client =
            rustls::ClientConnection::new(Arc::clone(connector.config()), server_name)?;
        let mut server = rustls::ServerConnection::new(server_config)?;

        for _ in 0..8 {
            let mut wire = Vec::new();
            client.write_tls(&mut wire).unwrap();
            server.read_tls(&mut std::io::Cursor::new(wire)).unwrap();
            server.process_new_packets()?;

            let mut wire = Vec::new();
            server.write_tls(&mut wire).unwrap();
            client.read_tls(&mut std::io::Cursor::new(wire)).unwrap();
            client.process_new_packets()?;

            if !client.is_handshaking() {
                return Ok(());
            }
        }

        panic!("fixture TLS handshake did not complete");
    }

    fn generate_three_tier_chain(
        san: &str,
    ) -> (
        CertAuthority,
        CertificateDer<'static>,
        String,
        CertificateDer<'static>,
        PrivateKeyDer<'static>,
    ) {
        let root = CertAuthority::generate();
        let now = OffsetDateTime::now_utc();

        let mut intermediate_params = rcgen::CertificateParams::default();
        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "microsandbox test intermediate");
        intermediate_params.distinguished_name = dn;
        intermediate_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
        intermediate_params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];
        intermediate_params.not_before = now - Duration::seconds(2);
        intermediate_params.not_after = now + Duration::hours(48);
        let intermediate_key = rcgen::KeyPair::generate().unwrap();
        let intermediate_cert = intermediate_params
            .signed_by(&intermediate_key, &root.issuer)
            .unwrap();
        let intermediate_issuer = rcgen::Issuer::new(intermediate_params, intermediate_key);

        let mut leaf_params = rcgen::CertificateParams::new(vec![san.to_owned()]).unwrap();
        let mut leaf_dn = rcgen::DistinguishedName::new();
        leaf_dn.push(rcgen::DnType::CommonName, san);
        leaf_params.distinguished_name = leaf_dn;
        leaf_params.is_ca = rcgen::IsCa::ExplicitNoCa;
        leaf_params.use_authority_key_identifier_extension = true;
        leaf_params.key_usages = vec![
            rcgen::KeyUsagePurpose::DigitalSignature,
            rcgen::KeyUsagePurpose::KeyEncipherment,
        ];
        leaf_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
        leaf_params.not_before = now - Duration::seconds(2);
        leaf_params.not_after = now + Duration::hours(24);
        let leaf_key = rcgen::KeyPair::generate().unwrap();
        let leaf_cert = leaf_params
            .signed_by(&leaf_key, &intermediate_issuer)
            .unwrap();

        (
            root,
            CertificateDer::from(intermediate_cert.der().to_vec()),
            intermediate_cert.pem(),
            CertificateDer::from(leaf_cert.der().to_vec()),
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(leaf_key.serialize_der())),
        )
    }

    #[cfg(any(windows, target_os = "macos"))]
    #[test]
    fn upstream_verification_uses_platform_verifier_on_macos_and_windows() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let connector = build_upstream_connector(&TlsConfig::default(), true, &[]).unwrap();
        let debug = format!("{:?}", connector.config());

        assert!(
            !debug.contains("WebPkiServerVerifier"),
            "expected platform verifier on macOS/Windows, got: {debug}"
        );
    }

    #[test]
    fn upstream_verification_validates_intermediate_chain_ip_sans_and_scope() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let (root, intermediate_der, intermediate_pem, api_leaf_der, api_leaf_key) =
            generate_three_tier_chain("api.internal");
        let other_leaf = certgen::generate_domain_cert("other.internal", &root, 24).unwrap();
        let unrelated_root = CertAuthority::generate();

        let root_path = write_temp_pem("upstream-chain-root", &root.cert_pem());
        let unrelated_path = write_temp_pem("upstream-chain-unrelated", &unrelated_root.cert_pem());

        let mut bundle_with_intermediate = intermediate_pem.into_bytes();
        bundle_with_intermediate.extend_from_slice(&root.cert_pem());
        let bundle_path = write_temp_pem("upstream-chain-bundle", &bundle_with_intermediate);

        // Also test malformed DER mixed with a valid CA cert in one file.
        let mut mixed_pem =
            b"-----BEGIN CERTIFICATE-----\nAAECAw==\n-----END CERTIFICATE-----\n".to_vec();
        mixed_pem.extend_from_slice(&root.cert_pem());
        let mixed_path = write_temp_pem("upstream-chain-mixed", &mixed_pem);

        let full_chain = vec![api_leaf_der.clone(), intermediate_der];
        let api_name = ServerName::try_from("api.internal".to_owned()).unwrap();
        let wrong_name = ServerName::try_from("wrong.internal".to_owned()).unwrap();

        // Default verifier rejects unknown test root.
        let default_connector = build_upstream_connector(&TlsConfig::default(), true, &[]).unwrap();
        assert!(
            verify_chain_fixture(
                &default_connector,
                full_chain.clone(),
                api_leaf_key.clone_key(),
                api_name.clone(),
            )
            .is_err()
        );

        // Unrelated extra CA must not trust the chain.
        let mut unrelated_config = TlsConfig::default();
        unrelated_config
            .upstream_ca_cert
            .push(unrelated_path.clone());
        let unrelated_connector = build_upstream_connector(&unrelated_config, true, &[]).unwrap();
        assert!(
            verify_chain_fixture(
                &unrelated_connector,
                full_chain.clone(),
                api_leaf_key.clone_key(),
                api_name.clone(),
            )
            .is_err()
        );

        // Trusted extra root verifies leaf -> intermediate -> root and still checks SAN.
        let mut trusted_config = TlsConfig::default();
        trusted_config.upstream_ca_cert.push(root_path.clone());
        let trusted_connector = build_upstream_connector(&trusted_config, true, &[]).unwrap();
        verify_chain_fixture(
            &trusted_connector,
            full_chain.clone(),
            api_leaf_key.clone_key(),
            api_name.clone(),
        )
        .expect("3-tier chain with trusted extra root must verify");
        assert!(
            verify_chain_fixture(
                &trusted_connector,
                full_chain.clone(),
                api_leaf_key.clone_key(),
                wrong_name,
            )
            .is_err()
        );

        // Leaf-only server succeeds when user supplies [intermediate, root] in
        // the extra CA bundle on macOS (`SecTrustSetAnchorCertificates`) and
        // Linux (`RootCertStore`). Windows CryptoAPI `hExclusiveRoot` only
        // matches self-signed root anchors.
        #[cfg(not(windows))]
        {
            let mut bundle_config = TlsConfig::default();
            bundle_config.upstream_ca_cert.push(bundle_path.clone());
            let bundle_connector = build_upstream_connector(&bundle_config, true, &[]).unwrap();
            verify_chain_fixture(
                &bundle_connector,
                vec![api_leaf_der.clone()],
                api_leaf_key.clone_key(),
                api_name.clone(),
            )
            .expect("leaf-only server with intermediate+root extra bundle must verify");
        }
        #[cfg(windows)]
        let _ = (&bundle_path, &api_leaf_der);

        // Malformed DER entry in the bundle is skipped without failing connector setup.
        let mut mixed_config = TlsConfig::default();
        mixed_config.upstream_ca_cert.push(mixed_path.clone());
        let mixed_connector = build_upstream_connector(&mixed_config, true, &[]).unwrap();
        verify_chain_fixture(
            &mixed_connector,
            full_chain.clone(),
            api_leaf_key.clone_key(),
            api_name.clone(),
        )
        .expect("valid CA alongside malformed DER entry must still verify");

        // Host-scoped extra root must apply only to matching SNIs and never leak.
        let mut scoped_config = TlsConfig::default();
        scoped_config
            .scoped_upstream_ca_cert
            .push(ScopedUpstreamCaCert {
                pattern: "api.internal".to_owned(),
                path: root_path.clone(),
            });
        let scoped_state =
            TlsState::new(scoped_config, SecretsHandle::new(SecretsConfig::default())).unwrap();
        verify_chain_fixture(
            scoped_state.upstream_connector_for("api.internal"),
            full_chain,
            api_leaf_key,
            api_name,
        )
        .expect("scoped connector must validate matching host chain");
        assert!(
            verify_fixture(
                scoped_state.upstream_connector_for("other.internal"),
                &other_leaf,
                "other.internal",
            )
            .is_err(),
            "scoped extra root must not leak to unrelated SNI"
        );

        // IPv4 and IPv6 SAN certificates (matching sdk/rust/tests/tls_intercept.rs).
        let now = OffsetDateTime::now_utc();
        for (ip_str, wrong_ip_str) in [("172.30.255.1", "192.0.2.1"), ("fd00::1", "2001:db8::1")] {
            let ip_key = rcgen::KeyPair::generate().unwrap();
            let mut ip_params = rcgen::CertificateParams::new(vec![ip_str.to_owned()]).unwrap();
            ip_params.is_ca = rcgen::IsCa::ExplicitNoCa;
            ip_params.extended_key_usages = vec![rcgen::ExtendedKeyUsagePurpose::ServerAuth];
            ip_params.not_before = now - Duration::seconds(2);
            ip_params.not_after = now + Duration::hours(24);
            let ip_cert = ip_params.signed_by(&ip_key, &root.issuer).unwrap();
            let ip_chain = vec![
                CertificateDer::from(ip_cert.der().to_vec()),
                root.cert_der.clone(),
            ];
            let ip_priv = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(ip_key.serialize_der()));
            let good_ip = ServerName::try_from(ip_str.to_owned()).unwrap();
            let bad_ip = ServerName::try_from(wrong_ip_str.to_owned()).unwrap();

            verify_chain_fixture(
                &trusted_connector,
                ip_chain.clone(),
                ip_priv.clone_key(),
                good_ip.clone(),
            )
            .unwrap_or_else(|e| panic!("IP SAN {ip_str} must verify with extra root: {e}"));
            assert!(
                verify_chain_fixture(
                    &trusted_connector,
                    ip_chain.clone(),
                    ip_priv.clone_key(),
                    bad_ip,
                )
                .is_err(),
                "mismatched IP SAN {wrong_ip_str} must be rejected"
            );
            assert!(
                verify_chain_fixture(&default_connector, ip_chain, ip_priv, good_ip).is_err(),
                "IP SAN {ip_str} must be rejected without extra root"
            );
        }

        for path in [root_path, unrelated_path, bundle_path, mixed_path] {
            let _ = std::fs::remove_file(path);
        }
    }
}
