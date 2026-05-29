//! Per-domain certificate generation signed by the sandbox CA.

use rcgen::{CertificateParams, ExtendedKeyUsagePurpose, IsCa, KeyUsagePurpose};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use time::{Duration, OffsetDateTime};

use super::ca::CertAuthority;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A generated certificate + key for a specific domain, with a cached
/// `ServerConfig` to avoid rebuilding it per connection.
pub struct DomainCert {
    /// Certificate chain: [leaf, CA].
    pub chain: Vec<CertificateDer<'static>>,
    /// Leaf certificate private key.
    pub key: PrivateKeyDer<'static>,
    /// Expiry time for the generated leaf certificate.
    pub expires_at: OffsetDateTime,
    /// Pre-built `ServerConfig` for this domain (avoids per-connection rebuild).
    pub server_config: std::sync::Arc<rustls::ServerConfig>,
}

/// Error generated while building an intercepted leaf certificate.
#[derive(Debug, thiserror::Error)]
pub enum DomainCertError {
    /// The requested domain cannot be encoded into the certificate SAN.
    #[error("invalid domain for certificate SAN `{domain}`: {source}")]
    InvalidDomain {
        /// Domain requested by the TLS client.
        domain: String,
        /// Underlying rcgen validation error.
        source: rcgen::Error,
    },

    /// A key pair could not be generated for the leaf certificate.
    #[error("failed to generate domain key pair: {0}")]
    KeyPair(#[source] rcgen::Error),

    /// The interception CA failed to sign the leaf certificate.
    #[error("failed to sign domain certificate: {0}")]
    Sign(#[source] rcgen::Error),

    /// rustls rejected the generated certificate chain or private key.
    #[error("failed to build ServerConfig for domain cert: {0}")]
    ServerConfig(#[source] rustls::Error),
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Generate a certificate for `domain` signed by the given CA.
pub fn generate_domain_cert(
    domain: &str,
    ca: &CertAuthority,
    validity_hours: u64,
) -> Result<DomainCert, DomainCertError> {
    let now: OffsetDateTime = OffsetDateTime::now_utc();
    let params: CertificateParams = build_domain_cert_params(domain, validity_hours, now)?;
    let expires_at: OffsetDateTime = params.not_after;

    let key_pair: rcgen::KeyPair = rcgen::KeyPair::generate().map_err(DomainCertError::KeyPair)?;

    let cert_der = params
        .signed_by(&key_pair, &ca.cert, &ca.key_pair)
        .map_err(DomainCertError::Sign)?;

    let chain = vec![
        CertificateDer::from(cert_der.der().to_vec()),
        ca.cert_der.clone(),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    // Pre-build ServerConfig so it can be reused across connections to the same domain.
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain.clone(), key.clone_key())
        .map_err(DomainCertError::ServerConfig)?;

    Ok(DomainCert {
        chain,
        key,
        expires_at,
        server_config: std::sync::Arc::new(server_config),
    })
}

fn build_domain_cert_params(
    domain: &str,
    validity_hours: u64,
    now: OffsetDateTime,
) -> Result<CertificateParams, DomainCertError> {
    let mut params = CertificateParams::new(vec![domain.to_string()]).map_err(|source| {
        DomainCertError::InvalidDomain {
            domain: domain.to_string(),
            source,
        }
    })?;

    let mut dn = rcgen::DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, domain);
    params.distinguished_name = dn;
    params.is_ca = IsCa::ExplicitNoCa;
    params.use_authority_key_identifier_extension = true;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];

    // Backdate not_before by 2 seconds to tolerate the sub-second clock
    // offset between the host (which generates the cert) and the guest
    // (which validates it on the first TLS request to each domain).
    params.not_before = now - Duration::seconds(2);
    params.not_after = now + Duration::hours(validity_hours as i64);

    Ok(params)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_cert_params_are_backdated_to_absorb_clock_skew() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let params = build_domain_cert_params("example.com", 24, now).unwrap();

        assert_eq!(params.not_before, now - Duration::seconds(2));
        assert_eq!(params.not_after, now + Duration::hours(24));
    }

    #[test]
    fn domain_cert_params_reject_invalid_san() {
        let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).unwrap();
        let err = build_domain_cert_params("snowman.☃", 24, now).unwrap_err();

        assert!(matches!(err, DomainCertError::InvalidDomain { .. }));
    }
}
