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
    /// Pre-built `ServerConfig` for this domain (avoids per-connection rebuild).
    pub server_config: std::sync::Arc<rustls::ServerConfig>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Generate a certificate for `domain` signed by the given CA.
pub fn generate_domain_cert(domain: &str, ca: &CertAuthority, validity_hours: u64) -> DomainCert {
    let now = OffsetDateTime::now_utc();
    let params = build_domain_cert_params(domain, validity_hours, now);

    let key_pair = rcgen::KeyPair::generate().expect("failed to generate domain key pair");

    let cert_der = params
        .signed_by(&key_pair, &ca.cert, &ca.key_pair)
        .expect("failed to sign domain certificate");

    let chain = vec![
        CertificateDer::from(cert_der.der().to_vec()),
        ca.cert_der.clone(),
    ];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));

    // Pre-build ServerConfig so it can be reused across connections to the same domain.
    let server_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(chain.clone(), key.clone_key())
        .expect("failed to build ServerConfig for domain cert");

    DomainCert {
        chain,
        key,
        server_config: std::sync::Arc::new(server_config),
    }
}

fn build_domain_cert_params(
    domain: &str,
    validity_hours: u64,
    now: OffsetDateTime,
) -> CertificateParams {
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .expect("invalid domain for certificate SAN");

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

    params
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
        let params = build_domain_cert_params("example.com", 24, now);

        assert_eq!(params.not_before, now - Duration::seconds(2));
        assert_eq!(params.not_after, now + Duration::hours(24));
    }
}
