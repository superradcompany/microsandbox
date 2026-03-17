//! Per-domain certificate generation signed by the microsandbox CA.
//!
//! Each intercepted domain gets a short-lived (24h) P-256 EC certificate with
//! the SNI domain as both CN and SAN. The cert is signed by the CA keypair.

use std::io;
use std::sync::Arc;

use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

use super::CaKeyPair;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A generated certificate and private key for a specific domain.
pub struct GeneratedCert {
    /// DER-encoded leaf certificate.
    pub cert_der: Vec<u8>,

    /// DER-encoded private key (PKCS#8).
    pub key_der: Vec<u8>,

    /// DER-encoded CA certificate (for the chain).
    pub ca_cert_der: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Generates a short-lived certificate for the given domain, signed by the CA.
pub fn generate_cert(domain: &str, ca: &CaKeyPair) -> io::Result<GeneratedCert> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| io::Error::other(format!("failed to generate domain keypair: {e}")))?;

    let mut params = CertificateParams::new(vec![domain.to_string()])
        .map_err(|e| io::Error::other(format!("failed to create cert params: {e}")))?;

    params
        .distinguished_name
        .push(DnType::CommonName, domain);

    // Short-lived: valid for 24 hours from now.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::hours(24);

    // Sign with the CA.
    let cert = params
        .signed_by(&key_pair, &ca.cert, &ca.key_pair)
        .map_err(|e| io::Error::other(format!("failed to sign domain cert: {e}")))?;

    Ok(GeneratedCert {
        cert_der: cert.der().to_vec(),
        key_der: key_pair.serialize_der(),
        ca_cert_der: ca.cert_der.clone(),
    })
}

/// Converts a `GeneratedCert` into a rustls `CertifiedKey` for use in TLS
/// handshakes.
pub fn to_certified_key(cert: &GeneratedCert) -> io::Result<Arc<CertifiedKey>> {
    let cert_chain = vec![
        CertificateDer::from(cert.cert_der.clone()),
        CertificateDer::from(cert.ca_cert_der.clone()),
    ];

    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(cert.key_der.clone()));
    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key)
        .map_err(|e| io::Error::other(format!("failed to create signing key: {e}")))?;

    Ok(Arc::new(CertifiedKey::new(cert_chain, signing_key)))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::ca;

    #[test]
    fn test_generate_and_convert() {
        let ca_config = crate::tls::CaConfig::default();
        let ca_kp = ca::generate_ca(&ca_config).unwrap();

        let cert = generate_cert("example.com", &ca_kp).unwrap();
        assert!(!cert.cert_der.is_empty());
        assert!(!cert.key_der.is_empty());

        let certified = to_certified_key(&cert).unwrap();
        assert_eq!(certified.cert.len(), 2); // leaf + CA
    }
}
