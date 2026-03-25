//! Per-domain certificate generation signed by the sandbox CA.

use rcgen::{CertificateParams, DistinguishedName};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

use super::ca::CertAuthority;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A generated certificate + key for a specific domain.
pub struct DomainCert {
    /// Certificate chain: [leaf, CA].
    pub chain: Vec<CertificateDer<'static>>,
    /// Leaf certificate private key.
    pub key: PrivateKeyDer<'static>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Generate a certificate for `domain` signed by the given CA.
pub fn generate_domain_cert(domain: &str, ca: &CertAuthority, _validity_hours: u64) -> DomainCert {
    let mut params = CertificateParams::new(vec![domain.to_string()])
        .expect("invalid domain for certificate SAN");

    let mut dn = DistinguishedName::new();
    dn.push(rcgen::DnType::CommonName, domain);
    params.distinguished_name = dn;

    let key_pair = rcgen::KeyPair::generate().expect("failed to generate domain key pair");

    let cert_der = params
        .signed_by(&key_pair, &ca.cert, &ca.key_pair)
        .expect("failed to sign domain certificate");

    DomainCert {
        chain: vec![
            CertificateDer::from(cert_der.der().to_vec()),
            ca.cert_der.clone(),
        ],
        key: PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
    }
}
