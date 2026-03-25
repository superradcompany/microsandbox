//! Certificate authority generation and loading.

use rcgen::{Certificate, CertificateParams, DistinguishedName, IsCa, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A certificate authority for signing per-domain certificates.
pub struct CertAuthority {
    /// Signed CA certificate (needed by rcgen for signing leaf certs).
    pub cert: Certificate,
    /// CA key pair.
    pub key_pair: KeyPair,
    /// DER-encoded CA certificate.
    pub cert_der: CertificateDer<'static>,
    /// PEM-encoded CA certificate (for guest installation).
    cert_pem: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CertAuthority {
    /// Generate a new self-signed CA.
    pub fn generate() -> Self {
        let mut params = CertificateParams::default();
        let mut dn = DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, "microsandbox CA");
        dn.push(rcgen::DnType::OrganizationName, "microsandbox");
        params.distinguished_name = dn;
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![
            rcgen::KeyUsagePurpose::KeyCertSign,
            rcgen::KeyUsagePurpose::CrlSign,
        ];

        let key_pair = KeyPair::generate().expect("failed to generate CA key pair");
        let cert = params
            .self_signed(&key_pair)
            .expect("failed to self-sign CA certificate");

        let cert_pem = cert.pem();
        let cert_der = CertificateDer::from(cert.der().to_vec());

        Self {
            cert,
            key_pair,
            cert_der,
            cert_pem,
        }
    }

    /// Get the CA certificate as PEM bytes (for guest installation).
    pub fn cert_pem(&self) -> Vec<u8> {
        self.cert_pem.as_bytes().to_vec()
    }

    /// Get the DER-encoded CA private key.
    pub fn key_der(&self) -> PrivateKeyDer<'static> {
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(self.key_pair.serialize_der()))
    }
}
