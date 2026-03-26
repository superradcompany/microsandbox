//! Certificate authority generation and loading.

use rcgen::{Certificate, CertificateParams, DistinguishedName, IsCa, KeyPair};
use rustls::pki_types::CertificateDer;

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

    /// Load a CA from PEM-encoded certificate and private key bytes.
    ///
    /// The original PEM/DER bytes are preserved for `cert_pem()`/`cert_der`
    /// so the identity served to guests matches the persisted file exactly.
    /// The re-signed `Certificate` is only used as rcgen's signing handle.
    pub fn load(cert_pem_bytes: &[u8], key_pem_bytes: &[u8]) -> Result<Self, String> {
        let cert_pem_str =
            std::str::from_utf8(cert_pem_bytes).map_err(|e| format!("invalid cert PEM: {e}"))?;
        let key_pem_str =
            std::str::from_utf8(key_pem_bytes).map_err(|e| format!("invalid key PEM: {e}"))?;

        let key_pair =
            KeyPair::from_pem(key_pem_str).map_err(|e| format!("failed to parse CA key: {e}"))?;

        // Re-sign to get an rcgen Certificate handle for signing leaf certs.
        let params = CertificateParams::from_ca_cert_pem(cert_pem_str)
            .map_err(|e| format!("failed to parse CA cert: {e}"))?;
        let cert = params
            .self_signed(&key_pair)
            .map_err(|e| format!("failed to re-sign CA cert: {e}"))?;

        // Parse the ORIGINAL PEM to get stable DER bytes (not the re-signed output).
        let original_der = pem_to_der(cert_pem_str)?;

        Ok(Self {
            cert,
            key_pair,
            cert_der: CertificateDer::from(original_der),
            cert_pem: cert_pem_str.to_string(),
        })
    }

    /// Get the CA certificate as PEM bytes (for guest installation).
    pub fn cert_pem(&self) -> Vec<u8> {
        self.cert_pem.as_bytes().to_vec()
    }

    /// Get the CA private key as PEM bytes (for persistence).
    pub fn key_pem(&self) -> Vec<u8> {
        self.key_pair.serialize_pem().as_bytes().to_vec()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Extract DER bytes from a PEM-encoded certificate string.
fn pem_to_der(pem: &str) -> Result<Vec<u8>, String> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::from_pem_slice(pem.as_bytes())
        .map(|cert| cert.to_vec())
        .map_err(|e| format!("failed to parse PEM: {e}"))
}
