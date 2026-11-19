//! Certificate authority generation and loading.

use pem::{EncodeConfig, LineEnding, Pem};
use rcgen::{Issuer, KeyPair, PublicKeyData};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::pem::PemObject;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A certificate authority for signing per-domain certificates.
pub struct CertAuthority {
    /// CA issuer handle for signing leaf certificates.
    pub issuer: Issuer<'static, KeyPair>,
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
        let (params, key_pair, cert) =
            crate::identity::generate().expect("failed to generate interception CA");
        let cert_pem = cert.pem();
        let cert_der = CertificateDer::from(cert.der().to_vec());
        let issuer = Issuer::new(params, key_pair);

        Self {
            issuer,
            cert_der,
            cert_pem,
        }
    }

    /// Load a CA from PEM-encoded certificate and private key bytes.
    ///
    /// Keep the original certificate DER and certificate chain. The PEM file
    /// may also contain private material, so only certificates cross into the guest.
    pub fn load(cert_pem_bytes: &[u8], key_pem_bytes: &[u8]) -> Result<Self, String> {
        let cert_pem_str =
            std::str::from_utf8(cert_pem_bytes).map_err(|e| format!("invalid cert PEM: {e}"))?;
        let key_pem_str =
            std::str::from_utf8(key_pem_bytes).map_err(|e| format!("invalid key PEM: {e}"))?;

        let key_pair =
            KeyPair::from_pem(key_pem_str).map_err(|e| format!("failed to parse CA key: {e}"))?;

        let issuer = Issuer::from_ca_cert_pem(cert_pem_str, key_pair)
            .map_err(|e| format!("failed to parse CA cert: {e}"))?;

        let mut certificates = CertificateDer::pem_slice_iter(cert_pem_bytes);
        let cert_der = certificates
            .next()
            .ok_or_else(|| "interception CA PEM contains no certificate".to_string())?
            .map_err(|e| format!("invalid interception certificate: {e}"))?;
        let mut public_chain = vec![Pem::new("CERTIFICATE", cert_der.as_ref())];
        for certificate in certificates {
            let certificate = certificate.map_err(|e| format!("invalid CA chain: {e}"))?;
            public_chain.push(Pem::new("CERTIFICATE", certificate.as_ref()));
        }

        Ok(Self {
            issuer,
            cert_der,
            cert_pem: pem::encode_many_config(
                &public_chain,
                EncodeConfig::new().set_line_ending(LineEnding::LF),
            ),
        })
    }

    /// Verify that leaves signed by this key chain to the advertised certificate.
    /// Parsing the issuer fields with rcgen alone does not establish ownership.
    pub(super) fn verify_signing_key(&self) -> Result<(), String> {
        let cert = rustls::server::ParsedCertificate::try_from(&self.cert_der)
            .map_err(|e| format!("invalid interception certificate: {e}"))?;
        if cert.subject_public_key_info().as_ref() != self.issuer.key().subject_public_key_info() {
            return Err("interception certificate and private key do not match".into());
        }
        Ok(())
    }

    /// Get the CA certificate as PEM bytes (for guest installation).
    pub fn cert_pem(&self) -> Vec<u8> {
        self.cert_pem.as_bytes().to_vec()
    }

    /// Get the CA private key as PEM bytes (for persistence).
    pub fn key_pem(&self) -> Vec<u8> {
        self.issuer.key().serialize_pem().as_bytes().to_vec()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::sync::Arc;

    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection};

    use super::CertAuthority;
    use crate::engine::tls::certgen::generate_domain_cert;

    /// Exercise certificate verification, rather than only comparing serialized PEM.
    /// The guest retains its original trust anchor while the host makes a fresh leaf.
    fn handshake(
        guest_trust: &CertAuthority,
        host_identity: &CertAuthority,
    ) -> Result<(), rustls::Error> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut roots = RootCertStore::empty();
        roots.add(guest_trust.cert_der.clone()).unwrap();
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let mut client = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("snapshot.example").unwrap(),
        )
        .unwrap();
        let leaf = generate_domain_cert("snapshot.example", host_identity, 1).unwrap();
        let mut server = ServerConnection::new(leaf.server_config).unwrap();
        for _ in 0..16 {
            let mut outbound = Vec::new();
            client.write_tls(&mut outbound).unwrap();
            server.read_tls(&mut Cursor::new(outbound)).unwrap();
            server.process_new_packets()?;
            let mut inbound = Vec::new();
            server.write_tls(&mut inbound).unwrap();
            client.read_tls(&mut Cursor::new(inbound)).unwrap();
            client.process_new_packets()?;
            if !client.is_handshaking() && !server.is_handshaking() {
                return Ok(());
            }
        }
        panic!("in-memory TLS handshake did not finish");
    }

    #[test]
    fn restored_dedicated_ca_preserves_guest_trust_for_new_connections() {
        let original = CertAuthority::generate();
        let restored = CertAuthority::load(&original.cert_pem(), &original.key_pem()).unwrap();
        // No leaf cache or TLS connection state is transferred to the destination.
        handshake(&original, &restored).unwrap();
    }

    #[test]
    fn guest_bundle_contains_only_public_certificates_in_original_order() {
        use rustls::pki_types::{CertificateDer, pem::PemObject};

        let ca = CertAuthority::generate();
        let chain = CertAuthority::generate();
        let mut bundle = ca.cert_pem();
        bundle.extend(ca.key_pem());
        bundle.extend(chain.cert_pem());
        let loaded = CertAuthority::load(&bundle, &ca.key_pem()).unwrap();
        let public = loaded.cert_pem();
        assert_eq!(
            pem::parse_many(&public)
                .unwrap()
                .iter()
                .map(|p| p.tag())
                .collect::<Vec<_>>(),
            ["CERTIFICATE", "CERTIFICATE"],
        );
        assert_eq!(
            CertificateDer::pem_slice_iter(&public)
                .collect::<Result<Vec<_>, _>>()
                .unwrap(),
            [ca.cert_der, chain.cert_der],
        );
    }

    #[test]
    fn mismatched_signing_key_is_refused_before_tls_handshakes() {
        let ca = CertAuthority::generate();
        let other = CertAuthority::generate();
        ca.verify_signing_key().unwrap();
        let mixed = CertAuthority::load(&ca.cert_pem(), &other.key_pem()).unwrap();
        assert!(mixed.verify_signing_key().is_err());
    }

    #[test]
    fn unrelated_destination_ca_cannot_replace_captured_guest_trust() {
        let source = CertAuthority::generate();
        let destination = CertAuthority::generate();
        assert!(matches!(
            handshake(&source, &destination),
            Err(rustls::Error::InvalidCertificate(_))
        ));
        // Establish that the refusal is an identity mismatch, not a broken fixture.
        handshake(&destination, &destination).unwrap();
    }
}
