//! Upstream TLS connection establishment.
//!
//! Connects to the real server using TLS, optionally verifying the server's
//! certificate against the host's system trust store.

use std::{io, net::SocketAddr, sync::Arc};

use rustls::{ClientConfig, pki_types::ServerName};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Builds a `rustls::ClientConfig` for upstream connections.
///
/// When `verify` is true, loads the host's native root certificates for server
/// verification. When false, disables certificate verification entirely
/// (testing only).
pub fn build_client_config(verify: bool) -> io::Result<Arc<ClientConfig>> {
    let config = if verify {
        let mut root_store = rustls::RootCertStore::empty();
        let native_certs = rustls_native_certs::load_native_certs();
        for cert in native_certs.certs {
            // Ignore individual cert parse errors — some system certs may be
            // in formats rustls doesn't accept.
            let _ = root_store.add(cert);
        }

        ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()
    } else {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerifier))
            .with_no_client_auth()
    };

    Ok(Arc::new(config))
}

/// Connects to an upstream server with TLS.
pub async fn connect(
    addr: SocketAddr,
    sni: &str,
    client_config: Arc<ClientConfig>,
) -> io::Result<TlsStream<TcpStream>> {
    let server_name = ServerName::try_from(sni.to_string())
        .map_err(|e| io::Error::other(format!("invalid SNI for upstream: {e}")))?;

    let tcp = TcpStream::connect(addr).await?;
    let connector = TlsConnector::from(client_config);
    let tls = connector.connect(server_name, tcp).await?;
    Ok(tls)
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Certificate verifier that accepts any certificate (for `verify_upstream: false`).
#[derive(Debug)]
struct NoVerifier;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
