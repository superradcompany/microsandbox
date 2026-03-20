//! CA keypair generation, loading, and persistence.
//!
//! On first use, generates a P-256 EC self-signed CA certificate and persists
//! it to `~/.microsandbox/tls/`. On subsequent starts, loads the existing CA.
//! User-provided CA paths override generation for corporate PKI integration.

use std::{
    fs, io,
    path::{Path, PathBuf},
};

use rcgen::{CertificateParams, DnType, IsCa, KeyPair, KeyUsagePurpose};
use rustls::pki_types::CertificateDer;

use super::CaConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A loaded CA keypair with both the certificate and signing key.
pub struct CaKeyPair {
    /// PEM-encoded CA certificate (public — injected into guest trust store).
    pub cert_pem: String,

    /// DER-encoded CA certificate.
    pub cert_der: Vec<u8>,

    /// The rcgen `Certificate` object used as issuer for `signed_by()`.
    pub(crate) cert: rcgen::Certificate,

    /// CA signing key (used to sign per-domain certificates).
    pub key_pair: KeyPair,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Loads an existing CA or generates a new one based on configuration.
///
/// Resolution order:
/// 1. If `ca_config.cert` and `ca_config.key` are both set, load from those paths.
/// 2. Check `~/.microsandbox/tls/ca.{pem,key}` — load if present.
/// 3. Generate a new CA and persist to `~/.microsandbox/tls/`.
pub fn load_or_generate(ca_config: &CaConfig) -> io::Result<CaKeyPair> {
    // User-provided CA paths.
    if let (Some(cert_path), Some(key_path)) = (&ca_config.cert, &ca_config.key) {
        return load_ca(cert_path, key_path);
    }

    // Default persistence directory.
    let tls_dir = default_tls_dir()?;
    let cert_path = tls_dir.join("ca.pem");
    let key_path = tls_dir.join("ca.key");

    if cert_path.exists() && key_path.exists() {
        return load_ca(&cert_path, &key_path);
    }

    // Generate and persist.
    let ca = generate_ca(ca_config)?;
    fs::create_dir_all(&tls_dir)?;
    persist_ca(&ca, &tls_dir)?;
    Ok(ca)
}

/// Loads a CA from PEM-encoded cert and key files.
fn load_ca(cert_path: &Path, key_path: &Path) -> io::Result<CaKeyPair> {
    let cert_pem = fs::read_to_string(cert_path)?;
    let key_pem = fs::read_to_string(key_path)?;

    let key_pair = KeyPair::from_pem(&key_pem)
        .map_err(|e| io::Error::other(format!("failed to parse CA key: {e}")))?;

    let cert_der = pem_to_der(&cert_pem)?;

    // Reconstruct the rcgen Certificate from the DER so it can be used as
    // issuer in signed_by(). We parse the DER back into CertificateParams,
    // then self-sign with the loaded key to get a Certificate object.
    let der_ref = CertificateDer::from(cert_der.as_slice());
    let ca_params = CertificateParams::from_ca_cert_der(&der_ref)
        .map_err(|e| io::Error::other(format!("failed to parse CA cert DER: {e}")))?;
    let cert = ca_params
        .self_signed(&key_pair)
        .map_err(|e| io::Error::other(format!("failed to reconstruct CA certificate: {e}")))?;

    Ok(CaKeyPair {
        cert_pem,
        cert_der,
        cert,
        key_pair,
    })
}

/// Generates a new P-256 EC self-signed CA certificate.
pub(crate) fn generate_ca(config: &CaConfig) -> io::Result<CaKeyPair> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| io::Error::other(format!("failed to generate CA keypair: {e}")))?;

    let mut params = CertificateParams::new(Vec::<String>::new())
        .map_err(|e| io::Error::other(format!("failed to create CA params: {e}")))?;

    params
        .distinguished_name
        .push(DnType::CommonName, &config.cn);
    params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Constrained(0));
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];

    // Validity period: from now to now + validity_days.
    let now = time::OffsetDateTime::now_utc();
    params.not_before = now;
    params.not_after = now + time::Duration::days(config.validity_days as i64);

    let cert = params
        .self_signed(&key_pair)
        .map_err(|e| io::Error::other(format!("failed to self-sign CA: {e}")))?;

    let cert_pem = cert.pem();
    let cert_der = cert.der().to_vec();

    Ok(CaKeyPair {
        cert_pem,
        cert_der,
        cert,
        key_pair,
    })
}

/// Persists the CA certificate and key to the given directory.
fn persist_ca(ca: &CaKeyPair, dir: &Path) -> io::Result<()> {
    let cert_path = dir.join("ca.pem");
    let key_path = dir.join("ca.key");

    fs::write(&cert_path, &ca.cert_pem)?;
    fs::write(&key_path, ca.key_pair.serialize_pem())?;

    // Restrict key file permissions to owner-only.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

/// Returns the default TLS directory: `~/.microsandbox/tls/`.
fn default_tls_dir() -> io::Result<PathBuf> {
    let home =
        dirs::home_dir().ok_or_else(|| io::Error::other("could not determine home directory"))?;
    Ok(home
        .join(microsandbox_utils::BASE_DIR_NAME)
        .join(microsandbox_utils::TLS_SUBDIR))
}

/// Extracts DER bytes from a PEM-encoded certificate string.
fn pem_to_der(pem: &str) -> io::Result<Vec<u8>> {
    let mut reader = io::BufReader::new(pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader).collect::<Result<Vec<_>, _>>()?;
    certs
        .into_iter()
        .next()
        .map(|c| c.to_vec())
        .ok_or_else(|| io::Error::other("no certificate found in PEM"))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_ca_roundtrip() {
        let config = CaConfig::default();
        let ca = generate_ca(&config).unwrap();

        assert!(!ca.cert_pem.is_empty());
        assert!(ca.cert_pem.contains("BEGIN CERTIFICATE"));
        assert!(!ca.cert_der.is_empty());

        // Verify the PEM can be parsed back to DER.
        let der = pem_to_der(&ca.cert_pem).unwrap();
        assert_eq!(der, ca.cert_der);
    }

    #[test]
    fn test_persist_and_load() {
        let dir = tempfile::tempdir().unwrap();
        let config = CaConfig::default();

        let ca = generate_ca(&config).unwrap();
        persist_ca(&ca, dir.path()).unwrap();

        let loaded = load_ca(&dir.path().join("ca.pem"), &dir.path().join("ca.key")).unwrap();

        assert_eq!(loaded.cert_pem, ca.cert_pem);
        assert_eq!(loaded.cert_der, ca.cert_der);
    }
}
