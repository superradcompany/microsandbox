//! Host-only generation of TLS interception authorities.
use rcgen::{Certificate, CertificateParams, DistinguishedName, IsCa, KeyPair, PublicKeyData};
use rustls::pki_types::{CertificateDer, pem::PemObject};
use sha2::{Digest, Sha256};
use x509_parser::parse_x509_certificate;
use zeroize::Zeroizing;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Material for a new sandbox. The secret buffer is cleared when the host has
/// persisted it. Only the public certificate may be delivered to the guest.
#[doc(hidden)]
pub fn generate_dedicated_ca() -> Result<(String, Zeroizing<String>), rcgen::Error> {
    let (_, key, certificate) = generate()?;
    Ok((certificate.pem(), Zeroizing::new(key.serialize_pem())))
}

/// Confirm that the private managed key corresponds to its single public
/// certificate before installing it in another sandbox.
#[doc(hidden)]
pub fn verify_dedicated_ca(public: &[u8], private: &[u8]) -> Result<String, String> {
    let mut chain = CertificateDer::pem_slice_iter(public);
    let cert = chain
        .next()
        .ok_or("missing dedicated CA certificate")?
        .map_err(|_| "invalid dedicated CA certificate")?;
    if chain.next().is_some() {
        return Err("unexpected dedicated CA chain".into());
    }
    let key =
        KeyPair::from_pem(std::str::from_utf8(private).map_err(|_| "invalid dedicated CA key")?)
            .map_err(|_| "invalid dedicated CA key")?;
    let (remaining, parsed) =
        parse_x509_certificate(cert.as_ref()).map_err(|_| "invalid dedicated CA certificate")?;
    // Matching a key also succeeds for a leaf. Only an authority issued for
    // signing can stand in for the sandbox signer on the destination.
    if !remaining.is_empty()
        || !parsed
            .basic_constraints()
            .map_err(|_| "invalid CA constraints")?
            .is_some_and(|ext| ext.value.ca)
        || !parsed
            .key_usage()
            .map_err(|_| "invalid CA key usage")?
            .is_some_and(|ext| ext.value.key_cert_sign())
    {
        return Err("dedicated certificate must be a CA with certificate signing usage".into());
    }
    if key.subject_public_key_info() != parsed.public_key().raw {
        return Err("dedicated CA key does not match its certificate".into());
    }
    Ok(hex::encode(Sha256::digest(cert.as_ref())))
}

pub(crate) fn generate() -> Result<(CertificateParams, KeyPair, Certificate), rcgen::Error> {
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

    let key = KeyPair::generate()?;
    let certificate = params.self_signed(&key)?;
    Ok((params, key, certificate))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_matching_keys_for_leaf_or_non_signing_certificates() {
        let (mut params, key, good) = generate().unwrap();
        let private = Zeroizing::new(key.serialize_pem());
        assert!(verify_dedicated_ca(good.pem().as_bytes(), private.as_bytes()).is_ok());
        params.is_ca = IsCa::ExplicitNoCa;
        let leaf = params.self_signed(&key).unwrap();
        assert!(verify_dedicated_ca(leaf.pem().as_bytes(), private.as_bytes()).is_err());
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
        let non_signer = params.self_signed(&key).unwrap();
        assert!(verify_dedicated_ca(non_signer.pem().as_bytes(), private.as_bytes()).is_err());
    }
}
