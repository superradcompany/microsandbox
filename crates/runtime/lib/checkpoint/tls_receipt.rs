//! Host-sealed TLS signing material for a durable full checkpoint.
use std::fs::File;
use std::io::{ErrorKind, Read, Write};
use std::path::Path;

use chacha20poly1305::aead::{Aead, KeyInit, OsRng, Payload, rand_core::RngCore};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use microsandbox_image::checkpoint::ResourceDescriptor;
use microsandbox_types::InterceptCaConfig;
use zeroize::Zeroizing;

use super::migration::{io, namespace};
use super::tls_identity::{ManagedIdentity, captured_identity, install_for_sandbox};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Filename reserved for an installed checkpoint’s host-sealed credential.
pub const SIDECAR: &str = ".intercept-ca.sealed";
const STORE: &str = "snapshot-keys";
const KEY: &str = "wrapping-key";
const HEADER: &[u8] = b"MSB-TLS-CA\x01";
const LIMIT: usize = 160 * 1024;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn wrapping_key(home: &Path, create: bool) -> Result<Zeroizing<[u8; 32]>, String> {
    let (canonical, _alias, _target) = namespace::configuration_home(home)?;
    let store = canonical.join(STORE);
    if create
        && let Err(error) = io::private_directory(&store)
        && microsandbox_utils::private_file::verify(&io::directory(&store)?).is_err()
    {
        return Err(error);
    }
    let _store = namespace::acquire_parents(vec![store.clone()], true, true)?;
    let directory = io::directory(&store)?;
    microsandbox_utils::private_file::verify(&directory).map_err(|e| e.to_string())?;
    let destination = store.join(KEY);
    if create
        && matches!(destination.symlink_metadata(), Err(ref e) if e.kind()==ErrorKind::NotFound)
    {
        let mut generated = Zeroizing::new([0u8; 32]);
        OsRng
            .try_fill_bytes(generated.as_mut())
            .map_err(|e| e.to_string())?;
        let mut staging = tempfile::NamedTempFile::new_in(&store).map_err(|e| e.to_string())?;
        io::harden_created(staging.path(), false)?;
        staging
            .write_all(generated.as_ref())
            .and_then(|()| staging.as_file().sync_all())
            .map_err(|e| e.to_string())?;
        // Concurrent first captures must agree on one key, including when a
        // creator dies immediately after publishing it.
        match staging.persist_noclobber(&destination) {
            Ok(_) => {}
            Err(e) if e.error.kind() == ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.error.to_string()),
        }
    }
    #[cfg(unix)]
    if create {
        directory.sync_all().map_err(|e| e.to_string())?;
    }
    let mut file = io::open(&directory, Path::new(KEY)).map_err(|_| {
        "local snapshot wrapping key unavailable; import a recipient-encrypted backup".to_owned()
    })?;
    microsandbox_utils::private_file::verify(&file).map_err(|e| e.to_string())?;
    let mut key = Zeroizing::new([0u8; 32]);
    if file.metadata().map_err(|e| e.to_string())?.len() != 32 {
        return Err("invalid snapshot wrapping key".into());
    }
    file.read_exact(key.as_mut()).map_err(|e| e.to_string())?;
    Ok(key)
}

fn credential_bytes(identity: &ManagedIdentity) -> Zeroizing<Vec<u8>> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(
        4 + identity.certificate.len() + identity.private_key.len(),
    ));
    bytes.extend_from_slice(&(identity.certificate.len() as u32).to_be_bytes());
    bytes.extend_from_slice(&identity.certificate);
    bytes.extend_from_slice(&identity.private_key);
    bytes
}

fn split_credential(bytes: &[u8]) -> Result<(&[u8], &[u8]), String> {
    let length = bytes.get(..4).ok_or("truncated signing credential")?;
    let len = u32::from_be_bytes(length.try_into().unwrap()) as usize;
    bytes[4..]
        .split_at_checked(len)
        .ok_or_else(|| "invalid signing credential length".into())
}

fn seal(home: &Path, root: &str, bytes: &[u8]) -> Result<Vec<u8>, String> {
    let key = wrapping_key(home, true)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| "invalid wrapping key")?;
    let mut nonce = [0u8; 24];
    OsRng
        .try_fill_bytes(&mut nonce)
        .map_err(|e| e.to_string())?;
    let encrypted = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: bytes,
                aad: root.as_bytes(),
            },
        )
        .map_err(|_| "seal checkpoint signing credential")?;
    let mut sealed = Vec::with_capacity(HEADER.len() + 24 + encrypted.len());
    sealed.extend_from_slice(HEADER);
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&encrypted);
    Ok(sealed)
}

/// Return only ciphertext to the snapshot publisher. A custom CA or an older
/// runtime without evidence cannot authorize copying private material.
pub fn capture(
    home: &Path,
    id: i32,
    configured: &InterceptCaConfig,
    resources: &[ResourceDescriptor],
    root: &str,
) -> Result<Option<Vec<u8>>, String> {
    captured_identity(home, id, configured, resources)?
        .map(|identity| seal(home, root, &credential_bytes(&identity)))
        .transpose()
}

/// Bound both memory use and file lookup to a single sidecar under the
/// installed artifact. Missing means a legacy, custom-CA or plaintext archive.
fn open_local(
    home: &Path,
    artifact: &Path,
    root: &str,
) -> Result<Option<Zeroizing<Vec<u8>>>, String> {
    let path = artifact.join(SIDECAR);
    if matches!(path.symlink_metadata(), Err(ref e) if e.kind()==ErrorKind::NotFound) {
        return Ok(None);
    }
    let mut bytes = Vec::new();
    io::open(&io::directory(artifact)?, Path::new(SIDECAR))?
        .take(LIMIT as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    let encoded = bytes
        .strip_prefix(HEADER)
        .ok_or("invalid sealed TLS credential")?;
    if bytes.len() > LIMIT || encoded.len() < 24 + 16 {
        return Err("invalid sealed TLS credential length".into());
    }
    let key = wrapping_key(home, false)?;
    let cipher =
        XChaCha20Poly1305::new_from_slice(key.as_ref()).map_err(|_| "invalid wrapping key")?;
    let (nonce, ciphertext) = encoded.split_at(24);
    let plain = cipher
        .decrypt(
            XNonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad: root.as_bytes(),
            },
        )
        .map_err(|_| "cannot authenticate TLS credential against this host and checkpoint")?;
    Ok(Some(Zeroizing::new(plain)))
}

/// Encrypt the retained host credential before crossing the runtime API boundary.
/// Bind the portable credential to its exact archive member as well as the
/// local wrapping layer's immutable checkpoint root.
#[cfg(feature = "encrypted-snapshot-identity")]
pub fn export_encrypted(
    home: &Path,
    artifact: &Path,
    root: &str,
    descriptor: &str,
    cipher: age::Encryptor,
) -> Result<Option<Vec<u8>>, String> {
    let Some(secret) = open_local(home, artifact, root)? else {
        return Ok(None);
    };
    let mut encrypted = Vec::new();
    let mut writer = cipher
        .wrap_output(&mut encrypted)
        .map_err(|e| e.to_string())?;
    writer
        .write_all(descriptor.as_bytes())
        .and_then(|()| writer.write_all(&[0]))
        .and_then(|()| writer.write_all(&secret))
        .map_err(|e| e.to_string())?;
    writer.finish().map_err(|e| e.to_string())?;
    Ok(Some(encrypted))
}

fn verified<'a>(
    bytes: &'a [u8],
    resources: &[ResourceDescriptor],
) -> Result<(&'a [u8], &'a [u8]), String> {
    if bytes.len() > LIMIT {
        return Err("oversized checkpoint signing credential".into());
    }
    let (cert, key) = split_credential(bytes)?;
    let fingerprint = microsandbox_network::identity::verify_dedicated_ca(cert, key)?;
    let expected = super::network::intercept_ca_requirement(resources)?
        .ok_or("checkpoint provides no evidence of its TLS signer")?;
    super::network::validate_intercept_ca(Some(&expected), Some(&fingerprint))?;
    Ok((cert, key))
}

/// Only the explicitly authenticated age importer supplies portable credentials.
pub fn seal_import(
    home: &Path,
    bytes: &[u8],
    resources: &[ResourceDescriptor],
    root: &str,
) -> Result<Vec<u8>, String> {
    verified(bytes, resources)?;
    seal(home, root, bytes)
}

/// Install the authenticated signer as a child-owned credential before full restore.
pub fn restore(
    home: &Path,
    id: i32,
    artifact: &Path,
    resources: &[ResourceDescriptor],
    root: &str,
) -> Result<Option<InterceptCaConfig>, String> {
    let Some(bytes) = open_local(home, artifact, root)? else {
        return Ok(None);
    };
    let (cert, key) = verified(&bytes, resources)?;
    install_for_sandbox(home, id, cert, key).map(Some)
}

/// Staging belongs to the caller. The immutable artifact publisher handles
/// directory sync and makes ciphertext visible together with the checkpoint.
pub fn write_staged(artifact: &Path, sealed: &[u8]) -> Result<(), String> {
    let mut file = File::create_new(artifact.join(SIDECAR)).map_err(|e| e.to_string())?;
    file.write_all(sealed)
        .and_then(|()| file.sync_all())
        .map_err(|e| e.to_string())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use microsandbox_image::checkpoint::ResourceTreatment;
    use std::collections::BTreeMap;

    #[test]
    fn checkpoint_receipt_requires_its_host_key_root_and_confirmed_signer() {
        let source = tempfile::tempdir().unwrap();
        let destination = tempfile::tempdir().unwrap();
        let artifact = tempfile::tempdir().unwrap();
        let restored = tempfile::tempdir().unwrap();
        let config = super::super::tls_identity::provision(source.path(), 1).unwrap();
        let cert = std::fs::read(config.cert_path.as_ref().unwrap()).unwrap();
        let key = Zeroizing::new(std::fs::read(config.key_path.as_ref().unwrap()).unwrap());
        let fingerprint = microsandbox_network::identity::verify_dedicated_ca(&cert, &key).unwrap();
        let resources = [ResourceDescriptor {
            kind: "network".into(),
            id: "net".into(),
            treatment: ResourceTreatment::Reconnect,
            binding: BTreeMap::from([("intercept_ca_sha256".into(), fingerprint)]),
        }];
        let sealed = capture(source.path(), 1, &config, &resources, "root-a")
            .unwrap()
            .unwrap();
        // Repeating capture uses the same wrapping key, signer, and checkpoint binding.
        // A fresh nonce is required even when the plaintext is identical.
        let repeated = capture(source.path(), 1, &config, &resources, "root-a")
            .unwrap()
            .unwrap();
        let nonce = HEADER.len()..HEADER.len() + 24;
        assert_ne!(sealed[nonce.clone()], repeated[nonce]);
        assert!(!sealed.windows(11).any(|s| s == b"PRIVATE KEY"));
        write_staged(artifact.path(), &sealed).unwrap();
        super::super::remove_sandbox_identity(source.path(), 1).unwrap();
        assert!(open_local(source.path(), artifact.path(), "root-b").is_err());
        assert!(open_local(destination.path(), artifact.path(), "root-a").is_err());
        let plain = open_local(source.path(), artifact.path(), "root-a")
            .unwrap()
            .unwrap();
        assert!(seal_import(destination.path(), &plain, &[], "root-a").is_err());
        let resealed = seal_import(destination.path(), &plain, &resources, "root-a").unwrap();
        assert_ne!(sealed, resealed);
        write_staged(restored.path(), &resealed).unwrap();
        let fresh = restore(destination.path(), 7, restored.path(), &resources, "root-a")
            .unwrap()
            .unwrap();
        assert_eq!(std::fs::read(fresh.cert_path.unwrap()).unwrap(), cert);
        let mut bad = resealed;
        *bad.last_mut().unwrap() ^= 1;
        std::fs::write(restored.path().join(SIDECAR), bad).unwrap();
        assert!(restore(destination.path(), 8, restored.path(), &resources, "root-a").is_err());
        assert!(!destination.path().join("sandbox-tls/8").exists());
    }
}
