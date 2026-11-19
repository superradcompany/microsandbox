//! Recipient encryption around the existing archive stream.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Read, Seek, Write};
use std::path::Path;
use std::sync::Arc;

use age::x25519;
#[cfg(feature = "net")]
use base64::{Engine, engine::general_purpose::STANDARD};
use zeroize::Zeroizing;

use super::{ArchiveInventory, LocalContext, Snapshot};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const CREDENTIALS: &str = "microsandbox.snapshot.tls-identities";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Each credential is also recipient-encrypted inside the archive inventory.
/// Streaming a decrypted archive to disk therefore exposes only ciphertext.
pub(super) fn export_credentials(
    local: &LocalContext,
    snapshots: &[Snapshot],
    recipients: &[String],
) -> MicrosandboxResult<BTreeMap<String, String>> {
    #[cfg(not(feature = "net"))]
    {
        let _ = (local, recipients);
        if snapshots.iter().any(|s| {
            s.path()
                .join(".intercept-ca.sealed")
                .symlink_metadata()
                .is_ok()
        }) {
            return Err(MicrosandboxError::InvalidConfig(
                "export of a TLS identity requires a networking-enabled build".into(),
            ));
        }
        Ok(BTreeMap::new())
    }
    #[cfg(feature = "net")]
    {
        let mut entries = BTreeMap::new();
        for snapshot in snapshots {
            let super::SnapshotState::Checkpoint(state) = &snapshot.manifest().state else {
                continue;
            };
            let Some(encrypted) = microsandbox_runtime::checkpoint::tls_receipt::export_encrypted(
                &local.config().home(),
                snapshot.path(),
                &state.checkpoint_root,
                snapshot.digest(),
                encryptor(recipients)?,
            )
            .map_err(MicrosandboxError::SnapshotIntegrity)?
            else {
                continue;
            };
            entries.insert(snapshot.id().to_string(), STANDARD.encode(encrypted));
        }
        Ok(entries)
    }
}

pub(super) fn import_credentials(
    local: &LocalContext,
    inventory: &ArchiveInventory,
    snapshots: &[Snapshot],
    keys: Option<&[x25519::Identity]>,
) -> MicrosandboxResult<Vec<String>> {
    let Some(values) = inventory.extensions.get(CREDENTIALS) else {
        return Ok(Vec::new());
    };
    let keys = keys.ok_or_else(|| MicrosandboxError::InvalidConfig(
        "TLS signing credentials require an explicitly recipient-encrypted archive and identity".into()
    ))?;
    #[cfg(not(feature = "net"))]
    {
        let _ = (local, snapshots, keys, values);
        Err(MicrosandboxError::InvalidConfig(
            "TLS credential import requires a networking-enabled build".into(),
        ))
    }
    #[cfg(feature = "net")]
    {
        use microsandbox_runtime::checkpoint::tls_receipt;
        let mut verified = Vec::new();
        let mut entries: BTreeMap<String, String> = serde_json::from_value(values.clone())?;
        for snapshot in snapshots {
            let Some(encoded) = entries.remove(snapshot.id().as_str()) else {
                continue;
            };
            let super::SnapshotState::Checkpoint(state) = &snapshot.manifest().state else {
                return Err(MicrosandboxError::SnapshotIntegrity(
                    "disk snapshot includes a TLS signing credential".into(),
                ));
            };
            let invalid = || {
                MicrosandboxError::SnapshotIntegrity(
                    "invalid encrypted checkpoint signing credential".into(),
                )
            };
            if encoded.len() > 256 * 1024 {
                return Err(invalid());
            }
            let ciphertext = STANDARD.decode(encoded).map_err(|_| invalid())?;
            let decoder =
                age::Decryptor::new_buffered(ciphertext.as_slice()).map_err(|_| invalid())?;
            let mut reader = decoder
                .decrypt(keys.iter().map(|k| k as &dyn age::Identity))
                .map_err(|_| invalid())?;
            let mut bytes = Zeroizing::new(Vec::new());
            reader
                .by_ref()
                .take(160 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() > 160 * 1024 {
                return Err(invalid());
            }
            let payload = bytes
                .strip_prefix(snapshot.digest().as_bytes())
                .and_then(|s| s.strip_prefix(&[0]))
                .ok_or_else(invalid)?;
            let root = microsandbox_image::checkpoint::ObjectId::new(&state.checkpoint_root)
                .map_err(|_| invalid())?;
            let closure = microsandbox_image::checkpoint::CheckpointClosure::inspect_manifest(
                &snapshot.path().join(super::CHECKPOINT_DIRECTORY),
                Some(&root),
            )
            .map_err(|_| invalid())?;
            let sealed = tls_receipt::seal_import(
                &local.config().home(),
                payload,
                &closure.resources,
                &state.checkpoint_root,
            )
            .map_err(MicrosandboxError::SnapshotIntegrity)?;
            tls_receipt::write_staged(snapshot.path(), &sealed)
                .map_err(MicrosandboxError::Runtime)?;
            verified.push(snapshot.id().to_string());
        }
        if !entries.is_empty() {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "TLS credential names a checkpoint absent from the archive".into(),
            ));
        }
        Ok(verified)
    }
}

pub(super) fn encryptor(recipients: &[String]) -> MicrosandboxResult<age::Encryptor> {
    let keys = recipients
        .iter()
        .map(|value| value.parse::<x25519::Recipient>())
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            MicrosandboxError::InvalidConfig(
                "an archive recipient must be an age X25519 public key".into(),
            )
        })?;
    age::Encryptor::with_recipients(keys.iter().map(|key| key as &dyn age::Recipient))
        .map_err(|error| MicrosandboxError::InvalidConfig(format!("archive recipients: {error}")))
}

pub(super) fn read_identities(path: &Path) -> MicrosandboxResult<Arc<Vec<x25519::Identity>>> {
    let file = File::open(path)?;
    if !file.metadata()?.is_file() {
        return Err(MicrosandboxError::InvalidConfig(
            "expected a regular age identity file".into(),
        ));
    }
    const MAX_BYTES: usize = 64 * 1024;
    let mut text = Zeroizing::new(String::new());
    file.take(MAX_BYTES as u64 + 1).read_to_string(&mut text)?;
    if text.len() > MAX_BYTES {
        return Err(MicrosandboxError::InvalidConfig(
            "age identity file exceeds 64 KiB".into(),
        ));
    }
    let keys = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::parse)
        .collect::<Result<Vec<x25519::Identity>, _>>()
        .map_err(|_| {
            MicrosandboxError::InvalidConfig(
                "expected X25519 identities in the age identity file".into(),
            )
        })?;
    if keys.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "empty age identity file".into(),
        ));
    }
    Ok(Arc::new(keys))
}

/// Authenticate through the final age chunk before handing any bytes to the
/// importer. An anonymous file bounds memory and disappears on process exit.
pub(super) fn decrypt(
    archive: &Path,
    keys: &[x25519::Identity],
    staging: &Path,
) -> MicrosandboxResult<File> {
    let encrypted = File::open(archive)?;
    let decryptor = age::Decryptor::new_buffered(BufReader::new(encrypted)).map_err(|e| {
        MicrosandboxError::SnapshotIntegrity(format!(
            "invalid age archive {}: {e}",
            archive.display()
        ))
    })?;
    let mut reader = decryptor
        .decrypt(keys.iter().map(|k| k as &dyn age::Identity))
        .map_err(|e| {
            MicrosandboxError::SnapshotIntegrity(format!(
                "could not unlock age archive {}: {e}",
                archive.display()
            ))
        })?;
    #[cfg(not(windows))]
    let mut plain = tempfile::tempfile_in(staging)?;
    #[cfg(windows)]
    let mut plain = {
        use std::os::windows::fs::OpenOptionsExt;
        use windows_sys::Win32::Foundation::{GENERIC_READ, GENERIC_WRITE};
        use windows_sys::Win32::Storage::FileSystem::{
            DELETE, FILE_ATTRIBUTE_TEMPORARY, FILE_FLAG_DELETE_ON_CLOSE, WRITE_DAC,
        };

        // The default anonymous tempfile handle lacks WRITE_DAC. SetSecurityInfo needs
        // that access on the original handle before writing any decrypted archive bytes.
        // Exclusive sharing and delete-on-close also cover interruption during decryption.
        tempfile::Builder::new()
            .make_in(staging, |path| {
                std::fs::OpenOptions::new()
                    .read(true)
                    .write(true)
                    .create_new(true)
                    .access_mode(GENERIC_READ | GENERIC_WRITE | DELETE | WRITE_DAC)
                    .share_mode(0)
                    .custom_flags(FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE)
                    .open(path)
            })?
            .into_file()
    };
    microsandbox_utils::private_file::harden(&plain, false)?;
    // Preserve storage write errors independently of authenticated-stream
    // failures and identify the failing input in a multi-archive import.
    let mut buffer = Zeroizing::new(vec![0u8; 64 * 1024]);
    loop {
        let count = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(n) => n,
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) if error.raw_os_error().is_some() => return Err(error.into()),
            Err(error) => {
                return Err(MicrosandboxError::SnapshotIntegrity(format!(
                    "could not authenticate encrypted archive {}: {error}",
                    archive.display()
                )));
            }
        };
        plain.write_all(&buffer[..count])?;
    }
    plain.rewind()?;
    Ok(plain)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Write;

    use super::*;

    #[test]
    fn authenticates_the_entire_archive_before_returning_plaintext() {
        let staging = tempfile::tempdir().unwrap();
        let path = staging.path().join("checkpoint.msb");
        let identity = x25519::Identity::generate();
        let other = x25519::Identity::generate();
        let cipher = encryptor(&[identity.to_public().to_string()]).unwrap();
        let mut writer = cipher.wrap_output(File::create(&path).unwrap()).unwrap();
        let expected = vec![0x79; 160_000]; // Span multiple authenticated chunks.
        writer.write_all(&expected).unwrap();
        writer.finish().unwrap();
        let mut actual = Vec::new();
        decrypt(&path, std::slice::from_ref(&identity), staging.path())
            .unwrap()
            .read_to_end(&mut actual)
            .unwrap();
        assert_eq!(actual, expected);
        assert!(decrypt(&path, &[other], staging.path()).is_err());
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() - 1]).unwrap();
        assert!(decrypt(&path, &[identity], staging.path()).is_err());
        assert_eq!(std::fs::read_dir(staging.path()).unwrap().count(), 1);
    }
}
