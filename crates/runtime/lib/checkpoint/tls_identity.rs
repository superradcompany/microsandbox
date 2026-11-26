//! Signing material owned by the host, outside the guest runtime mount.
use std::fs::OpenOptions;
use std::io::{ErrorKind, Read, Write};
use std::path::Path;

use microsandbox_image::checkpoint::ResourceDescriptor;
use microsandbox_types::InterceptCaConfig;
use zeroize::Zeroizing;

use super::migration::{io, namespace};
use super::tls_storage::{STORE, identity_path, key_home};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct ManagedIdentity {
    pub(super) certificate: Vec<u8>,
    pub(super) private_key: Zeroizing<Vec<u8>>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn install_for_sandbox(
    home: &Path,
    id: i32,
    certificate: &[u8],
    private_key: &[u8],
) -> Result<InterceptCaConfig, String> {
    let entry = Path::new(STORE).join(id.to_string());
    let storage = key_home(home, &entry, true)?.ok_or("cannot allocate private TLS storage")?;
    let canonical = &storage.path;
    let store = canonical.join(STORE);
    // Two first-time creators can race to publish the empty store. Accept
    // the winner only after validating its owner-only permissions.
    if let Err(error) = io::private_directory(&store) {
        if !store.is_dir() {
            return Err(error);
        }
        microsandbox_utils::private_file::verify(&io::directory(&store)?).map_err(|_| error)?;
    }
    let _store = namespace::acquire_parents(vec![store], true, true)?;
    install(&identity_path(canonical, id), certificate, private_key)
}

/// Called only while the SDK owns a fresh sandbox creation reservation. An
/// existing identity is never replaced, including after an interrupted start.
pub fn provision(home: &Path, id: i32) -> Result<InterceptCaConfig, String> {
    let (public, private) = microsandbox_network::identity::generate_dedicated_ca()
        .map_err(|e| format!("generate sandbox interception CA: {e}"))?;
    install_for_sandbox(home, id, public.as_bytes(), private.as_bytes())
}

/// An authorized local fork may receive its own copy of a managed CA. Custom
/// or machine-wide paths never confer authority to copy an arbitrary host file.
pub fn inherit_for_child(
    home: &Path,
    source: i32,
    child: i32,
    configured: &InterceptCaConfig,
    resources: &[ResourceDescriptor],
) -> Result<Option<InterceptCaConfig>, String> {
    let Some(identity) = captured_identity(home, source, configured, resources)? else {
        return Ok(None);
    };
    install_for_sandbox(home, child, &identity.certificate, &identity.private_key).map(Some)
}

pub(super) fn captured_identity(
    home: &Path,
    source: i32,
    configured: &InterceptCaConfig,
    resources: &[ResourceDescriptor],
) -> Result<Option<ManagedIdentity>, String> {
    let Some(cert_path) = configured.cert_path.as_deref() else {
        return Ok(None);
    };
    let Some(key_path) = configured.key_path.as_deref() else {
        return Ok(None);
    };
    let entry = Path::new(STORE).join(source.to_string());
    if !key_path.ends_with(entry.join("ca.key")) || !cert_path.ends_with(entry.join("ca.crt")) {
        return Ok(None);
    }
    let canonical = std::fs::canonicalize(home).map_err(|e| format!("resolve TLS storage: {e}"))?;
    let source_path = identity_path(&canonical, source);
    let store = home.join(STORE);
    #[cfg(windows)]
    let (source_path, store) = if key_path != source_path.join("ca.key") {
        use super::tls_storage::PROFILE_STORE;

        let Some(profile) = dirs::data_local_dir() else {
            return Ok(None);
        };
        let profile =
            std::fs::canonicalize(profile).map_err(|e| format!("resolve TLS profile: {e}"))?;
        if !key_path.starts_with(profile.join(PROFILE_STORE)) {
            return Ok(None);
        }
        let expected = profile
            .join(PROFILE_STORE)
            .join(namespace::windows_catalog_scope(
                &home.join(microsandbox_utils::DB_SUBDIR),
            )?);
        (identity_path(&expected, source), expected.join(STORE))
    } else {
        (source_path, store)
    };
    if key_path != source_path.join("ca.key") || cert_path != source_path.join("ca.crt") {
        return Ok(None);
    }
    let _source = namespace::acquire_parents(vec![store], true, true)?;
    let identity = read_managed(&source_path)?;

    let fingerprint = microsandbox_network::identity::verify_dedicated_ca(
        &identity.certificate,
        &identity.private_key,
    )?;
    // Older runtimes may reopen the configured key but supply no evidence
    // of the signer they actually used. Never export a key based only on a path.
    let Some(expected) = super::network::intercept_ca_requirement(resources)? else {
        return Ok(None);
    };
    super::network::validate_intercept_ca(Some(&expected), Some(&fingerprint))?;
    Ok(Some(identity))
}

fn read_managed(storage: &Path) -> Result<ManagedIdentity, String> {
    let directory = io::directory(storage)?;
    microsandbox_utils::private_file::verify(&directory)
        .map_err(|e| format!("validate private TLS directory: {e}"))?;
    fn read(directory: &std::fs::File, name: &str) -> Result<Zeroizing<Vec<u8>>, String> {
        const LIMIT: u64 = 64 * 1024;
        let file = io::open(directory, Path::new(name))?;
        microsandbox_utils::private_file::verify(&file)
            .map_err(|e| format!("verify private TLS file: {e}"))?;
        let mut data = Zeroizing::new(Vec::new());
        file.take(LIMIT + 1)
            .read_to_end(&mut data)
            .map_err(|e| format!("read private TLS file: {e}"))?;
        if data.len() as u64 > LIMIT {
            return Err("managed interception CA file exceeds 64 KiB".into());
        }
        Ok(data)
    }
    Ok(ManagedIdentity {
        certificate: read(&directory, "ca.crt")?.to_vec(),
        private_key: read(&directory, "ca.key")?,
    })
}

fn install(destination: &Path, public: &[u8], private: &[u8]) -> Result<InterceptCaConfig, String> {
    let sandbox = destination.parent().ok_or("missing TLS store")?;
    let parent = io::directory(sandbox)?;
    microsandbox_db::private_storage::verify_directory_authority(&parent, true)
        .map_err(|e| format!("validate sandbox TLS storage: {e}"))?;
    match destination.symlink_metadata() {
        Err(e) if e.kind() == ErrorKind::NotFound => {}
        Err(e) => return Err(format!("inspect sandbox TLS identity: {e}")),
        Ok(_) => return Err("sandbox TLS identity already exists".into()),
    }
    let staging = tempfile::Builder::new()
        .prefix(".tls-")
        .tempdir_in(sandbox)
        .map_err(|e| format!("create sandbox TLS staging: {e}"))?;
    io::harden_created(staging.path(), true)?;
    for (name, contents) in [("ca.crt", public), ("ca.key", private)] {
        let path = staging.path().join(name);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&path)
            .map_err(|e| format!("create sandbox TLS {name}: {e}"))?;
        // Apply the owner-only descriptor while the new file is still empty.
        io::harden_created(&path, false)?;
        file.write_all(contents)
            .and_then(|()| file.sync_all())
            .map_err(|e| format!("persist sandbox TLS {name}: {e}"))?;
    }
    #[cfg(unix)]
    io::directory(staging.path())?
        .sync_all()
        .map_err(|e| format!("sync sandbox TLS staging: {e}"))?;
    io::publish(staging.path(), destination)?;
    Ok(InterceptCaConfig {
        cert_path: Some(destination.join("ca.crt")),
        key_path: Some(destination.join("ca.key")),
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fork_owns_a_separate_key_file_and_ignores_custom_paths() {
        let source = tempfile::tempdir().unwrap();

        let managed = provision(source.path(), 1).unwrap();
        let cert = std::fs::read(managed.cert_path.as_ref().unwrap()).unwrap();
        let key = Zeroizing::new(std::fs::read(managed.key_path.as_ref().unwrap()).unwrap());
        let digest = microsandbox_network::identity::verify_dedicated_ca(&cert, &key).unwrap();
        let resources = [ResourceDescriptor {
            id: "net".into(),
            kind: "network".into(),
            treatment: microsandbox_image::checkpoint::ResourceTreatment::Reconnect,
            binding: std::collections::BTreeMap::from([("intercept_ca_sha256".into(), digest)]),
        }];
        assert!(
            inherit_for_child(source.path(), 3, 2, &managed, &resources)
                .unwrap()
                .is_none()
        );
        assert!(
            captured_identity(source.path(), 1, &managed, &[])
                .unwrap()
                .is_none()
        );
        let owned = inherit_for_child(source.path(), 1, 2, &managed, &resources)
            .unwrap()
            .unwrap();
        let received = std::fs::read(owned.cert_path.unwrap()).unwrap();
        assert_eq!(std::fs::read(managed.cert_path.unwrap()).unwrap(), received);
        super::super::tls_storage::remove_sandbox_identity(source.path(), 1).unwrap();
        let key = Zeroizing::new(std::fs::read(owned.key_path.unwrap()).unwrap());
        microsandbox_network::identity::verify_dedicated_ca(&received, &key).unwrap();
    }

    #[test]
    fn fresh_sandboxes_get_distinct_private_identities_and_never_overwrite() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let a = provision(first.path(), 1).unwrap();
        let b = provision(second.path(), 2).unwrap();
        let public = std::fs::read(a.cert_path.as_ref().unwrap()).unwrap();
        assert_ne!(public, std::fs::read(b.cert_path.unwrap()).unwrap());
        let key_path = a.key_path.unwrap();
        let key = std::fs::read(&key_path).unwrap();
        assert!(!public.windows(11).any(|s| s == b"PRIVATE KEY"));
        microsandbox_utils::private_file::verify(&std::fs::File::open(&key_path).unwrap()).unwrap();
        assert!(provision(first.path(), 1).is_err());
        assert_eq!(key, std::fs::read(key_path).unwrap());
        assert!(!first.path().join("guest-state").exists());
    }
}
