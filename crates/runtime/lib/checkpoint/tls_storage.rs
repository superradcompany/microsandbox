//! Lifecycle cleanup for host-owned sandbox credentials, including on clients built without networking.
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::migration::{io, namespace};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const STORE: &str = "sandbox-tls";
#[cfg(windows)]
pub(super) const PROFILE_STORE: &str = "microsandbox-credentials";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Derive the identity within its credential store from the catalog ID. Names
/// can be reused and callers can supply arbitrary custom certificate paths.
pub(super) fn identity_path(home: &Path, id: i32) -> PathBuf {
    home.join(STORE).join(id.to_string())
}

/// Locate a managed credential without changing the selected data drive. Existing
/// keys keep their location even if the operator later changes the home's ACL.
#[cfg(any(windows, feature = "net"))]
pub(super) fn key_home(
    home: &Path,
    entry: &Path,
    create: bool,
) -> Result<Option<namespace::ConfigurationHome>, String> {
    let local_entry = entry_exists(&home.join(entry))?;
    #[cfg(not(windows))]
    {
        if !local_entry && !create {
            return Ok(None);
        }
        namespace::configuration_home(home).map(Some)
    }
    #[cfg(windows)]
    {
        let local = namespace::configuration_home(home);
        if local_entry && local.is_ok() {
            return local.map(Some);
        }

        // A private entry may predate an ACL change. Never mint a second
        // wrapping key for old snapshots or replace an existing signing key.
        let allocate = create && !local_entry && local.is_err();
        if let Some(profile) = profile_key_home(home, allocate)?
            && (allocate || entry_exists(&profile.path.join(entry))?)
        {
            return Ok(Some(profile));
        }
        if local_entry || create {
            local.map(Some)
        } else {
            Ok(None)
        }
    }
}

fn entry_exists(path: &Path) -> Result<bool, String> {
    match path.symlink_metadata() {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(false),
        Err(error) => Err(format!("inspect TLS storage {}: {error}", path.display())),
    }
}

#[cfg(windows)]
fn profile_key_home(
    home: &Path,
    create: bool,
) -> Result<Option<namespace::ConfigurationHome>, String> {
    let catalog_dir = home.join(microsandbox_utils::DB_SUBDIR);
    if !create && !entry_exists(&catalog_dir)? {
        return Ok(None);
    }
    let Some(profile) = dirs::data_local_dir() else {
        return if create {
            Err("Windows local application data is unavailable for private TLS credentials".into())
        } else {
            Ok(None)
        };
    };
    let root = profile.join(PROFILE_STORE);
    if !create && !entry_exists(&root)? {
        return Ok(None);
    }
    // Use the OS folder identities, never an identifier supplied by the
    // shared catalog. A recreated catalog directory gets a separate key store.
    let scope = namespace::windows_catalog_scope(&catalog_dir)?;
    if !create && !entry_exists(&root.join(&scope))? {
        return Ok(None);
    }
    let base = namespace::configuration_home(&profile).map_err(|e| {
        format!("cannot protect TLS credentials in Windows local application data: {e}")
    })?;
    let mut path = base.path.clone();
    for component in [PROFILE_STORE, &scope] {
        path.push(component);
        if create {
            // Another first launch can publish the same private directory.
            let existed = entry_exists(&path)?;
            if let Err(error) = io::private_directory(&path) {
                io::verify_private_directory(&path).map_err(|_| error)?;
            }
            if !existed && component == scope {
                tracing::warn!(home = %home.display(), "using the Windows user profile for TLS credentials because the sandbox data directory is shared");
            }
        } else if !entry_exists(&path)? {
            return Ok(None);
        } else {
            io::verify_private_directory(&path)?;
        }
    }
    namespace::configuration_home(&path).map(Some)
}

/// Called while holding catalog ownership of the ID, before releasing its row.
pub fn remove_sandbox_identity(home: &Path, id: i32) -> Result<(), String> {
    #[cfg(windows)]
    let storage = key_home(home, &Path::new(STORE).join(id.to_string()), false)?;
    #[cfg(windows)]
    let Some(home) = storage.as_ref().map(|storage| storage.path.as_path()) else {
        return Ok(());
    };
    let path = identity_path(home, id);
    #[cfg(not(windows))]
    if !entry_exists(&path)? {
        return Ok(());
    }
    let _authority = namespace::acquire_parents(vec![home.join(STORE)], true, true)?;
    let dir = io::directory(&path)?;
    microsandbox_utils::private_file::verify(&dir).map_err(|e| e.to_string())?;
    drop(dir);
    std::fs::remove_dir_all(&path).map_err(|e| format!("remove sandbox TLS identity: {e}"))?;
    #[cfg(unix)]
    io::directory(&home.join(STORE))?
        .sync_all()
        .map_err(|e| format!("sync TLS identity removal: {e}"))?;
    Ok(())
}
