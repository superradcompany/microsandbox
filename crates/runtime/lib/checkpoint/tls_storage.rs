//! Lifecycle cleanup for host-owned sandbox credentials, including on clients built without networking.
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use super::migration::{io, namespace};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(super) const STORE: &str = "sandbox-tls";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Keep the sandbox catalog ID as the sole source of the key location. Names
/// can be reused and callers can supply arbitrary custom certificate paths.
pub(super) fn identity_path(home: &Path, id: i32) -> PathBuf {
    home.join(STORE).join(id.to_string())
}

/// Called while holding catalog ownership of the ID, before releasing its row.
pub fn remove_sandbox_identity(home: &Path, id: i32) -> Result<(), String> {
    let path = identity_path(home, id);
    match path.symlink_metadata() {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(format!("inspect sandbox TLS identity: {e}")),
        Ok(_) => {}
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
