//! Durable OCI state storage.

use std::fs;
use std::path::{Path, PathBuf};

use chrono::Utc;

use super::{
    MicrosandboxState, OciBundle, OciResult, OciRuntimeError, OciState, io_error, json_error,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const STATE_JSON: &str = "state.json";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Filesystem-backed OCI state store.
///
/// The root directory is normally supplied by the OCI runtime CLI's `--root`
/// option. Each container ID owns one subdirectory containing `state.json`
/// and Microsandbox runtime metadata.
#[derive(Debug, Clone)]
pub struct OciStateStore {
    root: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OciStateStore {
    /// Create a state store rooted at the supplied directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Return the state store root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Return the private state directory for a container ID.
    pub fn container_dir(&self, id: &str) -> OciResult<PathBuf> {
        validate_container_id(id)?;
        Ok(self.root.join(id))
    }

    /// Return the `state.json` path for a container ID.
    pub fn state_path(&self, id: &str) -> OciResult<PathBuf> {
        Ok(self.container_dir(id)?.join(STATE_JSON))
    }

    /// Create initial `created` state for a container.
    pub fn create_created(&self, id: &str, bundle: &OciBundle) -> OciResult<OciState> {
        let state_dir = self.container_dir(id)?;
        if state_dir.exists() {
            return Err(OciRuntimeError::AlreadyExists { id: id.to_string() });
        }

        fs::create_dir_all(&state_dir).map_err(|e| io_error("create directory", &state_dir, e))?;

        let microsandbox = MicrosandboxState::new(
            sandbox_name_for_container(id),
            &state_dir,
            bundle.rootfs_path(),
            Utc::now(),
        );
        let state = OciState::created(
            id,
            bundle.spec.version().clone(),
            bundle.path.clone(),
            bundle.annotations(),
            microsandbox,
        );
        self.save(&state)?;
        Ok(state)
    }

    /// Load the current state for a container.
    pub fn load(&self, id: &str) -> OciResult<OciState> {
        let path = self.state_path(id)?;
        if !path.exists() {
            return Err(OciRuntimeError::NotFound { id: id.to_string() });
        }
        let data = fs::read_to_string(&path).map_err(|e| io_error("read", &path, e))?;
        serde_json::from_str(&data).map_err(|e| json_error("parse", &path, e))
    }

    /// Atomically save state for a container.
    pub fn save(&self, state: &OciState) -> OciResult<()> {
        validate_container_id(&state.id)?;
        let dir = self.container_dir(&state.id)?;
        fs::create_dir_all(&dir).map_err(|e| io_error("create directory", &dir, e))?;

        let path = dir.join(STATE_JSON);
        let tmp_path = dir.join(format!("{STATE_JSON}.tmp"));
        let json =
            serde_json::to_vec_pretty(state).map_err(|e| json_error("serialize", &path, e))?;
        fs::write(&tmp_path, json).map_err(|e| io_error("write", &tmp_path, e))?;
        fs::rename(&tmp_path, &path).map_err(|e| io_error("rename", &path, e))?;
        Ok(())
    }

    /// Delete all state for a stopped container.
    pub fn delete(&self, id: &str) -> OciResult<()> {
        let dir = self.container_dir(id)?;
        if !dir.exists() {
            return Err(OciRuntimeError::NotFound { id: id.to_string() });
        }
        fs::remove_dir_all(&dir).map_err(|e| io_error("remove directory", &dir, e))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate a container ID for safe use as a state-directory name.
pub fn validate_container_id(id: &str) -> OciResult<()> {
    let valid = !id.is_empty()
        && id != "."
        && id != ".."
        && !id.contains('/')
        && !id.contains('\\')
        && !id.bytes().any(|b| b == 0);

    if valid {
        Ok(())
    } else {
        Err(OciRuntimeError::InvalidContainerId { id: id.to_string() })
    }
}

/// Return the Microsandbox sandbox name derived from an OCI container ID.
pub fn sandbox_name_for_container(id: &str) -> String {
    format!("oci-{id}")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::super::OciStatus;
    use super::*;

    fn bundle() -> (TempDir, OciBundle) {
        let temp = TempDir::new().expect("tempdir");
        fs::create_dir(temp.path().join("rootfs")).expect("rootfs");
        fs::write(
            temp.path().join("config.json"),
            r#"{
                "ociVersion": "1.2.0",
                "root": { "path": "rootfs" },
                "process": {
                    "user": { "uid": 0, "gid": 0 },
                    "cwd": "/",
                    "args": ["/bin/sh"]
                }
            }"#,
        )
        .expect("config");

        let bundle = OciBundle::load(temp.path()).expect("bundle");
        (temp, bundle)
    }

    #[test]
    fn create_created_persists_loadable_state() {
        let (_bundle_dir, bundle) = bundle();
        let state_root = TempDir::new().expect("state root");
        let store = OciStateStore::new(state_root.path());

        let state = store
            .create_created("abc123", &bundle)
            .expect("create state");
        let loaded = store.load("abc123").expect("load state");

        assert_eq!(loaded, state);
        assert_eq!(loaded.status, OciStatus::Created);
        assert_eq!(
            loaded
                .microsandbox
                .as_ref()
                .map(|msb| msb.sandbox_name.as_str()),
            Some("oci-abc123")
        );
    }

    #[test]
    fn create_created_rejects_duplicate_ids() {
        let (_bundle_dir, bundle) = bundle();
        let state_root = TempDir::new().expect("state root");
        let store = OciStateStore::new(state_root.path());

        store
            .create_created("abc123", &bundle)
            .expect("first create");
        let err = store
            .create_created("abc123", &bundle)
            .expect_err("duplicate should fail");

        assert!(matches!(err, OciRuntimeError::AlreadyExists { .. }));
    }

    #[test]
    fn container_id_must_not_escape_state_root() {
        assert!(validate_container_id("abc123").is_ok());
        assert!(validate_container_id("../abc").is_err());
        assert!(validate_container_id("a/b").is_err());
        assert!(validate_container_id("").is_err());
    }

    #[test]
    fn delete_removes_container_state_directory() {
        let (_bundle_dir, bundle) = bundle();
        let state_root = TempDir::new().expect("state root");
        let store = OciStateStore::new(state_root.path());
        store.create_created("abc123", &bundle).expect("create");

        store.delete("abc123").expect("delete");

        assert!(!state_root.path().join("abc123").exists());
    }
}
