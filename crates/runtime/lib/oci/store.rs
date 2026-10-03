//! Durable OCI state storage.

use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

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
        fs::create_dir_all(&self.root).map_err(|e| io_error("create directory", &self.root, e))?;
        match fs::create_dir(&state_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::AlreadyExists => {
                return Err(OciRuntimeError::AlreadyExists { id: id.to_string() });
            }
            Err(error) => return Err(io_error("create directory", &state_dir, error)),
        }

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
        if !dir.is_dir() {
            return Err(OciRuntimeError::NotFound {
                id: state.id.clone(),
            });
        }

        let path = dir.join(STATE_JSON);
        let json =
            serde_json::to_vec_pretty(state).map_err(|e| json_error("serialize", &path, e))?;
        let (mut tmp_file, tmp_path) = create_state_temp_file(&dir)?;
        tmp_file
            .write_all(&json)
            .map_err(|e| io_error("write", &tmp_path, e))?;
        tmp_file
            .sync_all()
            .map_err(|e| io_error("sync", &tmp_path, e))?;
        drop(tmp_file);

        if let Err(error) = fs::rename(&tmp_path, &path) {
            let _ = fs::remove_file(&tmp_path);
            return Err(io_error("rename", &path, error));
        }
        sync_directory(&dir)?;
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
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'));

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

fn create_state_temp_file(dir: &Path) -> OciResult<(File, PathBuf)> {
    for attempt in 0..128 {
        let tmp_path = dir.join(format!(
            ".{STATE_JSON}.{}.{}.tmp",
            std::process::id(),
            unique_temp_suffix(attempt)
        ));
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&tmp_path)
        {
            Ok(file) => return Ok((file, tmp_path)),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(io_error("create", &tmp_path, error)),
        }
    }

    let path = dir.join(format!(".{STATE_JSON}.tmp"));
    Err(io_error(
        "create",
        &path,
        std::io::Error::new(
            ErrorKind::AlreadyExists,
            "could not allocate unique state temp file",
        ),
    ))
}

fn unique_temp_suffix(attempt: u32) -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default()
        .saturating_add(attempt as u128)
}

#[cfg(unix)]
fn sync_directory(dir: &Path) -> OciResult<()> {
    let directory = File::open(dir).map_err(|e| io_error("open", dir, e))?;
    directory.sync_all().map_err(|e| io_error("sync", dir, e))
}

#[cfg(not(unix))]
fn sync_directory(_dir: &Path) -> OciResult<()> {
    Ok(())
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
        assert!(validate_container_id("abc_123-DEF.456+ghi").is_ok());
        assert!(validate_container_id("../abc").is_err());
        assert!(validate_container_id("a/b").is_err());
        assert!(validate_container_id("a\nb").is_err());
        assert!(validate_container_id("a b").is_err());
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

    #[test]
    fn save_does_not_recreate_deleted_container_directory() {
        let (_bundle_dir, bundle) = bundle();
        let state_root = TempDir::new().expect("state root");
        let store = OciStateStore::new(state_root.path());
        let state = store.create_created("abc123", &bundle).expect("create");
        fs::remove_dir_all(state_root.path().join("abc123")).expect("remove container dir");

        let err = store
            .save(&state)
            .expect_err("save should not recreate dir");

        assert!(matches!(err, OciRuntimeError::NotFound { .. }));
        assert!(!state_root.path().join("abc123").exists());
    }

    #[test]
    fn save_uses_unique_temp_files_without_leaving_shared_tmp() {
        let (_bundle_dir, bundle) = bundle();
        let state_root = TempDir::new().expect("state root");
        let store = OciStateStore::new(state_root.path());
        let state = store.create_created("abc123", &bundle).expect("create");

        store.save(&state).expect("save");

        assert!(
            !state_root
                .path()
                .join("abc123")
                .join("state.json.tmp")
                .exists()
        );
    }
}
