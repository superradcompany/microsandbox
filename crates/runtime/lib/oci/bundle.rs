//! OCI bundle parsing used by Microsandbox runtime integration.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use oci_spec::runtime::{Mount, Process, Spec};

use super::{OciResult, OciRuntimeError, io_error};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CONFIG_JSON: &str = "config.json";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// OCI bundle loaded from a host directory.
#[derive(Debug, Clone)]
pub struct OciBundle {
    /// Absolute path to the bundle directory.
    pub path: PathBuf,

    /// Parsed OCI `config.json`.
    pub spec: OciSpec,
}

/// OCI runtime specification parsed from `config.json`.
pub type OciSpec = Spec;

/// OCI process descriptor parsed from `config.json` or `process.json`.
pub type OciProcess = Process;

/// OCI mount descriptor parsed from `config.json`.
pub type OciMount = Mount;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OciBundle {
    /// Load and validate an OCI bundle from a directory.
    pub fn load(path: impl AsRef<Path>) -> OciResult<Self> {
        let path = absolutize_existing(path.as_ref())?;
        let config_path = path.join(CONFIG_JSON);
        let spec = OciSpec::load(&config_path).map_err(|e| OciRuntimeError::InvalidBundle {
            bundle: path.clone(),
            reason: format!(
                "failed to load `{}` with oci-spec: {e}",
                config_path.display()
            ),
        })?;

        let bundle = Self { path, spec };
        bundle.validate()?;
        Ok(bundle)
    }

    /// Resolve the OCI rootfs path to an absolute host path.
    pub fn rootfs_path(&self) -> PathBuf {
        let root = self
            .spec
            .root()
            .as_ref()
            .expect("validated OCI bundle must have a root filesystem");
        if root.path().is_absolute() {
            root.path().clone()
        } else {
            self.path.join(root.path())
        }
    }

    /// Return the OCI process configured for `start`, if present.
    pub fn process(&self) -> Option<&OciProcess> {
        self.spec.process().as_ref()
    }

    /// Return additional OCI mounts.
    pub fn mounts(&self) -> &[OciMount] {
        self.spec.mounts().as_deref().unwrap_or_default()
    }

    /// Return annotations as the deterministic map used by persisted OCI state.
    pub fn annotations(&self) -> BTreeMap<String, String> {
        self.spec
            .annotations()
            .as_ref()
            .map(|annotations| {
                annotations
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone()))
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Validate the bundle shape needed by Microsandbox's OCI layer.
    pub fn validate(&self) -> OciResult<()> {
        if self.spec.version().trim().is_empty() {
            return Err(OciRuntimeError::InvalidBundle {
                bundle: self.path.clone(),
                reason: "ociVersion must not be empty".to_string(),
            });
        }
        if self.spec.root().is_none() {
            return Err(OciRuntimeError::InvalidBundle {
                bundle: self.path.clone(),
                reason: "root must be present".to_string(),
            });
        }
        if let Some(process) = self.process() {
            validate_process(process, &self.path)?;
        }
        let rootfs = self.rootfs_path();
        if !rootfs.is_dir() {
            return Err(OciRuntimeError::InvalidBundle {
                bundle: self.path.clone(),
                reason: format!("rootfs `{}` is not a directory", rootfs.display()),
            });
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate process fields needed by Microsandbox's OCI execution layer.
pub fn validate_process(process: &OciProcess, bundle: &Path) -> OciResult<()> {
    if !process.cwd().is_absolute() {
        return Err(OciRuntimeError::InvalidBundle {
            bundle: bundle.to_path_buf(),
            reason: format!("process.cwd must be absolute: {}", process.cwd().display()),
        });
    }
    if process.args().as_deref().unwrap_or_default().is_empty() {
        return Err(OciRuntimeError::InvalidBundle {
            bundle: bundle.to_path_buf(),
            reason: "process.args must contain at least one entry".to_string(),
        });
    }
    Ok(())
}

fn absolutize_existing(path: &Path) -> OciResult<PathBuf> {
    std::fs::canonicalize(path).map_err(|e| io_error("canonicalize", path, e))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::TempDir;

    use super::*;

    #[test]
    fn load_resolves_relative_rootfs_against_bundle() {
        let temp = TempDir::new().expect("tempdir");
        let rootfs = temp.path().join("rootfs");
        fs::create_dir(&rootfs).expect("rootfs");
        fs::write(
            temp.path().join(CONFIG_JSON),
            r#"{
                "ociVersion": "1.2.0",
                "root": { "path": "rootfs" },
                "process": {
                    "user": { "uid": 0, "gid": 0 },
                    "cwd": "/",
                    "args": ["/bin/sh"],
                    "env": ["PATH=/bin"]
                },
                "annotations": {
                    "io.containerd.runtime.v2.task": "default/demo"
                }
            }"#,
        )
        .expect("config");

        let bundle = OciBundle::load(temp.path()).expect("load bundle");
        let rootfs = fs::canonicalize(rootfs).expect("canonical rootfs");

        assert_eq!(bundle.rootfs_path(), rootfs);
        assert_eq!(bundle.spec.version(), "1.2.0");
        assert_eq!(
            bundle.annotations()["io.containerd.runtime.v2.task"],
            "default/demo"
        );
    }

    #[test]
    fn load_rejects_relative_process_cwd() {
        let temp = TempDir::new().expect("tempdir");
        fs::create_dir(temp.path().join("rootfs")).expect("rootfs");
        fs::write(
            temp.path().join(CONFIG_JSON),
            r#"{
                "ociVersion": "1.2.0",
                "root": { "path": "rootfs" },
                "process": {
                    "user": { "uid": 0, "gid": 0 },
                    "cwd": "app",
                    "args": ["/bin/sh"]
                }
            }"#,
        )
        .expect("config");

        let err = OciBundle::load(temp.path()).expect_err("invalid cwd");

        assert!(err.to_string().contains("process.cwd must be absolute"));
    }
}
