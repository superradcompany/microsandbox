//! Persistent record of a sandbox's pre-relay-ready startup failure.
//!
//! When the sandbox process exits non-zero before the agent relay becomes
//! available, the parent CLI's `wait_for_relay` only sees "process exited";
//! it has no access to the sandbox's stderr (which is captured into
//! `runtime.log` by [`crate::vm`]). To bridge that gap, the sandbox
//! process atomically writes a small JSON record to `boot-error.json`
//! before exiting; the parent reads it and surfaces a real cause inline.
//!
//! Lifecycle:
//!
//! - **Written** at most once per failed start, atomically (`.tmp` +
//!   `rename`), in the same `log_dir` as `runtime.log`/`kernel.log`.
//! - **Read** by the parent CLI's `wait_for_relay` after detecting that
//!   the sandbox process has exited.
//! - **Deleted** by the parent CLI on the next successful relay-ready,
//!   so a stale file from a previous attempt cannot misattribute a
//!   later failure.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::RuntimeError;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Filename written into `log_dir`.
pub const BOOT_ERROR_FILENAME: &str = "boot-error.json";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Coarse classification of where in startup the failure occurred.
///
/// The CLI uses this together with `errno` to map known patterns to
/// actionable hints. `Other` is the catch-all when no single phase fits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootErrorStage {
    /// Volume / virtiofs mount setup failed.
    Mount,

    /// `VmBuilder::build()` or `Vm::enter()` returned an error.
    BuildVm,

    /// Bad MSB_* env, malformed boot params, database setup, etc.
    Config,

    /// Network backend setup, port allocation, smoltcp wiring.
    Network,

    /// Rootfs not found, image layer missing, disk format unreadable.
    Image,

    /// No specific stage fits.
    Other,
}

/// Structured payload persisted to `boot-error.json`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootError {
    /// RFC 3339 wall-clock timestamp at the moment of write.
    pub t: String,

    /// Coarse stage classification.
    pub stage: BootErrorStage,

    /// `errno` if the underlying failure was a syscall, else `None`.
    pub errno: Option<i32>,

    /// Human-readable message — the same string that goes to `runtime.log`.
    pub message: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BootError {
    /// Build a `BootError` from a runtime error, classifying its stage by
    /// inspecting the message and any chained `io::Error`.
    pub fn from_runtime_error(err: &RuntimeError) -> Self {
        let message = err.to_string();
        let errno = extract_errno(err);
        let stage = classify_stage(&message);
        Self {
            t: now_rfc3339(),
            stage,
            errno,
            message,
        }
    }

    /// Path to the boot-error file inside `log_dir`.
    pub fn path_in(log_dir: &Path) -> PathBuf {
        log_dir.join(BOOT_ERROR_FILENAME)
    }

    /// Atomically write the record to `<log_dir>/boot-error.json`.
    ///
    /// Writes to a sibling `.tmp` file then renames over the target so a
    /// reader never observes a half-written file.
    pub fn write_atomic(&self, log_dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(log_dir)?;
        let final_path = Self::path_in(log_dir);
        let tmp_path = log_dir.join(format!("{BOOT_ERROR_FILENAME}.tmp"));
        let json = serde_json::to_vec_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&tmp_path, &json)?;
        std::fs::rename(&tmp_path, &final_path)?;
        Ok(())
    }

    /// Read the record from `<log_dir>/boot-error.json` if present.
    ///
    /// Returns `Ok(None)` if the file does not exist; returns `Err` only
    /// for unexpected I/O failures or malformed JSON.
    pub fn read(log_dir: &Path) -> std::io::Result<Option<Self>> {
        let path = Self::path_in(log_dir);
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e),
        };
        let value = serde_json::from_slice(&bytes).map_err(std::io::Error::other)?;
        Ok(Some(value))
    }

    /// Delete the record if present. A missing file is not an error.
    pub fn delete(log_dir: &Path) -> std::io::Result<()> {
        let path = Self::path_in(log_dir);
        match std::fs::remove_file(&path) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn extract_errno(err: &RuntimeError) -> Option<i32> {
    match err {
        RuntimeError::Io(io_err) => io_err.raw_os_error(),
        RuntimeError::Nix(errno) => Some(*errno as i32),
        // The Custom variant flattens io::Error into a string of the
        // form `"... (os error N)"`. Recover N when present so hints
        // can still key off errno without invasive refactoring of
        // every error site in `vm.rs`.
        _ => parse_os_error_suffix(&err.to_string()),
    }
}

/// Pull the `N` out of a trailing `"(os error N)"` if any.
fn parse_os_error_suffix(message: &str) -> Option<i32> {
    let needle = "(os error ";
    let start = message.rfind(needle)? + needle.len();
    let rest = &message[start..];
    let end = rest.find(')')?;
    rest[..end].parse().ok()
}

/// Classify by message prefix. The error sites in `vm.rs` use a small
/// set of stable prefixes (e.g. `mount {tag}: ...`, `build VM: ...`,
/// `database connect: ...`) so substring matching is reliable enough
/// without invasive changes to every error site.
fn classify_stage(message: &str) -> BootErrorStage {
    let lower = message.to_ascii_lowercase();

    if lower.starts_with("build vm")
        || lower.contains("vm enter")
        || lower.contains("tokio runtime")
    {
        return BootErrorStage::BuildVm;
    }

    if lower.starts_with("mount ")
        || lower.starts_with("runtime mount")
        || lower.contains("virtiofs")
    {
        return BootErrorStage::Mount;
    }

    if lower.starts_with("rootfs")
        || lower.contains("trampoline rootfs")
        || lower.contains("disk format")
        || lower.contains("image not found")
    {
        return BootErrorStage::Image;
    }

    if lower.contains("network")
        || lower.contains("bind ")
        || lower.contains("address already in use")
        || lower.contains("smoltcp")
    {
        return BootErrorStage::Network;
    }

    if lower.starts_with("database")
        || lower.starts_with("serialize startup")
        || lower.starts_with("insert run")
        || lower.starts_with("mark run failed")
        || lower.contains("config parse")
        || lower.contains("invalid config")
    {
        return BootErrorStage::Config;
    }

    BootErrorStage::Other
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_known_prefixes() {
        assert_eq!(
            classify_stage("mount var_lib_doc_ce73cd33: No such file or directory"),
            BootErrorStage::Mount
        );
        assert_eq!(
            classify_stage("build VM: kernel image read failed"),
            BootErrorStage::BuildVm
        );
        assert_eq!(
            classify_stage("rootfs: not found at /Users/.../rootfs"),
            BootErrorStage::Image
        );
        assert_eq!(
            classify_stage("database connect: timed out"),
            BootErrorStage::Config
        );
        assert_eq!(
            classify_stage("bind 0.0.0.0:8080: Address already in use"),
            BootErrorStage::Network
        );
        assert_eq!(
            classify_stage("something completely unexpected"),
            BootErrorStage::Other
        );
    }

    #[test]
    fn write_read_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let err = BootError {
            t: "2026-04-30T20:32:59.690Z".to_string(),
            stage: BootErrorStage::Mount,
            errno: Some(2),
            message: "mount foo: No such file or directory (os error 2)".to_string(),
        };
        err.write_atomic(dir.path()).unwrap();

        let read = BootError::read(dir.path()).unwrap().unwrap();
        assert_eq!(read.stage, BootErrorStage::Mount);
        assert_eq!(read.errno, Some(2));
        assert_eq!(read.t, err.t);
        assert_eq!(read.message, err.message);
    }

    #[test]
    fn read_missing_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let read = BootError::read(dir.path()).unwrap();
        assert!(read.is_none());
    }

    #[test]
    fn delete_missing_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        BootError::delete(dir.path()).unwrap();
    }

    #[test]
    fn errno_extraction_from_io_error() {
        let io_err = std::io::Error::from_raw_os_error(2);
        let rt_err = RuntimeError::Io(io_err);
        assert_eq!(extract_errno(&rt_err), Some(2));
    }

    #[test]
    fn errno_extraction_from_custom_with_os_error_suffix() {
        let rt_err = RuntimeError::Custom(
            "mount tmp_x_2e56aa36: No such file or directory (os error 2)".into(),
        );
        assert_eq!(extract_errno(&rt_err), Some(2));
    }

    #[test]
    fn errno_extraction_from_custom_without_suffix() {
        let rt_err = RuntimeError::Custom("plain message".into());
        assert_eq!(extract_errno(&rt_err), None);
    }
}
