//! Per-sandbox private single-slot metrics files.
//!
//! When `runtime.private_metrics` is enabled on Linux, each sandbox receives its
//! own single-slot metrics file under `run/runtime-metrics/<name>` instead of
//! sharing the host-level `/dev/shm` registry.

use std::path::{Path, PathBuf};

use sha2::{Digest, Sha256};

#[cfg(target_os = "linux")]
use std::{
    ffi::CString,
    fs,
    io::{self, Write},
    os::unix::fs::PermissionsExt,
};

#[cfg(target_os = "linux")]
use microsandbox_metrics::{IdentifiedMetric, MetricsRegistry, ReserveSlot, SlotReservation};

#[cfg(target_os = "linux")]
use crate::{
    MicrosandboxError, MicrosandboxResult,
    host_file::{self, HostFileAccess, HostFileKind, HostFilePolicy},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Subdirectory under `run_dir` holding private per-sandbox metrics files.
const PRIVATE_METRICS_SUBDIR: &str = "runtime-metrics";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Deterministic POSIX shm name handed to the runtime for a sandbox's private
/// single-slot metrics registry.
pub(crate) fn shm_name(sandbox_name: &str) -> String {
    let digest = hex::encode(Sha256::digest(sandbox_name.as_bytes()));
    format!("/msb-met-{}", &digest[..20])
}

/// Host path of a sandbox's private metrics file under `run_dir`.
pub(crate) fn metrics_path(run_dir: &Path, sandbox_name: &str) -> PathBuf {
    run_dir.join(PRIVATE_METRICS_SUBDIR).join(sandbox_name)
}

/// Initialize and atomically install a private single-slot metrics file for a
/// sandbox launch, returning `(shm_name, slot, generation)`.
#[cfg(target_os = "linux")]
pub(crate) fn install(
    run_dir: &Path,
    sandbox_id: i32,
    sandbox_name: &str,
    memory_limit_bytes: u64,
) -> MicrosandboxResult<(String, u32, u64)> {
    struct ShmUnlinkGuard(CString);

    impl Drop for ShmUnlinkGuard {
        fn drop(&mut self) {
            // SAFETY: `self.0` is a valid NUL-terminated C string.
            unsafe {
                libc::shm_unlink(self.0.as_ptr());
            }
        }
    }

    let dir = run_dir.join(PRIVATE_METRICS_SUBDIR);
    fs::create_dir_all(&dir)?;
    fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;

    let tmp_shm = format!(
        "/msb-pmet-{}-{:016x}",
        std::process::id(),
        rand::random::<u64>()
    );
    let c_shm = CString::new(tmp_shm.as_str())
        .map_err(|err| MicrosandboxError::Runtime(format!("private metrics shm name: {err}")))?;
    let _unlink = ShmUnlinkGuard(c_shm);

    let registry = MetricsRegistry::open_or_create(&tmp_shm, 1).map_err(|err| {
        MicrosandboxError::Runtime(format!("private metrics registry init: {err}"))
    })?;
    let SlotReservation { slot, generation } = registry
        .reserve(ReserveSlot {
            sandbox_id,
            name: sandbox_name,
            memory_limit_bytes,
        })
        .map_err(|err| MicrosandboxError::Runtime(format!("private metrics reserve: {err}")))?;

    let shm_file = Path::new("/dev/shm").join(tmp_shm.trim_start_matches('/'));
    let bytes = fs::read(&shm_file)?;
    drop(registry);
    drop(_unlink);

    let mut temp = tempfile::NamedTempFile::new_in(&dir)?;
    fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o600))?;
    temp.write_all(&bytes)?;
    temp.flush()?;
    temp.persist(dir.join(sandbox_name))
        .map_err(|err| MicrosandboxError::Io(err.error))?;

    Ok((shm_name(sandbox_name), slot, generation))
}

/// Read a bounded snapshot from a sandbox's private metrics file.
#[cfg(target_os = "linux")]
pub(crate) fn read(
    home: &Path,
    run_dir: &Path,
    sandbox_name: &str,
    include_exited: bool,
) -> MicrosandboxResult<Option<Vec<IdentifiedMetric>>> {
    let path = metrics_path(run_dir, sandbox_name);
    let policy = HostFilePolicy::strict_beneath(home.to_path_buf());
    let file = match host_file::open(
        &path,
        HostFileKind::Regular,
        HostFileAccess::ReadOnly,
        &policy,
    ) {
        Ok(file) => file,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err.into()),
    };

    let registry = MetricsRegistry::read_file_snapshot(&file)
        .map_err(|err| MicrosandboxError::Custom(format!("private metrics snapshot: {err}")))?;
    Ok(Some(registry.identified_snapshot(include_exited)))
}

/// Remove a sandbox's private metrics file if present.
#[cfg(target_os = "linux")]
pub(crate) fn remove(run_dir: &Path, sandbox_name: &str) -> io::Result<()> {
    match fs::remove_file(metrics_path(run_dir, sandbox_name)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shm_name_is_deterministic_and_bounded() {
        let name = shm_name("example-sandbox");
        assert!(name.starts_with("/msb-met-"));
        assert_eq!(name.len(), "/msb-met-".len() + 20);
        assert_eq!(name, shm_name("example-sandbox"));
        assert_ne!(name, shm_name("other-sandbox"));
    }

    #[test]
    fn metrics_path_places_file_under_runtime_metrics() {
        let path = metrics_path(Path::new("/tmp/home/run"), "demo");
        assert_eq!(path, PathBuf::from("/tmp/home/run/runtime-metrics/demo"));
    }
}
