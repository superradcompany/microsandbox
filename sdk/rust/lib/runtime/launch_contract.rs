//! Internal launch selection for released v0.6.x executables.

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use std::{
    collections::HashMap,
    fs::File,
    io::Read as _,
    path::{Path, PathBuf},
    process::Stdio,
    sync::LazyLock,
    time::{Duration, SystemTime},
};

use semver::Version;
use tokio::{io::AsyncReadExt, process::Command, sync::Mutex};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

static CONTRACTS: LazyLock<Mutex<HashMap<PathBuf, CachedContract>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
const PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_VERSION_OUTPUT: u64 = 4096;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LaunchContract {
    pub patch: u64,
    pub machine: bool,
}

#[derive(Debug, PartialEq, Eq)]
struct FileIdentity {
    object: (u64, u64, u64),
    size: u64,
    modified: SystemTime,
    #[cfg(unix)]
    changed: (i64, i64),
}

struct CachedContract {
    identity: FileIdentity,
    contract: LaunchContract,
    // Retain the object so deleting/replacing a path cannot recycle its file ID.
    _file: File,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LaunchContract {
    /// Live resource resizing and its launch capacity flags arrived in v0.6.4.
    pub fn validate_capacity(
        self,
        cpus: u8,
        max_cpus: u8,
        memory: u32,
        max_memory: u32,
    ) -> MicrosandboxResult<()> {
        if self.patch < 4 && (max_cpus > cpus || max_memory > memory) {
            return Err(MicrosandboxError::unsupported(
                crate::error::Operation::SandboxStart,
                crate::error::UnsupportedReason::NotAvailable(
                    "resource hotplug capacity requires runtime v0.6.4 or newer; use fixed CPU and memory sizes with this runtime".into(),
                ),
            ));
        }
        Ok(())
    }

    pub fn legacy_env(self) -> bool {
        self.patch < 10
    }
    #[cfg(any(unix, test))]
    pub fn lifecycle_lock_argument(self) -> bool {
        self.patch >= 9
    }
    pub fn resolved_network(self) -> bool {
        self.patch >= 17
    }

    fn from_version(version: &Version) -> MicrosandboxResult<Self> {
        if version.major == 0 && version.minor == 6 && version.patch <= 18 && version.pre.is_empty()
        {
            Ok(Self {
                patch: version.patch,
                machine: false,
            })
        } else {
            Err(MicrosandboxError::Runtime(format!(
                "no tested sandbox launch contract for runtime {version}"
            )))
        }
    }
}

impl FileIdentity {
    fn capture(file: &File) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        #[cfg(unix)]
        let object = (metadata.dev(), metadata.ino(), 0);
        #[cfg(windows)]
        let object = {
            let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
            // SAFETY: the file owns this handle; the API initializes `info` on success.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let info = unsafe { info.assume_init() };
            (
                u64::from(info.dwVolumeSerialNumber),
                u64::from(info.nFileIndexHigh),
                u64::from(info.nFileIndexLow),
            )
        };
        Ok(Self {
            object,
            size: metadata.len(),
            modified: metadata.modified()?,
            #[cfg(unix)]
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Identify the selected installation for catalog initialization/serialization.
/// Absence is not an installation request. Existing malformed overrides fail
/// closed, and the version probe has the same bounds as launch discovery.
pub(crate) async fn catalog_patch(
    config: &crate::config::GlobalConfig,
) -> MicrosandboxResult<Option<u64>> {
    let runtime = match crate::setup::resolve_runtime(config) {
        Ok(runtime) => runtime,
        Err(MicrosandboxError::RuntimeNotInstalled(_)) => return Ok(None),
        Err(error) => return Err(error),
    };
    let path = runtime.msb_path;
    let mut magic = [0; 2];
    let wrapper = File::open(&path)?.read(&mut magic)? == 2 && magic == *b"#!";
    let embedded = if wrapper {
        None
    } else {
        crate::setup::resolve_runtime_version(&path)?
    };
    let version = match embedded {
        Some(version) => version,
        None => probe(&path).await?,
    };
    if version.major == 0 && version.minor == 6 && version.patch <= 18 && version.pre.is_empty() {
        Ok(Some(version.patch))
    } else if version == Version::parse(env!("CARGO_PKG_VERSION")).expect("Cargo version is semver")
    {
        Ok(None)
    } else {
        Err(MicrosandboxError::Runtime(format!(
            "no tested catalog contract for runtime {version}"
        )))
    }
}

pub(super) async fn resolve(path: &Path) -> MicrosandboxResult<LaunchContract> {
    let path = std::fs::canonicalize(path)?;
    // Serialize cold discovery so concurrent starts share one probe. No failed
    // or canceled discovery is cached, and the lock is released on cancellation.
    let mut contracts = CONTRACTS.lock().await;
    let file = File::open(&path)?;
    let identity = FileIdentity::capture(&file)?;
    let mut magic = [0; 2];
    let wrapper = (&file).read(&mut magic)? == 2 && magic == *b"#!";

    if let Some(cached) = contracts
        .get(&path)
        .filter(|cached| !wrapper && cached.identity == identity)
    {
        return Ok(cached.contract);
    }
    let inspect_path = path.clone();
    let embedded = if wrapper {
        None
    } else {
        tokio::task::spawn_blocking(move || crate::setup::resolve_runtime_version(inspect_path))
            .await
            .map_err(|_| {
                MicrosandboxError::Runtime("runtime version inspection task failed".into())
            })??
    };
    let modern = embedded.is_some();
    let version = match embedded {
        Some(version) => version,
        None => probe(&path).await?,
    };
    let contract = if modern
        && version == Version::parse(env!("CARGO_PKG_VERSION")).expect("Cargo version is semver")
    {
        LaunchContract {
            patch: 18,
            machine: true,
        }
    } else {
        let mut contract = LaunchContract::from_version(&version)?;
        contract.machine = modern;
        contract
    };
    if FileIdentity::capture(&File::open(&path)?)? != identity
        || FileIdentity::capture(&file)? != identity
    {
        return Err(MicrosandboxError::Runtime(
            "runtime executable changed during launch discovery".into(),
        ));
    }
    // A wrapper can select another binary without changing itself. Keep support
    // for it, but do not cache an identity that says nothing about that target.
    if wrapper {
        return Ok(contract);
    }
    // Bound retained handles in long-running hosts that resolve many executables.
    if contracts.len() >= 64 {
        contracts.clear();
    }
    contracts.insert(
        path,
        CachedContract {
            identity,
            contract,
            _file: file,
        },
    );
    Ok(contract)
}

/// Probe only the new combination. Ordinary starts/restores keep their cached,
/// process-free discovery path, and old runtimes still accept their existing wire.
pub(super) async fn require_restore_backing(path: &Path) -> MicrosandboxResult<()> {
    let output = bounded_probe(path, "__launch-protocol").await?;
    let supported = serde_json::from_slice::<
        microsandbox_runtime::launch_protocol::LaunchCapabilities,
    >(&output)
    .is_ok_and(|capabilities| {
        capabilities.protocols.contains(&2) && capabilities.required_restore_backing
    });
    if !supported {
        return Err(MicrosandboxError::Runtime(
            microsandbox_runtime::launch_protocol::upgrade_required(
                "relaxed external-object validation with required resource backing",
            ),
        ));
    }
    Ok(())
}

async fn probe(path: &Path) -> MicrosandboxResult<Version> {
    parse_version(&bounded_probe(path, "--version").await?)
}

async fn bounded_probe(path: &Path, argument: &str) -> MicrosandboxResult<Vec<u8>> {
    let mut child = Command::new(path)
        .arg(argument)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()?;
    let output = child.stdout.take().ok_or_else(|| {
        MicrosandboxError::Runtime("runtime version probe has no output pipe".into())
    })?;
    let mut output = output.take(MAX_VERSION_OUTPUT + 1);
    let mut bytes = Vec::new();
    let outcome = tokio::time::timeout(PROBE_TIMEOUT, async {
        output.read_to_end(&mut bytes).await?;
        if bytes.len() as u64 > MAX_VERSION_OUTPUT {
            return Err(std::io::Error::other(
                "runtime version output exceeds limit",
            ));
        }
        child.wait().await
    })
    .await;
    let status = match outcome {
        Ok(Ok(status)) => status,
        other => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(MicrosandboxError::Runtime(
                if other.is_err() {
                    "runtime version probe timed out"
                } else {
                    "runtime version probe failed"
                }
                .into(),
            ));
        }
    };
    if !status.success() {
        return Err(MicrosandboxError::Runtime(
            "runtime version probe exited unsuccessfully".into(),
        ));
    }
    Ok(bytes)
}

fn parse_version(bytes: &[u8]) -> MicrosandboxResult<Version> {
    let parsed = std::str::from_utf8(bytes)
        .ok()
        .and_then(|text| text.trim().strip_prefix("msb "))
        .and_then(|value| Version::parse(value).ok());
    parsed.ok_or_else(|| MicrosandboxError::Runtime("unrecognized runtime version response".into()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[tokio::test]
    async fn required_backing_probe_distinguishes_old_and_capable_runtimes() {
        let dir = tempfile::tempdir().unwrap();
        let old = script(
            dir.path(),
            "old-capabilities",
            "printf '%s' '{\"protocols\":[2,1]}'",
        );
        let error = require_restore_backing(&old).await.unwrap_err().to_string();
        assert!(error.contains("upgrade msb"));
        assert!(error.contains("required resource backing"));
        let new = script(
            dir.path(),
            "new-capabilities",
            "printf '%s' '{\"protocols\":[2,1],\"required_restore_backing\":true}'",
        );
        require_restore_backing(&new).await.unwrap();
        let malformed = script(
            dir.path(),
            "malformed-capabilities",
            "printf '%s' '{\"protocols\":[2],\"required_restore_backing\":\"true\"}'",
        );
        assert!(require_restore_backing(&malformed).await.is_err());
    }

    #[cfg(unix)]
    fn script(dir: &Path, name: &str, body: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let path = dir.join(name);
        std::fs::write(&path, format!("#!/bin/sh\n{body}\n")).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        path
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn version_probe_is_bounded_and_never_exposes_output() {
        let dir = tempfile::tempdir().unwrap();
        let path = script(dir.path(), "valid", "printf 'msb 0.6.4\\n'");
        assert_eq!(probe(&path).await.unwrap(), Version::new(0, 6, 4));
        let path = script(dir.path(), "invalid", "printf secret-marker");
        assert!(
            !probe(&path)
                .await
                .unwrap_err()
                .to_string()
                .contains("secret-marker")
        );
        let path = script(dir.path(), "large", "exec /usr/bin/head -c 8192 /dev/zero");
        assert!(probe(&path).await.is_err());
        let path = script(dir.path(), "slow", "exec /bin/sleep 10");
        let start = std::time::Instant::now();
        assert!(
            probe(&path)
                .await
                .unwrap_err()
                .to_string()
                .contains("timed out")
        );
        assert!(start.elapsed() < Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn a_wrapper_is_reprobed_when_its_target_changes() {
        let dir = tempfile::tempdir().unwrap();
        let version = dir.path().join("version");
        std::fs::write(&version, "msb 0.6.4").unwrap();
        let path = script(
            dir.path(),
            "wrapper",
            &format!("exec /bin/cat '{}'", version.display()),
        );
        assert_eq!(resolve(&path).await.unwrap().patch, 4);
        std::fs::write(&version, "msb 0.6.9").unwrap();
        assert_eq!(resolve(&path).await.unwrap().patch, 9);
    }

    #[tokio::test]
    #[ignore = "requires MSB_LAUNCH_CONTRACT_BINARY naming a real released runtime"]
    async fn released_runtime_contract_and_warm_resolution() {
        let path = PathBuf::from(std::env::var_os("MSB_LAUNCH_CONTRACT_BINARY").unwrap());
        let start = std::time::Instant::now();
        let contract = resolve(&path).await.unwrap();
        let cold = start.elapsed();
        let start = std::time::Instant::now();
        for _ in 0..100 {
            assert_eq!(resolve(&path).await.unwrap(), contract);
        }
        eprintln!(
            "launch contract patch={} cold_us={} warm_mean_us={}",
            contract.patch,
            cold.as_micros(),
            start.elapsed().as_micros() / 100
        );
        assert!(
            CONTRACTS
                .lock()
                .await
                .contains_key(&std::fs::canonicalize(path).unwrap())
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn canceled_discovery_releases_the_cache_and_terminates_its_probe() {
        let dir = tempfile::tempdir().unwrap();
        let pid_path = dir.path().join("probe.pid");
        let path = script(
            dir.path(),
            "slow",
            &format!("echo $$ > '{}'; exec /bin/sleep 30", pid_path.display()),
        );
        let task = tokio::spawn(async move { resolve(&path).await });
        let pid: i32 = tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                // Creation precedes the shell's write, so wait for a complete PID.
                if let Ok(contents) = std::fs::read_to_string(&pid_path)
                    && let Ok(pid) = contents.trim().parse()
                {
                    break pid;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        task.abort();
        assert!(task.await.unwrap_err().is_cancelled());
        let valid = script(dir.path(), "valid", "printf 'msb 0.6.4\\n'");
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(5), resolve(&valid))
                .await
                .unwrap()
                .unwrap()
                .patch,
            4
        );
        tokio::time::timeout(Duration::from_secs(2), async {
            // Signal zero checks existence without sending a signal; only this
            // test's recorded probe PID is inspected.
            while unsafe { libc::kill(pid, 0) } == 0 {
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
    }

    #[tokio::test]
    #[ignore = "requires MSB_LAUNCH_CONTRACT_OLD/NEW actual v0.6.4 and v0.6.9 runtime fixtures"]
    async fn released_binary_replacement_invalidates_concurrent_cached_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir
            .path()
            .join(if cfg!(windows) { "msb.exe" } else { "msb" });
        let replacement = dir.path().join("replacement");
        std::fs::copy(std::env::var_os("MSB_LAUNCH_CONTRACT_OLD").unwrap(), &path).unwrap();
        let (a, b) = tokio::join!(resolve(&path), resolve(&path));
        assert_eq!(a.unwrap().patch, 4);
        assert_eq!(b.unwrap().patch, 4);
        std::fs::copy(
            std::env::var_os("MSB_LAUNCH_CONTRACT_NEW").unwrap(),
            &replacement,
        )
        .unwrap();
        std::fs::rename(replacement, &path).unwrap();
        let (a, b) = tokio::join!(resolve(&path), resolve(&path));
        assert_eq!(a.unwrap().patch, 9);
        assert_eq!(b.unwrap().patch, 9);
        let canonical = std::fs::canonicalize(path).unwrap();
        CONTRACTS.lock().await.remove(&canonical);
    }

    #[test]
    fn released_contract_boundaries_are_explicit() {
        for patch in 0..=18 {
            let contract = LaunchContract::from_version(&Version::new(0, 6, patch)).unwrap();
            assert!(contract.validate_capacity(1, 1, 256, 256).is_ok());
            assert_eq!(
                contract.validate_capacity(1, 2, 256, 256).is_ok(),
                patch >= 4
            );
            assert_eq!(
                contract.validate_capacity(1, 1, 256, 512).is_ok(),
                patch >= 4
            );
            assert_eq!(contract.legacy_env(), patch < 10);
            assert_eq!(contract.lifecycle_lock_argument(), patch >= 9);
            assert_eq!(contract.resolved_network(), patch >= 17);
        }
        for version in ["0.5.0", "0.7.0", "0.6.19", "0.6.9-preview"] {
            assert!(LaunchContract::from_version(&Version::parse(version).unwrap()).is_err());
        }
        assert_eq!(
            parse_version(b"msb 0.6.4\r\n").unwrap(),
            Version::new(0, 6, 4)
        );
        assert!(parse_version(b"secret invalid").is_err());
    }
}
