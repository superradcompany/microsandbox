//! Select, validate, and encode the launch contract for an installed runtime.

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

#[cfg(feature = "net")]
use microsandbox_network::policy::{Action, Destination, Direction};
use microsandbox_protocol::bootstrap::*;
use microsandbox_runtime::launch::{LaunchCapabilities, LaunchConfig};
use microsandbox_types::compat as types_compat;
use microsandbox_types::{
    CpuPlacement, RootDisk, RootfsSource, TransparentHugePagePolicy, VolumeMount,
};
use semver::Version;
use serde_json::{Value, json};
use tokio::{io::AsyncReadExt, process::Command, sync::Mutex};
#[cfg(windows)]
use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};

use crate::runtime::launch_input::{legacy_env, unsupported};
use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig, config::GlobalConfig};

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

/// Selected process-launch contract. Previous patch numbers are v0.6.x releases.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LaunchContract {
    /// Previous runtime patch used for feature boundaries.
    pub patch: u64,
    /// Whether the executable uses the current `machine` entry point.
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
    /// Check unresolved network intent against the selected launch contract.
    /// Source values are resolved only when building the final launch payload.
    #[cfg(feature = "net")]
    pub(crate) fn validate_network(
        self,
        network: &microsandbox_network::config::NetworkConfig,
        profile: microsandbox_types::DeploymentProfile,
    ) -> MicrosandboxResult<()> {
        network.secrets.validate().map_err(|error| {
            MicrosandboxError::InvalidConfig(format!("invalid secret configuration: {error}"))
        })?;
        if self.machine {
            return Ok(());
        }
        if network.max_udp_connections.is_some() {
            return unsupported("UDP connection limits");
        }
        if let Some(limit) = network.max_tcp_connections {
            let Some(cap) = limit.cap() else {
                return unsupported("unlimited network connections");
            };
            if cap.get() > 4096 {
                return unsupported("network connection limits above 4096");
            }
            if profile == microsandbox_types::DeploymentProfile::MultiTenant && cap.get() > 256 {
                return unsupported("multi-tenant network connection limits above 256");
            }
        }
        if self.patch < 18
            && network.strict
            && network.policy.rules.iter().any(|rule| {
                rule.action == Action::Allow
                    && matches!(rule.direction, Direction::Egress | Direction::Any)
                    && matches!(
                        rule.destination,
                        Destination::Domain(_) | Destination::DomainSuffix(_)
                    )
            })
        {
            return unsupported("strict network authority");
        }
        if self.patch < 9 && network.rate_limiter.is_some() {
            return unsupported("network rate limits");
        }
        if self.patch < 17 && network.outbound_proxy.is_some() {
            return unsupported("outbound proxy");
        }
        let mut secrets = serde_json::to_value(&network.secrets)?;
        types_compat::v0_5_0::local::secrets::to_previous_version(
            secrets
                .as_object_mut()
                .expect("secret configuration object"),
        )
        .map_err(|reason| MicrosandboxError::InvalidConfig(reason.into()))?;
        Ok(())
    }

    /// Encode a launch for the selected executable without discarding unsupported intent.
    pub(crate) fn encode(self, launch: &LaunchConfig) -> MicrosandboxResult<Value> {
        #[cfg(feature = "net")]
        if let Some(network) = &launch.network {
            self.validate_network(network.config(), launch.deployment_profile)?;
        }
        if !self.machine {
            return self.to_previous_version(launch);
        }

        let value = serde_json::to_value(launch)?;
        #[cfg(feature = "net")]
        let value = {
            let mut value = value;
            if let Some(source) = launch
                .network
                .as_ref()
                .map(|network| &network.config().secrets)
            {
                value["network"]["config"]["secrets"] = serde_json::to_value(
                    types_compat::v0_7_0::local::secrets::to_previous_version(source),
                )?;
            }
            value
        };

        Ok(value)
    }

    fn to_previous_version(self, launch: &LaunchConfig) -> MicrosandboxResult<Value> {
        if launch.execution != microsandbox_runtime::launch::ExecutionIntent::Boot {
            return unsupported("execution restore");
        }
        if !launch.owned_volumes.is_empty() {
            return unsupported("sandbox-owned volumes");
        }
        if self.patch < 16 && !launch.file_mounts.is_empty() {
            return unsupported("isolated file mounts");
        }
        #[cfg(feature = "net")]
        if self.patch >= 16 && u64::from(launch.sandbox_slot) > u64::from(u16::MAX) {
            return unsupported("network slot outside the previous 16-bit range");
        }
        if !launch.rootfs.disk_layers.is_empty() || !launch.rootfs.upper_layers.is_empty() {
            return unsupported("layered execution restore");
        }
        let mut value = serde_json::to_value(launch)?;
        let fields = value.as_object_mut().expect("launch config object");
        for key in ["execution", "checkpoint_restore", "memory_cache_dir"] {
            fields.remove(key);
        }
        let rootfs = fields["rootfs"].as_object_mut().expect("rootfs object");
        for key in ["disk_layers", "upper_layers", "disk_runtime_owned"] {
            rootfs.remove(key);
        }
        if self.legacy_env() {
            if self.patch < 9 {
                if launch.cpu_placement != CpuPlacement::Inherit
                    || launch.placement_profile_name.is_some()
                    || launch.placement_profile.is_some()
                {
                    return unsupported("CPU placement");
                }
                if launch.thp != TransparentHugePagePolicy::Madvise {
                    return unsupported("transparent huge-page policy");
                }
                if !launch.vsock.is_empty() {
                    return unsupported("host socket forwarding");
                }
                if launch.rootfs.upper_format.is_some() {
                    return unsupported("custom root-disk format");
                }
                if matches!(
                    launch.bootstrap.block_root,
                    Some(BootstrapBlockRoot::OciErofs {
                        upper: BootstrapBlockRootUpper::Tmpfs { .. },
                        ..
                    })
                ) {
                    return unsupported("RAM-backed root disk");
                }
                #[cfg(feature = "net")]
                if launch.deployment_profile != microsandbox_types::DeploymentProfile::default() {
                    return unsupported("deployment profile");
                }
            }
            let env = legacy_env(&launch.bootstrap)?;
            value["env"] = json!(env);
            value["workdir"] = json!(launch.bootstrap.default_cwd);
            // Keep the typed input too: a compatible future entry point can consume
            // it without reintroducing delimiter constraints into its guest transport.
        }
        #[cfg(feature = "net")]
        if !self.resolved_network() && !value["network"].is_null() {
            if !value["network"]["outbound_proxy"].is_null() {
                return unsupported("outbound proxy");
            }
            value["network"] = value["network"]["config"].take();
        }
        #[cfg(feature = "net")]
        if !value["network"].is_null() {
            // Previous releases used the previous secret-policy field names.
            let network = if self.resolved_network() {
                &mut value["network"]["config"]
            } else {
                &mut value["network"]
            };
            // Explicit UDP values were rejected above; omit the new optional key
            // entirely when encoding a previous producer's network object.
            if let Some(fields) = network.as_object_mut() {
                fields.remove("max_udp_connections");
            }
            // Pin the previous default at the boundary; omission on the current contract
            // intentionally has a different meaning and must not broaden an old launch.
            if network["max_connections"].is_null() {
                network["max_connections"] = json!(256);
            }
            if let Some(secrets) = network.get_mut("secrets").and_then(Value::as_object_mut) {
                types_compat::v0_5_0::local::secrets::to_previous_version(secrets)
                    .map_err(|reason| MicrosandboxError::InvalidConfig(reason.into()))?;
            }
        }
        Ok(value)
    }

    /// Whether the previous launcher accepts a lifecycle lock descriptor.
    #[cfg(any(unix, test))]
    pub(crate) fn lifecycle_lock_argument(self) -> bool {
        self.patch >= 9
    }
    /// Whether guest settings use the previous environment transport.
    pub(crate) fn legacy_env(self) -> bool {
        self.patch < 10
    }
    /// Whether network settings use a resolved envelope.
    pub(crate) fn resolved_network(self) -> bool {
        self.patch >= 17
    }

    /// Validate CPU and memory expansion capacity carried in launch arguments.
    /// Live resizing requires v0.6.4 or a current runtime contract.
    pub(crate) fn validate_capacity(
        self,
        cpus: u8,
        max_cpus: u8,
        memory: u32,
        max_memory: u32,
    ) -> MicrosandboxResult<()> {
        if !self.machine && self.patch < 4 && (max_cpus > cpus || max_memory > memory) {
            return Err(MicrosandboxError::unsupported(
                crate::error::Operation::SandboxStart,
                crate::error::UnsupportedReason::NotAvailable(
                "resource hotplug capacity requires runtime v0.6.4 or newer; use fixed CPU and memory sizes with this runtime".into()),
            ));
        }
        Ok(())
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

    /// Check SDK launch intent before preparation can replace an existing sandbox.
    pub(crate) fn validate_launch_intent(self, config: &SandboxConfig) -> MicrosandboxResult<()> {
        #[cfg(feature = "net")]
        self.validate_network(
            &config.local_network_config()?,
            config.spec.deployment_profile,
        )?;
        if self.machine {
            return Ok(());
        }
        let resources = &config.spec.resources;

        self.validate_capacity(
            resources.cpus,
            resources.max_cpus,
            resources.memory_mib,
            resources.max_memory_mib,
        )?;
        if config.checkpoint_restore.is_some()
            || config.branch_source.is_some()
            || !config.snapshot_upper_layers.is_empty()
            || !config.snapshot_root_layer_sources.is_empty()
        {
            return Err(MicrosandboxError::Runtime(
                "checkpoint restore, branch, or disk chains require a newer runtime launch contract"
                    .into(),
            ));
        }
        let launch = LaunchConfig {
            bootstrap: crate::runtime::spawn::guest_bootstrap(config),
            cpu_placement: resources.cpu_placement,
            placement_profile_name: resources.placement_profile.clone(),
            thp: resources.thp,
            vsock: config.spec.vsock.routes.clone(),
            owned_volumes: config
                .spec
                .mounts
                .iter()
                .filter(|mount| matches!(mount, VolumeMount::Owned { .. }))
                .cloned()
                .collect(),
            #[cfg(feature = "net")]
            deployment_profile: config.spec.deployment_profile,
            ..Default::default()
        };
        if self.patch < 7
            && matches!(
                config.spec.image,
                RootfsSource::Bind {
                    follow_root_symlinks: true,
                    ..
                }
            )
        {
            return Err(MicrosandboxError::Runtime(
                "root symlink traversal requires a newer runtime launch contract".into(),
            ));
        }
        if self.patch < 9
            && let RootfsSource::Oci(oci) = &config.spec.image
            && matches!(
                &oci.root_disk,
                Some(RootDisk::Flat { .. } | RootDisk::Tmpfs { .. } | RootDisk::DiskImage { .. })
            )
        {
            return Err(MicrosandboxError::Runtime(
                "custom root disk requires a newer runtime launch contract".into(),
            ));
        }
        // These mount settings are supplied after host-side mount resolution, so
        // reject unsupported intent before replacement as well as at launch.
        for mount in &config.spec.mounts {
            if self.patch < 16
                && let VolumeMount::Bind { host, .. } = mount
                && host.is_file()
            {
                return unsupported("isolated file mounts");
            }
            let (options, follow_root_symlinks) = match mount {
                VolumeMount::Bind {
                    options,
                    follow_root_symlinks,
                    ..
                }
                | VolumeMount::Named {
                    options,
                    follow_root_symlinks,
                    ..
                } => (options, *follow_root_symlinks),
                VolumeMount::Owned { options, .. }
                | VolumeMount::Tmpfs { options, .. }
                | VolumeMount::DiskImage { options, .. } => (options, false),
            };
            if (self.patch < 7 && follow_root_symlinks)
                || (self.patch < 15
                    && (options.override_uid.is_some() || options.override_gid.is_some()))
            {
                return Err(MicrosandboxError::Runtime(
                    "mount options require a newer runtime launch contract".into(),
                ));
            }
        }
        self.encode(&launch)?;
        Ok(())
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

/// Check launch intent before create can replace an existing sandbox.
/// Host paths, named volumes and network slots are checked again in the final encoder.
pub(crate) async fn validate_runtime_config(
    config: &SandboxConfig,
    global: &GlobalConfig,
) -> MicrosandboxResult<()> {
    #[cfg(feature = "net")]
    config
        .local_network_config()?
        .secrets
        .validate()
        .map_err(|error| {
            MicrosandboxError::InvalidConfig(format!("invalid secret configuration: {error}"))
        })?;
    let runtime = match crate::setup::resolve_runtime(global) {
        Ok(runtime) => runtime,
        Err(MicrosandboxError::RuntimeNotInstalled(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    resolve(&runtime.msb_path)
        .await?
        .validate_launch_intent(config)
}

pub(crate) async fn resolve(path: &Path) -> MicrosandboxResult<LaunchContract> {
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
pub(crate) async fn require_restore_backing(path: &Path) -> MicrosandboxResult<()> {
    let output = bounded_probe(path, "__launch-protocol").await?;
    let supported =
        serde_json::from_slice::<LaunchCapabilities>(&output).is_ok_and(|capabilities| {
            capabilities.protocols.contains(&2) && capabilities.required_restore_backing
        });
    if !supported {
        return Err(MicrosandboxError::Runtime(upgrade_required(
            "relaxed external-object validation with required resource backing",
        )));
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

/// A consistent, actionable refusal for features that cannot be downgraded.
fn upgrade_required(feature: &str) -> String {
    format!(
        "selected msb runtime does not support {feature}; \
        upgrade msb in the configured home or select a newer runtime explicitly"
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn launch_checks_ignore_sdk_only_saved_metadata() {
        let mut config = crate::test_support::fixtures::decode(include_str!(
            "../db/fixtures/config-0.6.18.json"
        ))
        .unwrap();
        config.snapshot_parent = Some("parent-snapshot".into());
        LaunchContract {
            patch: 18,
            machine: false,
        }
        .validate_launch_intent(&config)
        .unwrap();
    }

    #[cfg(feature = "net")]
    #[test]
    fn launch_checks_preserve_secret_sources_and_reject_unsupported_network_intent() {
        let mut config = crate::test_support::fixtures::decode(include_str!(
            "../db/fixtures/config-0.6.18-secret-default.json"
        ))
        .unwrap();
        config.spec.network.secrets.as_mut().unwrap().secrets[0].source =
            Some(microsandbox_types::SecretSource::Env {
                var: "MSB_PREFLIGHT_DOES_NOT_RESOLVE_THIS_SOURCE".into(),
            });
        let contract = LaunchContract {
            patch: 18,
            machine: false,
        };
        contract.validate_launch_intent(&config).unwrap();
        config.spec.network.max_udp_connections = Some(50);
        assert!(
            contract
                .validate_launch_intent(&config)
                .unwrap_err()
                .to_string()
                .contains("UDP connection limits")
        );
    }

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
        // Keep writable script descriptors out of the test process: concurrent
        // forks can inherit them and make Linux exec fail with ETXTBSY.
        let status = std::process::Command::new("/bin/sh")
            .arg("-c")
            .arg("printf '%s\\n' '#!/bin/sh' \"$1\" > \"$2\"")
            .arg("write-launch-probe-fixture")
            .arg(body)
            .arg(&path)
            .status()
            .unwrap();
        assert!(status.success());
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod encoding {
    use super::*;
    use microsandbox_runtime::launch::LaunchConfig;
    use serde_json::{Value, json};

    #[test]
    fn capacity_support_follows_the_selected_contract() {
        for patch in 0..=18 {
            let contract = LaunchContract {
                patch,
                machine: false,
            };
            assert!(contract.validate_capacity(1, 1, 256, 256).is_ok());
            assert_eq!(
                contract.validate_capacity(1, 2, 256, 256).is_ok(),
                patch >= 4
            );
            assert_eq!(
                contract.validate_capacity(1, 1, 256, 512).is_ok(),
                patch >= 4
            );
        }
        let current = LaunchContract {
            patch: 0,
            machine: true,
        };
        assert!(current.validate_capacity(1, 2, 256, 512).is_ok());
    }

    #[cfg(feature = "net")]
    fn saved_secret_policy() -> microsandbox_types::SecretsConfig {
        let config = crate::test_support::fixtures::decode(include_str!(
            "../db/fixtures/config-0.6.18-secret-default.json"
        ))
        .unwrap();
        config.spec.network.secrets.unwrap()
    }

    #[cfg(feature = "net")]
    #[test]
    fn current_launch_projects_legacy_secrets_without_capability_fields() {
        use microsandbox_network::config::{EnvNetworkSecretResolver, NetworkConfig};
        let mut source = saved_secret_policy();
        source.passthrough_hosts = Some(vec![microsandbox_types::HostPattern::Exact(
            "global.example".into(),
        )]);
        let original = serde_json::to_value(&source).unwrap();
        let network: NetworkConfig = serde_json::from_value(json!({"secrets":source})).unwrap();
        let launch = LaunchConfig {
            network: Some(network.resolve(&EnvNetworkSecretResolver).unwrap()),
            ..Default::default()
        };
        let wire = LaunchContract {
            patch: 18,
            machine: true,
        }
        .encode(&launch)
        .unwrap();
        let secrets = &wire["network"]["config"]["secrets"];
        assert!(secrets.get("passthrough_hosts").is_none());
        assert_eq!(
            secrets["secrets"][0]["substitution"]
                .as_object()
                .unwrap()
                .len(),
            3
        );
        let projected: microsandbox_types::SecretsConfig =
            serde_json::from_value(secrets.clone()).unwrap();
        assert!(projected.secrets[0].passthrough_hosts.contains(
            &microsandbox_types::HostPattern::Exact("global.example".into())
        ));
        for allowed in &source.secrets[0].allowed_hosts {
            assert!(!projected.secrets[0].passthrough_hosts.contains(allowed));
        }
        assert_eq!(serde_json::to_value(&source).unwrap(), original);
        // The original global default still applies to a subsequently added entry.
        let mut added = source.secrets[0].clone();
        added.env_var = "ADDED".into();
        added.placeholder = "$ADDED".into();
        source.secrets.push(added);
        assert!(
            types_compat::v0_7_0::local::secrets::to_previous_version(&source).secrets[1]
                .passthrough_hosts
                .contains(&microsandbox_types::HostPattern::Exact(
                    "global.example".into()
                ))
        );
    }

    #[cfg(feature = "net")]
    #[test]
    fn projection_preserves_overrides_and_does_not_share_explicit_passthrough() {
        use microsandbox_types::{HostPattern, SecretViolationAction};
        let mut source = saved_secret_policy();
        source.passthrough_hosts = Some(vec![HostPattern::Exact("global.example".into())]);
        source.secrets[0].passthrough_hosts = vec![HostPattern::Exact("entry.example".into())];
        let mut other = source.secrets[0].clone();
        other.env_var = "OTHER".into();
        other.allowed_hosts = vec![HostPattern::Exact("other.example".into())];
        other.passthrough_hosts.clear();
        other.violation_action = Some(SecretViolationAction::BlockAndTerminate);
        source.secrets.push(other);
        let output = types_compat::v0_7_0::local::secrets::to_previous_version(&source);
        assert!(
            !output.secrets[0]
                .passthrough_hosts
                .contains(&HostPattern::Exact("other.example".into()))
        );
        assert!(
            !output.secrets[1]
                .passthrough_hosts
                .contains(&HostPattern::Exact("global.example".into()))
        );
        assert!(
            !output.secrets[1]
                .passthrough_hosts
                .contains(&HostPattern::Exact("entry.example".into()))
        );
        assert_eq!(
            output.secrets[1].violation_action,
            Some(SecretViolationAction::BlockAndTerminate)
        );
    }

    #[cfg(feature = "net")]
    #[test]
    fn projection_never_invents_wildcard_permission_or_enabled_scopes() {
        use microsandbox_types::HostPattern;
        let mut source = saved_secret_policy();
        source.secrets[0].allowed_hosts = vec![HostPattern::Any];
        source.secrets[0].substitution.headers = false;
        source.secrets[0].substitution.query = false;
        source.secrets[0].substitution.body = false;
        let output = types_compat::v0_7_0::local::secrets::to_previous_version(&source);
        assert!(output.secrets[0].passthrough_hosts.is_empty());
        assert!(!output.secrets[0].substitution.headers);
        assert!(!output.secrets[0].substitution.query);
        assert!(!output.secrets[0].substitution.body);
        source.secrets[0].passthrough_hosts.push(HostPattern::Any);
        assert_eq!(
            types_compat::v0_7_0::local::secrets::to_previous_version(&source).secrets[0]
                .passthrough_hosts,
            vec![HostPattern::Any]
        );
    }

    #[cfg(feature = "net")]
    #[test]
    fn udp_limits_require_current_launch_contract() {
        use microsandbox_network::config::{EnvNetworkSecretResolver, NetworkConfig};

        for requested in [None, Some(0), Some(1), Some(256), Some(4097)] {
            let network: NetworkConfig = serde_json::from_value(json!({
                "max_connections": 8,
                "max_udp_connections": requested,
            }))
            .unwrap();
            let launch = LaunchConfig {
                network: Some(network.resolve(&EnvNetworkSecretResolver).unwrap()),
                ..Default::default()
            };
            let current = LaunchContract {
                patch: 18,
                machine: true,
            }
            .encode(&launch)
            .unwrap();
            assert_eq!(current["network"]["config"]["max_connections"], 8);
            assert_eq!(
                current["network"]["config"]["max_udp_connections"],
                json!(requested)
            );
            assert!(
                current["network"]["config"]
                    .get("max_tcp_connections")
                    .is_none()
            );
            for patch in 0..=18 {
                let result = LaunchContract {
                    patch,
                    machine: false,
                }
                .encode(&launch);
                if requested.is_some() {
                    assert!(
                        result
                            .unwrap_err()
                            .to_string()
                            .contains("UDP connection limits")
                    );
                } else {
                    let value = result.unwrap();
                    let network = if patch >= 17 {
                        &value["network"]["config"]
                    } else {
                        &value["network"]
                    };
                    assert_eq!(network["max_connections"], 8);
                    assert!(network.get("max_udp_connections").is_none());
                }
            }
        }
    }

    #[cfg(feature = "net")]
    #[test]
    fn legacy_network_limits_reject_changed_meanings_before_launch() {
        use microsandbox_network::config::{EnvNetworkSecretResolver, NetworkConfig};
        use microsandbox_types::DeploymentProfile;

        for profile in [
            DeploymentProfile::SingleTenant,
            DeploymentProfile::MultiTenant,
        ] {
            for requested in [
                None,
                Some(0),
                Some(1),
                Some(256),
                Some(257),
                Some(4096),
                Some(4097),
            ] {
                let network: NetworkConfig =
                    serde_json::from_value(json!({"max_connections": requested})).unwrap();
                let launch = LaunchConfig {
                    network: Some(network.resolve(&EnvNetworkSecretResolver).unwrap()),
                    deployment_profile: profile,
                    ..Default::default()
                };
                // Current runtimes implement every explicit value, including zero/unlimited.
                assert_eq!(
                    LaunchContract {
                        patch: 18,
                        machine: true
                    }
                    .encode(&launch)
                    .unwrap(),
                    serde_json::to_value(&launch).unwrap(),
                );

                for patch in 0..=18 {
                    if profile == DeploymentProfile::MultiTenant && patch < 9 {
                        // Those releases predate deployment profiles entirely.
                        continue;
                    }
                    let result = LaunchContract {
                        patch,
                        machine: false,
                    }
                    .encode(&launch);
                    let unsupported = requested.is_some_and(|limit| {
                        limit == 0
                            || limit > 4096
                            || (profile == DeploymentProfile::MultiTenant && limit > 256)
                    });
                    if unsupported {
                        let error = result.unwrap_err().to_string();
                        assert!(error.contains("network connection"), "{error}");
                        assert!(error.contains("newer runtime launch contract"), "{error}");
                    } else {
                        let value = result.unwrap();
                        let network = if patch >= 17 {
                            &value["network"]["config"]
                        } else {
                            &value["network"]
                        };
                        // Omission pins the previous default. Representable explicit
                        // budgets must survive the previous launch transformation.
                        assert_eq!(network["max_connections"], json!(requested.unwrap_or(256)));
                    }
                }
            }
        }
    }

    #[test]
    fn owned_storage_is_never_silently_dropped_for_released_runtimes() {
        let launch = LaunchConfig {
            owned_volumes: vec![microsandbox_types::VolumeMount::Owned {
                guest: "/data".into(),
                storage: microsandbox_types::OwnedVolumeStorage::Directory { quota_mib: None },
                options: Default::default(),
                stat_virtualization: microsandbox_types::StatVirtualization::Strict,
                host_permissions: microsandbox_types::HostPermissions::Private,
            }],
            ..Default::default()
        };
        for patch in 0..=18 {
            assert!(
                LaunchContract {
                    patch,
                    machine: false
                }
                .encode(&launch)
                .unwrap_err()
                .to_string()
                .contains("sandbox-owned volumes")
            );
        }
        assert_eq!(
            LaunchContract {
                patch: 18,
                machine: true
            }
            .encode(&launch)
            .unwrap(),
            serde_json::to_value(&launch).unwrap()
        );
    }

    #[test]
    fn legacy_input_retains_guest_root_mounts_environment_and_cwd() {
        let mut launch = LaunchConfig::default();
        launch.bootstrap = GuestBootstrap {
            block_root: Some(BootstrapBlockRoot::OciErofs {
                lower: "/dev/vda".into(),
                upper: BootstrapBlockRootUpper::Device {
                    device: "/dev/vdb".into(),
                    fstype: "ext4".into(),
                },
            }),
            dir_mounts: vec![BootstrapDirMount {
                tag: "work".into(),
                guest_path: "/work".into(),
                flags: BootstrapMountFlags {
                    readonly: true,
                    noexec: true,
                    ..Default::default()
                },
            }],
            default_env: vec![BootstrapEnvVar {
                key: "APP".into(),
                value: "value=with spaces".into(),
            }],
            default_cwd: Some("/work".into()),
            security_profile: BootstrapSecurityProfile::Restricted,
            ..Default::default()
        };
        for patch in [0, 4, 8, 9] {
            let value = LaunchContract {
                patch,
                machine: false,
            }
            .encode(&launch)
            .unwrap();
            let env: Vec<String> = serde_json::from_value(value["env"].clone()).unwrap();
            assert!(env.contains(&"MSB_BLOCK_ROOT=kind=oci-erofs,lower=/dev/vda,upper=/dev/vdb,upper_fstype=ext4".into()));
            assert!(env.contains(&"MSB_DIR_MOUNTS=work:/work:ro,noexec".into()));
            assert!(env.contains(&"APP=value=with spaces".into()));
            assert!(env.contains(&"MSB_SECURITY_PROFILE=restricted".into()));
            assert_eq!(value["workdir"], "/work");
        }
    }

    #[test]
    fn typed_values_are_preserved_and_legacy_delimiter_collisions_fail() {
        let mut launch = LaunchConfig::default();
        launch.bootstrap.dir_mounts.push(BootstrapDirMount {
            tag: "x".into(),
            guest_path: "/data:ro;injected:/x".into(),
            flags: Default::default(),
        });
        assert!(
            LaunchContract {
                patch: 4,
                machine: false
            }
            .encode(&launch)
            .is_err()
        );
        assert_eq!(
            LaunchContract {
                patch: 10,
                machine: false
            }
            .encode(&launch)
            .unwrap()["bootstrap"],
            serde_json::to_value(&launch.bootstrap).unwrap()
        );
        launch.bootstrap.dir_mounts.clear();
        for value in ["non-ascii-雪", "a\"b", "a\nb"] {
            launch.bootstrap.default_env = vec![BootstrapEnvVar {
                key: "APP".into(),
                value: value.into(),
            }];
            let error = LaunchContract {
                patch: 9,
                machine: false,
            }
            .encode(&launch)
            .unwrap_err()
            .to_string();
            assert!(!error.contains(value));
        }
    }

    #[cfg(feature = "net")]
    #[test]
    fn newer_resolved_network_shape_keeps_the_original_policy() {
        let launch = LaunchConfig {
            network: Some(
                microsandbox_network::config::NetworkConfig::default()
                    .resolve(&microsandbox_network::config::EnvNetworkSecretResolver)
                    .unwrap(),
            ),
            ..Default::default()
        };
        let expected = serde_json::to_value(&launch.network).unwrap();
        for patch in [17, 18] {
            let value = LaunchContract {
                patch,
                machine: false,
            }
            .encode(&launch)
            .unwrap();
            let mut expected = expected.clone();
            expected["config"]["max_connections"] = json!(256);
            expected["config"]
                .as_object_mut()
                .unwrap()
                .remove("max_udp_connections");
            if let Some(secrets) = expected["config"]
                .get_mut("secrets")
                .and_then(Value::as_object_mut)
            {
                if let Some(action) = secrets.remove("violation_action") {
                    secrets.insert("on_violation".into(), action);
                }
            }
            assert_eq!(value["network"], expected);
            assert!(value["network"]["outbound_proxy"].is_null());
        }
    }
}

#[cfg(test)]
mod protocol {
    use crate::SandboxConfig;
    use crate::runtime::launch_contract::LaunchContract;
    use microsandbox_runtime::compat::launch::decode_legacy;
    use microsandbox_runtime::launch::{ExecutionIntent, LaunchConfig};
    use serde_json::{Value, json};

    const LEGACY: LaunchContract = LaunchContract {
        patch: 18,
        machine: false,
    };

    fn encode_bytes(config: &LaunchConfig, contract: LaunchContract) -> Result<Vec<u8>, String> {
        let value = contract.encode(config).map_err(|error| error.to_string())?;
        serde_json::to_vec(&value).map_err(|error| error.to_string())
    }

    #[test]
    fn sdk_encoder_round_trips_through_runtime_for_every_supported_release() {
        for patch in 0..=18 {
            let mut config = LaunchConfig {
                agent_sock: "/tmp/agent.sock".into(),
                ..Default::default()
            };
            config
                .bootstrap
                .default_env
                .push(microsandbox_protocol::bootstrap::BootstrapEnvVar {
                    key: "APP_MODE".into(),
                    value: "test".into(),
                });
            config.bootstrap.default_cwd = Some("/work".into());
            let bytes = encode_bytes(
                &config,
                LaunchContract {
                    patch,
                    machine: false,
                },
            )
            .unwrap();
            let decoded =
                decode_legacy(&bytes).unwrap_or_else(|error| panic!("v0.6.{patch}: {error}"));
            assert_eq!(decoded.agent_sock, config.agent_sock, "v0.6.{patch}");
            assert_eq!(
                decoded.bootstrap.default_cwd, config.bootstrap.default_cwd,
                "v0.6.{patch}"
            );
            assert!(
                decoded
                    .bootstrap
                    .default_env
                    .iter()
                    .any(|entry| entry.key == "APP_MODE" && entry.value == "test"),
                "v0.6.{patch}"
            );
        }
    }

    #[test]
    fn legacy_boot_round_trip_keeps_paths_and_startup() {
        let config = LaunchConfig {
            agent_sock: "/tmp/agent.sock".into(),
            ..Default::default()
        };
        let bytes = encode_bytes(&config, LEGACY).unwrap();
        assert!(LaunchConfig::decode(&bytes).is_err());
        assert_eq!(decode_legacy(&bytes).unwrap().agent_sock, config.agent_sock);
        assert!(
            !serde_json::from_slice::<Value>(&bytes)
                .unwrap()
                .as_object()
                .unwrap()
                .contains_key("execution")
        );
    }

    #[test]
    fn modern_payload_cannot_be_reinterpreted_as_legacy() {
        let bytes = serde_json::to_vec(&LaunchConfig::default()).unwrap();
        assert!(decode_legacy(&bytes).unwrap_err().contains("boot-only"));
        let mut value: Value =
            serde_json::from_slice(&encode_bytes(&LaunchConfig::default(), LEGACY).unwrap())
                .unwrap();
        value["checkpoint_restore"] = Value::Null;
        assert!(decode_legacy(&serde_json::to_vec(&value).unwrap()).is_err());
    }

    #[test]
    fn disk_chains_cannot_be_silently_dropped() {
        let mut config = LaunchConfig::default();
        config
            .rootfs
            .disk_layers
            .push(microsandbox_runtime::launch::RootfsUpperLayerConfig {
                path: "/tmp/disk".into(),
                format: "qcow2".into(),
            });
        assert!(
            encode_bytes(&config, LEGACY)
                .unwrap_err()
                .contains("requires a newer runtime launch contract")
        );
    }

    #[test]
    fn legacy_codec_refuses_valid_restore_and_new_file_mount_features() {
        let config = LaunchConfig {
            execution: ExecutionIntent::Restore,
            checkpoint_restore: Some(microsandbox_runtime::launch::CheckpointRestoreConfig {
                closure: "/tmp/checkpoint".into(),
                checkpoint_root: "blake3:root".into(),
                checkpoint_id: "saved".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        assert!(
            encode_bytes(&config, LEGACY)
                .unwrap_err()
                .contains("requires a newer runtime launch contract")
        );
        assert!(
            encode_bytes(
                &config,
                LaunchContract {
                    patch: 18,
                    machine: true
                }
            )
            .is_ok()
        );
        let config = LaunchConfig {
            file_mounts: vec![microsandbox_runtime::launch::FileMountConfig {
                mount: "tag:/tmp/file".into(),
                filename: "file".into(),
            }],
            ..Default::default()
        };
        let old = LaunchContract {
            patch: 15,
            machine: false,
        };
        assert!(
            encode_bytes(&config, old)
                .unwrap_err()
                .contains("isolated file mounts")
        );
        for patch in 16..=18 {
            let bytes = encode_bytes(
                &config,
                LaunchContract {
                    patch,
                    machine: false,
                },
            )
            .unwrap();
            let decoded = decode_legacy(&bytes).unwrap();
            assert_eq!(decoded.file_mounts.len(), 1);
            assert_eq!(decoded.file_mounts[0].filename, "file");
        }
    }

    #[cfg(feature = "net")]
    #[test]
    fn migrated_all_disabled_secrets_are_rejected_before_launch() {
        let mut config = SandboxConfig::default();
        let network = serde_json::from_value(json!({"secrets":{"secrets":[{
            "env_var":"KEY", "placeholder":"$KEY", "value":"private-marker",
            "allowed_hosts":[{"exact":"example.com"}],
            "substitution":{"headers":false,"query":false,"body":false}
        }]}}))
        .unwrap();
        config.set_local_network_config(network).unwrap();
        for machine in [false, true] {
            let error = LaunchContract { patch: 18, machine }
                .validate_launch_intent(&config)
                .unwrap_err()
                .to_string();
            assert!(
                error.contains("at least one substitution location"),
                "{error}"
            );
            assert!(!error.contains("private-marker"));
        }
    }

    #[cfg(feature = "net")]
    #[test]
    fn strict_hostname_allows_require_a_capable_launch_contract() {
        use microsandbox_network::config::{EnvNetworkSecretResolver, NetworkConfig};
        use microsandbox_network::policy::{Action, Destination, Direction, NetworkPolicy, Rule};

        let encode = |launch: &LaunchConfig, contract: LaunchContract| contract.encode(launch);

        for destination in [
            Destination::Any,
            Destination::Cidr("203.0.113.0/24".parse().unwrap()),
            Destination::Domain("example.com".parse().unwrap()),
            Destination::DomainSuffix("example.com".parse().unwrap()),
        ] {
            for direction in [Direction::Ingress, Direction::Egress, Direction::Any] {
                for action in [Action::Allow, Action::Deny] {
                    for strict in [true, false] {
                        let network = NetworkConfig {
                            strict,
                            policy: NetworkPolicy {
                                rules: vec![Rule {
                                    direction,
                                    action,
                                    ..Rule::allow_egress(destination.clone())
                                }],
                                ..NetworkPolicy::default()
                            },
                            ..NetworkConfig::default()
                        };
                        let launch = LaunchConfig {
                            network: Some(network.resolve(&EnvNetworkSecretResolver).unwrap()),
                            ..Default::default()
                        };
                        let needs_strict = strict
                            && action == Action::Allow
                            && direction != Direction::Ingress
                            && matches!(
                                destination,
                                Destination::Domain(_) | Destination::DomainSuffix(_)
                            );
                        for patch in 0..=18 {
                            let result = encode(
                                &launch,
                                LaunchContract {
                                    patch,
                                    machine: false,
                                },
                            );
                            if needs_strict && patch < 18 {
                                assert!(
                                    result
                                        .unwrap_err()
                                        .to_string()
                                        .contains("strict network authority")
                                );
                            } else {
                                let value = result.unwrap();
                                let network = if patch >= 17 {
                                    &value["network"]["config"]
                                } else {
                                    &value["network"]
                                };
                                assert_eq!(network["strict"], strict);
                            }
                        }
                        assert_eq!(
                            encode(
                                &launch,
                                LaunchContract {
                                    patch: 18,
                                    machine: true
                                }
                            )
                            .unwrap(),
                            serde_json::to_value(&launch).unwrap(),
                        );
                    }
                }
            }
        }
    }

    #[cfg(feature = "net")]
    #[test]
    fn flat_network_round_trip_preserves_disabled_network() {
        let mut value = serde_json::to_value(LaunchConfig::default()).unwrap();
        value["network"] = serde_json::json!({"config": {"enabled": false, "strict": false}, "outbound_proxy": null});
        let config: LaunchConfig = serde_json::from_value(value).unwrap();
        let bytes = encode_bytes(
            &config,
            LaunchContract {
                patch: 15,
                machine: false,
            },
        )
        .unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&bytes).unwrap()["network"]["enabled"],
            false
        );
        assert!(
            !decode_legacy(&bytes)
                .unwrap()
                .network
                .unwrap()
                .config()
                .enabled
        );
    }
}
