//! Configuration schema for the microsandbox library.
//!
//! [`GlobalConfigPatch`] reads and writes sparse user settings in `config.json`.
//! [`GlobalConfig`] holds resolved settings after defaults and patches are applied.
//! [`LocalBackend`](crate::backend::LocalBackend) owns the configuration layers
//! and caches their resolved values. Accessors live on
//! explicit backend instances, with [`config`] providing an ambient
//! helper for the active local backend. See D6.7 Layer 2a in
//! `planning/microsandbox/design/api/local-cloud-backend.md`.
//!
//! Layer 1 process-wide knobs ([`set_sdk_msb_path`],
//! [`set_sdk_libkrunfw_path`]) stay in this module — they are documented as
//! process-singleton-by-physics (one dylib per process address space,
//! one resolved `msb` binary).

pub(crate) mod backend;
pub(crate) mod layers;
mod persistence;
mod registry;

use std::{
    collections::{BTreeMap, HashMap},
    num::NonZero,
    path::PathBuf,
    sync::{Arc, OnceLock},
};

use microsandbox_types::SandboxLogLevel as LogLevel;
use microsandbox_types::{
    ConfigPatch, CpuPlacement, DeploymentProfile, OutboundProxy, PlacementProfile, RootDisk,
    TransparentHugePagePolicy,
};
use serde::{Deserialize, Serialize};

use crate::backend::Profile;
#[cfg(feature = "local")]
use crate::error::Operation;
use crate::{MicrosandboxError, MicrosandboxResult};
#[cfg(test)]
use std::path::Path;

mod runtime_paths;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default number of vCPUs per sandbox.
pub(crate) const DEFAULT_CPUS: u8 = 1;

/// Default guest memory in MiB.
pub(crate) const DEFAULT_MEMORY_MIB: u32 = 512;

/// Default database max connections.
pub(crate) const DEFAULT_MAX_CONNECTIONS: u32 = 5;

/// Default database connection acquisition timeout in seconds.
pub(crate) const DEFAULT_CONNECT_TIMEOUT_SECS: u64 = 30;

/// Default sandbox metrics sampling interval in milliseconds.
pub const DEFAULT_METRICS_SAMPLE_INTERVAL_MS: u64 = 1000;

/// Default SSH session inactivity timeout in seconds.
pub const DEFAULT_SSH_INACTIVITY_TIMEOUT_SECS: u64 = 600;

/// Default value for `metrics_sample_interval_ms` fields.
pub fn default_metrics_sample_interval() -> Option<NonZero<u64>> {
    NonZero::new(DEFAULT_METRICS_SAMPLE_INTERVAL_MS)
}

/// Serde adapter mapping the `metrics_sample_interval_ms` wire format `u64` to `Option<NonZero<u64>>` (`0` ↔ `None`).
pub(crate) mod metrics_interval_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::num::NonZero;

    pub fn serialize<S: Serializer>(v: &Option<NonZero<u64>>, s: S) -> Result<S::Ok, S::Error> {
        v.map(|n| n.get()).unwrap_or(0).serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<NonZero<u64>>, D::Error> {
        Ok(NonZero::new(u64::deserialize(d)?))
    }
}

/// Serde adapter for the human-facing deployment profile names used in `config.json`.
///
/// Sandbox wire data uses snake_case, while the CLI and SDKs expose kebab-case
/// names. Accepting both forms keeps existing serialized values readable and
/// gives the hand-edited global config one canonical spelling.
mod deployment_profile_serde {
    use microsandbox_types::DeploymentProfile;
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub fn serialize<S: Serializer>(
        profile: &Option<DeploymentProfile>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        match profile {
            Some(DeploymentProfile::SingleTenant) => serializer.serialize_some("single-tenant"),
            Some(DeploymentProfile::MultiTenant) => serializer.serialize_some("multi-tenant"),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<DeploymentProfile>, D::Error> {
        match Option::<String>::deserialize(deserializer)?.as_deref() {
            Some("single-tenant" | "single_tenant") => Ok(Some(DeploymentProfile::SingleTenant)),
            Some("multi-tenant" | "multi_tenant") => Ok(Some(DeploymentProfile::MultiTenant)),
            Some(other) => Err(D::Error::custom(format!(
                "unknown deployment profile {other:?}; expected `single-tenant` or `multi-tenant`"
            ))),
            None => Ok(None),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Statics: Layer 1 (process-level)
//--------------------------------------------------------------------------------------------------

/// Explicit process-level executable override, below `MSB_PATH` and above
/// configuration and filesystem candidates. Package discovery uses its own fallback.
static SDK_MSB_PATH: OnceLock<PathBuf> = OnceLock::new();

/// Explicit process-level firmware override set via [`set_sdk_libkrunfw_path`].
static SDK_LIBKRUNFW_PATH: OnceLock<PathBuf> = OnceLock::new();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Resolved global configuration for backend selection, sandbox defaults, and host settings.
///
/// Produced by applying configuration patches to built-in defaults.
/// Use [`GlobalConfigPatch::load`] and [`GlobalConfigPatch::save`] to edit saved user settings.
/// Backends retain their configuration sources for the lifetime of the instance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(Default, ConfigPatch)]
#[config_patch(serde)]
pub struct GlobalConfig {
    /// Profile selected when no backend or profile is explicitly requested.
    /// Empty or absent uses the local backend fallback.
    pub active_profile: Option<String>,

    /// Named local or cloud backend profiles.
    #[config_patch(merge)]
    pub profiles: HashMap<String, Profile>,

    /// Root directory for all microsandbox data.
    pub home: Option<PathBuf>,

    /// Default runtime log level for SDK-spawned sandbox processes.
    ///
    /// `None` means sandbox runtime processes are silent unless overridden
    /// per-sandbox.
    pub log_level: Option<LogLevel>,

    /// Authoritative host-runtime isolation profile for local sandboxes.
    ///
    /// When set, this operator policy overrides the profile requested by an
    /// individual sandbox on create and restart. `None` preserves per-sandbox
    /// selection and its built-in `single-tenant` default.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "deployment_profile_serde"
    )]
    pub deployment_profile: Option<DeploymentProfile>,

    /// Database configuration.
    #[config_patch(nested)]
    pub database: DatabaseConfig,

    /// Path overrides.
    #[config_patch(nested)]
    pub paths: PathsConfig,

    /// Default values for sandbox configuration.
    #[config_patch(nested)]
    pub sandbox_defaults: SandboxDefaults,

    /// Host runtime performance policy.
    #[config_patch(nested)]
    pub runtime: RuntimeConfig,

    /// Registry authentication configuration.
    #[config_patch(nested)]
    pub registries: RegistriesConfig,

    /// SSH session defaults.
    #[config_patch(nested)]
    pub ssh: SshConfig,

    /// Live metrics registry configuration.
    #[config_patch(nested)]
    pub metrics: MetricsConfig,
}

/// Compatibility alias for the backend-owned global configuration.
#[deprecated(since = "0.6.15", note = "renamed to GlobalConfig")]
pub type LocalConfig = GlobalConfig;

/// Default settings for host-side SSH sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(ConfigPatch)]
#[config_patch(serde)]
pub struct SshConfig {
    /// Disconnect an SSH session after this many seconds without SSH traffic.
    ///
    /// A value of `0` disables the inactivity timeout.
    pub inactivity_timeout_secs: u64,
}

/// Live metrics registry configuration.
///
/// Controls the host-side shared-memory registry that backs
/// `Sandbox::metrics()` and `all_sandbox_metrics()`. The capacity here
/// determines how many concurrent sandboxes can have a live metrics slot.
///
/// The capacity is locked when the registry is first created for a given
/// `MSB_HOME`; processes that subsequently supply a different value are
/// rejected at open time. To change the capacity, stop all sandboxes for
/// the same home and `shm_unlink` the registry segment before the next
/// host process boots.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
#[derive(ConfigPatch)]
#[config_patch(serde)]
pub struct MetricsConfig {
    /// Number of slots reserved in the metrics shared-memory segment.
    /// A value of `0` (the default) falls back to the built-in default at
    /// read time via [`GlobalConfig::metrics_registry_capacity`]. The
    /// derived `Default` therefore avoids pinning serialized configs to a
    /// particular release's default capacity.
    pub capacity: u32,
}

/// Database configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(ConfigPatch)]
#[config_patch(serde)]
pub struct DatabaseConfig {
    /// Database connection URL. `None` uses the default SQLite path.
    pub url: Option<String>,

    /// Maximum connection pool size.
    pub max_connections: u32,

    /// Timeout when acquiring a database connection from the pool.
    pub connect_timeout_secs: u64,

    /// SQLite `busy_timeout` PRAGMA: seconds SQLite waits on a contended
    /// lock before surfacing `SQLITE_BUSY` to the retry layer.
    pub busy_timeout_secs: u64,
}

/// Path overrides for runtime binaries and data directories.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
#[derive(ConfigPatch)]
#[config_patch(serde)]
pub struct PathsConfig {
    /// Path to `msb` binary.
    pub msb: Option<PathBuf>,

    /// Path to `libkrunfw.{so,dylib}`.
    pub libkrunfw: Option<PathBuf>,

    /// Path to the Linux guest Agentd executable.
    ///
    /// `MSB_AGENTD_PATH` takes precedence. When neither is set, the runtime
    /// uses the Agentd payload embedded in `msb`.
    pub agentd: Option<PathBuf>,

    /// Cache directory.
    pub cache: Option<PathBuf>,

    /// Per-sandbox state directory.
    pub sandboxes: Option<PathBuf>,

    /// Named volumes directory.
    pub volumes: Option<PathBuf>,

    /// Snapshot artifacts directory.
    pub snapshots: Option<PathBuf>,

    /// Logs directory.
    pub logs: Option<PathBuf>,

    /// Secrets directory.
    pub secrets: Option<PathBuf>,
}

/// Default values applied to sandboxes when not overridden per-sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
#[derive(ConfigPatch)]
#[config_patch(serde)]
pub struct SandboxDefaults {
    /// Default vCPU count.
    pub cpus: u8,

    /// Default guest memory in MiB.
    pub memory_mib: u32,

    /// Default host CPU placement policy.
    pub cpu_placement: CpuPlacement,

    /// Default host-defined placement profile name.
    pub placement_profile: Option<String>,

    /// Default guest transparent huge-page policy.
    pub thp: TransparentHugePagePolicy,

    /// Default OCI rootfs settings.
    #[config_patch(nested)]
    pub oci: OciSandboxDefaults,

    /// Default shell for interactive sessions and scripts.
    pub shell: String,

    /// Default working directory inside the sandbox.
    pub workdir: Option<String>,

    /// Default outbound SOCKS proxy for local sandboxes. Managed values override
    /// per-sandbox proxies; managed null clears them without enabling networking.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outbound_proxy: Option<OutboundProxy>,

    /// Default metrics sampling interval in milliseconds; `0` disables sampling globally.
    #[serde(
        default = "default_metrics_sample_interval",
        with = "metrics_interval_serde"
    )]
    pub metrics_sample_interval_ms: Option<NonZero<u64>>,

    /// Force-disable metrics sampling regardless of `metrics_sample_interval_ms`.
    #[serde(default)]
    pub disable_metrics_sample: bool,
}

/// Default values applied to OCI-rooted sandboxes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
#[derive(ConfigPatch)]
#[config_patch(serde)]
pub struct OciSandboxDefaults {
    /// Default writable overlay upper size in MiB.
    ///
    /// `None` uses microsandbox's built-in formatter default.
    pub upper_size_mib: Option<u32>,

    /// Default writable root disk for OCI sandboxes.
    ///
    /// This is mutually exclusive with the deprecated [`Self::upper_size_mib`] field. `None`
    /// preserves the managed layered root disk default.
    pub root_disk: Option<RootDisk>,
}

/// Host runtime performance policy.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
#[derive(ConfigPatch)]
#[config_patch(serde)]
pub struct RuntimeConfig {
    /// Buffered host writeback containment and pressure-sharing policy.
    pub block_writeback: BlockWritebackConfig,

    /// Host-owned placement profiles selectable by sandbox name.
    #[config_patch(merge)]
    pub placement_profiles: BTreeMap<String, PlacementProfile>,
}

/// Controls buffered host dirty data for writable raw disks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "lowercase", deny_unknown_fields)]
pub enum BlockWritebackConfig {
    /// Use the measured per-disk maximum and share the aggregate pool under pressure.
    Auto {
        /// Optional host-global dirty-credit pressure-pool override in MiB.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pool_mib: Option<NonZero<u64>>,
    },

    /// Use an explicit per-disk maximum and derive the pressure pool unless overridden.
    Fixed {
        /// Maximum page-aligned dirty data charged to one writable raw disk, in MiB.
        per_disk_mib: NonZero<u64>,

        /// Optional host-global dirty-credit pressure-pool override in MiB.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        pool_mib: Option<NonZero<u64>>,
    },

    /// Disable bounded writeback without changing guest-visible durability semantics.
    Off {},
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl GlobalConfig {
    /// Resolve the executable from the same complete pair used for sandbox launches.
    #[cfg(feature = "local")]
    pub fn resolve_msb_path(&self) -> MicrosandboxResult<PathBuf> {
        crate::setup::resolve_runtime(self).map(|runtime| runtime.msb_path)
    }

    /// Resolve the firmware from the same complete pair used for sandbox launches.
    #[cfg(feature = "local")]
    pub fn resolve_libkrunfw_path(&self) -> MicrosandboxResult<PathBuf> {
        crate::setup::resolve_runtime(self).map(|runtime| runtime.libkrunfw_path)
    }

    /// Validate defaults that affect sandbox construction.
    pub(crate) fn validate_sandbox_defaults(&self) -> MicrosandboxResult<()> {
        #[cfg(not(feature = "net"))]
        if self.sandbox_defaults.outbound_proxy.is_some() {
            return Err(MicrosandboxError::InvalidConfig(
                "sandbox_defaults.outbound_proxy requires the net feature".into(),
            ));
        }

        let oci = &self.sandbox_defaults.oci;
        if oci.upper_size_mib.is_some() && oci.root_disk.is_some() {
            return Err(MicrosandboxError::InvalidConfig(
                "sandbox_defaults.oci.root_disk and deprecated sandbox_defaults.oci.upper_size_mib are mutually exclusive".into(),
            ));
        }

        if matches!(oci.root_disk, Some(RootDisk::DiskImage { .. })) {
            return Err(MicrosandboxError::InvalidConfig(
                "sandbox_defaults.oci.root_disk cannot be a shared disk-image; specify user-owned disk images per sandbox".into(),
            ));
        }

        if let Some(profile_name) = &self.sandbox_defaults.placement_profile {
            self.resolve_placement_profile(profile_name)?;
        }

        Ok(())
    }

    /// Resolve and structurally validate a host-owned placement profile.
    pub(crate) fn resolve_placement_profile(
        &self,
        name: &str,
    ) -> MicrosandboxResult<PlacementProfile> {
        let profile = self
            .runtime
            .placement_profiles
            .get(name)
            .copied()
            .ok_or_else(|| {
                MicrosandboxError::InvalidConfig(format!(
                    "placement profile `{name}` is not defined in runtime.placement_profiles"
                ))
            })?;
        Ok(profile)
    }

    /// Get the resolved home directory.
    pub fn home(&self) -> PathBuf {
        self.home.clone().unwrap_or_else(resolve_default_home)
    }

    /// Resolve the `sandboxes` directory.
    pub fn sandboxes_dir(&self) -> PathBuf {
        self.paths
            .sandboxes
            .clone()
            .unwrap_or_else(|| self.home().join(microsandbox_utils::SANDBOXES_SUBDIR))
    }

    /// Resolve the `volumes` directory.
    pub fn volumes_dir(&self) -> PathBuf {
        self.paths
            .volumes
            .clone()
            .unwrap_or_else(|| self.home().join(microsandbox_utils::VOLUMES_SUBDIR))
    }

    /// Resolve the `snapshots` directory.
    pub fn snapshots_dir(&self) -> PathBuf {
        self.paths
            .snapshots
            .clone()
            .unwrap_or_else(|| self.home().join(microsandbox_utils::SNAPSHOTS_SUBDIR))
    }

    /// Resolve the `logs` directory.
    pub fn logs_dir(&self) -> PathBuf {
        self.paths
            .logs
            .clone()
            .unwrap_or_else(|| self.home().join(microsandbox_utils::LOGS_SUBDIR))
    }

    /// Resolve the `cache` directory.
    pub fn cache_dir(&self) -> PathBuf {
        self.paths
            .cache
            .clone()
            .unwrap_or_else(|| self.home().join(microsandbox_utils::CACHE_SUBDIR))
    }

    /// Resolve the `secrets` directory.
    pub fn secrets_dir(&self) -> PathBuf {
        self.paths
            .secrets
            .clone()
            .unwrap_or_else(|| self.home().join(microsandbox_utils::SECRETS_SUBDIR))
    }

    /// Resolve the `ssh` directory used for host-side SSH state.
    pub fn ssh_dir(&self) -> PathBuf {
        self.home().join(microsandbox_utils::SSH_SUBDIR)
    }

    /// Resolve the `run` directory used for ephemeral runtime artifacts.
    pub fn run_dir(&self) -> PathBuf {
        self.home().join(microsandbox_utils::RUN_SUBDIR)
    }

    /// Resolve the optional diagnostic file under `run/metrics` that records
    /// the derived shared-memory registry name and capacity.
    #[cfg(feature = "local")]
    pub fn metrics_registry_name_path(&self) -> PathBuf {
        self.run_dir()
            .join(microsandbox_utils::METRICS_RUN_SUBDIR)
            .join(microsandbox_utils::metrics_registry_name_filename(
                microsandbox_metrics::REGISTRY_ABI_VERSION,
            ))
    }

    /// Deterministic POSIX shared-memory object name for the live metrics
    /// registry. Hashes the resolved home directory so concurrent
    /// `MSB_HOME`-isolated environments do not collide.
    #[cfg(feature = "local")]
    pub fn metrics_registry_shm_name(&self) -> String {
        microsandbox_utils::metrics_registry_shm_name(
            &self.home(),
            microsandbox_metrics::REGISTRY_ABI_VERSION,
        )
    }

    /// Resolved capacity for the live metrics registry. Falls back to the
    /// built-in default when `metrics.capacity` is zero or unset.
    #[cfg(feature = "local")]
    pub fn metrics_registry_capacity(&self) -> u32 {
        if self.metrics.capacity == 0 {
            microsandbox_metrics::default_capacity()
        } else {
            self.metrics.capacity
        }
    }
}

impl PathsConfigPatch {
    /// Capture runtime paths from the environment, falling back to SDK-provided paths.
    pub(crate) fn from_env_or_sdk() -> Self {
        let libkrunfw = std::env::var("MSB_LIBKRUNFW_PATH")
            .ok()
            .map(PathBuf::from)
            .or_else(sdk_libkrunfw_path);

        let msb = std::env::var("MSB_PATH")
            .ok()
            .map(PathBuf::from)
            .or_else(sdk_msb_path);

        let mut patch = Self::new();
        if let Some(msb) = msb {
            patch.msb_mut(msb);
        }
        if let Some(libkrunfw) = libkrunfw {
            patch.libkrunfw_mut(libkrunfw);
        }
        if let Some(agentd) = std::env::var_os("MSB_AGENTD_PATH") {
            patch.agentd_mut(PathBuf::from(agentd));
        }
        patch
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: None,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            connect_timeout_secs: DEFAULT_CONNECT_TIMEOUT_SECS,
            busy_timeout_secs: 5,
        }
    }
}

impl Default for SshConfig {
    fn default() -> Self {
        Self {
            inactivity_timeout_secs: DEFAULT_SSH_INACTIVITY_TIMEOUT_SECS,
        }
    }
}

impl Default for SandboxDefaults {
    fn default() -> Self {
        Self {
            cpus: DEFAULT_CPUS,
            memory_mib: DEFAULT_MEMORY_MIB,
            cpu_placement: CpuPlacement::Inherit,
            placement_profile: None,
            thp: TransparentHugePagePolicy::Madvise,
            oci: OciSandboxDefaults::default(),
            shell: "/bin/sh".into(),
            workdir: None,
            outbound_proxy: None,
            metrics_sample_interval_ms: default_metrics_sample_interval(),
            disable_metrics_sample: false,
        }
    }
}

impl Default for BlockWritebackConfig {
    fn default() -> Self {
        // Auto is portable: Linux bounds dirty data and shares a derived pool, while other hosts
        // treat the unconfigured policy as a no-op.
        Self::Auto { pool_mib: None }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return the active default backend's local config.
///
/// This is the ambient convenience path for callers that do not explicitly
/// construct a [`LocalBackend`](crate::backend::LocalBackend). It returns
/// [`MicrosandboxError::Unsupported`] when the active backend is cloud.
#[cfg(feature = "local")]
pub fn config() -> MicrosandboxResult<Arc<GlobalConfig>> {
    let backend = crate::backend::default_backend();
    let local = backend
        .as_local()
        .ok_or_else(|| MicrosandboxError::local_only(Operation::Config))?;
    Ok(local.config_handle())
}

/// Resolve the path to the persisted local config file.
pub fn config_path() -> PathBuf {
    if let Ok(p) = std::env::var("MSB_CONFIG_PATH") {
        return PathBuf::from(p);
    }
    resolve_default_home().join(microsandbox_utils::CONFIG_FILENAME)
}

/// Load the persisted config file or return the default config if it does not exist.
///
/// Reads both backend profiles and local settings, validating the config version.
/// Returns saved user values; managed overrides are applied during backend resolution.
pub fn load_persisted_config_or_default() -> MicrosandboxResult<GlobalConfig> {
    Ok(GlobalConfigPatch::load()?.into_config())
}

/// Persist the provided local config to disk as pretty JSON.
pub fn save_persisted_config(config: &GlobalConfig) -> MicrosandboxResult<()> {
    let patch: GlobalConfigPatch = serde_json::from_value(serde_json::to_value(config)?)?;
    patch.save()
}

/// Set an explicit process-level `msb` path.
///
/// Automatic package discovery should use [`set_sdk_packaged_msb_path`] instead.
///
/// This is an internal SDK bridge for runtimes where mutating `process.env`
/// does not update the native process environment. User-provided `MSB_PATH`
/// still wins over this value. Set-once: subsequent calls are ignored.
pub fn set_sdk_msb_path(path: impl Into<PathBuf>) {
    let _ = SDK_MSB_PATH.set(path.into());
}

pub(crate) fn sdk_msb_path() -> Option<PathBuf> {
    SDK_MSB_PATH.get().cloned()
}

/// Resolve the ambient runtime executable as part of a complete runtime pair.
#[cfg(feature = "local")]
pub fn resolve_msb_path() -> MicrosandboxResult<PathBuf> {
    config()?.resolve_msb_path()
}

/// Set the `libkrunfw` path resolved by an SDK package (e.g. one that ships a
/// bundled libkrunfw dylib inside its language-package wheel/npm-package).
///
/// Set-once: subsequent calls are ignored. The user-facing
/// `MSB_LIBKRUNFW_PATH` environment override still wins.
///
/// Mirrors [`set_sdk_msb_path`]; both share the same precedence shape.
pub fn set_sdk_libkrunfw_path(path: impl Into<PathBuf>) {
    let _ = SDK_LIBKRUNFW_PATH.set(path.into());
}

pub(crate) fn sdk_libkrunfw_path() -> Option<PathBuf> {
    SDK_LIBKRUNFW_PATH.get().cloned()
}

/// Resolve the ambient firmware library as part of a complete runtime pair.
#[cfg(feature = "local")]
pub fn resolve_libkrunfw_path() -> MicrosandboxResult<PathBuf> {
    config()?.resolve_libkrunfw_path()
}

/// Resolve the default home directory (`~/.microsandbox`, or non-empty `$MSB_HOME`).
fn resolve_default_home() -> PathBuf {
    microsandbox_utils::resolve_home()
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub(crate) use registry::RegistrySettingsPatch;
pub use registry::{
    RegistriesConfig, RegistriesConfigPatch, RegistryAuthEntry, RegistryConfig,
    RegistryCredentialStore, RegistryEntry, RegistryEntryPatch, RegistryOptions,
    delete_registry_keyring_auth, get_registry_keyring_auth, set_registry_keyring_auth,
};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn saved_patch(config: &GlobalConfig) -> GlobalConfigPatch {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("config.json");
        let patch: GlobalConfigPatch =
            serde_json::from_value(serde_json::to_value(config).unwrap()).unwrap();
        patch.save_to(&path).unwrap();
        GlobalConfigPatch::load_from(&path).unwrap()
    }

    #[test]
    fn test_saved_patch_preserves_values_across_all_sections() {
        let expected = serde_json::json!({
            "active_profile": "work",
            "profiles": {"work": {
                "backend": "cloud",
                "url": "https://api.example.test",
                "api_key_ref": "env:MSB_TEST_API_KEY"
            }},
            "home": "/configured/home",
            "log_level": "debug",
            "deployment_profile": "multi-tenant",
            "database": {
                "url": "sqlite:///configured/db.sqlite",
                "max_connections": 11,
                "connect_timeout_secs": 12,
                "busy_timeout_secs": 13
            },
            "paths": {
                "msb": "/configured/msb",
                "agentd": "/configured/agentd",
                "libkrunfw": "/configured/libkrunfw",
                "cache": "/configured/cache",
                "sandboxes": "/configured/sandboxes",
                "volumes": "/configured/volumes",
                "snapshots": "/configured/snapshots",
                "logs": "/configured/logs",
                "secrets": "/configured/secrets"
            },
            "sandbox_defaults": {
                "cpus": 4,
                "memory_mib": 2048,
                "cpu_placement": "spread",
                "placement_profile": "latency",
                "thp": "always",
                "oci": {
                    "upper_size_mib": null,
                    "root_disk": {"kind": "tmpfs", "size_mib": 4096}
                },
                "shell": "/bin/bash",
                "workdir": "/workspace",
                "outbound_proxy": {
                    "protocol": "socks4",
                    "address": "127.0.0.1:1080",
                    "user_id": "employee"
                },
                "metrics_sample_interval_ms": 2500,
                "disable_metrics_sample": true
            },
            "runtime": {
                "block_writeback": {"mode": "fixed", "per_disk_mib": 1280, "pool_mib": 5120},
                "placement_profiles": {"latency": {
                    "numa": {"mode": "prefer_single"},
                    "memory": {"mode": "follow_cpu"}
                }}
            },
            "registries": {
                "ca_certs": "/configured/ca.pem",
                "hosts": {"registry.example": {
                    "auth": {
                        "username": "employee",
                        "store": null,
                        "password_env": "REGISTRY_TOKEN",
                        "secret_name": null
                    },
                    "insecure": true
                }}
            },
            "ssh": {"inactivity_timeout_secs": 45},
            "metrics": {"capacity": 128}
        });
        let config: GlobalConfig = serde_json::from_value(expected.clone()).unwrap();
        let patch: GlobalConfigPatch = saved_patch(&config);
        let mut resolved = GlobalConfig::default();
        patch.apply_to(&mut resolved);

        // Compare against explicit expected values, including fields with non-default settings.
        assert_eq!(serde_json::to_value(resolved).unwrap(), expected);
    }

    #[test]
    fn test_saved_patch_distinguishes_nulls_from_skipped_fields() {
        let patch = saved_patch(&GlobalConfig::default());
        assert_eq!(patch.active_profile, Some(None));
        assert_eq!(patch.home, Some(None));
        assert_eq!(patch.log_level, Some(None));
        assert_eq!(patch.database.url, Some(None));
        for path in [
            &patch.paths.msb,
            &patch.paths.agentd,
            &patch.paths.libkrunfw,
            &patch.paths.cache,
            &patch.paths.sandboxes,
            &patch.paths.volumes,
            &patch.paths.snapshots,
            &patch.paths.logs,
            &patch.paths.secrets,
        ] {
            assert_eq!(path, &Some(None));
        }
        assert_eq!(patch.sandbox_defaults.workdir, Some(None));
        assert_eq!(patch.sandbox_defaults.placement_profile, Some(None));
        assert_eq!(patch.sandbox_defaults.oci.root_disk, Some(None));
        assert_eq!(patch.sandbox_defaults.oci.upper_size_mib, Some(None));
        assert_eq!(patch.registries.ca_certs, Some(None));
        assert_eq!(patch.deployment_profile, None);
        assert_eq!(patch.sandbox_defaults.outbound_proxy, None);

        let mut resolved: GlobalConfig = serde_json::from_value(serde_json::json!({
            "active_profile": "old",
            "home": "/old/home",
            "log_level": "trace",
            "deployment_profile": "multi-tenant",
            "database": {"url": "sqlite:///old/db.sqlite"},
            "paths": {"cache": "/old/cache"},
            "sandbox_defaults": {
                "workdir": "/old/workdir",
                "placement_profile": "old",
                "oci": {"root_disk": {"kind": "tmpfs", "size_mib": 2048}},
                "outbound_proxy": {"protocol": "socks5", "address": "127.0.0.1:1080"}
            },
            "registries": {"ca_certs": "/old/ca.pem"}
        }))
        .unwrap();
        let proxy = resolved.sandbox_defaults.outbound_proxy.clone();
        patch.apply_to(&mut resolved);

        assert_eq!(resolved.active_profile, None);
        assert_eq!(resolved.home, None);
        assert_eq!(resolved.log_level, None);
        assert_eq!(resolved.database.url, None);
        assert_eq!(resolved.paths.cache, None);
        assert_eq!(resolved.sandbox_defaults.workdir, None);
        assert_eq!(resolved.sandbox_defaults.placement_profile, None);
        assert_eq!(resolved.sandbox_defaults.oci.root_disk, None);
        assert_eq!(resolved.registries.ca_certs, None);
        assert_eq!(
            resolved.deployment_profile,
            Some(DeploymentProfile::MultiTenant)
        );
        assert_eq!(resolved.sandbox_defaults.outbound_proxy, proxy);
    }

    #[test]
    fn test_saved_patch_preserves_custom_serde_values() {
        for (profile, serialized_profile) in [
            (DeploymentProfile::SingleTenant, "single-tenant"),
            (DeploymentProfile::MultiTenant, "multi-tenant"),
        ] {
            for interval in [0, 2500] {
                let mut config = GlobalConfig {
                    deployment_profile: Some(profile),
                    ..Default::default()
                };
                config.sandbox_defaults.metrics_sample_interval_ms = NonZero::new(interval);
                let serialized = serde_json::to_value(&config).unwrap();
                assert_eq!(serialized["deployment_profile"], serialized_profile);
                assert_eq!(
                    serialized["sandbox_defaults"]["metrics_sample_interval_ms"],
                    interval
                );

                let patch = saved_patch(&config);
                assert_eq!(patch.deployment_profile, Some(Some(profile)));
                assert_eq!(
                    patch.sandbox_defaults.metrics_sample_interval_ms,
                    Some(NonZero::new(interval))
                );
                let mut resolved = GlobalConfig::default();
                patch.apply_to(&mut resolved);
                assert_eq!(resolved.deployment_profile, Some(profile));
                assert_eq!(
                    resolved.sandbox_defaults.metrics_sample_interval_ms,
                    NonZero::new(interval)
                );
            }
        }
    }

    #[test]
    fn test_saved_patch_replaces_supplied_map_entries_and_keeps_other_keys() {
        let config: GlobalConfig = serde_json::from_value(serde_json::json!({
            "profiles": {"work": {"backend": "local"}},
            "registries": {"hosts": {"registry.example": {}}}
        }))
        .unwrap();
        let mut resolved: GlobalConfig = serde_json::from_value(serde_json::json!({
            "profiles": {
                "work": {"backend": "cloud", "url": "https://old.example", "api_key_ref": "env:OLD_KEY"},
                "keep": {"backend": "local"}
            },
            "registries": {"hosts": {
                "registry.example": {"auth": {"username": "old", "password_env": "OLD_TOKEN"}, "insecure": true},
                "keep.example": {"insecure": true}
            }}
        }))
        .unwrap();
        saved_patch(&config).apply_to(&mut resolved);

        // Fields skipped within an atomic map entry must not retain the replaced entry's values.
        let profile = &resolved.profiles["work"];
        assert_eq!(profile.backend, crate::backend::ProfileBackend::Local);
        assert_eq!(profile.url, None);
        assert_eq!(profile.api_key_ref, None);
        assert!(resolved.profiles.contains_key("keep"));
        let registry = &resolved.registries.hosts["registry.example"];
        assert!(registry.auth.is_none());
        assert!(!registry.insecure);
        assert!(resolved.registries.hosts["keep.example"].insecure);
    }

    #[test]
    fn test_default_config() {
        let cfg = GlobalConfig::default();
        assert_eq!(cfg.sandbox_defaults.cpus, 1);
        assert_eq!(cfg.sandbox_defaults.memory_mib, 512);
        assert_eq!(cfg.sandbox_defaults.cpu_placement, CpuPlacement::Inherit);
        assert_eq!(cfg.sandbox_defaults.placement_profile, None);
        assert_eq!(cfg.sandbox_defaults.thp, TransparentHugePagePolicy::Madvise);
        assert_eq!(cfg.sandbox_defaults.oci.upper_size_mib, None);
        assert_eq!(cfg.sandbox_defaults.oci.root_disk, None);
        assert_eq!(cfg.sandbox_defaults.shell, "/bin/sh");
        assert_eq!(cfg.sandbox_defaults.outbound_proxy, None);
        assert_eq!(
            cfg.sandbox_defaults.metrics_sample_interval_ms,
            NonZero::new(DEFAULT_METRICS_SAMPLE_INTERVAL_MS)
        );
        assert_eq!(cfg.log_level, None);
        assert_eq!(cfg.deployment_profile, None);
        assert_eq!(cfg.database.max_connections, 5);
        assert_eq!(cfg.database.connect_timeout_secs, 30);
        assert_eq!(cfg.database.busy_timeout_secs, 5);
        assert_eq!(cfg.ssh.inactivity_timeout_secs, 600);
        assert_eq!(
            cfg.runtime.block_writeback,
            BlockWritebackConfig::Auto { pool_mib: None }
        );
        assert!(cfg.runtime.placement_profiles.is_empty());
        assert_eq!(
            serde_json::to_value(cfg.runtime.block_writeback).unwrap(),
            serde_json::json!({ "mode": "auto" })
        );
    }

    #[cfg(not(feature = "net"))]
    #[test]
    fn outbound_proxy_defaults_require_net_feature() {
        let config: GlobalConfig = serde_json::from_value(serde_json::json!({
            "sandbox_defaults": {"outbound_proxy": {
                "protocol": "socks5", "address": "127.0.0.1:1080"
            }}
        }))
        .unwrap();
        let error = config.validate_sandbox_defaults().unwrap_err();
        assert!(error.to_string().contains("requires the net feature"));
    }

    #[test]
    fn test_deserialize_empty_json() {
        let cfg: GlobalConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg.sandbox_defaults.cpus, 1);
        assert!(cfg.home.is_none());
        assert_eq!(
            cfg.runtime.block_writeback,
            BlockWritebackConfig::Auto { pool_mib: None }
        );
    }

    #[test]
    fn test_deserialize_partial_json() {
        let json = r#"{"sandbox_defaults": {"cpus": 4}}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.sandbox_defaults.cpus, 4);
        assert_eq!(cfg.sandbox_defaults.memory_mib, 512);
    }

    #[test]
    fn test_deployment_profile_uses_human_facing_config_values() {
        let cfg: GlobalConfig =
            serde_json::from_str(r#"{"deployment_profile":"multi-tenant"}"#).unwrap();
        assert_eq!(cfg.deployment_profile, Some(DeploymentProfile::MultiTenant));

        let json = serde_json::to_value(cfg).unwrap();
        assert_eq!(json["deployment_profile"], "multi-tenant");
    }

    #[test]
    fn test_deployment_profile_accepts_snake_case_wire_values() {
        let cfg: GlobalConfig =
            serde_json::from_str(r#"{"deployment_profile":"single_tenant"}"#).unwrap();
        assert_eq!(
            cfg.deployment_profile,
            Some(DeploymentProfile::SingleTenant)
        );
    }

    #[test]
    fn test_deployment_profile_rejects_unknown_values() {
        let error =
            serde_json::from_str::<GlobalConfig>(r#"{"deployment_profile":"shared"}"#).unwrap_err();
        assert!(error.to_string().contains("unknown deployment profile"));
    }

    #[test]
    fn test_deserialize_performance_defaults() {
        let json = r#"{
            "sandbox_defaults": {
                "cpu_placement": "spread",
                "thp": "always",
                "oci": {
                    "root_disk": {
                        "kind": "flat",
                        "size_mib": 8192,
                        "clone": "copy"
                    }
                }
            },
            "runtime": { "block_writeback": { "mode": "off" } }
        }"#;

        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.sandbox_defaults.cpu_placement, CpuPlacement::Spread);
        assert_eq!(cfg.sandbox_defaults.thp, TransparentHugePagePolicy::Always);
        assert_eq!(
            cfg.sandbox_defaults.oci.root_disk,
            Some(RootDisk::Flat {
                size_mib: Some(8192),
                fstype: None,
                clone: microsandbox_types::FlatClone::Copy,
            })
        );
        assert_eq!(cfg.runtime.block_writeback, BlockWritebackConfig::Off {});
    }

    #[test]
    fn test_placement_profile_round_trip_and_default_resolution() {
        let json = r#"{
            "sandbox_defaults": {
                "cpu_placement": "auto",
                "placement_profile": "latency"
            },
            "runtime": {
                "placement_profiles": {
                    "latency": {
                        "numa": { "mode": "prefer_single" },
                        "memory": { "mode": "follow_cpu" }
                    }
                }
            }
        }"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();

        cfg.validate_sandbox_defaults().unwrap();
        assert_eq!(
            cfg.sandbox_defaults.placement_profile.as_deref(),
            Some("latency")
        );
        let profile = cfg.resolve_placement_profile("latency").unwrap();
        assert_eq!(
            profile.numa,
            microsandbox_types::NumaPlacement::PreferSingle
        );
        assert_eq!(
            profile.memory,
            microsandbox_types::MemoryPlacement::FollowCpu
        );

        let round: GlobalConfig =
            serde_json::from_value(serde_json::to_value(cfg).unwrap()).unwrap();
        assert_eq!(
            round.sandbox_defaults.placement_profile.as_deref(),
            Some("latency")
        );
    }

    #[test]
    fn test_validate_rejects_unknown_default_placement_profile() {
        let cfg: GlobalConfig =
            serde_json::from_str(r#"{"sandbox_defaults":{"placement_profile":"missing"}}"#)
                .unwrap();

        let error = cfg.validate_sandbox_defaults().unwrap_err();
        assert!(
            error.to_string().contains(
                "placement profile `missing` is not defined in runtime.placement_profiles"
            )
        );
    }

    #[test]
    fn test_block_writeback_fixed_round_trip() {
        let json = r#"{
            "runtime": {
                "block_writeback": {
                    "mode": "fixed",
                    "per_disk_mib": 1280,
                    "pool_mib": 5120
                }
            }
        }"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();

        assert_eq!(
            cfg.runtime.block_writeback,
            BlockWritebackConfig::Fixed {
                per_disk_mib: NonZero::new(1280).unwrap(),
                pool_mib: NonZero::new(5120),
            }
        );

        let serialized = serde_json::to_value(cfg.runtime.block_writeback).unwrap();
        assert_eq!(
            serialized,
            serde_json::json!({
                "mode": "fixed",
                "per_disk_mib": 1280,
                "pool_mib": 5120
            })
        );
    }

    #[test]
    fn test_block_writeback_modes_reject_incompatible_fields() {
        let auto_with_fixed_limit = r#"{
            "runtime": {
                "block_writeback": {
                    "mode": "auto",
                    "per_disk_mib": 1536
                }
            }
        }"#;
        let off_with_pool = r#"{
            "runtime": {
                "block_writeback": {
                    "mode": "off",
                    "pool_mib": 4096
                }
            }
        }"#;

        assert!(serde_json::from_str::<GlobalConfig>(auto_with_fixed_limit).is_err());
        assert!(serde_json::from_str::<GlobalConfig>(off_with_pool).is_err());
    }

    #[test]
    fn test_validate_rejects_legacy_and_typed_root_disk_defaults() {
        let json = r#"{
            "sandbox_defaults": {
                "oci": {
                    "upper_size_mib": 4096,
                    "root_disk": { "kind": "flat" }
                }
            }
        }"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();

        let error = cfg.validate_sandbox_defaults().unwrap_err();
        assert!(error.to_string().contains("mutually exclusive"));
    }

    #[test]
    fn test_deserialize_metrics_interval_missing_uses_default() {
        let json = r#"{"sandbox_defaults": {}}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            cfg.sandbox_defaults.metrics_sample_interval_ms,
            NonZero::new(DEFAULT_METRICS_SAMPLE_INTERVAL_MS)
        );
    }

    #[test]
    fn test_deserialize_metrics_interval_zero_disables() {
        let json = r#"{"sandbox_defaults": {"metrics_sample_interval_ms": 0}}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.sandbox_defaults.metrics_sample_interval_ms.is_none());
    }

    #[test]
    fn test_deserialize_metrics_interval_positive() {
        let json = r#"{"sandbox_defaults": {"metrics_sample_interval_ms": 2500}}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(
            cfg.sandbox_defaults.metrics_sample_interval_ms,
            NonZero::new(2500)
        );
    }

    #[test]
    fn test_serialize_metrics_interval_disabled_round_trips() {
        let mut cfg = GlobalConfig::default();
        cfg.sandbox_defaults.metrics_sample_interval_ms = None;
        let json = serde_json::to_string(&cfg).unwrap();
        assert!(
            json.contains("\"metrics_sample_interval_ms\":0"),
            "expected `0` serialization, got: {json}"
        );
        let round: GlobalConfig = serde_json::from_str(&json).unwrap();
        assert!(round.sandbox_defaults.metrics_sample_interval_ms.is_none());
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_metrics_capacity_default_uses_crate_default() {
        let cfg = GlobalConfig::default();
        assert_eq!(
            cfg.metrics_registry_capacity(),
            microsandbox_metrics::default_capacity()
        );
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_metrics_capacity_zero_falls_back_to_default() {
        let json = r#"{"metrics": {"capacity": 0}}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.metrics.capacity, 0);
        assert_eq!(
            cfg.metrics_registry_capacity(),
            microsandbox_metrics::default_capacity()
        );
    }

    #[cfg(feature = "local")]
    #[test]
    fn test_metrics_capacity_explicit_value_overrides_default() {
        let json = r#"{"metrics": {"capacity": 2048}}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.metrics.capacity, 2048);
        assert_eq!(cfg.metrics_registry_capacity(), 2048);
    }

    #[test]
    fn test_deserialize_disable_metrics_sample_default_false() {
        let cfg: GlobalConfig = serde_json::from_str("{}").unwrap();
        assert!(!cfg.sandbox_defaults.disable_metrics_sample);
    }

    #[test]
    fn test_deserialize_disable_metrics_sample_true() {
        let json = r#"{"sandbox_defaults": {"disable_metrics_sample": true}}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.sandbox_defaults.disable_metrics_sample);
    }

    #[test]
    fn test_deserialize_log_level() {
        let json = r#"{"log_level":"debug"}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.log_level, Some(LogLevel::Debug));
    }

    #[test]
    fn test_deserialize_database_config() {
        let json = r#"{
            "database": {
                "max_connections": 9,
                "connect_timeout_secs": 7,
                "busy_timeout_secs": 12
            }
        }"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.database.max_connections, 9);
        assert_eq!(cfg.database.connect_timeout_secs, 7);
        assert_eq!(cfg.database.busy_timeout_secs, 12);
    }

    #[test]
    fn test_deserialize_ssh_config() {
        let json = r#"{"ssh": {"inactivity_timeout_secs": 1800}}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.ssh.inactivity_timeout_secs, 1800);
    }

    #[test]
    fn test_deserialize_ssh_timeout_disabled() {
        let json = r#"{"ssh": {"inactivity_timeout_secs": 0}}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.ssh.inactivity_timeout_secs, 0);
    }

    #[test]
    fn test_home_resolution() {
        let cfg = GlobalConfig {
            home: Some(PathBuf::from("/custom/home")),
            ..Default::default()
        };
        assert_eq!(cfg.home(), PathBuf::from("/custom/home"));
    }

    #[test]
    fn test_sandboxes_dir_override() {
        let cfg = GlobalConfig {
            paths: PathsConfig {
                sandboxes: Some(PathBuf::from("/custom/sandboxes")),
                ..Default::default()
            },
            ..Default::default()
        };
        assert_eq!(cfg.sandboxes_dir(), PathBuf::from("/custom/sandboxes"));
    }

    #[test]
    fn test_deserialize_agentd_path() {
        let json = r#"{"paths": {"agentd": "/opt/microsandbox/agentd"}}"#;
        let cfg: GlobalConfig = serde_json::from_str(json).unwrap();

        assert_eq!(
            cfg.paths.agentd,
            Some(PathBuf::from("/opt/microsandbox/agentd"))
        );
    }

    #[test]
    fn test_load_config_from_missing_file() {
        let result = GlobalConfigPatch::load_from(Path::new("/nonexistent/config.json"));
        assert!(result.unwrap().is_empty());
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub(crate) use runtime_paths::sdk_packaged_msb_path;
pub use runtime_paths::set_sdk_packaged_msb_path;
