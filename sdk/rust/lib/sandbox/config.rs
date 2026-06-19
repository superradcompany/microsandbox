//! Sandbox configuration.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::num::NonZero;
use std::path::PathBuf;

use microsandbox_runtime::logging::LogLevel;
use microsandbox_types::{
    EnvVar, SandboxLogLevel, SandboxResources, SandboxRuntimeOptions, SandboxSpec,
};
use serde::{Deserialize, Serialize};

use microsandbox_image::{ImageConfig, RegistryAuth};
use microsandbox_protocol::{HANDOFF_INIT_AUTO, HANDOFF_INIT_IMAGE_ENTRYPOINT_CANDIDATES};

use super::types::{MountOptions, RootfsSource, VolumeMount};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEFAULT_OCI_TMPFS_PATH: &str = "/tmp";
const DEFAULT_OCI_TMPFS_MAX_SIZE_MIB: u32 = 512;
const DEFAULT_OCI_TMPFS_MEMORY_DIVISOR: u32 = 4;
pub(crate) const DEFAULT_OCI_UPPER_SIZE_MIB: u32 = 4 * 1024;

/// Default timeout given to the existing sandbox during a `.replace()`
/// create before it is force-killed.
///
/// Distinct from [`SandboxHandle::stop`]'s timeout: this one applies
/// to the builder's override-an-existing-sandbox flow, not the
/// user-facing stop. They share a numeric value today by coincidence,
/// not by design.
///
/// [`SandboxHandle::stop`]: super::SandboxHandle::stop
pub const DEFAULT_REPLACE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

// Compile-time defaults for `SandboxConfig` serde. Serde's `#[serde(default
// = "fn")]` attribute can't take parameters, so these can't consult a
// `LocalBackend`. They intentionally mirror `LocalConfig::default()` /
// `SandboxDefaults::default()` for the same fields, so DB-row
// deserialization (and `sandbox_config_from_cloud`) are side-effect-free.
// A `LocalBackend` with non-default sandbox defaults applies them through
// `SandboxBuilder` at create time, not via serde.

fn default_cpus() -> u8 {
    crate::config::DEFAULT_CPUS
}

fn default_memory_mib() -> u32 {
    crate::config::DEFAULT_MEMORY_MIB
}

fn default_log_level() -> Option<SandboxLogLevel> {
    None
}

fn default_metrics_sample_interval_ms() -> Option<NonZero<u64>> {
    crate::config::default_metrics_sample_interval()
}

fn default_disable_metrics_sample() -> bool {
    false
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for a sandbox.
///
/// The durable task description lives in [`SandboxSpec`]. This type keeps
/// local SDK/runtime operation state beside that shared contract, such as
/// registry credentials, replacement flags, and resolved snapshot metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Backend-neutral sandbox task description shared across SDKs and services.
    #[serde(flatten)]
    pub spec: SandboxSpec,

    /// Registry authentication for private OCI registries.
    ///
    /// Redacted (set to `None`) before serialization to database — credentials
    /// are only needed during the pull.
    #[serde(default, skip_serializing)]
    pub registry_auth: Option<RegistryAuth>,

    /// Access the registry over plain HTTP (SDK override).
    #[serde(skip)]
    pub(crate) insecure: bool,

    /// Additional PEM-encoded CA certs (SDK override).
    #[serde(skip)]
    pub(crate) ca_certs: Vec<Vec<u8>>,

    /// Replace an existing sandbox with the same name during create.
    ///
    /// If the existing sandbox is still active, microsandbox stops it and
    /// waits for it to exit before recreating it.
    ///
    /// This is an operation flag, not persisted sandbox state.
    #[serde(skip)]
    pub replace_existing: bool,

    /// How long to wait after SIGTERM for the existing sandbox process to
    /// exit gracefully before escalating to SIGKILL during a replace.
    ///
    /// Only consulted when `replace_existing` is true. A zero duration
    /// skips SIGTERM entirely and goes straight to SIGKILL. Default is
    /// `DEFAULT_REPLACE_TIMEOUT`, which gives the exit observer plenty
    /// of headroom to flush logs and clean up the agent socket on a
    /// healthy sandbox before we escalate.
    ///
    /// This is an operation flag, not persisted sandbox state.
    #[serde(skip)]
    pub replace_with_timeout: std::time::Duration,

    /// Manifest digest for the resolved OCI image.
    ///
    /// Set at create time. Used by spawn to derive VMDK and fsmeta paths
    /// from the global cache. `None` for non-OCI rootfs sources.
    #[serde(default)]
    pub(crate) manifest_digest: Option<String>,

    /// Path to a snapshot's `upper.ext4` file to copy into the new
    /// sandbox's upper layer at create time, replacing the fresh-format
    /// step.
    ///
    /// Transient: set by `SandboxBuilder::from_snapshot` and consumed
    /// during `create_with_mode`. Never persisted.
    #[serde(skip)]
    pub(crate) snapshot_upper_source: Option<PathBuf>,

    /// Initial command requested by a CLI `msb run` invocation.
    ///
    /// This is transient CLI intent. It lets `--init auto` decide before VM
    /// spawn whether an image-declared init entrypoint should receive the OCI
    /// command as argv.
    #[serde(skip)]
    pub(crate) initial_command: Option<Vec<String>>,

    /// Whether a consumed initial command should become persisted startup argv.
    ///
    /// Attached `msb run` commands are one-shot foreground intent; detached
    /// `msb run -d` commands are startup intent when an image init consumes
    /// them.
    #[serde(skip)]
    pub(crate) initial_command_persistent: bool,

    /// Whether [`initial_command`](Self::initial_command) was consumed by
    /// the handoff init instead of being executed through agentd.
    #[serde(skip)]
    pub(crate) initial_command_consumed_by_init: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxConfig {
    /// Resolve the effective metrics sampling interval, accounting for the disable override.
    pub fn effective_metrics_interval(&self) -> Option<NonZero<u64>> {
        if self.spec.runtime.disable_metrics_sample {
            None
        } else {
            self.spec
                .runtime
                .metrics_sample_interval_ms
                .and_then(NonZero::new)
        }
    }

    /// Return whether the attached initial command was launched by the
    /// handoff init rather than through agentd.
    #[doc(hidden)]
    pub fn initial_command_consumed_by_init(&self) -> bool {
        self.initial_command_consumed_by_init
    }

    /// Return the config shape that should be persisted for future starts.
    ///
    /// Attached `msb run --init auto` may pass a one-off foreground command to
    /// an image-declared init entrypoint. Detached `msb run -d --init auto`
    /// uses the same handoff path for startup intent. Only the latter should
    /// be replayed by `msb start`.
    pub(crate) fn clone_for_persistence(&self) -> Self {
        let mut config = self.clone();
        if config.initial_command_consumed_by_init
            && !config.initial_command_persistent
            && let Some(init) = &mut config.spec.init
        {
            init.args.clear();
        }
        config.initial_command = None;
        config.initial_command_persistent = false;
        config.initial_command_consumed_by_init = false;
        config
    }

    /// Set one-shot initial command intent for attached `msb run`.
    pub(crate) fn set_initial_command(&mut self, command: Vec<String>) {
        self.initial_command = Some(command);
        self.initial_command_persistent = false;
        self.initial_command_consumed_by_init = false;
    }

    /// Set startup initial command intent for detached `msb run -d`.
    pub(crate) fn set_persistent_initial_command(&mut self, command: Vec<String>) {
        self.initial_command = Some(command);
        self.initial_command_persistent = true;
        self.initial_command_consumed_by_init = false;
    }

    /// Apply OCI image config as defaults. User-provided values take precedence.
    ///
    /// - `env`: image env vars form the base; user env vars override by key, otherwise append.
    /// - `labels`: image labels form the base; user labels override by key.
    /// - `cmd`, `entrypoint`, `workdir`, `user`: image value used only if user did not set one.
    /// - `init`: an `auto` init may resolve from a known init at the start of the image entrypoint and inherit the effective entrypoint env.
    pub fn merge_image_defaults(&mut self, image: &ImageConfig) {
        self.spec.env = merge_env(&image.env, &self.spec.env);
        self.spec.labels = merge_image_labels(&image.labels, &self.spec.labels);

        let inherit_entrypoint = self.spec.runtime.entrypoint.is_none();

        if self.spec.runtime.cmd.is_none() {
            self.spec.runtime.cmd = image.cmd.clone();
        }
        if self.spec.runtime.entrypoint.is_none() {
            self.spec.runtime.entrypoint = image.entrypoint.clone();
        }
        if self.spec.runtime.workdir.is_none() {
            self.spec.runtime.workdir = image
                .working_dir
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(String::from);
        }
        if self.spec.runtime.user.is_none() {
            self.spec.runtime.user = image
                .user
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(String::from);
        }

        self.resolve_auto_init_from_image_entrypoint(
            image.entrypoint.as_deref(),
            inherit_entrypoint,
        );
    }

    /// Resolve `init = "auto"` from a known init path declared as the
    /// image entrypoint.
    ///
    /// When an attached `msb run` provided an initial command, and the
    /// image declares a container-init entrypoint such as `/init`, the
    /// remaining OCI process vector is passed to the init as argv. The
    /// image init token is still stripped from the persisted workload
    /// entrypoint so later agentd exec command resolution never tries
    /// to direct-exec `/init`.
    fn resolve_auto_init_from_image_entrypoint(
        &mut self,
        image_entrypoint: Option<&[String]>,
        inherited_entrypoint: bool,
    ) {
        let Some(init) = self.spec.init.as_ref() else {
            return;
        };
        if init.cmd.as_os_str() != HANDOFF_INIT_AUTO {
            return;
        }
        let init_args_empty = init.args.is_empty();

        let Some(entrypoint) = image_entrypoint else {
            return;
        };
        let Some(init_path) = entrypoint
            .first()
            .map(String::as_str)
            .filter(|path| is_image_entrypoint_init(path))
        else {
            return;
        };

        let init_argv_tail = if inherited_entrypoint && init_args_empty {
            self.image_init_entrypoint_argv_tail(init_path, entrypoint)
        } else {
            None
        };

        let init = self
            .spec
            .init
            .as_mut()
            .expect("init was present at start of auto resolution");
        init.cmd = PathBuf::from(init_path);
        init.env = merge_init_env(&self.spec.env, &init.env);
        if let Some(argv_tail) = init_argv_tail {
            init.args = argv_tail;
            self.initial_command_consumed_by_init = true;
        }

        if !inherited_entrypoint {
            return;
        }

        let Some(mut entrypoint) = self.spec.runtime.entrypoint.take() else {
            return;
        };
        if entrypoint
            .first()
            .is_some_and(|first| first.as_str() == init_path)
        {
            entrypoint.remove(0);
        }
        self.spec.runtime.entrypoint = (!entrypoint.is_empty()).then_some(entrypoint);
    }

    fn image_init_entrypoint_argv_tail(
        &self,
        init_path: &str,
        image_entrypoint: &[String],
    ) -> Option<Vec<String>> {
        let initial_command = self.initial_command.as_ref()?;
        if init_path != "/init" && image_entrypoint.len() <= 1 {
            return None;
        }

        let mut process = image_entrypoint.to_vec();
        if initial_command.is_empty() {
            process.extend(self.spec.runtime.cmd.iter().flatten().cloned());
        } else {
            process.extend(initial_command.iter().cloned());
        }

        let argv_tail: Vec<_> = process.into_iter().skip(1).collect();
        (!argv_tail.is_empty()).then_some(argv_tail)
    }

    /// Materialize rootfs defaults that should be persisted with the sandbox.
    pub(crate) fn apply_rootfs_defaults(&mut self, upper_size_mib: Option<u32>) {
        if self.snapshot_upper_source.is_none()
            && let RootfsSource::Oci(oci) = &mut self.spec.image
            && oci.upper_size_mib.is_none()
        {
            oci.upper_size_mib = Some(upper_size_mib.unwrap_or(DEFAULT_OCI_UPPER_SIZE_MIB));
        }
    }

    /// Apply runtime defaults that should exist for OCI sandboxes unless the
    /// user explicitly overrode them.
    pub(crate) fn apply_runtime_defaults(&mut self) {
        if !matches!(self.spec.image, RootfsSource::Oci(_)) {
            return;
        }

        if self
            .spec
            .mounts
            .iter()
            .any(|mount| guest_mount_is(mount, DEFAULT_OCI_TMPFS_PATH))
        {
            return;
        }

        self.spec.mounts.push(VolumeMount::Tmpfs {
            guest: DEFAULT_OCI_TMPFS_PATH.to_string(),
            size_mib: Some(default_oci_tmpfs_size_mib(self.spec.resources.memory_mib)),
            options: MountOptions::default(),
        });
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Merge two sets of env-var pairs. Base entries are kept unless overridden by
/// key, then all override entries are appended.
pub(crate) fn merge_env_pairs(base: &[EnvVar], overrides: &[EnvVar]) -> Vec<EnvVar> {
    let override_keys: HashSet<&str> = overrides.iter().map(|var| var.key.as_str()).collect();

    let mut merged: Vec<EnvVar> = base
        .iter()
        .filter(|var| !override_keys.contains(var.key.as_str()))
        .cloned()
        .collect();

    merged.extend(overrides.iter().cloned());
    merged
}

fn merge_init_env(base: &[EnvVar], overrides: &[(String, String)]) -> Vec<(String, String)> {
    let overrides = overrides
        .iter()
        .cloned()
        .map(EnvVar::from)
        .collect::<Vec<_>>();

    merge_env_pairs(base, &overrides)
        .into_iter()
        .map(Into::into)
        .collect()
}

/// Merge image env vars (OCI `KEY=VALUE` strings) with user env var pairs.
fn merge_env(image_env: &[String], user_env: &[EnvVar]) -> Vec<EnvVar> {
    let base: Vec<EnvVar> = image_env
        .iter()
        .filter_map(|entry| match entry.split_once('=') {
            Some((key, value)) => Some(EnvVar::new(key, value)),
            None => {
                tracing::warn!(entry = %entry, "skipping malformed image env var (expected KEY=VALUE)");
                None
            }
        })
        .collect();

    merge_env_pairs(&base, user_env)
}

/// Merge OCI image labels (base) with user labels (override on key collision).
///
/// Image labels carrying a reserved prefix or an empty key are skipped: they
/// cannot become metric attributes and would otherwise bypass user-label
/// validation (which already ran before the image was pulled).
fn merge_image_labels(
    image_labels: &HashMap<String, String>,
    user_labels: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut merged: BTreeMap<String, String> = image_labels
        .iter()
        .filter(|(key, _)| !key.is_empty() && super::reserved_label_prefix(key).is_none())
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    // User labels win on collision.
    for (key, value) in user_labels {
        merged.insert(key.clone(), value.clone());
    }
    merged
}

fn is_image_entrypoint_init(path: &str) -> bool {
    HANDOFF_INIT_IMAGE_ENTRYPOINT_CANDIDATES.contains(&path)
}

fn default_oci_tmpfs_size_mib(memory_mib: u32) -> u32 {
    (memory_mib / DEFAULT_OCI_TMPFS_MEMORY_DIVISOR).clamp(1, DEFAULT_OCI_TMPFS_MAX_SIZE_MIB)
}

fn guest_mount_is(mount: &VolumeMount, path: &str) -> bool {
    match mount {
        VolumeMount::Bind { guest, .. }
        | VolumeMount::Named { guest, .. }
        | VolumeMount::Tmpfs { guest, .. }
        | VolumeMount::DiskImage { guest, .. } => {
            normalized_guest_path(guest) == normalized_guest_path(path)
        }
    }
}

fn normalized_guest_path(path: &str) -> &str {
    let trimmed = path.trim_end_matches('/');
    if trimmed.is_empty() { "/" } else { trimmed }
}

pub(crate) fn sandbox_log_level_from_runtime(level: LogLevel) -> SandboxLogLevel {
    match level {
        LogLevel::Error => SandboxLogLevel::Error,
        LogLevel::Warn => SandboxLogLevel::Warn,
        LogLevel::Info => SandboxLogLevel::Info,
        LogLevel::Debug => SandboxLogLevel::Debug,
        LogLevel::Trace => SandboxLogLevel::Trace,
    }
}

#[cfg(feature = "net")]
pub(crate) fn network_spec_from_config(
    config: &microsandbox_network::config::NetworkConfig,
) -> crate::MicrosandboxResult<microsandbox_types::NetworkSpec> {
    Ok(serde_json::from_value(serde_json::to_value(config)?)?)
}

#[cfg(feature = "net")]
pub(crate) fn network_config_from_spec(
    spec: &microsandbox_types::NetworkSpec,
) -> crate::MicrosandboxResult<microsandbox_network::config::NetworkConfig> {
    Ok(serde_json::from_value(serde_json::to_value(spec)?)?)
}

#[cfg(feature = "net")]
impl SandboxConfig {
    pub(crate) fn local_network_config(
        &self,
    ) -> crate::MicrosandboxResult<microsandbox_network::config::NetworkConfig> {
        network_config_from_spec(&self.spec.network)
    }

    pub(crate) fn set_local_network_config(
        &mut self,
        config: microsandbox_network::config::NetworkConfig,
    ) -> crate::MicrosandboxResult<()> {
        self.spec.network = network_spec_from_config(&config)?;
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            spec: SandboxSpec {
                resources: SandboxResources {
                    cpus: default_cpus(),
                    memory_mib: default_memory_mib(),
                },
                runtime: SandboxRuntimeOptions {
                    log_level: default_log_level(),
                    metrics_sample_interval_ms: default_metrics_sample_interval_ms()
                        .map(NonZero::get),
                    disable_metrics_sample: default_disable_metrics_sample(),
                    ..Default::default()
                },
                ..Default::default()
            },
            registry_auth: None,
            insecure: false,
            ca_certs: Vec::new(),
            replace_existing: false,
            replace_with_timeout: DEFAULT_REPLACE_TIMEOUT,
            manifest_digest: None,
            snapshot_upper_source: None,
            initial_command: None,
            initial_command_persistent: false,
            initial_command_consumed_by_init: false,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::{SandboxConfig, merge_env};
    use crate::sandbox::{HandoffInit, MountOptions, RootfsSource, VolumeMount};
    use microsandbox_image::ImageConfig;
    use microsandbox_types::{
        EnvVar, SandboxLogLevel, SandboxPolicy, SandboxResources, SandboxRuntimeOptions,
        SandboxSpec, SecurityProfile,
    };

    #[test]
    fn test_merge_env_image_base_with_user_override() {
        let image_env = vec![
            "PATH=/usr/local/bin:/usr/bin".to_string(),
            "PYTHON_VERSION=3.14".to_string(),
        ];
        let user_env = vec![
            EnvVar::new("PATH", "/custom/bin"),
            EnvVar::new("MY_VAR", "hello"),
        ];

        let merged = merge_env(&image_env, &user_env);

        assert_eq!(
            merged,
            vec![
                EnvVar::new("PYTHON_VERSION", "3.14"),
                EnvVar::new("PATH", "/custom/bin"),
                EnvVar::new("MY_VAR", "hello"),
            ]
        );
    }

    #[test]
    fn test_merge_env_empty_user_inherits_image() {
        let image_env = vec!["PATH=/usr/bin".to_string(), "LANG=C.UTF-8".to_string()];
        let user_env = Vec::new();

        let merged = merge_env(&image_env, &user_env);

        assert_eq!(
            merged,
            vec![
                EnvVar::new("PATH", "/usr/bin"),
                EnvVar::new("LANG", "C.UTF-8"),
            ]
        );
    }

    #[test]
    fn test_merge_env_empty_image_keeps_user() {
        let image_env = vec![];
        let user_env = vec![EnvVar::new("MY_VAR", "val")];

        let merged = merge_env(&image_env, &user_env);

        assert_eq!(merged, vec![EnvVar::new("MY_VAR", "val")]);
    }

    #[test]
    fn test_merge_image_defaults_replace_fields() {
        let image = ImageConfig {
            cmd: Some(vec!["python3".to_string()]),
            entrypoint: Some(vec!["/entrypoint.sh".to_string()]),
            working_dir: Some("/app".to_string()),
            user: Some("appuser".to_string()),
            ..Default::default()
        };

        let mut config = SandboxConfig::default();
        config.merge_image_defaults(&image);

        assert_eq!(config.spec.runtime.cmd, Some(vec!["python3".to_string()]));
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/entrypoint.sh".to_string()])
        );
        assert_eq!(config.spec.runtime.workdir, Some("/app".to_string()));
        assert_eq!(config.spec.runtime.user, Some("appuser".to_string()));
    }

    #[test]
    fn test_merge_image_defaults_user_overrides_take_precedence() {
        let image = ImageConfig {
            cmd: Some(vec!["python3".to_string()]),
            entrypoint: Some(vec!["/entrypoint.sh".to_string()]),
            working_dir: Some("/app".to_string()),
            user: Some("appuser".to_string()),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                runtime: SandboxRuntimeOptions {
                    cmd: Some(vec!["bash".to_string()]),
                    workdir: Some("/workspace".to_string()),
                    user: Some("root".to_string()),
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };
        config.merge_image_defaults(&image);

        assert_eq!(config.spec.runtime.cmd, Some(vec!["bash".to_string()]));
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/entrypoint.sh".to_string()])
        );
        assert_eq!(config.spec.runtime.workdir, Some("/workspace".to_string()));
        assert_eq!(config.spec.runtime.user, Some("root".to_string()));
    }

    #[test]
    fn test_merge_image_defaults_resolves_auto_init_from_image_entrypoint() {
        let image = ImageConfig {
            entrypoint: Some(vec![
                "/init".to_string(),
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
            ]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: PathBuf::from("auto"),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        config.merge_image_defaults(&image);

        let init = config
            .spec
            .init
            .as_ref()
            .expect("init should remain configured");
        assert_eq!(init.cmd, PathBuf::from("/init"));
        assert!(init.args.is_empty());
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/opt/hermes/docker/main-wrapper.sh".to_string()])
        );
    }

    #[test]
    fn test_merge_image_defaults_passes_initial_command_to_init_entrypoint() {
        let image = ImageConfig {
            entrypoint: Some(vec![
                "/init".to_string(),
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
            ]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: PathBuf::from("auto"),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        config.set_initial_command(vec!["gateway".to_string(), "run".to_string()]);
        config.merge_image_defaults(&image);

        let init = config
            .spec
            .init
            .as_ref()
            .expect("init should remain configured");
        assert_eq!(init.cmd, PathBuf::from("/init"));
        assert_eq!(
            init.args,
            vec![
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
                "gateway".to_string(),
                "run".to_string()
            ]
        );
        assert!(config.initial_command_consumed_by_init());
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/opt/hermes/docker/main-wrapper.sh".to_string()])
        );
    }

    #[test]
    fn test_merge_image_defaults_passes_effective_env_to_init_entrypoint() {
        let image = ImageConfig {
            entrypoint: Some(vec![
                "/init".to_string(),
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
            ]),
            env: vec![
                "PATH=/image/bin:/usr/bin:/bin".to_string(),
                "IMAGE_ONLY=1".to_string(),
                "OVERRIDE=image".to_string(),
            ],
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: PathBuf::from("auto"),
                    args: Vec::new(),
                    env: vec![
                        ("PATH".to_string(), "/init/bin:/usr/bin:/bin".to_string()),
                        ("INIT_ONLY".to_string(), "1".to_string()),
                    ],
                }),
                env: vec![
                    EnvVar::new("HERMES_DASHBOARD", "1"),
                    EnvVar::new("OVERRIDE", "user"),
                ],
                ..Default::default()
            },
            ..Default::default()
        };
        config.set_initial_command(vec!["gateway".to_string(), "run".to_string()]);
        config.merge_image_defaults(&image);

        let init = config
            .spec
            .init
            .as_ref()
            .expect("init should remain configured");
        assert_eq!(
            init.env,
            vec![
                ("IMAGE_ONLY".to_string(), "1".to_string()),
                ("HERMES_DASHBOARD".to_string(), "1".to_string()),
                ("OVERRIDE".to_string(), "user".to_string()),
                ("PATH".to_string(), "/init/bin:/usr/bin:/bin".to_string()),
                ("INIT_ONLY".to_string(), "1".to_string()),
            ]
        );
    }

    #[test]
    fn test_clone_for_persistence_drops_consumed_init_args() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: PathBuf::from("/init"),
                    args: vec![
                        "/opt/hermes/docker/main-wrapper.sh".to_string(),
                        "gateway".to_string(),
                        "run".to_string(),
                    ],
                    env: vec![("HERMES_DASHBOARD".to_string(), "1".to_string())],
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        config.set_initial_command(vec!["gateway".to_string(), "run".to_string()]);
        config.initial_command_consumed_by_init = true;

        let persisted = config.clone_for_persistence();

        let runtime_init = config.spec.init.as_ref().expect("runtime init");
        assert_eq!(
            runtime_init.args,
            vec![
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
                "gateway".to_string(),
                "run".to_string(),
            ]
        );
        let persisted_init = persisted.spec.init.as_ref().expect("persisted init");
        assert!(persisted_init.args.is_empty());
        assert_eq!(
            persisted_init.env,
            vec![("HERMES_DASHBOARD".to_string(), "1".to_string())]
        );
        assert!(!persisted.initial_command_consumed_by_init());
    }

    #[test]
    fn test_clone_for_persistence_keeps_detached_startup_init_args() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: PathBuf::from("/init"),
                    args: vec![
                        "/opt/hermes/docker/main-wrapper.sh".to_string(),
                        "gateway".to_string(),
                        "run".to_string(),
                    ],
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        config.set_persistent_initial_command(vec!["gateway".to_string(), "run".to_string()]);
        config.initial_command_consumed_by_init = true;

        let persisted = config.clone_for_persistence();

        let persisted_init = persisted.spec.init.as_ref().expect("persisted init");
        assert_eq!(
            persisted_init.args,
            vec![
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
                "gateway".to_string(),
                "run".to_string(),
            ]
        );
        assert!(!persisted.initial_command_consumed_by_init());
    }

    #[test]
    fn test_clone_for_persistence_keeps_user_init_args() {
        let config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: PathBuf::from("/lib/systemd/systemd"),
                    args: vec!["--unit=multi-user.target".to_string()],
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };

        let persisted = config.clone_for_persistence();

        let persisted_init = persisted.spec.init.as_ref().expect("persisted init");
        assert_eq!(
            persisted_init.args,
            vec!["--unit=multi-user.target".to_string()]
        );
    }

    #[test]
    fn test_merge_image_defaults_passes_image_cmd_to_init_entrypoint() {
        let image = ImageConfig {
            entrypoint: Some(vec!["/init".to_string()]),
            cmd: Some(vec!["/app/server".to_string(), "--serve".to_string()]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: PathBuf::from("auto"),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        config.set_initial_command(Vec::new());
        config.merge_image_defaults(&image);

        let init = config
            .spec
            .init
            .as_ref()
            .expect("init should remain configured");
        assert_eq!(init.cmd, PathBuf::from("/init"));
        assert_eq!(
            init.args,
            vec!["/app/server".to_string(), "--serve".to_string()]
        );
        assert!(config.initial_command_consumed_by_init());
        assert_eq!(config.spec.runtime.entrypoint, None);
    }

    #[test]
    fn test_merge_image_defaults_bare_systemd_does_not_consume_initial_command() {
        let image = ImageConfig {
            entrypoint: Some(vec!["/lib/systemd/systemd".to_string()]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: PathBuf::from("auto"),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        config.set_initial_command(vec!["bash".to_string()]);
        config.merge_image_defaults(&image);

        let init = config
            .spec
            .init
            .as_ref()
            .expect("init should remain configured");
        assert_eq!(init.cmd, PathBuf::from("/lib/systemd/systemd"));
        assert!(init.args.is_empty());
        assert!(!config.initial_command_consumed_by_init());
        assert_eq!(config.spec.runtime.entrypoint, None);
    }

    #[test]
    fn test_merge_image_defaults_keeps_user_entrypoint_when_resolving_auto_init() {
        let image = ImageConfig {
            entrypoint: Some(vec![
                "/init".to_string(),
                "/opt/hermes/docker/main-wrapper.sh".to_string(),
            ]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                runtime: SandboxRuntimeOptions {
                    entrypoint: Some(vec!["/bin/sh".to_string()]),
                    ..Default::default()
                },
                init: Some(HandoffInit {
                    cmd: PathBuf::from("auto"),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        config.set_initial_command(vec!["gateway".to_string(), "run".to_string()]);
        config.merge_image_defaults(&image);

        let init = config
            .spec
            .init
            .as_ref()
            .expect("init should remain configured");
        assert_eq!(init.cmd, PathBuf::from("/init"));
        assert!(init.args.is_empty());
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/bin/sh".to_string()])
        );
        assert!(!config.initial_command_consumed_by_init());
    }

    #[test]
    fn test_merge_image_defaults_leaves_auto_init_for_unknown_entrypoint() {
        let image = ImageConfig {
            entrypoint: Some(vec!["/entrypoint.sh".to_string()]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                init: Some(HandoffInit {
                    cmd: PathBuf::from("auto"),
                    args: Vec::new(),
                    env: Vec::new(),
                }),
                ..Default::default()
            },
            ..Default::default()
        };
        config.merge_image_defaults(&image);

        assert_eq!(
            config.spec.init.expect("init should remain configured").cmd,
            PathBuf::from("auto")
        );
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["/entrypoint.sh".to_string()])
        );
    }

    #[test]
    fn test_merge_image_defaults_imports_labels() {
        use std::collections::HashMap;

        let image = ImageConfig {
            labels: HashMap::from([
                (
                    "org.opencontainers.image.source".to_string(),
                    "https://example.com/repo".to_string(),
                ),
                ("vendor".to_string(), "image-vendor".to_string()),
                // Reserved prefix and empty key must be skipped.
                ("sandbox.id".to_string(), "spoofed".to_string()),
                (String::new(), "x".to_string()),
            ]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            spec: SandboxSpec {
                labels: [
                    ("user.id".to_string(), "alice".to_string()),
                    // Collides with an image label; the user value must win.
                    ("vendor".to_string(), "user-vendor".to_string()),
                ]
                .into_iter()
                .collect(),
                ..Default::default()
            },
            ..Default::default()
        };
        config.merge_image_defaults(&image);

        assert_eq!(
            config
                .spec
                .labels
                .get("org.opencontainers.image.source")
                .map(String::as_str),
            Some("https://example.com/repo")
        );
        assert_eq!(
            config.spec.labels.get("user.id").map(String::as_str),
            Some("alice")
        );
        assert_eq!(
            config.spec.labels.get("vendor").map(String::as_str),
            Some("user-vendor")
        );
        assert!(!config.spec.labels.contains_key("sandbox.id"));
        assert!(!config.spec.labels.contains_key(""));
    }

    #[test]
    fn test_merge_image_defaults_empty_strings_treated_as_none() {
        let image = ImageConfig {
            working_dir: Some(String::new()),
            user: Some(String::new()),
            ..Default::default()
        };

        let mut config = SandboxConfig::default();
        config.merge_image_defaults(&image);

        assert!(
            config.spec.runtime.workdir.is_none(),
            "empty working_dir should not propagate"
        );
        assert!(
            config.spec.runtime.user.is_none(),
            "empty user should not propagate"
        );
    }

    #[test]
    fn test_sandbox_config_serializes_manifest_digest_but_redacts_registry_auth() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                name: "persisted".into(),
                ..Default::default()
            },
            ..Default::default()
        };
        config.replace_existing = true;
        config.manifest_digest = Some("sha256:abc123".into());

        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("registry_auth"));
        assert!(!json.contains("replace_existing"));
        assert!(json.contains("manifest_digest"));
        assert!(json.contains("sha256:abc123"));

        let decoded: SandboxConfig = serde_json::from_str(&json).unwrap();
        assert!(decoded.registry_auth.is_none());
        assert!(!decoded.replace_existing);
        assert_eq!(decoded.manifest_digest, config.manifest_digest);
    }

    #[test]
    fn test_sandbox_config_embeds_shared_spec() {
        let spec = microsandbox_types::SandboxSpec {
            name: "spec-test".into(),
            image: RootfsSource::oci("python:3.12"),
            resources: SandboxResources {
                cpus: 2,
                memory_mib: 1024,
            },
            runtime: SandboxRuntimeOptions {
                workdir: Some("/app".into()),
                shell: Some("/bin/bash".into()),
                scripts: [("setup".to_string(), "echo hi".to_string())]
                    .into_iter()
                    .collect(),
                entrypoint: Some(vec!["python".into(), "-u".into()]),
                cmd: Some(vec!["worker.py".into()]),
                hostname: Some("worker".into()),
                user: Some("appuser".into()),
                log_level: Some(SandboxLogLevel::Trace),
                metrics_sample_interval_ms: Some(750),
                disable_metrics_sample: true,
            },
            env: vec![EnvVar::new("A", "B")],
            labels: [("team".to_string(), "infra".to_string())]
                .into_iter()
                .collect(),
            rlimits: vec![microsandbox_types::Rlimit {
                resource: microsandbox_types::RlimitResource::Nofile,
                soft: 1024,
                hard: 2048,
            }],
            security_profile: SecurityProfile::Restricted,
            lifecycle: SandboxPolicy {
                max_duration_secs: Some(3600),
                idle_timeout_secs: Some(120),
            },
            ..Default::default()
        };

        let config = SandboxConfig {
            spec,
            ..Default::default()
        };

        assert_eq!(config.spec.name, "spec-test");
        assert!(
            matches!(config.spec.image, RootfsSource::Oci(ref oci) if oci.reference == "python:3.12")
        );
        assert_eq!(config.spec.resources.cpus, 2);
        assert_eq!(config.spec.resources.memory_mib, 1024);
        assert_eq!(config.spec.runtime.log_level, Some(SandboxLogLevel::Trace));
        assert_eq!(config.spec.runtime.metrics_sample_interval_ms, Some(750));
        assert!(config.spec.runtime.disable_metrics_sample);
        assert_eq!(config.spec.runtime.workdir.as_deref(), Some("/app"));
        assert_eq!(config.spec.runtime.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(
            config.spec.runtime.scripts.get("setup"),
            Some(&"echo hi".into())
        );
        assert_eq!(config.spec.env, vec![EnvVar::new("A", "B")]);
        assert_eq!(config.spec.labels.get("team"), Some(&"infra".into()));
        assert_eq!(config.spec.rlimits.len(), 1);
        assert_eq!(
            config.spec.runtime.entrypoint,
            Some(vec!["python".to_string(), "-u".to_string()])
        );
        assert_eq!(config.spec.runtime.cmd, Some(vec!["worker.py".to_string()]));
        assert_eq!(config.spec.runtime.hostname.as_deref(), Some("worker"));
        assert_eq!(config.spec.runtime.user.as_deref(), Some("appuser"));
        assert_eq!(config.spec.security_profile, SecurityProfile::Restricted);
        assert_eq!(config.spec.lifecycle.max_duration_secs, Some(3600));
        assert_eq!(config.spec.lifecycle.idle_timeout_secs, Some(120));
    }

    #[test]
    fn test_sandbox_config_deserializes_legacy_readonly_mounts() {
        let json = r#"{"name":"legacy","mounts":[{"type":"Tmpfs","guest":"/tmp","size_mib":512,"readonly":false}]}"#;

        let decoded: SandboxConfig = serde_json::from_str(json).unwrap();

        assert_eq!(decoded.spec.mounts.len(), 1);
        match &decoded.spec.mounts[0] {
            VolumeMount::Tmpfs {
                guest,
                size_mib,
                options,
            } => {
                assert_eq!(guest, "/tmp");
                assert_eq!(*size_mib, Some(512));
                assert_eq!(*options, MountOptions::default());
            }
            mount => panic!("expected tmpfs mount, got {mount:?}"),
        }
    }

    #[test]
    fn test_apply_runtime_defaults_adds_tmpfs_for_oci_tmp() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                resources: SandboxResources {
                    memory_mib: 2048,
                    ..Default::default()
                },
                ..Default::default()
            },
            ..Default::default()
        };

        config.apply_runtime_defaults();

        assert_eq!(config.spec.mounts.len(), 1);
        match &config.spec.mounts[0] {
            VolumeMount::Tmpfs {
                guest,
                size_mib,
                options,
            } => {
                assert_eq!(guest, "/tmp");
                assert_eq!(*size_mib, Some(512));
                assert_eq!(*options, MountOptions::default());
            }
            mount => panic!("expected tmpfs mount, got {mount:?}"),
        }
    }

    #[test]
    fn test_apply_rootfs_defaults_sets_oci_upper_size() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                ..Default::default()
            },
            ..Default::default()
        };

        config.apply_rootfs_defaults(None);

        assert_eq!(config.spec.image.oci_upper_size_mib(), Some(4096));
    }

    #[test]
    fn test_apply_rootfs_defaults_uses_backend_oci_upper_size() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                ..Default::default()
            },
            ..Default::default()
        };

        config.apply_rootfs_defaults(Some(8192));

        assert_eq!(config.spec.image.oci_upper_size_mib(), Some(8192));
    }

    #[test]
    fn test_apply_rootfs_defaults_skips_snapshot_upper_source() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                ..Default::default()
            },
            snapshot_upper_source: Some("/tmp/upper.ext4".into()),
            ..Default::default()
        };

        config.apply_rootfs_defaults(Some(8192));

        assert_eq!(config.spec.image.oci_upper_size_mib(), None);
    }

    #[test]
    fn test_apply_runtime_defaults_preserves_explicit_tmp_mount() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::oci("python:3.12"),
                mounts: vec![VolumeMount::Bind {
                    host: "/host/tmp".into(),
                    guest: "/tmp/".into(),
                    options: MountOptions::default(),
                    stat_virtualization: crate::sandbox::StatVirtualization::Strict,
                    host_permissions: crate::sandbox::HostPermissions::Private,
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        config.apply_runtime_defaults();

        assert_eq!(config.spec.mounts.len(), 1);
        match &config.spec.mounts[0] {
            VolumeMount::Bind { guest, .. } => assert_eq!(guest, "/tmp/"),
            mount => panic!("expected bind mount, got {mount:?}"),
        }
    }

    #[test]
    fn test_apply_runtime_defaults_skips_non_oci_roots() {
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::Bind("/tmp/rootfs".into()),
                ..Default::default()
            },
            ..Default::default()
        };

        config.apply_runtime_defaults();

        assert!(config.spec.mounts.is_empty());
    }

    #[test]
    fn test_apply_runtime_defaults_skips_disk_image_roots() {
        // Disk-image rootfses bring their own /tmp (it's part of the
        // shipped filesystem), so we don't synthesise an implicit tmpfs
        // for them. This test pins the policy so a future change has to
        // be deliberate.
        use crate::sandbox::DiskImageFormat;
        let mut config = SandboxConfig {
            spec: SandboxSpec {
                image: RootfsSource::DiskImage {
                    path: "/tmp/disk.qcow2".into(),
                    format: DiskImageFormat::Qcow2,
                    fstype: None,
                },
                ..Default::default()
            },
            ..Default::default()
        };

        config.apply_runtime_defaults();

        assert!(config.spec.mounts.is_empty());
    }
}
