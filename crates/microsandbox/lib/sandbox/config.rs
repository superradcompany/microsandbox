//! Sandbox configuration.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use microsandbox_runtime::{logging::LogLevel, policy::SandboxPolicy};
use serde::{Deserialize, Serialize};

use microsandbox_image::{ImageConfig, PullPolicy, RegistryAuth};

use super::{
    exec::Rlimit,
    types::{Patch, RootfsSource, SecretsConfig, SshConfig, VolumeMount},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEFAULT_OCI_TMPFS_PATH: &str = "/tmp";
const DEFAULT_OCI_TMPFS_MAX_SIZE_MIB: u32 = 512;
const DEFAULT_OCI_TMPFS_MEMORY_DIVISOR: u32 = 4;

fn default_cpus() -> u8 {
    crate::config::config().sandbox_defaults.cpus
}

fn default_memory_mib() -> u32 {
    crate::config::config().sandbox_defaults.memory_mib
}

fn default_log_level() -> Option<LogLevel> {
    crate::config::config().log_level
}

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Configuration for a sandbox.
///
/// All config structs derive `Default` for direct construction and
/// `Serialize`/`Deserialize` for file-based configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxConfig {
    /// Unique sandbox name (required).
    pub name: String,

    /// Root filesystem source (required).
    #[serde(default)]
    pub image: RootfsSource,

    /// Number of virtual CPUs.
    #[serde(default = "default_cpus")]
    pub cpus: u8,

    /// Guest memory in MiB.
    #[serde(default = "default_memory_mib")]
    pub memory_mib: u32,

    /// Runtime log level for the sandbox process.
    ///
    /// `None` means the sandbox process stays silent.
    #[serde(default = "default_log_level")]
    pub log_level: Option<LogLevel>,

    /// Working directory inside the sandbox.
    #[serde(default)]
    pub workdir: Option<String>,

    /// Default shell for scripts and interactive sessions.
    #[serde(default)]
    pub shell: Option<String>,

    /// Named scripts available at `/.msb/scripts/<name>` in the guest.
    #[serde(default)]
    pub scripts: HashMap<String, String>,

    /// Environment variables.
    #[serde(default)]
    pub env: Vec<(String, String)>,

    /// Sandbox-wide resource limits inherited by guest processes.
    ///
    /// Unlike per-exec rlimits, these are applied by agentd during PID 1
    /// startup so long-lived daemons and bootstrap scripts inherit the same
    /// raised baseline automatically.
    #[serde(default)]
    pub rlimits: Vec<Rlimit>,

    /// Volume mounts.
    #[serde(default)]
    pub mounts: Vec<VolumeMount>,

    /// Rootfs patches applied before VM start.
    ///
    /// OCI roots bake patches into `upper.ext4`; bind roots patch the host
    /// directory directly.
    #[serde(default)]
    pub patches: Vec<Patch>,

    /// Network configuration.
    #[cfg(feature = "net")]
    #[serde(default)]
    pub network: microsandbox_network::config::NetworkConfig,

    /// Secrets configuration.
    #[serde(default)]
    pub secrets: SecretsConfig,

    /// SSH configuration.
    #[serde(default)]
    pub ssh: SshConfig,

    /// Image entrypoint (inherited from image config, overridable).
    #[serde(default)]
    pub entrypoint: Option<Vec<String>>,

    /// Image default command (inherited from image config, overridable).
    #[serde(default)]
    pub cmd: Option<Vec<String>>,

    /// Guest hostname. Defaults to the sandbox name.
    #[serde(default)]
    pub hostname: Option<String>,

    /// User identity inside sandbox (inherited from image config, overridable).
    #[serde(default)]
    pub user: Option<String>,

    /// Image labels (merged from image config, user labels override).
    #[serde(default)]
    pub labels: HashMap<String, String>,

    /// Signal for graceful shutdown (inherited from image config, overridable).
    #[serde(default)]
    pub stop_signal: Option<String>,

    /// Pull policy for OCI images. Default: `IfMissing`.
    #[serde(default)]
    pub pull_policy: PullPolicy,

    /// Sandbox lifecycle policy.
    #[serde(default)]
    pub policy: SandboxPolicy,

    /// Registry authentication for private OCI registries.
    ///
    /// Redacted (set to `None`) before serialization to database — credentials
    /// are only needed during the pull.
    #[serde(default, skip_serializing)]
    pub registry_auth: Option<RegistryAuth>,

    /// Override the libkrunfw shared library path for this sandbox.
    ///
    /// When `None`, resolution falls back to the global config path, a sibling
    /// of the `msb` binary, or `~/.microsandbox/lib/` (in that order).
    ///
    /// Not persisted — libkrunfw is a host-side resource, not sandbox state.
    #[serde(skip)]
    pub libkrunfw_path: Option<PathBuf>,

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

    /// Manifest digest for the resolved OCI image.
    ///
    /// Set at create time. Used by spawn to derive VMDK and fsmeta paths
    /// from the global cache. `None` for non-OCI rootfs sources.
    #[serde(default)]
    pub(crate) manifest_digest: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxConfig {
    /// Apply OCI image config as defaults. User-provided values take precedence.
    ///
    /// - `env`: image env vars form the base; user env vars override by key, otherwise append.
    /// - `cmd`, `entrypoint`, `workdir`, `user`, `stop_signal`: image value used only if user did not set one.
    /// - `labels`: image labels form the base; user labels override on key conflict.
    pub fn merge_image_defaults(&mut self, image: &ImageConfig) {
        self.env = merge_env(&image.env, &self.env);

        if self.cmd.is_none() {
            self.cmd = image.cmd.clone();
        }
        if self.entrypoint.is_none() {
            self.entrypoint = image.entrypoint.clone();
        }
        if self.workdir.is_none() {
            self.workdir = image
                .working_dir
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(String::from);
        }
        if self.user.is_none() {
            self.user = image
                .user
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(String::from);
        }
        if self.stop_signal.is_none() {
            self.stop_signal = image
                .stop_signal
                .as_deref()
                .filter(|s| !s.is_empty())
                .map(String::from);
        }

        let mut merged = image.labels.clone();
        merged.extend(self.labels.drain());
        self.labels = merged;
    }

    /// Apply runtime defaults that should exist for OCI sandboxes unless the
    /// user explicitly overrode them.
    pub(crate) fn apply_runtime_defaults(&mut self) {
        if !matches!(self.image, RootfsSource::Oci(_)) {
            return;
        }

        if self
            .mounts
            .iter()
            .any(|mount| guest_mount_is(mount, DEFAULT_OCI_TMPFS_PATH))
        {
            return;
        }

        self.mounts.push(VolumeMount::Tmpfs {
            guest: DEFAULT_OCI_TMPFS_PATH.to_string(),
            size_mib: Some(default_oci_tmpfs_size_mib(self.memory_mib)),
            readonly: false,
        });
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Merge two sets of env-var pairs. Base entries are kept unless overridden by
/// key, then all override entries are appended.
pub(crate) fn merge_env_pairs(
    base: &[(String, String)],
    overrides: &[(String, String)],
) -> Vec<(String, String)> {
    let override_keys: HashSet<&str> = overrides.iter().map(|(k, _)| k.as_str()).collect();

    let mut merged: Vec<(String, String)> = base
        .iter()
        .filter(|(k, _)| !override_keys.contains(k.as_str()))
        .cloned()
        .collect();

    merged.extend(overrides.iter().cloned());
    merged
}

/// Merge image env vars (OCI `KEY=VALUE` strings) with user env var pairs.
fn merge_env(image_env: &[String], user_env: &[(String, String)]) -> Vec<(String, String)> {
    let base: Vec<(String, String)> = image_env
        .iter()
        .filter_map(|entry| match entry.split_once('=') {
            Some((k, v)) => Some((k.to_string(), v.to_string())),
            None => {
                tracing::warn!(entry = %entry, "skipping malformed image env var (expected KEY=VALUE)");
                None
            }
        })
        .collect();

    merge_env_pairs(&base, user_env)
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

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            image: RootfsSource::default(),
            cpus: default_cpus(),
            memory_mib: default_memory_mib(),
            log_level: default_log_level(),
            workdir: None,
            shell: None,
            scripts: HashMap::new(),
            env: Vec::new(),
            rlimits: Vec::new(),
            mounts: Vec::new(),
            patches: Vec::new(),
            #[cfg(feature = "net")]
            network: microsandbox_network::config::NetworkConfig::default(),
            secrets: SecretsConfig::default(),
            ssh: SshConfig::default(),
            hostname: None,
            entrypoint: None,
            cmd: None,
            user: None,
            labels: HashMap::new(),
            stop_signal: None,
            pull_policy: PullPolicy::default(),
            policy: SandboxPolicy::default(),
            registry_auth: None,
            libkrunfw_path: None,
            insecure: false,
            ca_certs: Vec::new(),
            replace_existing: false,
            manifest_digest: None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use microsandbox_image::ImageConfig;

    use crate::sandbox::{RootfsSource, VolumeMount};

    use super::{SandboxConfig, merge_env};

    #[test]
    fn test_merge_env_image_base_with_user_override() {
        let image_env = vec![
            "PATH=/usr/local/bin:/usr/bin".to_string(),
            "PYTHON_VERSION=3.14".to_string(),
        ];
        let user_env = vec![
            ("PATH".to_string(), "/custom/bin".to_string()),
            ("MY_VAR".to_string(), "hello".to_string()),
        ];

        let merged = merge_env(&image_env, &user_env);

        assert_eq!(
            merged,
            vec![
                ("PYTHON_VERSION".to_string(), "3.14".to_string()),
                ("PATH".to_string(), "/custom/bin".to_string()),
                ("MY_VAR".to_string(), "hello".to_string()),
            ]
        );
    }

    #[test]
    fn test_merge_env_empty_user_inherits_image() {
        let image_env = vec!["PATH=/usr/bin".to_string(), "LANG=C.UTF-8".to_string()];
        let user_env = vec![];

        let merged = merge_env(&image_env, &user_env);

        assert_eq!(
            merged,
            vec![
                ("PATH".to_string(), "/usr/bin".to_string()),
                ("LANG".to_string(), "C.UTF-8".to_string()),
            ]
        );
    }

    #[test]
    fn test_merge_env_empty_image_keeps_user() {
        let image_env = vec![];
        let user_env = vec![("MY_VAR".to_string(), "val".to_string())];

        let merged = merge_env(&image_env, &user_env);

        assert_eq!(merged, vec![("MY_VAR".to_string(), "val".to_string())]);
    }

    #[test]
    fn test_merge_image_defaults_replace_fields() {
        let image = ImageConfig {
            cmd: Some(vec!["python3".to_string()]),
            entrypoint: Some(vec!["/entrypoint.sh".to_string()]),
            working_dir: Some("/app".to_string()),
            user: Some("appuser".to_string()),
            stop_signal: Some("SIGTERM".to_string()),
            ..Default::default()
        };

        let mut config = SandboxConfig::default();
        config.merge_image_defaults(&image);

        assert_eq!(config.cmd, Some(vec!["python3".to_string()]));
        assert_eq!(config.entrypoint, Some(vec!["/entrypoint.sh".to_string()]));
        assert_eq!(config.workdir, Some("/app".to_string()));
        assert_eq!(config.user, Some("appuser".to_string()));
        assert_eq!(config.stop_signal, Some("SIGTERM".to_string()));
    }

    #[test]
    fn test_merge_image_defaults_user_overrides_take_precedence() {
        let image = ImageConfig {
            cmd: Some(vec!["python3".to_string()]),
            entrypoint: Some(vec!["/entrypoint.sh".to_string()]),
            working_dir: Some("/app".to_string()),
            user: Some("appuser".to_string()),
            stop_signal: Some("SIGTERM".to_string()),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            cmd: Some(vec!["bash".to_string()]),
            workdir: Some("/workspace".to_string()),
            user: Some("root".to_string()),
            ..Default::default()
        };
        config.merge_image_defaults(&image);

        assert_eq!(config.cmd, Some(vec!["bash".to_string()]));
        assert_eq!(config.entrypoint, Some(vec!["/entrypoint.sh".to_string()]));
        assert_eq!(config.workdir, Some("/workspace".to_string()));
        assert_eq!(config.user, Some("root".to_string()));
        assert_eq!(config.stop_signal, Some("SIGTERM".to_string()));
    }

    #[test]
    fn test_merge_image_defaults_labels_merged_user_wins() {
        let image = ImageConfig {
            labels: HashMap::from([
                ("maintainer".to_string(), "alice".to_string()),
                ("version".to_string(), "1.0".to_string()),
            ]),
            ..Default::default()
        };

        let mut config = SandboxConfig {
            labels: HashMap::from([
                ("version".to_string(), "custom".to_string()),
                ("my.label".to_string(), "foo".to_string()),
            ]),
            ..Default::default()
        };
        config.merge_image_defaults(&image);

        assert_eq!(config.labels.get("maintainer").unwrap(), "alice");
        assert_eq!(config.labels.get("version").unwrap(), "custom");
        assert_eq!(config.labels.get("my.label").unwrap(), "foo");
    }

    #[test]
    fn test_merge_image_defaults_empty_strings_treated_as_none() {
        let image = ImageConfig {
            working_dir: Some(String::new()),
            user: Some(String::new()),
            stop_signal: Some(String::new()),
            ..Default::default()
        };

        let mut config = SandboxConfig::default();
        config.merge_image_defaults(&image);

        assert!(
            config.workdir.is_none(),
            "empty working_dir should not propagate"
        );
        assert!(config.user.is_none(), "empty user should not propagate");
        assert!(
            config.stop_signal.is_none(),
            "empty stop_signal should not propagate"
        );
    }

    #[test]
    fn test_sandbox_config_serializes_manifest_digest_but_redacts_registry_auth() {
        let mut config = SandboxConfig {
            name: "persisted".into(),
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
    fn test_apply_runtime_defaults_adds_tmpfs_for_oci_tmp() {
        let mut config = SandboxConfig {
            image: RootfsSource::Oci("python:3.12".into()),
            memory_mib: 2048,
            ..Default::default()
        };

        config.apply_runtime_defaults();

        assert_eq!(config.mounts.len(), 1);
        match &config.mounts[0] {
            VolumeMount::Tmpfs {
                guest,
                size_mib,
                readonly,
            } => {
                assert_eq!(guest, "/tmp");
                assert_eq!(*size_mib, Some(512));
                assert!(!*readonly);
            }
            mount => panic!("expected tmpfs mount, got {mount:?}"),
        }
    }

    #[test]
    fn test_apply_runtime_defaults_preserves_explicit_tmp_mount() {
        let mut config = SandboxConfig {
            image: RootfsSource::Oci("python:3.12".into()),
            mounts: vec![VolumeMount::Bind {
                host: "/host/tmp".into(),
                guest: "/tmp/".into(),
                readonly: false,
            }],
            ..Default::default()
        };

        config.apply_runtime_defaults();

        assert_eq!(config.mounts.len(), 1);
        match &config.mounts[0] {
            VolumeMount::Bind { guest, .. } => assert_eq!(guest, "/tmp/"),
            mount => panic!("expected bind mount, got {mount:?}"),
        }
    }

    #[test]
    fn test_apply_runtime_defaults_skips_non_oci_roots() {
        let mut config = SandboxConfig {
            image: RootfsSource::Bind("/tmp/rootfs".into()),
            ..Default::default()
        };

        config.apply_runtime_defaults();

        assert!(config.mounts.is_empty());
    }
}
