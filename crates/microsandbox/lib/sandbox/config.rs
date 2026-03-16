//! Sandbox configuration.

use std::{collections::HashMap, path::PathBuf};

use microsandbox_runtime::{
    logging::LogLevel,
    policy::{ChildPolicies, SupervisorPolicy},
};
use serde::{Deserialize, Serialize};

use microsandbox_image::RegistryAuth;

use microsandbox_network::config::NetworkConfig;

use super::types::{Patch, RootfsSource, SecretsConfig, SshConfig, VolumeMount};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

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
#[derive(Debug, Serialize, Deserialize)]
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

    /// Runtime log level for `msb supervisor` and `msb microvm`.
    ///
    /// `None` means sandbox runtime processes stay silent.
    #[serde(default = "default_log_level")]
    pub log_level: Option<LogLevel>,

    /// Working directory inside the sandbox.
    #[serde(default)]
    pub workdir: Option<String>,

    /// Default shell for scripts and interactive sessions.
    #[serde(default)]
    pub shell: Option<String>,

    /// Custom init binary path. `None` uses the embedded init.
    #[serde(default)]
    pub init: Option<String>,

    /// Named scripts available at `/.msb/scripts/<name>` in the guest.
    #[serde(default)]
    pub scripts: HashMap<String, String>,

    /// Environment variables.
    #[serde(default)]
    pub env: Vec<(String, String)>,

    /// Volume mounts.
    #[serde(default)]
    pub mounts: Vec<VolumeMount>,

    /// Rootfs patches applied as overlay layers before VM start.
    #[serde(default)]
    pub patches: Vec<Patch>,

    /// Network configuration.
    #[serde(default)]
    pub network: NetworkConfig,

    /// Secrets configuration.
    #[serde(default)]
    pub secrets: SecretsConfig,

    /// SSH configuration.
    #[serde(default)]
    pub ssh: SshConfig,

    /// Supervisor lifecycle policy.
    #[serde(default)]
    pub supervisor_policy: SupervisorPolicy,

    /// Per-child process policies.
    #[serde(default)]
    pub child_policies: ChildPolicies,

    /// Registry authentication for private OCI registries.
    ///
    /// Redacted (set to `None`) before serialization to database — credentials
    /// are only needed during the pull.
    #[serde(default, skip_serializing)]
    pub registry_auth: Option<RegistryAuth>,

    /// Replace an existing stopped sandbox with the same name during create.
    ///
    /// This is an operation flag, not persisted sandbox state.
    #[serde(skip)]
    pub replace_existing: bool,

    /// Resolved rootfs lower layer paths (populated at create time for OCI images).
    ///
    /// Sidecar indexes are discovered by naming convention in the runtime as
    /// `<lower>.index`, so only the lower directory path is carried here.
    /// Persisted so existing sandboxes can reuse the pinned lower stack
    /// without re-resolving a mutable OCI reference.
    #[serde(default)]
    pub(crate) resolved_rootfs_layers: Vec<PathBuf>,
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
            init: None,
            scripts: HashMap::new(),
            env: Vec::new(),
            mounts: Vec::new(),
            patches: Vec::new(),
            network: NetworkConfig::default(),
            secrets: SecretsConfig::default(),
            ssh: SshConfig::default(),
            supervisor_policy: SupervisorPolicy::default(),
            child_policies: ChildPolicies::default(),
            registry_auth: None,
            replace_existing: false,
            resolved_rootfs_layers: Vec::new(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use microsandbox_image::RegistryAuth;

    use super::SandboxConfig;

    #[test]
    fn test_sandbox_config_serializes_pinned_rootfs_layers_but_redacts_registry_auth() {
        let mut config = SandboxConfig {
            name: "persisted".into(),
            ..Default::default()
        };
        config.registry_auth = Some(RegistryAuth::Basic {
            username: "alice".into(),
            password: "secret".into(),
        });
        config.replace_existing = true;
        config.resolved_rootfs_layers = vec!["/tmp/layer0".into(), "/tmp/layer1".into()];

        let json = serde_json::to_string(&config).unwrap();
        assert!(!json.contains("registry_auth"));
        assert!(!json.contains("replace_existing"));
        assert!(json.contains("resolved_rootfs_layers"));

        let decoded: SandboxConfig = serde_json::from_str(&json).unwrap();
        assert!(decoded.registry_auth.is_none());
        assert!(!decoded.replace_existing);
        assert_eq!(
            decoded.resolved_rootfs_layers,
            config.resolved_rootfs_layers
        );
    }
}
