//! Sandbox configuration.

use std::collections::HashMap;

use microsandbox_runtime::policy::{ChildPolicies, SupervisorPolicy};
use serde::{Deserialize, Serialize};

use super::types::{NetworkConfig, Patch, RootfsSource, SecretsConfig, SshConfig, VolumeMount};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

fn default_cpus() -> u8 {
    crate::config::config().sandbox_defaults.cpus
}

fn default_memory_mib() -> u32 {
    crate::config::config().sandbox_defaults.memory_mib
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
        }
    }
}
