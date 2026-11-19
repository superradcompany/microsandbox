//! Persisted configuration observations, distinct from creation input.

use std::collections::BTreeMap;

use microsandbox_types::{
    DiskImageFormat, DnsConfig, EnvVar, HostPattern, HostPermissions, InterfaceOverrides,
    MountOptions, NetworkPolicy, PublishedPortSpec, Rlimit, SandboxPolicy, SandboxRuntimeOptions,
    SandboxSpec, StatVirtualization, TlsConfig,
};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fresh persisted settings. This is an observation, not a creation request or
/// a statement about which settings have been applied to the current VM.
#[derive(Debug, Clone, Serialize)]
pub struct SandboxConfigInspection {
    /// Name reported by this observation.
    pub name: String,
    /// Backend-specific settings; serialized as `kind` and `spec`.
    #[serde(flatten)]
    pub settings: SandboxInspectedSettings,
    /// Paths in `spec` whose details the backend does not expose.
    pub unavailable: Vec<String>,
    /// Paths deliberately withheld by the backend, not empty configured values.
    pub redacted: Vec<String>,
}

/// Local persisted specifications and remote projections have different contracts.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", content = "spec", rename_all = "snake_case")]
pub enum SandboxInspectedSettings {
    /// The local persisted task specification, excluding process-local options.
    Local(Box<SandboxSpec>),
    /// The provider's allowlisted inspection view, never synthesized into a full spec.
    Remote(Box<RemoteSandboxInspection>),
}

/// Typed inspection response from the remote provider. Required fields are not
/// defaulted: malformed or incomplete observations must not look like settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSandboxInspection {
    /// OCI reference; `None` means the provider does not expose this root's source.
    pub image: Option<String>,
    /// Persisted resource sizes, not measured runtime allocation.
    pub resources: RemoteResourceInspection,
    /// Persisted execution settings.
    pub runtime: SandboxRuntimeOptions,
    /// Guest environment entries.
    pub env: Vec<EnvVar>,
    /// Resource labels.
    pub labels: BTreeMap<String, String>,
    /// Resource limits.
    pub rlimits: Vec<Rlimit>,
    /// Lifecycle settings.
    pub lifecycle: SandboxPolicy,
    /// Mount presentation; provider source identities are deliberately absent.
    pub mounts: Vec<RemoteMountInspection>,
    /// Network settings with secret descriptors instead of secret material.
    pub network: RemoteNetworkInspection,
}

/// Persisted remote capacity. Missing numbers are invalid, not default allocations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteResourceInspection {
    /// Configured virtual CPU count.
    pub vcpus: u8,
    /// Configured guest memory in MiB.
    pub memory_mib: u32,
    /// Writable OCI disk size, when reported by the provider.
    pub disk_size_mib: Option<u32>,
}

/// A mount observation has no usable host path or volume identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RemoteMountInspection {
    /// Host-backed mount with its host source withheld.
    Bind {
        /// Guest mount point.
        guest: String,
        /// Mount flags exposed by the provider.
        options: MountOptions,
        /// Guest metadata presentation policy.
        stat_virtualization: StatVirtualization,
        /// Host permission mapping policy.
        host_permissions: HostPermissions,
        /// Directory quota in MiB, when configured.
        quota_mib: Option<u32>,
    },
    /// Named-volume mount with its source identity withheld.
    Named {
        /// Guest mount point.
        guest: String,
        /// Mount flags exposed by the provider.
        options: MountOptions,
        /// Guest metadata presentation policy.
        stat_virtualization: StatVirtualization,
        /// Host permission mapping policy.
        host_permissions: HostPermissions,
    },
    /// Memory-backed guest filesystem.
    Tmpfs {
        /// Guest mount point.
        guest: String,
        /// Memory filesystem capacity in MiB, when configured.
        size_mib: Option<u32>,
        /// Mount flags exposed by the provider.
        options: MountOptions,
    },
    /// Disk-image mount with its source withheld.
    DiskImage {
        /// Guest mount point.
        guest: String,
        /// Disk container format.
        format: DiskImageFormat,
        /// Guest filesystem type, when specified.
        fstype: Option<String>,
        /// Mount flags exposed by the provider.
        options: MountOptions,
    },
}

/// Provider network view. Absence of optional settings is distinct from a fabricated default.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteNetworkInspection {
    /// Whether guest networking is enabled.
    pub enabled: bool,
    /// Published guest ports.
    pub ports: Vec<PublishedPortSpec>,
    /// Whether host certificate authorities are trusted.
    pub trust_host_cas: bool,
    /// Provider-reported connection limit.
    pub max_connections: Option<usize>,
    /// Explicit guest interface overrides, when reported.
    pub interface: Option<InterfaceOverrides>,
    /// Network policy, when reported.
    pub policy: Option<NetworkPolicy>,
    /// DNS settings, when reported.
    pub dns: Option<DnsConfig>,
    /// TLS settings, when reported.
    pub tls: Option<TlsConfig>,
    /// Redacted secret descriptors; omitted by the provider when empty.
    #[serde(default)]
    pub secrets: Vec<RemoteSecretInspection>,
}

/// Redacted secret metadata. No value, vault path or source reference is decoded.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSecretInspection {
    /// Guest environment variable containing the placeholder.
    pub env_var: String,
    /// Substitute visible to the guest, not the secret value.
    pub placeholder: String,
    /// Allowed destination host patterns.
    pub allowed_hosts: Vec<HostPattern>,
    /// Request locations eligible for substitution.
    pub injection: RemoteSecretInjection,
    /// Explicit per-secret violation policy, when reported.
    pub on_violation: Option<RemoteSecretViolation>,
}

/// Locations reported by the provider's secret-injection policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RemoteSecretInjection {
    /// Substitute in HTTP headers.
    pub headers: bool,
    /// Substitute in HTTP Basic authentication.
    pub basic_auth: bool,
    /// Substitute in query parameters.
    pub query_params: bool,
    /// Substitute in request bodies.
    pub body: bool,
}

/// Provider violation policy; passthrough includes its allowed hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteSecretViolation {
    /// Block the request.
    Block,
    /// Block and log the request.
    BlockAndLog,
    /// Block and terminate the sandbox.
    BlockAndTerminate,
    /// Forward the placeholder unchanged only to these hosts.
    Passthrough(Vec<HostPattern>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxConfigInspection {
    /// Runtime settings shared by both inspection shapes.
    pub fn runtime(&self) -> &SandboxRuntimeOptions {
        match &self.settings {
            SandboxInspectedSettings::Local(spec) => &spec.runtime,
            SandboxInspectedSettings::Remote(spec) => &spec.runtime,
        }
    }

    /// Full local task specification, unavailable for a redacted remote view.
    pub fn local_spec(&self) -> Option<&SandboxSpec> {
        match &self.settings {
            SandboxInspectedSettings::Local(spec) => Some(spec),
            _ => None,
        }
    }

    /// Typed remote projection, unavailable for a local observation.
    pub fn remote_spec(&self) -> Option<&RemoteSandboxInspection> {
        match &self.settings {
            SandboxInspectedSettings::Remote(spec) => Some(spec),
            _ => None,
        }
    }

    pub(crate) fn local(spec: SandboxSpec) -> Self {
        Self {
            name: spec.name.clone(),
            settings: SandboxInspectedSettings::Local(Box::new(spec)),
            unavailable: vec![],
            redacted: vec![],
        }
    }

    pub(crate) fn remote(name: String, spec: RemoteSandboxInspection) -> Self {
        let mut unavailable: Vec<String> = [
            "init",
            "security_profile",
            "deployment_profile",
            "patches",
            "pull_policy",
            "vsock",
            "network.max_inbound_tcp_connections",
            "network.max_udp_connections",
            "network.nat64_prefixes",
            "network.strict",
            "network.outbound_proxy",
            "network.http",
            "network.rate_limiter",
            "network.tcp_accept_queue_size",
            "resources.max_cpus",
            "resources.max_memory_mib",
            "resources.cpu_placement",
            "resources.placement_profile",
            "resources.nested_virt",
            "resources.thp",
        ]
        .into_iter()
        .map(String::from)
        .collect();
        if spec.image.is_none() {
            unavailable.push("image".into());
        }
        let mut redacted = vec![];
        for (index, mount) in spec.mounts.iter().enumerate() {
            if !matches!(mount, RemoteMountInspection::Tmpfs { .. }) {
                redacted.push(format!("mounts[{index}].source"));
            }
        }
        for index in 0..spec.network.secrets.len() {
            for field in ["value", "source"] {
                redacted.push(format!("network.secrets[{index}].{field}"));
            }
            unavailable.push(format!("network.secrets[{index}].require_tls_identity"));
        }
        Self {
            name,
            settings: SandboxInspectedSettings::Remote(Box::new(spec)),
            unavailable,
            redacted,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::json;

    pub(crate) fn projection() -> serde_json::Value {
        json!({
            "image": "python", "resources": {"vcpus":2,"memory_mib":512},
            "runtime": {"shell":"/bin/bash","workdir":"/tmp","entrypoint":["printf"],"cmd":["ok"]},
            "env": [], "labels": {}, "rlimits": [], "lifecycle": {"ephemeral":false},
            "mounts": [], "network": {"enabled":true,"ports":[],"trust_host_cas":false}
        })
    }

    #[test]
    fn projection_is_not_creation_input_and_preserves_redaction() {
        let mut value = projection();
        value["image"] = serde_json::Value::Null;
        value["network"]["secrets"] = json!([{
            "env_var":"TOKEN", "placeholder":"placeholder", "allowed_hosts":[{"exact":"example.com"}],
            "injection":{"headers":true,"basic_auth":false,"query_params":false,"body":false},
            "on_violation":{"passthrough":[{"wildcard":"*.example.com"}]},
            "value":"must-not-retain", "vault_path":"must-not-retain"
        }]);
        let view =
            SandboxConfigInspection::remote("task".into(), serde_json::from_value(value).unwrap());
        assert_eq!(view.runtime().shell.as_deref(), Some("/bin/bash"));
        assert!(view.local_spec().is_none());
        assert!(view.unavailable.contains(&"image".into()));
        assert!(view.redacted.contains(&"network.secrets[0].value".into()));
        let encoded = serde_json::to_string(&view).unwrap();
        assert!(!encoded.contains("must-not-retain"));
        assert!(!encoded.contains("vault_path"));
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&encoded).unwrap()["kind"],
            "remote"
        );
    }

    #[test]
    fn incomplete_or_malformed_projection_is_not_defaulted() {
        for field in ["runtime", "resources", "mounts", "network", "env"] {
            let mut value = projection();
            value.as_object_mut().unwrap().remove(field);
            assert!(
                serde_json::from_value::<RemoteSandboxInspection>(value).is_err(),
                "{field}"
            );
        }
        for field in ["vcpus", "memory_mib"] {
            let mut value = projection();
            value["resources"].as_object_mut().unwrap().remove(field);
            assert!(serde_json::from_value::<RemoteSandboxInspection>(value).is_err());
        }
        let mut value = projection();
        value["runtime"]["shell"] = json!(123);
        assert!(serde_json::from_value::<RemoteSandboxInspection>(value).is_err());
    }

    #[test]
    fn mount_projection_does_not_invent_sources() {
        let mut value = projection();
        value["mounts"] = json!([
            {"type":"Bind","guest":"/bind","options":{},"stat_virtualization":"off","host_permissions":"private"},
            {"type":"Named","guest":"/named","options":{},"stat_virtualization":"off","host_permissions":"private"},
            {"type":"Tmpfs","guest":"/tmp","options":{}},
            {"type":"DiskImage","guest":"/disk","format":"Raw","options":{}}
        ]);
        let view =
            SandboxConfigInspection::remote("task".into(), serde_json::from_value(value).unwrap());
        assert_eq!(
            view.redacted,
            ["mounts[0].source", "mounts[1].source", "mounts[3].source"]
        );
    }
}
