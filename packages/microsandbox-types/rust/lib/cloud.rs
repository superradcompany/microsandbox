//! Wire types for the cloud backend's HTTP calls.
//!
//! HTTP route versions choose this concrete request shape. The request shape is
//! user-facing intent, so disk sizing sits beside CPU and memory; conversion
//! into the domain spec moves that value onto the OCI rootfs where the runtime
//! realizes it.

use std::collections::BTreeMap;
use std::path::PathBuf;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use crate::domain::{
    DiskImageFormat, EnvVar, HandoffInit, NetworkPolicy, NetworkSpec, OciRootfsSource, Patch,
    PullPolicy, Rlimit, RootfsSource, SandboxLogLevel, SandboxPolicy, SandboxResources,
    SandboxRuntimeOptions, SandboxSpec, SecretsConfig, SecurityProfile, VolumeMount,
};
use crate::{TypesError, TypesResult};

//--------------------------------------------------------------------------------------------------
// Types: Request
//--------------------------------------------------------------------------------------------------

/// Wire shape of a cloud sandbox create request body.
///
/// Flattens [`CloudSandboxSpec`] onto the request body, so on the wire this is
/// byte-identical to `CloudSandboxSpec`. typeshare cannot model `#[serde(flatten)]`,
/// so the generated bindings surface the flattened shape as `CloudSandboxSpec`
/// directly (see [`CloudCreateSandboxResponse::spec`], typed `CloudSandboxSpec`).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
pub struct CloudCreateSandboxRequest {
    /// The cloud sandbox specification, flattened onto the request body.
    #[serde(flatten)]
    pub spec: CloudSandboxSpec,
}

/// Cloud sandbox specification carried on create routes.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct CloudSandboxSpec {
    /// Unique sandbox name.
    pub name: String,

    /// Root filesystem source.
    #[cfg_attr(feature = "utoipa", schema(value_type = Object))]
    pub image: CloudRootfsSource,

    /// CPU, memory, and user-facing disk resources.
    pub resources: CloudSandboxResources,

    /// Guest runtime options (curated; platform-controlled fields omitted).
    pub runtime: CloudSandboxRuntimeOptions,

    /// Environment variables visible to commands in the sandbox.
    pub env: Vec<EnvVar>,

    /// User-defined labels attached to the sandbox.
    pub labels: BTreeMap<String, String>,

    /// Sandbox-wide resource limits inherited by guest processes.
    pub rlimits: Vec<Rlimit>,

    /// Volume mounts.
    pub mounts: Vec<VolumeMount>,

    /// Rootfs patches applied before VM start.
    pub patches: Vec<Patch>,

    /// Network specification (curated; platform-controlled fields omitted).
    pub network: CloudNetworkSpec,

    /// Hand off PID 1 to a guest init binary after agentd setup.
    pub init: Option<HandoffInit>,

    /// Pull policy for OCI images.
    pub pull_policy: PullPolicy,

    /// In-guest security profile.
    pub security_profile: SecurityProfile,

    /// Sandbox lifecycle policy.
    pub lifecycle: SandboxPolicy,
}

/// Cloud resource request.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct CloudSandboxResources {
    /// Number of virtual CPUs.
    pub vcpus: u8,

    /// Guest memory in MiB.
    pub memory_mib: u32,

    /// Writable disk size in MiB. Applies only to OCI root filesystems.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disk_size_mib: Option<u32>,
}

/// Cloud root filesystem source.
///
/// Mirrors the domain [`RootfsSource`] JSON shape, but keeps writable-disk
/// sizing out of the image payload. Cloud callers express that intent through
/// [`CloudSandboxResources::disk_size_mib`]; conversion to the domain spec
/// attaches it to OCI rootfs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudRootfsSource {
    /// Use a host directory directly as the root filesystem.
    #[serde(alias = "Bind")]
    Bind(
        /// Host path to bind mount.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        PathBuf,
    ),

    /// Use an OCI image reference with an EROFS lower and ext4 overlay upper.
    #[serde(alias = "Oci")]
    Oci {
        /// OCI image reference (e.g. `python`).
        reference: String,
    },

    /// Use a disk image file as the root filesystem via virtio-blk.
    #[serde(alias = "DiskImage")]
    DiskImage {
        /// Path to the disk image file on the host.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        path: PathBuf,
        /// Disk image format.
        format: DiskImageFormat,
        /// Inner filesystem type (optional; auto-detected if absent).
        fstype: Option<String>,
    },
}

/// Cloud network specification. Mirrors the domain [`NetworkSpec`] but omits
/// the platform-controlled fields: interface overrides, host port mapping,
/// DNS, TLS interception, and host-CA trust are set by the cloud, not the
/// caller. `deny_unknown_fields` — posting an omitted field is an error, not a
/// silent drop.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default, deny_unknown_fields)]
pub struct CloudNetworkSpec {
    /// Whether networking is enabled for this sandbox.
    pub enabled: bool,

    /// Egress/ingress policy. The cloud floors it (hard-denies the internal
    /// network) before boot; public egress stays the caller's to govern.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<NetworkPolicy>,

    /// Secret-injection config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SecretsConfig>,

    /// Max concurrent guest connections (the cloud clamps it to a ceiling).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_connections: Option<usize>,
}

impl Default for CloudNetworkSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            policy: None,
            secrets: None,
            max_connections: None,
        }
    }
}

/// Cloud guest runtime options. Mirrors [`SandboxRuntimeOptions`] but omits the
/// platform-controlled fields: the hostname (pinned to the sandbox id) and the
/// metrics-sampling knobs (metering integrity). `deny_unknown_fields`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default, deny_unknown_fields)]
pub struct CloudSandboxRuntimeOptions {
    /// Working directory for guest commands.
    pub workdir: Option<String>,

    /// Default shell.
    pub shell: Option<String>,

    /// Named in-guest scripts.
    pub scripts: BTreeMap<String, String>,

    /// Entrypoint override.
    pub entrypoint: Option<Vec<String>>,

    /// Command override.
    pub cmd: Option<Vec<String>>,

    /// Guest user.
    pub user: Option<String>,

    /// Runtime log level.
    pub log_level: Option<SandboxLogLevel>,
}

//--------------------------------------------------------------------------------------------------
// Types: Response
//--------------------------------------------------------------------------------------------------

/// Wire shape of the cloud sandbox response returned by sandbox endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudCreateSandboxResponse {
    /// Server-side UUID.
    pub id: String,
    /// Owning org's UUID.
    pub org_id: String,
    /// User-facing, per-org sandbox name.
    pub name: String,
    /// Canonical, resolved SSH username token.
    pub slug: String,
    /// Current lifecycle status.
    pub status: CloudSandboxStatus,
    /// The sandbox spec the cloud control plane stored for this sandbox.
    pub spec: CloudSandboxSpec,
    /// Whether the sandbox should be removed when its allocation terminates.
    pub ephemeral: bool,
    /// Creation timestamp.
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub created_at: DateTime<Utc>,
    /// Last start timestamp, when known.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub started_at: Option<DateTime<Utc>>,
    /// Last stop timestamp, when known.
    #[serde(default)]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub stopped_at: Option<DateTime<Utc>>,
    /// Last failure reason, when any.
    #[serde(default)]
    pub last_error: Option<String>,
}

/// Sandbox lifecycle status returned by the cloud control plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudSandboxStatus {
    /// Created in the database but not yet started.
    Created,
    /// Start request has been submitted.
    Starting,
    /// Sandbox is running.
    Running,
    /// Stop request has been submitted.
    Stopping,
    /// Sandbox is stopped.
    Stopped,
    /// Sandbox failed.
    Failed,
}

/// Wire shape of paginated list responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudPaginated<T> {
    /// Page of response items.
    pub data: Vec<T>,
    /// Cursor for the next page, when one exists.
    #[serde(default)]
    pub next_cursor: Option<String>,
}

/// Wire shape of the message response returned by mutation endpoints.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudMessageResponse {
    /// Human-readable response message.
    pub message: String,
}

/// Wire shape of the typed error body returned by cloud APIs on 4xx/5xx responses.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudErrorBody {
    /// Flat machine-readable error code, when returned in this shape.
    #[serde(default)]
    pub code: Option<String>,
    /// Flat human-readable error message, when returned in this shape.
    #[serde(default)]
    pub message: Option<String>,
    /// Nested error object returned by the API error responder.
    #[serde(default)]
    pub error: Option<CloudErrorDetails>,
}

/// Nested cloud API error details.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudErrorDetails {
    /// Machine-readable error code.
    #[serde(default)]
    pub code: Option<String>,
    /// Human-readable error message.
    #[serde(default)]
    pub message: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl TryFrom<CloudCreateSandboxRequest> for SandboxSpec {
    type Error = TypesError;

    fn try_from(req: CloudCreateSandboxRequest) -> TypesResult<Self> {
        req.spec.try_into()
    }
}

impl TryFrom<CloudSandboxSpec> for SandboxSpec {
    type Error = TypesError;

    fn try_from(spec: CloudSandboxSpec) -> TypesResult<Self> {
        let disk_size_mib = spec.resources.disk_size_mib;
        let image = match spec.image {
            CloudRootfsSource::Oci { reference } => RootfsSource::Oci(OciRootfsSource {
                reference,
                upper_size_mib: disk_size_mib,
            }),
            CloudRootfsSource::Bind(_) | CloudRootfsSource::DiskImage { .. }
                if disk_size_mib.is_some() =>
            {
                return Err(TypesError::invalid_config(
                    "resources.disk_size_mib is only valid for OCI rootfs",
                ));
            }
            CloudRootfsSource::Bind(path) => RootfsSource::Bind(path),
            CloudRootfsSource::DiskImage {
                path,
                format,
                fstype,
            } => RootfsSource::DiskImage {
                path,
                format,
                fstype,
            },
        };

        let resources = SandboxResources {
            vcpus: spec.resources.vcpus,
            memory_mib: spec.resources.memory_mib,
            // The cloud wire type has no boot-capacity fields yet; treat the
            // effective resources as the maximum (mirrors SandboxResources
            // deserialization for legacy configs).
            max_vcpus: spec.resources.vcpus,
            max_memory_mib: spec.resources.memory_mib,
        };

        // Fill the platform-controlled fields the cloud twins omit with safe
        // defaults; the resolver + driver floor set/override them.
        let network = NetworkSpec {
            enabled: spec.network.enabled,
            policy: spec.network.policy,
            secrets: spec.network.secrets,
            max_connections: spec.network.max_connections,
            ..NetworkSpec::default()
        };
        let runtime = SandboxRuntimeOptions {
            workdir: spec.runtime.workdir,
            shell: spec.runtime.shell,
            scripts: spec.runtime.scripts,
            entrypoint: spec.runtime.entrypoint,
            cmd: spec.runtime.cmd,
            user: spec.runtime.user,
            log_level: spec.runtime.log_level,
            ..SandboxRuntimeOptions::default()
        };

        Ok(Self {
            name: spec.name,
            image,
            resources,
            runtime,
            env: spec.env,
            labels: spec.labels,
            rlimits: spec.rlimits,
            mounts: spec.mounts,
            patches: spec.patches,
            network,
            init: spec.init,
            pull_policy: spec.pull_policy,
            security_profile: spec.security_profile,
            lifecycle: spec.lifecycle,
        })
    }
}

impl From<SandboxSpec> for CloudCreateSandboxRequest {
    fn from(spec: SandboxSpec) -> Self {
        Self { spec: spec.into() }
    }
}

impl From<SandboxSpec> for CloudSandboxSpec {
    fn from(spec: SandboxSpec) -> Self {
        let (image, disk_size_mib) = match spec.image {
            RootfsSource::Oci(oci) => (
                CloudRootfsSource::Oci {
                    reference: oci.reference,
                },
                oci.upper_size_mib,
            ),
            RootfsSource::Bind(path) => (CloudRootfsSource::Bind(path), None),
            RootfsSource::DiskImage {
                path,
                format,
                fstype,
            } => (
                CloudRootfsSource::DiskImage {
                    path,
                    format,
                    fstype,
                },
                None,
            ),
        };

        Self {
            name: spec.name,
            image,
            resources: CloudSandboxResources {
                vcpus: spec.resources.vcpus,
                memory_mib: spec.resources.memory_mib,
                disk_size_mib,
            },
            runtime: CloudSandboxRuntimeOptions {
                workdir: spec.runtime.workdir,
                shell: spec.runtime.shell,
                scripts: spec.runtime.scripts,
                entrypoint: spec.runtime.entrypoint,
                cmd: spec.runtime.cmd,
                user: spec.runtime.user,
                log_level: spec.runtime.log_level,
            },
            env: spec.env,
            labels: spec.labels,
            rlimits: spec.rlimits,
            mounts: spec.mounts,
            patches: spec.patches,
            network: CloudNetworkSpec {
                enabled: spec.network.enabled,
                policy: spec.network.policy,
                secrets: spec.network.secrets,
                max_connections: spec.network.max_connections,
            },
            init: spec.init,
            pull_policy: spec.pull_policy,
            security_profile: spec.security_profile,
            lifecycle: spec.lifecycle,
        }
    }
}

impl Default for CloudSandboxResources {
    fn default() -> Self {
        let resources = SandboxResources::default();
        Self {
            vcpus: resources.vcpus,
            memory_mib: resources.memory_mib,
            disk_size_mib: None,
        }
    }
}

impl CloudRootfsSource {
    /// Create an OCI rootfs source from an image reference.
    pub fn oci(reference: impl Into<String>) -> Self {
        Self::Oci {
            reference: reference.into(),
        }
    }

    /// Return the OCI image reference if this is an OCI rootfs.
    pub fn oci_reference(&self) -> Option<&str> {
        match self {
            Self::Oci { reference } => Some(reference),
            _ => None,
        }
    }
}

impl Default for CloudRootfsSource {
    fn default() -> Self {
        Self::oci(String::new())
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        DEFAULT_SANDBOX_MEMORY_MIB, DEFAULT_SANDBOX_VCPUS, OciRootfsSource, RootfsSource,
    };

    fn spec(name: &str) -> CloudSandboxSpec {
        CloudSandboxSpec {
            name: name.into(),
            image: CloudRootfsSource::Oci {
                reference: "python:3.12".into(),
            },
            ..Default::default()
        }
    }

    #[test]
    fn create_request_flattens_spec() {
        let req = CloudCreateSandboxRequest {
            spec: spec("agent-1"),
        };
        let json = serde_json::to_value(&req).unwrap();
        // Spec fields are flattened onto the top level (SDK parity).
        assert_eq!(json["name"], "agent-1");
        assert!(json.get("image").is_some());

        let back: CloudCreateSandboxRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.spec.name, "agent-1");
    }

    #[test]
    fn create_request_converts_disk_size_to_oci_rootfs() {
        let mut req = CloudCreateSandboxRequest {
            spec: spec("agent-1"),
        };
        req.spec.resources.disk_size_mib = Some(8192);

        let domain = SandboxSpec::try_from(req).unwrap();

        assert_eq!(domain.resources.vcpus, DEFAULT_SANDBOX_VCPUS);
        assert_eq!(domain.resources.memory_mib, DEFAULT_SANDBOX_MEMORY_MIB);
        match domain.image {
            RootfsSource::Oci(oci) => {
                assert_eq!(oci.reference, "python:3.12");
                assert_eq!(oci.upper_size_mib, Some(8192));
            }
            other => panic!("expected OCI rootfs, got {other:?}"),
        }
    }

    #[test]
    fn create_request_rejects_disk_size_for_non_oci_rootfs() {
        let mut req = CloudCreateSandboxRequest {
            spec: spec("agent-1"),
        };
        req.spec.image = CloudRootfsSource::Bind("/tmp/rootfs".into());
        req.spec.resources.disk_size_mib = Some(8192);

        let err = SandboxSpec::try_from(req).unwrap_err();

        assert!(err.to_string().contains("disk_size_mib"));
    }

    #[test]
    fn domain_spec_converts_oci_size_to_cloud_resources() {
        let domain = SandboxSpec {
            name: "agent-1".into(),
            image: RootfsSource::Oci(OciRootfsSource {
                reference: "python:3.12".into(),
                upper_size_mib: Some(8192),
            }),
            ..Default::default()
        };

        let req = CloudCreateSandboxRequest::from(domain);

        assert_eq!(req.spec.resources.disk_size_mib, Some(8192));
        match req.spec.image {
            CloudRootfsSource::Oci { reference } => {
                assert_eq!(reference, "python:3.12");
            }
            other => panic!("expected OCI rootfs, got {other:?}"),
        }
    }

    #[test]
    fn create_request_minimal_defaults() {
        // Only the spec's name + image are set; everything else defaults.
        let req = CloudCreateSandboxRequest {
            spec: spec("agent-1"),
        };
        let json = serde_json::to_value(&req).unwrap();
        let back: CloudCreateSandboxRequest = serde_json::from_value(json).unwrap();
        assert_eq!(back.spec.name, "agent-1");
    }

    #[test]
    fn sandbox_status_round_trips_snake_case() {
        for status in [
            CloudSandboxStatus::Created,
            CloudSandboxStatus::Starting,
            CloudSandboxStatus::Running,
            CloudSandboxStatus::Stopping,
            CloudSandboxStatus::Stopped,
            CloudSandboxStatus::Failed,
        ] {
            let s = serde_json::to_string(&status).unwrap();
            assert_eq!(
                serde_json::from_str::<CloudSandboxStatus>(&s).unwrap(),
                status
            );
        }
        assert_eq!(
            serde_json::to_string(&CloudSandboxStatus::Starting).unwrap(),
            "\"starting\""
        );
    }

    #[test]
    fn sandbox_response_round_trips() {
        let sb = CloudCreateSandboxResponse {
            id: "00000000-0000-0000-0000-000000000002".into(),
            org_id: "00000000-0000-0000-0000-000000000001".into(),
            name: "agent-1".into(),
            slug: "brave-otter".into(),
            status: CloudSandboxStatus::Created,
            spec: spec("agent-1"),
            ephemeral: true,
            created_at: "2026-05-17T12:00:00Z".parse().unwrap(),
            started_at: None,
            stopped_at: None,
            last_error: None,
        };
        let json = serde_json::to_value(&sb).unwrap();
        assert_eq!(json["slug"], "brave-otter");
        assert_eq!(json["name"], "agent-1");

        let back: CloudCreateSandboxResponse = serde_json::from_value(json).unwrap();
        assert_eq!(back.slug, "brave-otter");
        assert_eq!(back.status, CloudSandboxStatus::Created);
        assert_eq!(back.spec.name, "agent-1");
        assert!(back.started_at.is_none());
    }
}
