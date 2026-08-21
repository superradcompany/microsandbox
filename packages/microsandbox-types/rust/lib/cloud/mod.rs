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
    CpuPlacement, DeploymentProfile, EnvVar, HandoffInit, NetworkSpec, OciRootfsSource, RootDisk,
    RootfsSource, SandboxPolicy, SandboxResources, SandboxRuntimeOptions, SandboxSpec,
    SecurityProfile, TransparentHugePagePolicy, VsockSpec,
};
use crate::{TypesError, TypesResult};

mod compat;
mod secrets;
mod snapshots;
mod specs;

pub use secrets::{
    CloudHostPattern, CloudSecretEntry, CloudSecretSource, CloudSecretsConfig, CloudViolationAction,
};
pub use snapshots::{
    CloudCreateSnapshotRequest, CloudSnapshot, CloudSnapshotLocation, CloudSnapshotOperation,
    CloudSnapshotOperationStatus,
};
pub use specs::{
    CloudDiskImageFormat, CloudNetworkSpec, CloudPatch, CloudPullPolicy, CloudRlimit,
    CloudRlimitResource, CloudRootfsSource, CloudSandboxRuntimeOptions, CloudVolumeMount,
};

//--------------------------------------------------------------------------------------------------
// Types: Request
//--------------------------------------------------------------------------------------------------

/// Wire shape of a cloud sandbox create request body.
///
/// Each root filesystem origin is a distinct source variant. The common
/// sandbox settings remain flat beside the source-specific fields. Legacy
/// requests carrying an `image` object are accepted during migration.
#[derive(Debug, Clone, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "source", rename_all = "snake_case")]
pub enum CloudCreateSandboxRequest {
    /// Create a sandbox from an OCI image.
    Oci {
        /// Settings shared by every sandbox source.
        #[serde(flatten)]
        sandbox: CloudSandboxSpec,
        /// OCI image reference.
        reference: String,
        /// CPU, memory, and writable-disk resources.
        #[serde(default)]
        resources: CloudSandboxResources,
        /// Rootfs patches applied before VM start.
        #[serde(default)]
        patches: Vec<CloudPatch>,
        /// OCI image pull policy.
        #[serde(default)]
        pull_policy: CloudPullPolicy,
    },
    /// Create a sandbox from a host directory.
    Bind {
        /// Settings shared by every sandbox source.
        #[serde(flatten)]
        sandbox: CloudSandboxSpec,
        /// Host directory used as the root filesystem.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        path: PathBuf,
        /// CPU and memory resources.
        #[serde(default)]
        resources: CloudSandboxComputeResources,
        /// Rootfs patches applied before VM start.
        #[serde(default)]
        patches: Vec<CloudPatch>,
    },
    /// Create a sandbox from a disk image file.
    DiskImage {
        /// Settings shared by every sandbox source.
        #[serde(flatten)]
        sandbox: CloudSandboxSpec,
        /// Host path to the disk image.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        path: PathBuf,
        /// Disk image format.
        format: CloudDiskImageFormat,
        /// Inner filesystem type, when it cannot be detected automatically.
        fstype: Option<String>,
        /// CPU and memory resources.
        #[serde(default)]
        resources: CloudSandboxComputeResources,
        /// Rootfs patches applied before VM start.
        #[serde(default)]
        patches: Vec<CloudPatch>,
    },
    /// Create a fresh-booted sandbox from a disk snapshot.
    DiskSnapshot {
        /// Settings shared by every sandbox source.
        #[serde(flatten)]
        sandbox: CloudSandboxSpec,
        /// Disk snapshot to restore.
        disk_snapshot_ref: CloudSnapshotLocation,
        /// CPU and memory resources.
        #[serde(default)]
        resources: CloudSandboxComputeResources,
        /// Pull policy used if the snapshot's pinned base image must be fetched.
        #[serde(default)]
        pull_policy: CloudPullPolicy,
    },
}

/// Settings shared by every cloud sandbox creation source.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default, deny_unknown_fields)]
pub struct CloudSandboxSpec {
    /// Unique sandbox name.
    #[cfg_attr(feature = "utoipa", schema(required = true))]
    pub name: String,

    /// Guest runtime options.
    pub runtime: CloudSandboxRuntimeOptions,

    /// Environment variables visible to commands in the sandbox.
    pub env: Vec<EnvVar>,

    /// User-defined labels attached to the sandbox.
    pub labels: BTreeMap<String, String>,

    /// Sandbox-wide resource limits inherited by guest processes.
    pub rlimits: Vec<CloudRlimit>,

    /// Volume mounts.
    pub mounts: Vec<CloudVolumeMount>,

    /// Network specification.
    pub network: CloudNetworkSpec,

    /// Hand off PID 1 to a guest init binary after agentd setup.
    pub init: Option<HandoffInit>,

    /// In-guest security profile.
    pub security_profile: SecurityProfile,

    /// Sandbox lifecycle policy.
    pub lifecycle: SandboxPolicy,
}

/// CPU and memory request shared by sources without a managed writable disk.
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default, deny_unknown_fields)]
pub struct CloudSandboxComputeResources {
    /// Number of virtual CPUs.
    pub vcpus: u8,

    /// Guest memory in MiB.
    pub memory_mib: u32,
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
    /// Why the sandbox is not running yet, when known. Only present while
    /// `status` is `starting`.
    #[serde(default)]
    pub status_reason: Option<CloudSandboxStatusReason>,
    /// Curated resolved-spec projection returned by the control plane, when
    /// available. Lifecycle and agent operations intentionally do not depend
    /// on reconstructing the create request from this server-owned view.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "ts", ts(type = "unknown | null | undefined"))]
    pub spec: Option<serde_json::Value>,
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
    /// Human-readable message for the most recent failure, when any.
    #[serde(default)]
    pub last_failure_message: Option<String>,
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

/// Reason a sandbox start is still in progress. Only meaningful while
/// `status` is `starting`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudSandboxStatusReason {
    /// The start has been accepted and is being scheduled.
    Scheduling,
    /// No capacity is currently available; the start proceeds when
    /// capacity frees up.
    InsufficientCapacity,
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
        match req {
            CloudCreateSandboxRequest::Oci {
                sandbox,
                reference,
                resources,
                patches,
                pull_policy,
            } => sandbox.into_domain_spec(
                RootfsSource::Oci(OciRootfsSource {
                    reference,
                    root_disk: resources.disk_size_mib.map(RootDisk::managed),
                }),
                resources.into(),
                patches,
                pull_policy,
            ),
            CloudCreateSandboxRequest::Bind {
                sandbox,
                path,
                resources,
                patches,
            } => sandbox.into_domain_spec(
                RootfsSource::Bind {
                    path,
                    follow_root_symlinks: false,
                },
                resources,
                patches,
                CloudPullPolicy::default(),
            ),
            CloudCreateSandboxRequest::DiskImage {
                sandbox,
                path,
                format,
                fstype,
                resources,
                patches,
            } => sandbox.into_domain_spec(
                RootfsSource::DiskImage {
                    path,
                    format: format.into(),
                    fstype,
                },
                resources,
                patches,
                CloudPullPolicy::default(),
            ),
            CloudCreateSandboxRequest::DiskSnapshot { .. } => Err(TypesError::invalid_config(
                "disk_snapshot_ref is not supported here: resolve the snapshot reference \
                 to a concrete image before converting to a sandbox spec",
            )),
        }
    }
}

impl CloudCreateSandboxRequest {
    /// Return settings shared by every sandbox source.
    pub const fn sandbox_spec(&self) -> &CloudSandboxSpec {
        match self {
            Self::Oci { sandbox, .. }
            | Self::Bind { sandbox, .. }
            | Self::DiskImage { sandbox, .. }
            | Self::DiskSnapshot { sandbox, .. } => sandbox,
        }
    }

    /// Return mutable settings shared by every sandbox source.
    pub const fn sandbox_spec_mut(&mut self) -> &mut CloudSandboxSpec {
        match self {
            Self::Oci { sandbox, .. }
            | Self::Bind { sandbox, .. }
            | Self::DiskImage { sandbox, .. }
            | Self::DiskSnapshot { sandbox, .. } => sandbox,
        }
    }

    /// Return the disk snapshot reference, when restoring one.
    pub const fn disk_snapshot_ref(&self) -> Option<&CloudSnapshotLocation> {
        match self {
            Self::DiskSnapshot {
                disk_snapshot_ref, ..
            } => Some(disk_snapshot_ref),
            _ => None,
        }
    }

    /// Return the OCI image reference, when creating from OCI.
    pub fn oci_reference(&self) -> Option<&str> {
        match self {
            Self::Oci { reference, .. } => Some(reference),
            _ => None,
        }
    }

    /// Return the requested CPU and memory resources.
    pub const fn compute_resources(&self) -> CloudSandboxComputeResources {
        match self {
            Self::Oci { resources, .. } => CloudSandboxComputeResources {
                vcpus: resources.vcpus,
                memory_mib: resources.memory_mib,
            },
            Self::Bind { resources, .. }
            | Self::DiskImage { resources, .. }
            | Self::DiskSnapshot { resources, .. } => *resources,
        }
    }

    /// Return the requested OCI writable-disk size, if this is an OCI source.
    pub const fn oci_disk_size_mib(&self) -> Option<Option<u32>> {
        match self {
            Self::Oci { resources, .. } => Some(resources.disk_size_mib),
            _ => None,
        }
    }

    /// Set the OCI writable-disk size, returning whether this is an OCI source.
    pub fn set_oci_disk_size_mib(&mut self, disk_size_mib: u32) -> bool {
        let Self::Oci { resources, .. } = self else {
            return false;
        };
        resources.disk_size_mib = Some(disk_size_mib);
        true
    }
}

impl CloudSandboxSpec {
    fn into_domain_spec(
        self,
        image: RootfsSource,
        resources: CloudSandboxComputeResources,
        patches: Vec<CloudPatch>,
        pull_policy: CloudPullPolicy,
    ) -> TypesResult<SandboxSpec> {
        let resources = SandboxResources {
            cpus: resources.vcpus,
            memory_mib: resources.memory_mib,
            // The cloud wire type has no boot-capacity fields yet; treat the
            // effective resources as the maximum (mirrors SandboxResources
            // deserialization for legacy configs).
            max_cpus: resources.vcpus,
            max_memory_mib: resources.memory_mib,
            // Host runtime policy never crosses the cloud wire. A managed
            // service applies its own placement and guest-memory defaults
            // after resolving the tenant-controlled resource request.
            cpu_placement: CpuPlacement::Inherit,
            placement_profile: None,
            thp: TransparentHugePagePolicy::Madvise,
        };

        // Fields not present on `CloudNetworkSpec` are defaulted here, listed
        // explicitly (not `..default()`) so a new `NetworkSpec` field forces a
        // decision here.
        let network = NetworkSpec {
            enabled: self.network.enabled,
            interface: None,
            ports: Vec::new(),
            policy: self.network.policy,
            dns: None,
            tls: None,
            secrets: self.network.secrets.map(Into::into),
            max_connections: self.network.max_connections,
            rate_limiter: None,
            trust_host_cas: false,
        };
        let runtime = SandboxRuntimeOptions {
            workdir: self.runtime.workdir,
            shell: self.runtime.shell,
            scripts: self.runtime.scripts,
            entrypoint: self.runtime.entrypoint,
            cmd: self.runtime.cmd,
            hostname: None,
            user: self.runtime.user,
            log_level: self.runtime.log_level,
            metrics_sample_interval_ms: None,
            disable_metrics_sample: false,
        };

        Ok(SandboxSpec {
            name: self.name,
            image,
            resources,
            runtime,
            env: self.env,
            labels: self.labels,
            rlimits: self.rlimits.into_iter().map(Into::into).collect(),
            mounts: self.mounts.into_iter().map(Into::into).collect(),
            patches: patches.into_iter().map(Into::into).collect(),
            network,
            vsock: VsockSpec::default(),
            init: self.init,
            pull_policy: pull_policy.into(),
            security_profile: self.security_profile,
            deployment_profile: DeploymentProfile::default(),
            lifecycle: self.lifecycle,
        })
    }
}

impl From<SandboxSpec> for CloudCreateSandboxRequest {
    fn from(spec: SandboxSpec) -> Self {
        let resources = CloudSandboxComputeResources {
            vcpus: spec.resources.cpus,
            memory_mib: spec.resources.memory_mib,
        };
        let patches = spec.patches.into_iter().map(Into::into).collect();
        let pull_policy = spec.pull_policy.into();
        let sandbox = CloudSandboxSpec {
            name: spec.name,
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
            rlimits: spec.rlimits.into_iter().map(Into::into).collect(),
            mounts: spec.mounts.into_iter().map(Into::into).collect(),
            network: CloudNetworkSpec {
                enabled: spec.network.enabled,
                policy: spec.network.policy,
                secrets: spec.network.secrets.map(Into::into),
                max_connections: spec.network.max_connections,
            },
            init: spec.init,
            security_profile: spec.security_profile,
            lifecycle: spec.lifecycle,
        };

        match spec.image {
            RootfsSource::Oci(oci) => Self::Oci {
                sandbox,
                reference: oci.reference,
                resources: CloudSandboxResources {
                    vcpus: resources.vcpus,
                    memory_mib: resources.memory_mib,
                    disk_size_mib: match oci.root_disk {
                        Some(RootDisk::Managed { size_mib }) => size_mib,
                        _ => None,
                    },
                },
                patches,
                pull_policy,
            },
            RootfsSource::Bind { path, .. } => Self::Bind {
                sandbox,
                path,
                resources,
                patches,
            },
            RootfsSource::DiskImage {
                path,
                format,
                fstype,
            } => Self::DiskImage {
                sandbox,
                path,
                format: format.into(),
                fstype,
                resources,
                patches,
            },
        }
    }
}

impl Default for CloudSandboxResources {
    fn default() -> Self {
        let resources = SandboxResources::default();
        Self {
            vcpus: resources.cpus,
            memory_mib: resources.memory_mib,
            disk_size_mib: None,
        }
    }
}

impl Default for CloudSandboxComputeResources {
    fn default() -> Self {
        let resources = SandboxResources::default();
        Self {
            vcpus: resources.cpus,
            memory_mib: resources.memory_mib,
        }
    }
}

impl From<CloudSandboxResources> for CloudSandboxComputeResources {
    fn from(resources: CloudSandboxResources) -> Self {
        Self {
            vcpus: resources.vcpus,
            memory_mib: resources.memory_mib,
        }
    }
}

impl Default for CloudCreateSandboxRequest {
    fn default() -> Self {
        Self::Oci {
            sandbox: CloudSandboxSpec::default(),
            reference: String::new(),
            resources: CloudSandboxResources::default(),
            patches: Vec::new(),
            pull_policy: CloudPullPolicy::default(),
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

#[cfg(test)]
mod tests;
