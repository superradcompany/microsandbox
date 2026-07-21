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

use zeroize::Zeroizing;

use crate::domain::{
    DiskImageFormat, EnvVar, HandoffInit, HostPattern, HostPermissions, MountOptions,
    NetworkPolicy, NetworkSpec, OciRootfsSource, Patch, PullPolicy, Rlimit, RlimitResource,
    RootDisk, RootfsSource, SandboxLogLevel, SandboxPolicy, SandboxResources,
    SandboxRuntimeOptions, SandboxSpec, SecretEntry, SecretInjection, SecretsConfig,
    SecurityProfile, StatVirtualization, ViolationAction, VolumeMount, default_private,
    default_strict,
};
use crate::modify::SecretSource;
use crate::{TypesError, TypesResult};

//--------------------------------------------------------------------------------------------------
// Types: Request
//--------------------------------------------------------------------------------------------------

/// Wire shape of a cloud sandbox create request body.
///
/// Flattens [`CloudSandboxSpec`] onto the request body, so on the wire this is
/// byte-identical to `CloudSandboxSpec`. The generated bindings surface the
/// flattened shape as `CloudSandboxSpec` directly (see
/// [`CloudCreateSandboxResponse::spec`], typed `CloudSandboxSpec`).
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

    /// Rootfs patches applied before VM start.
    pub patches: Vec<CloudPatch>,

    /// Network specification.
    pub network: CloudNetworkSpec,

    /// Hand off PID 1 to a guest init binary after agentd setup.
    pub init: Option<HandoffInit>,

    /// Pull policy for OCI images.
    pub pull_policy: CloudPullPolicy,

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

//--------------------------------------------------------------------------------------------------
// Types: Spec sub-twins
//
// Snake_case wire twins for domain enums that serialize PascalCase, so the whole
// cloud contract stays snake_case without changing the domain (runtime/SDK) wire.
//--------------------------------------------------------------------------------------------------

/// Cloud pull policy. Twin of domain [`PullPolicy`] with a snake_case wire.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudPullPolicy {
    /// Use cached layers if complete, pull otherwise.
    #[default]
    IfMissing,
    /// Always fetch the manifest, reusing cached layers whose digests match.
    Always,
    /// Never contact the registry; error if the image is not fully cached.
    Never,
}

impl From<PullPolicy> for CloudPullPolicy {
    fn from(policy: PullPolicy) -> Self {
        match policy {
            PullPolicy::IfMissing => Self::IfMissing,
            PullPolicy::Always => Self::Always,
            PullPolicy::Never => Self::Never,
        }
    }
}

impl From<CloudPullPolicy> for PullPolicy {
    fn from(policy: CloudPullPolicy) -> Self {
        match policy {
            CloudPullPolicy::IfMissing => Self::IfMissing,
            CloudPullPolicy::Always => Self::Always,
            CloudPullPolicy::Never => Self::Never,
        }
    }
}

/// Disk image format for cloud disk-image sources. Twin of [`DiskImageFormat`]
/// with a snake_case wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudDiskImageFormat {
    /// QEMU Copy-on-Write v2.
    Qcow2,
    /// Raw disk image.
    Raw,
    /// VMware Disk (FLAT/ZERO only, no delta links).
    Vmdk,
}

impl From<DiskImageFormat> for CloudDiskImageFormat {
    fn from(format: DiskImageFormat) -> Self {
        match format {
            DiskImageFormat::Qcow2 => Self::Qcow2,
            DiskImageFormat::Raw => Self::Raw,
            DiskImageFormat::Vmdk => Self::Vmdk,
        }
    }
}

impl From<CloudDiskImageFormat> for DiskImageFormat {
    fn from(format: CloudDiskImageFormat) -> Self {
        match format {
            CloudDiskImageFormat::Qcow2 => Self::Qcow2,
            CloudDiskImageFormat::Raw => Self::Raw,
            CloudDiskImageFormat::Vmdk => Self::Vmdk,
        }
    }
}

/// POSIX resource-limit identifiers. Twin of [`RlimitResource`] with a
/// snake_case wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum CloudRlimitResource {
    /// Max CPU time in seconds (`RLIMIT_CPU`).
    Cpu,
    /// Max file size in bytes (`RLIMIT_FSIZE`).
    Fsize,
    /// Max data segment size (`RLIMIT_DATA`).
    Data,
    /// Max stack size (`RLIMIT_STACK`).
    Stack,
    /// Max core file size (`RLIMIT_CORE`).
    Core,
    /// Max resident set size (`RLIMIT_RSS`).
    Rss,
    /// Max number of processes (`RLIMIT_NPROC`).
    Nproc,
    /// Max open file descriptors (`RLIMIT_NOFILE`).
    Nofile,
    /// Max locked memory (`RLIMIT_MEMLOCK`).
    Memlock,
    /// Max address space size (`RLIMIT_AS`).
    As,
    /// Max file locks (`RLIMIT_LOCKS`).
    Locks,
    /// Max pending signals (`RLIMIT_SIGPENDING`).
    Sigpending,
    /// Max bytes in POSIX message queues (`RLIMIT_MSGQUEUE`).
    Msgqueue,
    /// Max nice priority (`RLIMIT_NICE`).
    Nice,
    /// Max real-time priority (`RLIMIT_RTPRIO`).
    Rtprio,
    /// Max real-time timeout (`RLIMIT_RTTIME`).
    Rttime,
}

impl From<RlimitResource> for CloudRlimitResource {
    fn from(resource: RlimitResource) -> Self {
        match resource {
            RlimitResource::Cpu => Self::Cpu,
            RlimitResource::Fsize => Self::Fsize,
            RlimitResource::Data => Self::Data,
            RlimitResource::Stack => Self::Stack,
            RlimitResource::Core => Self::Core,
            RlimitResource::Rss => Self::Rss,
            RlimitResource::Nproc => Self::Nproc,
            RlimitResource::Nofile => Self::Nofile,
            RlimitResource::Memlock => Self::Memlock,
            RlimitResource::As => Self::As,
            RlimitResource::Locks => Self::Locks,
            RlimitResource::Sigpending => Self::Sigpending,
            RlimitResource::Msgqueue => Self::Msgqueue,
            RlimitResource::Nice => Self::Nice,
            RlimitResource::Rtprio => Self::Rtprio,
            RlimitResource::Rttime => Self::Rttime,
        }
    }
}

impl From<CloudRlimitResource> for RlimitResource {
    fn from(resource: CloudRlimitResource) -> Self {
        match resource {
            CloudRlimitResource::Cpu => Self::Cpu,
            CloudRlimitResource::Fsize => Self::Fsize,
            CloudRlimitResource::Data => Self::Data,
            CloudRlimitResource::Stack => Self::Stack,
            CloudRlimitResource::Core => Self::Core,
            CloudRlimitResource::Rss => Self::Rss,
            CloudRlimitResource::Nproc => Self::Nproc,
            CloudRlimitResource::Nofile => Self::Nofile,
            CloudRlimitResource::Memlock => Self::Memlock,
            CloudRlimitResource::As => Self::As,
            CloudRlimitResource::Locks => Self::Locks,
            CloudRlimitResource::Sigpending => Self::Sigpending,
            CloudRlimitResource::Msgqueue => Self::Msgqueue,
            CloudRlimitResource::Nice => Self::Nice,
            CloudRlimitResource::Rtprio => Self::Rtprio,
            CloudRlimitResource::Rttime => Self::Rttime,
        }
    }
}

/// A POSIX resource limit. Twin of [`Rlimit`] using [`CloudRlimitResource`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudRlimit {
    /// Resource type.
    pub resource: CloudRlimitResource,
    /// Soft limit (can be raised up to the hard limit by the process).
    pub soft: u64,
    /// Hard limit (ceiling, requires privileges to raise).
    pub hard: u64,
}

impl From<Rlimit> for CloudRlimit {
    fn from(rlimit: Rlimit) -> Self {
        Self {
            resource: rlimit.resource.into(),
            soft: rlimit.soft,
            hard: rlimit.hard,
        }
    }
}

impl From<CloudRlimit> for Rlimit {
    fn from(rlimit: CloudRlimit) -> Self {
        Self {
            resource: rlimit.resource.into(),
            soft: rlimit.soft,
            hard: rlimit.hard,
        }
    }
}

/// Rootfs patch applied before VM start. Twin of [`Patch`], internally tagged
/// with a snake_case `type` instead of the domain's external PascalCase tag.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudPatch {
    /// Write text content to a file.
    Text {
        /// Absolute guest path, such as `/etc/app.conf`.
        path: String,
        /// Text content to write.
        content: String,
        /// File permissions, such as `0o644`. `None` uses the default.
        mode: Option<u32>,
        /// Allow replacing a file that already exists in the rootfs.
        replace: bool,
    },
    /// Write raw bytes to a file.
    File {
        /// Absolute guest path.
        path: String,
        /// Raw byte content to write.
        content: Vec<u8>,
        /// File permissions, such as `0o644`. `None` uses the default.
        mode: Option<u32>,
        /// Allow replacing a file that already exists in the rootfs.
        replace: bool,
    },
    /// Copy a file from the host into the rootfs.
    CopyFile {
        /// Host path to copy from.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        src: PathBuf,
        /// Absolute guest destination path.
        dst: String,
        /// File permissions. `None` preserves source permissions.
        mode: Option<u32>,
        /// Allow replacing a file that already exists in the rootfs.
        replace: bool,
    },
    /// Copy a directory from the host into the rootfs.
    CopyDir {
        /// Host directory to copy from.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        src: PathBuf,
        /// Absolute guest destination path.
        dst: String,
        /// Allow replacing files that already exist in the rootfs.
        replace: bool,
    },
    /// Create a symlink.
    Symlink {
        /// Symlink target path.
        target: String,
        /// Absolute guest path where the symlink is created.
        link: String,
        /// Allow replacing a path that already exists in the rootfs.
        replace: bool,
    },
    /// Create a directory.
    Mkdir {
        /// Absolute guest path.
        path: String,
        /// Directory permissions, such as `0o755`. `None` uses the default.
        mode: Option<u32>,
    },
    /// Remove a file or directory.
    Remove {
        /// Absolute guest path to remove.
        path: String,
    },
    /// Append content to an existing file.
    Append {
        /// Absolute guest path of the file to append to.
        path: String,
        /// Content to append.
        content: String,
    },
}

impl From<Patch> for CloudPatch {
    fn from(patch: Patch) -> Self {
        match patch {
            Patch::Text {
                path,
                content,
                mode,
                replace,
            } => Self::Text {
                path,
                content,
                mode,
                replace,
            },
            Patch::File {
                path,
                content,
                mode,
                replace,
            } => Self::File {
                path,
                content,
                mode,
                replace,
            },
            Patch::CopyFile {
                src,
                dst,
                mode,
                replace,
            } => Self::CopyFile {
                src,
                dst,
                mode,
                replace,
            },
            Patch::CopyDir { src, dst, replace } => Self::CopyDir { src, dst, replace },
            Patch::Symlink {
                target,
                link,
                replace,
            } => Self::Symlink {
                target,
                link,
                replace,
            },
            Patch::Mkdir { path, mode } => Self::Mkdir { path, mode },
            Patch::Remove { path } => Self::Remove { path },
            Patch::Append { path, content } => Self::Append { path, content },
        }
    }
}

impl From<CloudPatch> for Patch {
    fn from(patch: CloudPatch) -> Self {
        match patch {
            CloudPatch::Text {
                path,
                content,
                mode,
                replace,
            } => Self::Text {
                path,
                content,
                mode,
                replace,
            },
            CloudPatch::File {
                path,
                content,
                mode,
                replace,
            } => Self::File {
                path,
                content,
                mode,
                replace,
            },
            CloudPatch::CopyFile {
                src,
                dst,
                mode,
                replace,
            } => Self::CopyFile {
                src,
                dst,
                mode,
                replace,
            },
            CloudPatch::CopyDir { src, dst, replace } => Self::CopyDir { src, dst, replace },
            CloudPatch::Symlink {
                target,
                link,
                replace,
            } => Self::Symlink {
                target,
                link,
                replace,
            },
            CloudPatch::Mkdir { path, mode } => Self::Mkdir { path, mode },
            CloudPatch::Remove { path } => Self::Remove { path },
            CloudPatch::Append { path, content } => Self::Append { path, content },
        }
    }
}

/// Cloud root filesystem source.
///
/// Mirrors the domain [`RootfsSource`] JSON shape, but keeps writable-disk
/// sizing out of the image payload. Cloud callers express that intent through
/// [`CloudSandboxResources::disk_size_mib`]; conversion to the domain spec
/// attaches it to OCI rootfs.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudRootfsSource {
    /// Use a host directory directly as the root filesystem.
    Bind {
        /// Host path to bind mount.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        path: PathBuf,
    },

    /// Use an OCI image reference with an EROFS lower and ext4 overlay upper.
    Oci {
        /// OCI image reference (e.g. `python`).
        reference: String,
    },

    /// Use a disk image file as the root filesystem via virtio-blk.
    DiskImage {
        /// Path to the disk image file on the host.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        path: PathBuf,
        /// Disk image format.
        format: CloudDiskImageFormat,
        /// Inner filesystem type (optional; auto-detected if absent).
        fstype: Option<String>,
    },
}

/// Cloud volume mount. Internal-tagged mirror of the domain [`VolumeMount`];
/// the transient `create` field is not carried on the wire.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudVolumeMount {
    /// Bind mount a host directory into the guest.
    Bind {
        /// Host directory to bind into the guest.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        host: PathBuf,
        /// Guest path to mount at.
        guest: String,
        /// Mount options (read-only, no-exec, …).
        #[serde(default)]
        options: MountOptions,
        /// How guest `stat()` results are virtualized.
        #[serde(default = "default_strict")]
        stat_virtualization: StatVirtualization,
        /// Host permission policy applied to the mount.
        #[serde(default = "default_private")]
        host_permissions: HostPermissions,
        /// Optional guest-write quota in MiB.
        #[serde(default)]
        quota_mib: Option<u32>,
    },

    /// Mount a named volume into the guest.
    Named {
        /// Named volume to mount.
        name: String,
        /// Guest path to mount at.
        guest: String,
        /// Mount options (read-only, no-exec, …).
        #[serde(default)]
        options: MountOptions,
        /// How guest `stat()` results are virtualized.
        #[serde(default = "default_strict")]
        stat_virtualization: StatVirtualization,
        /// Host permission policy applied to the mount.
        #[serde(default = "default_private")]
        host_permissions: HostPermissions,
    },

    /// Temporary filesystem backed by guest memory.
    Tmpfs {
        /// Guest path to mount at.
        guest: String,
        /// Optional size cap in MiB.
        #[serde(default)]
        size_mib: Option<u32>,
        /// Mount options (read-only, no-exec, …).
        #[serde(default)]
        options: MountOptions,
    },

    /// Mount a disk image file as a virtio-blk device at a guest path.
    DiskImage {
        /// Host path to the disk image file.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        host: PathBuf,
        /// Guest path to mount at.
        guest: String,
        /// Disk image format.
        format: CloudDiskImageFormat,
        /// Inner filesystem type (auto-detected if absent).
        #[serde(default)]
        fstype: Option<String>,
        /// Mount options (read-only, no-exec, …).
        #[serde(default)]
        options: MountOptions,
    },
}

impl From<CloudVolumeMount> for VolumeMount {
    fn from(m: CloudVolumeMount) -> Self {
        match m {
            CloudVolumeMount::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                quota_mib,
            } => VolumeMount::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                // The cloud wire type does not carry the opt-out yet; default to
                // the protective no-follow behavior.
                follow_root_symlinks: false,
                quota_mib,
            },
            CloudVolumeMount::Named {
                name,
                guest,
                options,
                stat_virtualization,
                host_permissions,
            } => VolumeMount::Named {
                name,
                guest,
                create: None,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks: false,
            },
            CloudVolumeMount::Tmpfs {
                guest,
                size_mib,
                options,
            } => VolumeMount::Tmpfs {
                guest,
                size_mib,
                options,
            },
            CloudVolumeMount::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            } => VolumeMount::DiskImage {
                host,
                guest,
                format: format.into(),
                fstype,
                options,
            },
        }
    }
}

impl From<VolumeMount> for CloudVolumeMount {
    fn from(m: VolumeMount) -> Self {
        match m {
            VolumeMount::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks: _,
                quota_mib,
            } => CloudVolumeMount::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                quota_mib,
            },
            VolumeMount::Named {
                name,
                guest,
                create: _,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks: _,
            } => CloudVolumeMount::Named {
                name,
                guest,
                options,
                stat_virtualization,
                host_permissions,
            },
            VolumeMount::Tmpfs {
                guest,
                size_mib,
                options,
            } => CloudVolumeMount::Tmpfs {
                guest,
                size_mib,
                options,
            },
            VolumeMount::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            } => CloudVolumeMount::DiskImage {
                host,
                guest,
                format: format.into(),
                fstype,
                options,
            },
        }
    }
}

/// Cloud network specification: a subset of the domain [`NetworkSpec`].
/// Interface overrides, host port mapping, DNS, TLS interception, and host-CA
/// trust are not part of this type. `deny_unknown_fields` — posting an omitted
/// field is an error, not a silent drop.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default, deny_unknown_fields)]
pub struct CloudNetworkSpec {
    /// Whether networking is enabled for this sandbox.
    pub enabled: bool,

    /// Egress/ingress policy.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<NetworkPolicy>,

    /// Secret-injection config.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<CloudSecretsConfig>,

    /// Max concurrent guest connections.
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

/// Cloud guest runtime options: a subset of [`SandboxRuntimeOptions`]. The
/// hostname and the metrics-sampling knobs are not part of this type.
/// `deny_unknown_fields`.
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
    /// Why the sandbox is not running yet, when known. Only present while
    /// `status` is `starting`.
    #[serde(default)]
    pub status_reason: Option<CloudSandboxStatusReason>,
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
        req.spec.try_into()
    }
}

impl TryFrom<CloudSandboxSpec> for SandboxSpec {
    type Error = TypesError;

    fn try_from(spec: CloudSandboxSpec) -> TypesResult<Self> {
        let disk_size_mib = spec.resources.disk_size_mib;
        let image = match spec.image {
            // The cloud wire expresses only the managed kind (a size); tmpfs and
            // disk-image root disks are local-only until the wire grows a kind field.
            CloudRootfsSource::Oci { reference } => RootfsSource::Oci(OciRootfsSource {
                reference,
                root_disk: disk_size_mib.map(RootDisk::managed),
            }),
            CloudRootfsSource::Bind { .. } | CloudRootfsSource::DiskImage { .. }
                if disk_size_mib.is_some() =>
            {
                return Err(TypesError::invalid_config(
                    "resources.disk_size_mib is only valid for OCI rootfs",
                ));
            }
            CloudRootfsSource::Bind { path } => RootfsSource::Bind {
                path,
                follow_root_symlinks: false,
            },
            CloudRootfsSource::DiskImage {
                path,
                format,
                fstype,
            } => RootfsSource::DiskImage {
                path,
                format: format.into(),
                fstype,
            },
        };

        let resources = SandboxResources {
            cpus: spec.resources.vcpus,
            memory_mib: spec.resources.memory_mib,
            // The cloud wire type has no boot-capacity fields yet; treat the
            // effective resources as the maximum (mirrors SandboxResources
            // deserialization for legacy configs).
            max_cpus: spec.resources.vcpus,
            max_memory_mib: spec.resources.memory_mib,
        };

        // Fields not present on `CloudNetworkSpec` are defaulted here, listed
        // explicitly (not `..default()`) so a new `NetworkSpec` field forces a
        // decision here.
        let network = NetworkSpec {
            enabled: spec.network.enabled,
            interface: None,
            ports: Vec::new(),
            policy: spec.network.policy,
            dns: None,
            tls: None,
            secrets: spec.network.secrets.map(Into::into),
            max_connections: spec.network.max_connections,
            trust_host_cas: false,
        };
        let runtime = SandboxRuntimeOptions {
            workdir: spec.runtime.workdir,
            shell: spec.runtime.shell,
            scripts: spec.runtime.scripts,
            entrypoint: spec.runtime.entrypoint,
            cmd: spec.runtime.cmd,
            hostname: None,
            user: spec.runtime.user,
            log_level: spec.runtime.log_level,
            metrics_sample_interval_ms: None,
            disable_metrics_sample: false,
        };

        Ok(Self {
            name: spec.name,
            image,
            resources,
            runtime,
            env: spec.env,
            labels: spec.labels,
            rlimits: spec.rlimits.into_iter().map(Into::into).collect(),
            mounts: spec.mounts.into_iter().map(Into::into).collect(),
            patches: spec.patches.into_iter().map(Into::into).collect(),
            network,
            init: spec.init,
            pull_policy: spec.pull_policy.into(),
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
            // Only the managed size is representable on the cloud wire today; tmpfs and
            // disk-image root disks are local-only and map to no disk_size_mib.
            RootfsSource::Oci(oci) => (
                CloudRootfsSource::Oci {
                    reference: oci.reference,
                },
                match &oci.root_disk {
                    Some(RootDisk::Managed { size_mib }) => *size_mib,
                    _ => None,
                },
            ),
            RootfsSource::Bind { path, .. } => (CloudRootfsSource::Bind { path }, None),
            RootfsSource::DiskImage {
                path,
                format,
                fstype,
            } => (
                CloudRootfsSource::DiskImage {
                    path,
                    format: format.into(),
                    fstype,
                },
                None,
            ),
        };

        Self {
            name: spec.name,
            image,
            resources: CloudSandboxResources {
                vcpus: spec.resources.cpus,
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
            rlimits: spec.rlimits.into_iter().map(Into::into).collect(),
            mounts: spec.mounts.into_iter().map(Into::into).collect(),
            patches: spec.patches.into_iter().map(Into::into).collect(),
            network: CloudNetworkSpec {
                enabled: spec.network.enabled,
                policy: spec.network.policy,
                secrets: spec.network.secrets.map(Into::into),
                max_connections: spec.network.max_connections,
            },
            init: spec.init,
            pull_policy: spec.pull_policy.into(),
            security_profile: spec.security_profile,
            lifecycle: spec.lifecycle,
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
// Types: Secrets
//--------------------------------------------------------------------------------------------------

/// Secret-injection config for the cloud API. Twin of domain [`SecretsConfig`].
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretsConfig {
    /// Secrets to inject.
    #[serde(default)]
    pub entries: Vec<CloudSecretEntry>,
    /// Default action when a placeholder leaks to a disallowed host.
    #[serde(default)]
    pub on_violation: CloudViolationAction,
}

/// A single cloud secret entry. Twin of domain [`SecretEntry`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CloudSecretEntry {
    /// Environment variable name exposed to the sandbox.
    pub env_var: String,
    /// The secret value (empty when `source` carries a reference instead).
    #[serde(default)]
    pub value: String,
    /// Host-side source resolved into `value` at spawn time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<CloudSecretSource>,
    /// Placeholder the sandbox sees instead of the real value.
    pub placeholder: String,
    /// Hosts allowed to receive this secret.
    #[serde(default)]
    pub allowed_hosts: Vec<CloudHostPattern>,
    /// Where the secret may be injected.
    #[serde(default)]
    pub injection: SecretInjection,
    /// Per-secret violation action overriding the config default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_violation: Option<CloudViolationAction>,
    /// Require verified TLS identity before substituting (default: true).
    #[serde(default = "cloud_default_true")]
    pub require_tls_identity: bool,
}

/// Host-side source for a cloud secret. Twin of [`SecretSource`].
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudSecretSource {
    /// Read from a host environment variable at apply time.
    Env {
        /// Host environment variable name.
        var: String,
    },
    /// Read from a host-side secret store reference.
    Store {
        /// Store-specific secret reference.
        reference: String,
    },
}

/// Host allowlist pattern for cloud secrets. Twin of [`HostPattern`], with the
/// domain's scalar variants normalized to `{ value }` for a uniform union.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudHostPattern {
    /// Exact hostname match.
    Exact {
        /// Hostname to match exactly.
        value: String,
    },
    /// Wildcard match (e.g. `*.openai.com`).
    Wildcard {
        /// Wildcard pattern.
        value: String,
    },
    /// Any host (dangerous — the secret can be exfiltrated).
    Any,
}

/// Action on a cloud secret violation. Twin of [`ViolationAction`], with
/// `Passthrough`'s host list normalized to a `hosts` field.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CloudViolationAction {
    /// Block the request silently.
    Block,
    /// Block and log (default).
    #[default]
    BlockAndLog,
    /// Block and terminate the sandbox.
    BlockAndTerminate,
    /// Forward the request with the placeholder unchanged for matching hosts.
    Passthrough {
        /// Hosts for which the placeholder passes through unchanged.
        hosts: Vec<CloudHostPattern>,
    },
}

fn cloud_default_true() -> bool {
    true
}

//--------------------------------------------------------------------------------------------------
// Conversions: Secrets
//--------------------------------------------------------------------------------------------------

impl From<HostPattern> for CloudHostPattern {
    fn from(pattern: HostPattern) -> Self {
        match pattern {
            HostPattern::Exact(value) => Self::Exact { value },
            HostPattern::Wildcard(value) => Self::Wildcard { value },
            HostPattern::Any => Self::Any,
        }
    }
}

impl From<CloudHostPattern> for HostPattern {
    fn from(pattern: CloudHostPattern) -> Self {
        match pattern {
            CloudHostPattern::Exact { value } => Self::Exact(value),
            CloudHostPattern::Wildcard { value } => Self::Wildcard(value),
            CloudHostPattern::Any => Self::Any,
        }
    }
}

impl From<ViolationAction> for CloudViolationAction {
    fn from(action: ViolationAction) -> Self {
        match action {
            ViolationAction::Block => Self::Block,
            ViolationAction::BlockAndLog => Self::BlockAndLog,
            ViolationAction::BlockAndTerminate => Self::BlockAndTerminate,
            ViolationAction::Passthrough(hosts) => Self::Passthrough {
                hosts: hosts.into_iter().map(Into::into).collect(),
            },
        }
    }
}

impl From<CloudViolationAction> for ViolationAction {
    fn from(action: CloudViolationAction) -> Self {
        match action {
            CloudViolationAction::Block => Self::Block,
            CloudViolationAction::BlockAndLog => Self::BlockAndLog,
            CloudViolationAction::BlockAndTerminate => Self::BlockAndTerminate,
            CloudViolationAction::Passthrough { hosts } => {
                Self::Passthrough(hosts.into_iter().map(Into::into).collect())
            }
        }
    }
}

impl From<SecretSource> for CloudSecretSource {
    fn from(source: SecretSource) -> Self {
        match source {
            SecretSource::Env { var } => Self::Env { var },
            SecretSource::Store { reference } => Self::Store { reference },
        }
    }
}

impl From<CloudSecretSource> for SecretSource {
    fn from(source: CloudSecretSource) -> Self {
        match source {
            CloudSecretSource::Env { var } => Self::Env { var },
            CloudSecretSource::Store { reference } => Self::Store { reference },
        }
    }
}

impl From<SecretEntry> for CloudSecretEntry {
    fn from(entry: SecretEntry) -> Self {
        Self {
            env_var: entry.env_var,
            value: entry.value.to_string(),
            source: entry.source.map(Into::into),
            placeholder: entry.placeholder,
            allowed_hosts: entry.allowed_hosts.into_iter().map(Into::into).collect(),
            injection: entry.injection,
            on_violation: entry.on_violation.map(Into::into),
            require_tls_identity: entry.require_tls_identity,
        }
    }
}

impl From<CloudSecretEntry> for SecretEntry {
    fn from(entry: CloudSecretEntry) -> Self {
        Self {
            env_var: entry.env_var,
            value: Zeroizing::new(entry.value),
            source: entry.source.map(Into::into),
            placeholder: entry.placeholder,
            allowed_hosts: entry.allowed_hosts.into_iter().map(Into::into).collect(),
            injection: entry.injection,
            on_violation: entry.on_violation.map(Into::into),
            require_tls_identity: entry.require_tls_identity,
        }
    }
}

impl From<SecretsConfig> for CloudSecretsConfig {
    fn from(config: SecretsConfig) -> Self {
        Self {
            entries: config.secrets.into_iter().map(Into::into).collect(),
            on_violation: config.on_violation.into(),
        }
    }
}

impl From<CloudSecretsConfig> for SecretsConfig {
    fn from(config: CloudSecretsConfig) -> Self {
        Self {
            secrets: config.entries.into_iter().map(Into::into).collect(),
            on_violation: config.on_violation.into(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::{
        DEFAULT_SANDBOX_CPUS, DEFAULT_SANDBOX_MEMORY_MIB, OciRootfsSource, RootDisk, RootfsSource,
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
    fn cloud_rootfs_source_uses_internal_tagging() {
        let json = serde_json::to_value(CloudRootfsSource::Oci {
            reference: "python:3.12".into(),
        })
        .unwrap();
        assert_eq!(
            json,
            serde_json::json!({"type": "oci", "reference": "python:3.12"})
        );

        let bind = serde_json::to_value(CloudRootfsSource::Bind {
            path: "/host".into(),
        })
        .unwrap();
        assert_eq!(bind, serde_json::json!({"type": "bind", "path": "/host"}));

        let back: CloudRootfsSource = serde_json::from_value(json).unwrap();
        assert!(matches!(back, CloudRootfsSource::Oci { reference } if reference == "python:3.12"));
    }

    #[test]
    fn cloud_secret_twins_use_internal_tagging() {
        // Scalar domain variants normalize to a uniform `{ "type", value }` union.
        assert_eq!(
            serde_json::to_value(CloudHostPattern::Exact {
                value: "api.example.com".into(),
            })
            .unwrap(),
            serde_json::json!({"type": "exact", "value": "api.example.com"})
        );
        assert_eq!(
            serde_json::to_value(CloudSecretSource::Env {
                var: "OPENAI".into()
            })
            .unwrap(),
            serde_json::json!({"type": "env", "var": "OPENAI"})
        );
        assert_eq!(
            serde_json::to_value(CloudViolationAction::Passthrough {
                hosts: vec![CloudHostPattern::Any],
            })
            .unwrap(),
            serde_json::json!({"type": "passthrough", "hosts": [{"type": "any"}]})
        );
    }

    #[test]
    fn cloud_secrets_config_round_trips_through_domain() {
        let cloud = CloudSecretsConfig {
            entries: vec![CloudSecretEntry {
                env_var: "OPENAI_API_KEY".into(),
                value: "sk-x".into(),
                source: Some(CloudSecretSource::Env {
                    var: "OPENAI".into(),
                }),
                placeholder: "$MSB_OPENAI".into(),
                allowed_hosts: vec![CloudHostPattern::Exact {
                    value: "api.openai.com".into(),
                }],
                injection: SecretInjection::default(),
                on_violation: Some(CloudViolationAction::BlockAndTerminate),
                require_tls_identity: true,
            }],
            on_violation: CloudViolationAction::BlockAndLog,
        };

        let back: CloudSecretsConfig = SecretsConfig::from(cloud.clone()).into();
        assert_eq!(back.entries.len(), 1);
        assert_eq!(back.entries[0].value, "sk-x");
        assert_eq!(back.entries[0].allowed_hosts.len(), 1);
        assert!(matches!(
            back.entries[0].on_violation,
            Some(CloudViolationAction::BlockAndTerminate)
        ));
    }

    #[test]
    fn create_request_converts_disk_size_to_oci_rootfs() {
        let mut req = CloudCreateSandboxRequest {
            spec: spec("agent-1"),
        };
        req.spec.resources.disk_size_mib = Some(8192);

        let domain = SandboxSpec::try_from(req).unwrap();

        assert_eq!(domain.resources.cpus, DEFAULT_SANDBOX_CPUS);
        assert_eq!(domain.resources.memory_mib, DEFAULT_SANDBOX_MEMORY_MIB);
        match domain.image {
            RootfsSource::Oci(oci) => {
                assert_eq!(oci.reference, "python:3.12");
                assert_eq!(oci.root_disk, Some(RootDisk::managed(8192)));
            }
            other => panic!("expected OCI rootfs, got {other:?}"),
        }
    }

    #[test]
    fn create_request_rejects_disk_size_for_non_oci_rootfs() {
        let mut req = CloudCreateSandboxRequest {
            spec: spec("agent-1"),
        };
        req.spec.image = CloudRootfsSource::Bind {
            path: "/tmp/rootfs".into(),
        };
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
                root_disk: Some(RootDisk::managed(8192)),
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
    fn sandbox_response_round_trips() {
        let sb = CloudCreateSandboxResponse {
            id: "00000000-0000-0000-0000-000000000002".into(),
            org_id: "00000000-0000-0000-0000-000000000001".into(),
            name: "agent-1".into(),
            slug: "brave-otter".into(),
            status: CloudSandboxStatus::Created,
            status_reason: None,
            spec: spec("agent-1"),
            ephemeral: true,
            created_at: "2026-05-17T12:00:00Z".parse().unwrap(),
            started_at: None,
            stopped_at: None,
            last_failure_message: None,
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
