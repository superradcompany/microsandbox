//! Cloud sandbox spec wire twins and domain conversions.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use super::CloudSecretsConfig;
use crate::domain::{
    DiskImageFormat, HostPermissions, MountOptions, NetworkPolicy, Patch, PullPolicy, Rlimit,
    RlimitResource, SandboxLogLevel, StatVirtualization, VolumeMount, default_private,
    default_strict,
};

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
/// Mirrors the domain [`crate::domain::RootfsSource`] JSON shape, but keeps writable-disk
/// sizing out of the image payload. Cloud callers express that intent through
/// [`super::CloudSandboxResources::disk_size_mib`]; conversion to the domain spec
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

/// Cloud network specification: a subset of the domain [`crate::domain::NetworkSpec`].
/// Interface overrides, host port mapping, DNS, TLS interception, rate limits,
/// and host-CA trust are not part of this type. `deny_unknown_fields` — posting
/// an omitted field is an error, not a silent drop.
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

/// Cloud guest runtime options: a subset of [`crate::domain::SandboxRuntimeOptions`]. The
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
