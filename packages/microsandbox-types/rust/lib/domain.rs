//! Shared sandbox domain types.

use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;
use std::str::FromStr;

use ipnetwork::{IpNetwork, Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::modify::SecretSource;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default number of virtual CPUs in a sandbox specification.
pub const DEFAULT_SANDBOX_CPUS: u8 = 1;

/// Default guest memory in MiB in a sandbox specification.
pub const DEFAULT_SANDBOX_MEMORY_MIB: u32 = 512;

/// Default metrics sampling interval in milliseconds.
pub const DEFAULT_METRICS_SAMPLE_INTERVAL_MS: u64 = 1000;

//--------------------------------------------------------------------------------------------------
// Types: Root Filesystems
//--------------------------------------------------------------------------------------------------

/// Disk image format for virtio-blk root filesystems and volume mounts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum DiskImageFormat {
    /// QEMU Copy-on-Write v2.
    Qcow2,
    /// Raw disk image.
    Raw,
    /// VMware Disk (FLAT/ZERO only, no delta links).
    Vmdk,
}

/// Root filesystem source for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum RootfsSource {
    /// Use a host directory directly as the root filesystem.
    Bind {
        /// Host path to bind mount.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        path: PathBuf,
        /// Whether to follow symlinks when resolving the host rootfs path.
        ///
        /// Defaults to `false`: the path is resolved following no symlink in any
        /// component, matching the `--mount` protection, so a symlink at or under
        /// the rootfs path cannot redirect the mount. Set `true` to opt out when
        /// the host rootfs path legitimately traverses a symlink.
        #[serde(default)]
        follow_root_symlinks: bool,
    },

    /// Use an OCI image reference with an EROFS lower and ext4 overlay upper.
    Oci(OciRootfsSource),

    /// Use a disk image file as the root filesystem via virtio-blk.
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

/// OCI root filesystem source.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct OciRootfsSource {
    /// OCI image reference (e.g. `python`).
    pub reference: String,

    /// Writable rootfs layer backing. `None` resolves to a managed 4 GiB upper.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub root_disk: Option<RootDisk>,
}

/// Backing for the writable rootfs layer (overlay upper) of an OCI sandbox.
///
/// This lives only on [`OciRootfsSource`]: the root disk is a property of how an OCI image
/// becomes a rootfs. Every user surface (CLI `--root-disk`, SDK builders) is sugar resolving
/// into this type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum RootDisk {
    /// Sparse ext4 created and owned by microsandbox in the sandbox dir. Default. Persistent;
    /// grow-only via modify; deleted with the sandbox.
    Managed {
        /// Virtual size in MiB. `None` resolves to 4096.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size_mib: Option<u32>,
    },

    /// RAM-backed upper. Ephemeral: the rootfs is pristine on every boot. Pages come from
    /// guest memory, so the size must not exceed the sandbox memory.
    Tmpfs {
        /// Size in MiB. `None` resolves to half the sandbox memory.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size_mib: Option<u32>,
    },

    /// User-supplied disk image attached writable as the upper. User-owned lifecycle: never
    /// created, resized, or deleted by microsandbox.
    DiskImage {
        /// Host path to the image file.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        path: PathBuf,
        /// Disk image format. Never probed from file contents.
        format: DiskImageFormat,
        /// Inner filesystem type. `None` resolves to ext4.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fstype: Option<String>,
    },
}

/// Controls when an OCI registry is contacted for manifest freshness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum PullPolicy {
    /// Use cached layers if complete, pull otherwise.
    #[default]
    IfMissing,

    /// Always fetch the manifest from the registry, reusing cached layers whose digests still match.
    Always,

    /// Never contact the registry. Error if the image is not fully cached locally.
    Never,
}

//--------------------------------------------------------------------------------------------------
// Types: Mounts
//--------------------------------------------------------------------------------------------------

/// Stat virtualization policy for a virtiofs-backed volume mount.
///
/// Serializes/deserializes as the lowercase variant name (`"strict"`, `"relaxed"`, `"off"`) so persisted JSON aligns with the CLI grammar (`stat-virt=strict|relaxed|off`) and the NAPI string contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum StatVirtualization {
    /// Fail-closed: probe the host backing path; require xattr support.
    Strict,
    /// Opportunistic: apply the overlay when present; tolerate missing xattr support.
    Relaxed,
    /// Literal host metadata: do not read or apply the override xattr.
    Off,
}

/// Host permission propagation policy for a virtiofs-backed volume mount.
///
/// Serializes/deserializes as the lowercase variant name (`"private"`, `"mirror"`) to align with the CLI and NAPI spellings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum HostPermissions {
    /// Guest chmod stays in the metadata overlay only.
    Private,
    /// Mirror ordinary rwx bits for regular files and directories to the host inode.
    Mirror,
}

/// Sandbox-level in-guest security profile.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum SecurityProfile {
    /// Preserve normal guest-root semantics.
    ///
    /// Exec sessions do not set `no_new_privs` and keep `CAP_SYS_ADMIN`, so workflows such as `sudo`, package managers, and Docker-in-Docker work as they would in a regular VM.
    #[default]
    Default,

    /// Harden guest exec sessions.
    ///
    /// Agentd sets `no_new_privs`, drops `CAP_SYS_ADMIN`, and forces `nosuid,nodev` on user mounts. Workloads that need privilege elevation or guest mount administration, such as `sudo` and Docker-in-Docker, are intentionally incompatible with this profile.
    Restricted,
}

/// Guest mount behavior shared by every volume mount kind.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct MountOptions {
    /// Whether the mount is read-only.
    ///
    /// Guest writes fail with the kernel's read-only filesystem behavior. Virtiofs-backed mounts also reject writes on the host-side filesystem server as defense in depth.
    pub readonly: bool,

    /// Whether direct execution from the mount is disabled.
    ///
    /// This prevents `execve` of binaries or scripts located on the mount. Interpreters can still read files from the mount, for example `sh /mnt/script.sh`, because the interpreter itself executes from a different filesystem.
    pub noexec: bool,

    /// Whether setuid and setgid privilege elevation from files on the mount is ignored.
    pub nosuid: bool,

    /// Whether device files on the mount are ignored.
    pub nodev: bool,
}

/// Storage kind for a named volume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum VolumeKind {
    /// Directory-backed named volume mounted through virtiofs.
    Directory,

    /// Raw ext4 disk-image named volume mounted through virtio-blk.
    Disk,
}

/// Configuration for creating a named volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct VolumeSpec {
    /// Volume name.
    pub name: String,

    /// Storage kind.
    pub kind: VolumeKind,

    /// Size quota in MiB. `None` means unlimited.
    pub quota_mib: Option<u32>,

    /// Disk capacity in MiB. Required for disk volumes.
    pub capacity_mib: Option<u32>,

    /// Labels for organization.
    pub labels: Vec<(String, String)>,
}

/// Sandbox-time behavior for a named volume mount.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum NamedVolumeMode {
    /// Require the named volume to already exist.
    Existing,

    /// Create the named volume and fail if it already exists.
    Create,

    /// Ensure the named volume exists, or reuse a compatible existing volume.
    EnsureExists,
}

/// Creation metadata for sandbox-time named volume provisioning.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct NamedVolumeCreate {
    /// Creation behavior for this named volume mount.
    pub mode: NamedVolumeMode,

    /// Volume name to create or ensure exists.
    pub name: String,

    /// Storage kind to create or ensure exists.
    pub kind: VolumeKind,

    /// Directory quota in MiB, if configured.
    pub quota_mib: Option<u32>,

    /// Disk capacity in MiB, if configured.
    pub capacity_mib: Option<u32>,

    /// Labels to attach to newly-created volumes.
    pub labels: Vec<(String, String)>,
}

/// A volume mount specification for a sandbox.
#[derive(Clone)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(tag = "type"))]
pub enum VolumeMount {
    /// Bind mount a host directory into the guest.
    Bind {
        /// Host path to bind mount.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        host: PathBuf,
        /// Guest mount path.
        guest: String,
        /// Guest mount behavior.
        options: MountOptions,
        /// Guest-visible stat virtualization policy.
        stat_virtualization: StatVirtualization,
        /// Host permission propagation policy.
        host_permissions: HostPermissions,
        /// Whether to follow symlinks when resolving the host mount root.
        ///
        /// Defaults to `false`: the host path is resolved following no symlink in
        /// any component, so a symlink planted at (or under) the mount root cannot
        /// redirect the mount out of its intended target. Set `true` to opt out
        /// when the host path legitimately traverses a symlink.
        follow_root_symlinks: bool,
        /// Guest-write byte budget in MiB.
        ///
        /// Bounds how much the guest may add beyond the directory's existing
        /// contents. `None` applies the protective default at spawn time; set a
        /// value to override it.
        quota_mib: Option<u32>,
    },

    /// Mount a named volume into the guest.
    Named {
        /// Volume name.
        name: String,
        /// Guest mount path.
        guest: String,
        /// Creation metadata for sandbox-time named volume provisioning.
        ///
        /// This is transient and intentionally skipped when sandbox configs are persisted; restarting a sandbox mounts the already-created volume.
        create: Option<NamedVolumeCreate>,
        /// Guest mount behavior.
        options: MountOptions,
        /// Guest-visible stat virtualization policy.
        stat_virtualization: StatVirtualization,
        /// Host permission propagation policy.
        host_permissions: HostPermissions,
        /// Whether to follow symlinks when resolving the host mount root.
        ///
        /// Defaults to `false` (resolve following no symlink). See
        /// [`VolumeMount::Bind`] for details.
        follow_root_symlinks: bool,
    },

    /// Temporary filesystem backed by guest memory.
    Tmpfs {
        /// Guest mount path.
        guest: String,
        /// Size limit in MiB.
        size_mib: Option<u32>,
        /// Guest mount behavior.
        options: MountOptions,
    },

    /// Mount a disk image file as a virtio-blk device at a guest path.
    DiskImage {
        /// Host path to the disk image file.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        #[cfg_attr(feature = "utoipa", schema(value_type = String))]
        host: PathBuf,
        /// Guest mount path.
        guest: String,
        /// Disk image format.
        format: DiskImageFormat,
        /// Inner filesystem type. When `None`, agentd probes `/proc/filesystems`.
        fstype: Option<String>,
        /// Guest mount behavior.
        options: MountOptions,
    },
}

/// Rootfs patch applied before VM startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum Patch {
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

//--------------------------------------------------------------------------------------------------
// Types: Networking
//--------------------------------------------------------------------------------------------------

/// Complete network specification for a sandbox.
///
/// Common, backend-visible fields are typed directly. Rich local-engine subdocuments such as policy, DNS, TLS, secrets, and interface overrides are carried as JSON so the shared contract can preserve them without depending on the local networking engine crate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct NetworkSpec {
    /// Whether networking is enabled for this sandbox.
    pub enabled: bool,

    /// Guest interface overrides for the local network engine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<InterfaceOverrides>,

    /// Host-to-guest port mappings.
    pub ports: Vec<PublishedPortSpec>,

    /// Egress and ingress policy subdocument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<NetworkPolicy>,

    /// DNS interception and filtering subdocument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<DnsConfig>,

    /// TLS interception subdocument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<TlsConfig>,

    /// Secret injection subdocument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<SecretsConfig>,

    /// Max concurrent guest connections.
    pub max_connections: Option<usize>,

    /// Whether to copy trusted host CAs into the guest at boot.
    pub trust_host_cas: bool,
}

/// A published port mapping between host and guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct PublishedPortSpec {
    /// Host-side port to bind.
    pub host_port: u16,

    /// Guest-side port to forward to.
    pub guest_port: u16,

    /// Transport protocol.
    #[serde(default)]
    pub protocol: PortProtocol,

    /// Host address to bind. Defaults to loopback.
    pub host_bind: String,
}

/// Transport protocol for a published port.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum PortProtocol {
    /// TCP.
    #[default]
    #[serde(rename = "tcp")]
    Tcp,

    /// UDP.
    #[serde(rename = "udp")]
    Udp,
}

//--------------------------------------------------------------------------------------------------
// Types: Init
//--------------------------------------------------------------------------------------------------

/// Fully-assembled handoff-init specification.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct HandoffInit {
    /// Init binary: absolute path inside the guest rootfs, or the literal `auto`.
    ///
    /// Always a Linux-style `/`-separated path — never build it with host OS path APIs, whose semantics diverge on Windows (`\` separators, `/sbin/init` treated as relative).
    pub cmd: String,

    /// Supplemental argv. `argv[0]` is implicitly `cmd`.
    #[serde(default)]
    pub args: Vec<String>,

    /// Extra env vars merged on top of the inherited env.
    #[serde(default)]
    pub env: Vec<(String, String)>,
}

//--------------------------------------------------------------------------------------------------
// Types: Lifecycle
//--------------------------------------------------------------------------------------------------

/// Sandbox lifecycle policy.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SandboxPolicy {
    /// Whether the sandbox is ephemeral.
    ///
    /// Ephemeral sandboxes are one-off: the host runtime that owns the
    /// process removes the persisted DB row and on-disk state when the VM
    /// reaches a terminal status, and other host runtimes opportunistically
    /// clean up ephemeral leftovers from runtimes that died before they
    /// could self-clean. Defaults to `false` (persistent); named and created
    /// sandboxes stay inspectable and restartable after they stop.
    #[serde(default)]
    pub ephemeral: bool,

    /// Hard cap on total sandbox lifetime in seconds. `None` = run forever.
    pub max_duration_secs: Option<u64>,

    /// Idle timeout in seconds. `None` = no idle detection.
    pub idle_timeout_secs: Option<u64>,
}

//--------------------------------------------------------------------------------------------------
// Types: Snapshots
//--------------------------------------------------------------------------------------------------

/// Where to place a new snapshot artifact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum SnapshotDestination {
    /// Bare name resolved under the default snapshots directory.
    Name(String),

    /// Explicit absolute or relative path to the artifact directory.
    Path(
        /// Destination path.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        PathBuf,
    ),
}

/// Inputs to create a snapshot.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SnapshotSpec {
    /// Name of the source sandbox. Must be stopped.
    pub source_sandbox: String,

    /// Where to write the artifact.
    pub destination: SnapshotDestination,

    /// User-supplied labels.
    pub labels: Vec<(String, String)>,

    /// Overwrite an existing artifact at the destination.
    pub force: bool,

    /// Compute and record upper-layer content integrity at creation time.
    pub record_integrity: bool,
}

//--------------------------------------------------------------------------------------------------
// Types: Sandbox Specs
//--------------------------------------------------------------------------------------------------

/// Backend-neutral sandbox task description.
///
/// This is the durable contract for fields that are already shared across backends. Local-only execution state such as resolved manifest digests, snapshot upper-layer paths, registry credentials, replace flags, and backend dispatch stays outside this type.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct SandboxSpec {
    /// Unique sandbox name.
    pub name: String,

    /// Root filesystem source.
    #[cfg_attr(feature = "utoipa", schema(value_type = Object))]
    pub image: RootfsSource,

    /// CPU and memory resources.
    pub resources: SandboxResources,

    /// Guest runtime options.
    pub runtime: SandboxRuntimeOptions,

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

    /// Network specification.
    pub network: NetworkSpec,

    /// Hand off PID 1 to a guest init binary after agentd setup.
    pub init: Option<HandoffInit>,

    /// Pull policy for OCI images.
    pub pull_policy: PullPolicy,

    /// In-guest security profile.
    pub security_profile: SecurityProfile,

    /// Sandbox lifecycle policy.
    pub lifecycle: SandboxPolicy,
}

/// CPU and memory resources for a sandbox.
#[derive(Debug, Clone, Copy, Serialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SandboxResources {
    /// Number of virtual CPUs currently presented to the guest at boot.
    pub cpus: u8,

    /// Guest memory currently presented to the guest at boot, in MiB.
    pub memory_mib: u32,

    /// Maximum virtual CPUs the sandbox may expose after boot-time hotplug support lands.
    pub max_cpus: u8,

    /// Maximum guest memory the sandbox may expose after boot-time hotplug support lands, in MiB.
    pub max_memory_mib: u32,
}

/// Guest runtime options for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct SandboxRuntimeOptions {
    /// Working directory inside the guest.
    pub workdir: Option<String>,

    /// Default shell for scripts and interactive sessions.
    pub shell: Option<String>,

    /// Named scripts available inside the guest.
    pub scripts: BTreeMap<String, String>,

    /// Image entrypoint override.
    pub entrypoint: Option<Vec<String>>,

    /// Image command override.
    pub cmd: Option<Vec<String>>,

    /// Guest hostname override.
    pub hostname: Option<String>,

    /// Guest user identity override.
    pub user: Option<String>,

    /// Runtime log verbosity.
    pub log_level: Option<SandboxLogLevel>,

    /// Metrics sampling interval in milliseconds. `None` disables sampling.
    pub metrics_sample_interval_ms: Option<u64>,

    /// Force-disable metrics sampling regardless of `metrics_sample_interval_ms`.
    pub disable_metrics_sample: bool,
}

/// Environment variable entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct EnvVar {
    /// Environment variable name.
    pub key: String,

    /// Environment variable value.
    pub value: String,
}

/// Runtime log verbosity for sandbox specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum SandboxLogLevel {
    /// Emit only error logs.
    Error,

    /// Emit warning and error logs.
    Warn,

    /// Emit info, warning, and error logs.
    Info,

    /// Emit debug and higher-severity logs.
    Debug,

    /// Emit trace and higher-severity logs.
    Trace,
}

//--------------------------------------------------------------------------------------------------
// Types: Exec
//--------------------------------------------------------------------------------------------------

/// POSIX resource limit identifiers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum RlimitResource {
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

/// A POSIX resource limit.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Rlimit {
    /// Resource type.
    pub resource: RlimitResource,

    /// Soft limit (can be raised up to hard limit by the process).
    pub soft: u64,

    /// Hard limit (ceiling, requires privileges to raise).
    pub hard: u64,
}

//--------------------------------------------------------------------------------------------------
// Types: Logs
//--------------------------------------------------------------------------------------------------

/// Source tag on a captured log entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "lowercase")]
pub enum LogSource {
    /// Captured from a session's stdout (pipe mode).
    Stdout,

    /// Captured from a session's stderr (pipe mode).
    Stderr,

    /// Captured from a session in pty mode (stdout + stderr merged at the kernel level inside the guest arrive as a single stream tagged `output`).
    Output,

    /// Synthetic system entry: lifecycle markers, runtime diagnostics, kernel console output.
    System,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl DiskImageFormat {
    /// Returns the format as a CLI-safe lowercase string.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Qcow2 => "qcow2",
            Self::Raw => "raw",
            Self::Vmdk => "vmdk",
        }
    }

    /// Parse a disk image format from a file extension.
    ///
    /// Returns `None` if the extension is not a recognized disk image format.
    pub fn from_extension(ext: &str) -> Option<Self> {
        match ext {
            "qcow2" => Some(Self::Qcow2),
            "raw" => Some(Self::Raw),
            "vmdk" => Some(Self::Vmdk),
            _ => None,
        }
    }
}

impl OciRootfsSource {
    /// Create a new OCI rootfs source.
    pub fn new(reference: impl Into<String>) -> Self {
        Self {
            reference: reference.into(),
            root_disk: None,
        }
    }
}

impl RootDisk {
    /// Create a managed root disk with the given size in MiB.
    pub fn managed(size_mib: u32) -> Self {
        Self::Managed {
            size_mib: Some(size_mib),
        }
    }

    /// Create a tmpfs root disk with the given size in MiB.
    pub fn tmpfs(size_mib: u32) -> Self {
        Self::Tmpfs {
            size_mib: Some(size_mib),
        }
    }

    /// Return the configured size in MiB, if this kind carries one.
    pub fn size_mib(&self) -> Option<u32> {
        match self {
            Self::Managed { size_mib } | Self::Tmpfs { size_mib } => *size_mib,
            Self::DiskImage { .. } => None,
        }
    }

    /// Return the lowercase kind tag used on the wire, in the DB, and in CLI output.
    pub fn kind_str(&self) -> &'static str {
        match self {
            Self::Managed { .. } => "managed",
            Self::Tmpfs { .. } => "tmpfs",
            Self::DiskImage { .. } => "disk-image",
        }
    }

    /// Whether this is the managed (default) kind.
    pub fn is_managed(&self) -> bool {
        matches!(self, Self::Managed { .. })
    }
}

impl RootfsSource {
    /// Create an OCI rootfs source from an image reference.
    pub fn oci(reference: impl Into<String>) -> Self {
        Self::Oci(OciRootfsSource::new(reference))
    }

    /// Return the OCI image reference if this is an OCI rootfs.
    pub fn oci_reference(&self) -> Option<&str> {
        match self {
            Self::Oci(oci) => Some(&oci.reference),
            _ => None,
        }
    }

    /// Return the configured root disk if this is an OCI rootfs.
    pub fn oci_root_disk(&self) -> Option<&RootDisk> {
        match self {
            Self::Oci(oci) => oci.root_disk.as_ref(),
            _ => None,
        }
    }

    /// Return the managed root disk size in MiB if this is an OCI rootfs with a managed
    /// (or unset, i.e. default-managed) root disk. Non-managed kinds return `None`.
    pub fn oci_managed_root_disk_size_mib(&self) -> Option<u32> {
        match self {
            Self::Oci(oci) => match &oci.root_disk {
                Some(RootDisk::Managed { size_mib }) => *size_mib,
                Some(_) => None,
                None => None,
            },
            _ => None,
        }
    }
}

impl EnvVar {
    /// Create an environment variable entry.
    pub fn new(key: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            value: value.into(),
        }
    }

    /// Return this entry as key and value string slices.
    pub fn as_pair(&self) -> (&str, &str) {
        (&self.key, &self.value)
    }
}

impl VolumeKind {
    /// Return the lowercase database and CLI representation.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "dir",
            Self::Disk => "disk",
        }
    }

    /// Parse a persisted database value, defaulting to directory for unknown values.
    pub fn from_db_value(value: &str) -> Self {
        match value {
            "disk" => Self::Disk,
            _ => Self::Directory,
        }
    }
}

impl VolumeSpec {
    /// Create a directory-backed volume spec with default options.
    pub fn new(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            kind: VolumeKind::Directory,
            quota_mib: None,
            capacity_mib: None,
            labels: Vec::new(),
        }
    }
}

impl NamedVolumeCreate {
    /// Creation behavior for this named volume mount.
    pub fn mode(&self) -> NamedVolumeMode {
        self.mode
    }

    /// Volume name to create or ensure exists.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Storage kind to create or ensure exists.
    pub fn kind(&self) -> VolumeKind {
        self.kind
    }

    /// Directory quota in MiB, if configured.
    pub fn quota_mib(&self) -> Option<u32> {
        self.quota_mib
    }

    /// Disk capacity in MiB, if configured.
    pub fn capacity_mib(&self) -> Option<u32> {
        self.capacity_mib
    }

    /// Labels to attach to newly-created volumes.
    pub fn labels(&self) -> &[(String, String)] {
        &self.labels
    }
}

impl VolumeMount {
    /// The absolute path where this mount appears inside the guest.
    pub fn guest(&self) -> &str {
        match self {
            Self::Bind { guest, .. }
            | Self::Named { guest, .. }
            | Self::Tmpfs { guest, .. }
            | Self::DiskImage { guest, .. } => guest,
        }
    }

    /// Return named-volume creation metadata when this mount provisions a named volume.
    pub fn named_create(&self) -> Option<&NamedVolumeCreate> {
        match self {
            Self::Named { create, .. } => create.as_ref(),
            _ => None,
        }
    }
}

impl RlimitResource {
    /// Returns the lowercase string representation used on the wire.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Cpu => "cpu",
            Self::Fsize => "fsize",
            Self::Data => "data",
            Self::Stack => "stack",
            Self::Core => "core",
            Self::Rss => "rss",
            Self::Nproc => "nproc",
            Self::Nofile => "nofile",
            Self::Memlock => "memlock",
            Self::As => "as",
            Self::Locks => "locks",
            Self::Sigpending => "sigpending",
            Self::Msgqueue => "msgqueue",
            Self::Nice => "nice",
            Self::Rtprio => "rtprio",
            Self::Rttime => "rttime",
        }
    }
}

impl LogSource {
    /// Apply the empty-means-default rule used by log readers.
    pub fn effective(requested: &[Self]) -> Vec<Self> {
        if requested.is_empty() {
            vec![Self::Stdout, Self::Stderr, Self::Output]
        } else {
            let mut sources = requested.to_vec();
            sources.sort_by_key(|src| match src {
                Self::Stdout => 0,
                Self::Stderr => 1,
                Self::Output => 2,
                Self::System => 3,
            });
            sources.dedup();
            sources
        }
    }
}

impl SandboxLogLevel {
    /// Return the lowercase string representation for this level.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
            Self::Debug => "debug",
            Self::Trace => "trace",
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Display for DiskImageFormat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for DiskImageFormat {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "qcow2" => Ok(Self::Qcow2),
            "raw" => Ok(Self::Raw),
            "vmdk" => Ok(Self::Vmdk),
            _ => Err(format!("unknown disk image format: {s}")),
        }
    }
}

impl Default for RootfsSource {
    fn default() -> Self {
        Self::oci(String::new())
    }
}

impl Default for SandboxResources {
    fn default() -> Self {
        Self {
            cpus: DEFAULT_SANDBOX_CPUS,
            memory_mib: DEFAULT_SANDBOX_MEMORY_MIB,
            max_cpus: DEFAULT_SANDBOX_CPUS,
            max_memory_mib: DEFAULT_SANDBOX_MEMORY_MIB,
        }
    }
}

impl<'de> Deserialize<'de> for SandboxResources {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        #[derive(Deserialize)]
        struct RawResources {
            #[serde(default = "default_sandbox_cpus")]
            cpus: u8,
            #[serde(default = "default_sandbox_memory_mib")]
            memory_mib: u32,
            max_cpus: Option<u8>,
            max_memory_mib: Option<u32>,
        }

        let raw = RawResources::deserialize(deserializer)?;
        Ok(Self {
            cpus: raw.cpus,
            memory_mib: raw.memory_mib,
            // Legacy configs predate boot-capacity fields. Treat their effective
            // resources as their maximum capacity so old sandboxes do not
            // deserialize into an impossible cpus > max_cpus state.
            max_cpus: raw.max_cpus.unwrap_or(raw.cpus),
            max_memory_mib: raw.max_memory_mib.unwrap_or(raw.memory_mib),
        })
    }
}

impl Default for SandboxRuntimeOptions {
    fn default() -> Self {
        Self {
            workdir: None,
            shell: None,
            scripts: BTreeMap::new(),
            entrypoint: None,
            cmd: None,
            hostname: None,
            user: None,
            log_level: None,
            metrics_sample_interval_ms: Some(DEFAULT_METRICS_SAMPLE_INTERVAL_MS),
            disable_metrics_sample: false,
        }
    }
}

impl Default for NetworkSpec {
    fn default() -> Self {
        Self {
            enabled: true,
            interface: None,
            ports: Vec::new(),
            policy: None,
            dns: None,
            tls: None,
            secrets: None,
            max_connections: None,
            trust_host_cas: false,
        }
    }
}

impl Default for PublishedPortSpec {
    fn default() -> Self {
        Self {
            host_port: 0,
            guest_port: 0,
            protocol: PortProtocol::Tcp,
            host_bind: "127.0.0.1".into(),
        }
    }
}

impl From<(String, String)> for EnvVar {
    fn from((key, value): (String, String)) -> Self {
        Self { key, value }
    }
}

impl From<EnvVar> for (String, String) {
    fn from(var: EnvVar) -> Self {
        (var.key, var.value)
    }
}

impl FromStr for SandboxLogLevel {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "error" => Ok(Self::Error),
            "warn" => Ok(Self::Warn),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
            _ => Err(format!("unknown sandbox log level: {s}")),
        }
    }
}

impl Serialize for VolumeMount {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;

        match self {
            Self::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
                quota_mib,
            } => {
                let mut map = serializer.serialize_map(Some(8))?;
                map.serialize_entry("type", "Bind")?;
                map.serialize_entry("host", host)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("options", options)?;
                map.serialize_entry("stat_virtualization", stat_virtualization)?;
                map.serialize_entry("host_permissions", host_permissions)?;
                map.serialize_entry("follow_root_symlinks", follow_root_symlinks)?;
                map.serialize_entry("quota_mib", quota_mib)?;
                map.end()
            }
            Self::Named {
                name,
                guest,
                create: _,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
            } => {
                let mut map = serializer.serialize_map(Some(7))?;
                map.serialize_entry("type", "Named")?;
                map.serialize_entry("name", name)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("options", options)?;
                map.serialize_entry("stat_virtualization", stat_virtualization)?;
                map.serialize_entry("host_permissions", host_permissions)?;
                map.serialize_entry("follow_root_symlinks", follow_root_symlinks)?;
                map.end()
            }
            Self::Tmpfs {
                guest,
                size_mib,
                options,
            } => {
                let mut map = serializer.serialize_map(Some(4))?;
                map.serialize_entry("type", "Tmpfs")?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("size_mib", size_mib)?;
                map.serialize_entry("options", options)?;
                map.end()
            }
            Self::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            } => {
                let mut map = serializer.serialize_map(Some(6))?;
                map.serialize_entry("type", "DiskImage")?;
                map.serialize_entry("host", host)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("format", format)?;
                map.serialize_entry("fstype", fstype)?;
                map.serialize_entry("options", options)?;
                map.end()
            }
        }
    }
}

impl<'de> Deserialize<'de> for VolumeMount {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        fn default_strict() -> StatVirtualization {
            StatVirtualization::Strict
        }

        fn default_private() -> HostPermissions {
            HostPermissions::Private
        }

        #[derive(Deserialize)]
        #[serde(tag = "type")]
        enum VolumeMountHelper {
            Bind {
                host: PathBuf,
                guest: String,
                #[serde(default)]
                options: Option<MountOptions>,
                #[serde(default)]
                readonly: bool,
                #[serde(default = "default_strict")]
                stat_virtualization: StatVirtualization,
                #[serde(default = "default_private")]
                host_permissions: HostPermissions,
                #[serde(default)]
                follow_root_symlinks: bool,
                #[serde(default)]
                quota_mib: Option<u32>,
            },
            Named {
                name: String,
                guest: String,
                #[serde(default)]
                options: Option<MountOptions>,
                #[serde(default)]
                readonly: bool,
                #[serde(default = "default_strict")]
                stat_virtualization: StatVirtualization,
                #[serde(default = "default_private")]
                host_permissions: HostPermissions,
                #[serde(default)]
                follow_root_symlinks: bool,
            },
            Tmpfs {
                guest: String,
                #[serde(default)]
                size_mib: Option<u32>,
                #[serde(default)]
                options: Option<MountOptions>,
                #[serde(default)]
                readonly: bool,
            },
            DiskImage {
                host: PathBuf,
                guest: String,
                format: DiskImageFormat,
                #[serde(default)]
                fstype: Option<String>,
                #[serde(default)]
                options: Option<MountOptions>,
                #[serde(default)]
                readonly: bool,
            },
        }

        let helper = VolumeMountHelper::deserialize(deserializer)?;
        Ok(match helper {
            VolumeMountHelper::Bind {
                host,
                guest,
                options,
                readonly,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
                quota_mib,
            } => Self::Bind {
                host,
                guest,
                options: decode_mount_options(options, readonly),
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
                quota_mib,
            },
            VolumeMountHelper::Named {
                name,
                guest,
                options,
                readonly,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
            } => Self::Named {
                name,
                guest,
                create: None,
                options: decode_mount_options(options, readonly),
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
            },
            VolumeMountHelper::Tmpfs {
                guest,
                size_mib,
                options,
                readonly,
            } => Self::Tmpfs {
                guest,
                size_mib,
                options: decode_mount_options(options, readonly),
            },
            VolumeMountHelper::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
                readonly,
            } => Self::DiskImage {
                host,
                guest,
                format,
                fstype,
                options: decode_mount_options(options, readonly),
            },
        })
    }
}

impl fmt::Debug for VolumeMount {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
                quota_mib,
            } => f
                .debug_struct("Bind")
                .field("host", host)
                .field("guest", guest)
                .field("options", options)
                .field("stat_virtualization", stat_virtualization)
                .field("host_permissions", host_permissions)
                .field("follow_root_symlinks", follow_root_symlinks)
                .field("quota_mib", quota_mib)
                .finish(),
            Self::Named {
                name,
                guest,
                create,
                options,
                stat_virtualization,
                host_permissions,
                follow_root_symlinks,
            } => f
                .debug_struct("Named")
                .field("name", name)
                .field("guest", guest)
                .field("create", create)
                .field("options", options)
                .field("stat_virtualization", stat_virtualization)
                .field("host_permissions", host_permissions)
                .field("follow_root_symlinks", follow_root_symlinks)
                .finish(),
            Self::Tmpfs {
                guest,
                size_mib,
                options,
            } => f
                .debug_struct("Tmpfs")
                .field("guest", guest)
                .field("size_mib", size_mib)
                .field("options", options)
                .finish(),
            Self::DiskImage {
                host,
                guest,
                format,
                fstype,
                options,
            } => f
                .debug_struct("DiskImage")
                .field("host", host)
                .field("guest", guest)
                .field("format", format)
                .field("fstype", fstype)
                .field("options", options)
                .finish(),
        }
    }
}

/// Case-insensitive string to [`RlimitResource`] conversion.
impl TryFrom<&str> for RlimitResource {
    type Error = String;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        match s.to_ascii_lowercase().as_str() {
            "cpu" => Ok(Self::Cpu),
            "fsize" => Ok(Self::Fsize),
            "data" => Ok(Self::Data),
            "stack" => Ok(Self::Stack),
            "core" => Ok(Self::Core),
            "rss" => Ok(Self::Rss),
            "nproc" => Ok(Self::Nproc),
            "nofile" => Ok(Self::Nofile),
            "memlock" => Ok(Self::Memlock),
            "as" => Ok(Self::As),
            "locks" => Ok(Self::Locks),
            "sigpending" => Ok(Self::Sigpending),
            "msgqueue" => Ok(Self::Msgqueue),
            "nice" => Ok(Self::Nice),
            "rtprio" => Ok(Self::Rtprio),
            "rttime" => Ok(Self::Rttime),
            _ => Err(format!("unknown rlimit resource: {s}")),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_sandbox_cpus() -> u8 {
    DEFAULT_SANDBOX_CPUS
}

fn default_sandbox_memory_mib() -> u32 {
    DEFAULT_SANDBOX_MEMORY_MIB
}

fn decode_mount_options(options: Option<MountOptions>, readonly: bool) -> MountOptions {
    options.unwrap_or(MountOptions {
        readonly,
        ..MountOptions::default()
    })
}

/// Default stat-virtualization policy (`Strict`) for a deserialized volume mount.
pub(crate) fn default_strict() -> StatVirtualization {
    StatVirtualization::Strict
}

/// Default host-permission policy (`Private`) for a deserialized volume mount.
pub(crate) fn default_private() -> HostPermissions {
    HostPermissions::Private
}

/// Maximum supported secret placeholder length in bytes.
pub const MAX_SECRET_PLACEHOLDER_BYTES: usize = 1024;

/// Placeholder-based secret injection for a sandbox's TLS-intercepted egress.
///
/// The sandbox only ever sees each secret's `placeholder`; the local network
/// engine substitutes the real `value` into outbound requests bound for an
/// allowed host (and blocks/forwards per [`ViolationAction`] otherwise). Carried
/// in [`NetworkSpec::secrets`](NetworkSpec).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SecretsConfig {
    /// List of secrets to inject.
    #[serde(default)]
    pub secrets: Vec<SecretEntry>,

    /// Default action when a placeholder leaks to a disallowed host.
    #[serde(default)]
    pub on_violation: ViolationAction,
}

/// A single secret entry.
///
/// `value` is the sensitive material — it never enters the sandbox and is
/// redacted by the [`Debug`](fmt::Debug) impl.
#[derive(Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SecretEntry {
    /// Environment variable name exposed to the sandbox (holds the placeholder).
    ///
    /// Must be non-empty and must not contain `=` or NUL. microsandbox does
    /// not require shell-identifier syntax because Linux environment entries
    /// only require a `NAME=value` shape.
    pub env_var: String,

    /// The actual secret value (never enters the sandbox).
    ///
    /// Empty when the entry carries a [`source`](Self::source) reference
    /// instead: reference-model entries resolve the value host-side at spawn
    /// time so the durable sandbox config never stores raw secret material.
    ///
    /// Wrapped in [`Zeroizing`] so the owned plaintext copy is wiped when the
    /// entry drops.
    #[serde(default = "empty_secret_value")]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    pub value: Zeroizing<String>,

    /// Host-side source reference resolved into [`value`](Self::value) at
    /// spawn time. `None` means `value` already carries the material (the
    /// inline model used by value-based secrets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<SecretSource>,

    /// Placeholder string the sandbox sees instead of the real value.
    ///
    /// Must be non-empty, no longer than [`MAX_SECRET_PLACEHOLDER_BYTES`], and
    /// must not contain NUL, CR, or LF.
    pub placeholder: String,

    /// Hosts allowed to receive this secret.
    #[serde(default)]
    pub allowed_hosts: Vec<HostPattern>,

    /// Where the secret can be injected.
    #[serde(default)]
    pub injection: SecretInjection,

    /// Action on a violation for this secret (overrides the config default).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub on_violation: Option<ViolationAction>,

    /// Require verified TLS identity before substituting (default: true).
    ///
    /// When true, the secret is only substituted if the connection uses TLS
    /// interception (not bypass) and the SNI matches an allowed host.
    #[serde(default = "default_true")]
    pub require_tls_identity: bool,
}

/// Host pattern for a secret allowlist.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "kebab-case")]
pub enum HostPattern {
    /// Exact hostname match.
    #[serde(alias = "Exact")]
    Exact(String),
    /// Wildcard match (e.g., `*.openai.com`).
    #[serde(alias = "Wildcard")]
    Wildcard(String),
    /// Any host (dangerous — secret can be exfiltrated).
    #[serde(alias = "Any")]
    Any,
}

/// Where in the HTTP request a secret can be injected.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SecretInjection {
    /// Substitute in HTTP headers (default: true).
    #[serde(default = "default_true")]
    pub headers: bool,

    /// Substitute in HTTP Basic Auth (default: true).
    #[serde(default = "default_true")]
    pub basic_auth: bool,

    /// Substitute in URL query parameters (default: false).
    #[serde(default)]
    pub query_params: bool,

    /// Substitute in request body (default: false).
    ///
    /// Fixed-length HTTP/1 bodies up to 16 MiB update `Content-Length`;
    /// larger fixed-length bodies are blocked. Chunked HTTP/1 bodies are
    /// decoded and re-encoded with fresh chunk sizes. Encoded bodies pass
    /// through unchanged. HTTP/2 DATA-frame body substitution is not
    /// supported; matching body placeholders are blocked.
    #[serde(default)]
    pub body: bool,
}

/// Action when a secret placeholder is detected going to a disallowed host.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "kebab-case")]
pub enum ViolationAction {
    /// Block the request silently.
    #[serde(alias = "Block")]
    Block,
    /// Block and log (default).
    #[default]
    #[serde(alias = "BlockAndLog", alias = "block_and_log")]
    BlockAndLog,
    /// Block and terminate the sandbox.
    #[serde(alias = "BlockAndTerminate", alias = "block_and_terminate")]
    BlockAndTerminate,
    /// Forward the request with the placeholder unchanged for matching hosts.
    #[serde(alias = "Passthrough")]
    Passthrough(Vec<HostPattern>),
}

/// Invalid secret configuration.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SecretConfigError {
    /// The environment variable name is empty.
    #[error("secret #{secret_index}: env_var must not be empty")]
    EmptyEnvVar {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The environment variable name contains `=`.
    #[error("secret #{secret_index}: env_var must not contain `=`")]
    EnvVarContainsEquals {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The environment variable name contains NUL.
    #[error("secret #{secret_index}: env_var must not contain NUL")]
    EnvVarContainsNul {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// No allowed hosts were configured for a secret.
    #[error("secret #{secret_index}: at least one allowed host is required")]
    MissingAllowedHosts {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The placeholder is empty.
    #[error("secret #{secret_index}: placeholder must not be empty")]
    EmptyPlaceholder {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The placeholder exceeds the supported byte length.
    #[error(
        "secret #{secret_index}: placeholder must be at most {max_bytes} bytes, got {actual_bytes}"
    )]
    PlaceholderTooLong {
        /// Index of the invalid secret entry.
        secret_index: usize,
        /// Actual placeholder length in bytes.
        actual_bytes: usize,
        /// Maximum supported placeholder length in bytes.
        max_bytes: usize,
    },

    /// The placeholder contains NUL.
    #[error("secret #{secret_index}: placeholder must not contain NUL")]
    PlaceholderContainsNul {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },

    /// The placeholder contains a line break.
    #[error("secret #{secret_index}: placeholder must not contain CR or LF")]
    PlaceholderContainsLineBreak {
        /// Index of the invalid secret entry.
        secret_index: usize,
    },
}

impl SecretsConfig {
    /// Validate all configured secret entries.
    pub fn validate(&self) -> Result<(), SecretConfigError> {
        for (index, secret) in self.secrets.iter().enumerate() {
            secret.validate(index)?;
        }
        Ok(())
    }
}

impl SecretEntry {
    /// Validate this secret entry.
    pub fn validate(&self, secret_index: usize) -> Result<(), SecretConfigError> {
        validate_env_var(&self.env_var, secret_index)?;

        if self.allowed_hosts.is_empty() {
            return Err(SecretConfigError::MissingAllowedHosts { secret_index });
        }

        validate_placeholder(&self.placeholder, secret_index)
    }
}

// The secret value must never reach a log line or an error message.
impl fmt::Debug for SecretEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretEntry")
            .field("env_var", &self.env_var)
            .field("value", &"[REDACTED]")
            .field("source", &self.source)
            .field("placeholder", &self.placeholder)
            .field("allowed_hosts", &self.allowed_hosts)
            .field("injection", &self.injection)
            .field("on_violation", &self.on_violation)
            .field("require_tls_identity", &self.require_tls_identity)
            .finish()
    }
}

impl HostPattern {
    /// Parse a user-facing host string: `*` is any host, `*.`-prefixed
    /// strings are wildcards, everything else matches exactly.
    pub fn parse(host: &str) -> Self {
        if host == "*" {
            HostPattern::Any
        } else if host.starts_with("*.") {
            HostPattern::Wildcard(host.to_string())
        } else {
            HostPattern::Exact(host.to_string())
        }
    }

    /// Check if a hostname matches this pattern.
    ///
    /// Uses ASCII case-insensitive comparison to avoid `to_lowercase()`
    /// allocations (DNS hostnames are ASCII per RFC 4343).
    pub fn matches(&self, hostname: &str) -> bool {
        match self {
            HostPattern::Exact(h) => hostname.eq_ignore_ascii_case(h),
            HostPattern::Wildcard(pattern) => {
                if let Some(suffix) = pattern.strip_prefix("*.") {
                    hostname.eq_ignore_ascii_case(suffix)
                        || (hostname.len() > suffix.len() + 1
                            && hostname.as_bytes()[hostname.len() - suffix.len() - 1] == b'.'
                            && hostname[hostname.len() - suffix.len()..]
                                .eq_ignore_ascii_case(suffix))
                } else {
                    hostname.eq_ignore_ascii_case(pattern)
                }
            }
            HostPattern::Any => true,
        }
    }
}

impl Default for SecretInjection {
    fn default() -> Self {
        Self {
            headers: true,
            basic_auth: true,
            query_params: false,
            body: false,
        }
    }
}

fn default_true() -> bool {
    true
}

fn validate_env_var(env_var: &str, secret_index: usize) -> Result<(), SecretConfigError> {
    if env_var.is_empty() {
        return Err(SecretConfigError::EmptyEnvVar { secret_index });
    }
    if env_var.contains('=') {
        return Err(SecretConfigError::EnvVarContainsEquals { secret_index });
    }
    if env_var.contains('\0') {
        return Err(SecretConfigError::EnvVarContainsNul { secret_index });
    }
    Ok(())
}

fn validate_placeholder(placeholder: &str, secret_index: usize) -> Result<(), SecretConfigError> {
    if placeholder.is_empty() {
        return Err(SecretConfigError::EmptyPlaceholder { secret_index });
    }

    let actual_bytes = placeholder.len();
    if actual_bytes > MAX_SECRET_PLACEHOLDER_BYTES {
        return Err(SecretConfigError::PlaceholderTooLong {
            secret_index,
            actual_bytes,
            max_bytes: MAX_SECRET_PLACEHOLDER_BYTES,
        });
    }

    if placeholder.contains('\0') {
        return Err(SecretConfigError::PlaceholderContainsNul { secret_index });
    }
    if placeholder.contains('\r') || placeholder.contains('\n') {
        return Err(SecretConfigError::PlaceholderContainsLineBreak { secret_index });
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Types: TLS interception
//--------------------------------------------------------------------------------------------------

/// TLS interception configuration. Carried in [`NetworkSpec::tls`](NetworkSpec).
///
/// The local network engine terminates TCP at its in-process stack, so TLS MITM
/// is handled by proxy tasks — these fields configure which ports/domains are
/// intercepted and how the interception CA is sourced.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct TlsConfig {
    /// Whether TLS interception is enabled.
    #[serde(default)]
    pub enabled: bool,

    /// TCP ports subject to TLS interception (default: `[443]`).
    #[serde(default = "default_intercepted_ports")]
    pub intercepted_ports: Vec<u16>,

    /// Domains to bypass (no MITM). Supports exact match and `*.suffix` wildcards.
    #[serde(default)]
    pub bypass: Vec<String>,

    /// Whether to verify the upstream server's TLS certificate.
    #[serde(default = "default_true")]
    pub verify_upstream: bool,

    /// Drop UDP to intercepted ports when TLS interception is active, forcing
    /// QUIC traffic to fall back to TCP/TLS.
    #[serde(default = "default_true")]
    pub block_quic_on_intercept: bool,

    /// CA certificate PEM files to trust for upstream server verification.
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Vec<String>))]
    #[cfg_attr(feature = "ts", ts(type = "Array<string>"))]
    pub upstream_ca_cert: Vec<PathBuf>,

    /// Host-scoped CA certificate PEM files to trust for upstream server verification.
    #[serde(default, alias = "scoped_upstream_ca_certs")]
    pub scoped_upstream_ca_cert: Vec<ScopedUpstreamCaCert>,

    /// Host-scoped upstream verification overrides.
    #[serde(default)]
    pub scoped_verify_upstream: Vec<ScopedVerifyUpstream>,

    /// Interception CA configuration. The TLS proxy uses this CA to sign
    /// per-domain certs it presents to the guest during interception.
    #[serde(default, alias = "ca")]
    pub intercept_ca: InterceptCaConfig,

    /// Per-domain certificate cache configuration.
    #[serde(default)]
    pub cache: CertCacheConfig,
}

/// Certificate authority configuration for TLS interception.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct InterceptCaConfig {
    /// Path to an existing CA certificate PEM file. If `None`, a CA is
    /// auto-generated and persisted.
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub cert_path: Option<PathBuf>,

    /// Path to an existing CA private key PEM file. If `None`, a key is
    /// auto-generated and persisted.
    #[serde(default)]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub key_path: Option<PathBuf>,
}

/// Per-domain certificate cache configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct CertCacheConfig {
    /// Maximum number of cached certificates. Default: 1000.
    #[serde(default = "default_cache_capacity")]
    pub capacity: usize,

    /// Certificate validity duration in hours. Default: 24.
    #[serde(default = "default_cert_validity_hours")]
    pub validity_hours: u64,
}

/// A CA certificate PEM file trusted only for matching upstream hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ScopedUpstreamCaCert {
    /// Host pattern this CA applies to. Supports exact hosts and `*.suffix` wildcards.
    pub pattern: String,

    /// Path to the CA certificate PEM file.
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub path: PathBuf,
}

/// An upstream certificate verification override for matching hosts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct ScopedVerifyUpstream {
    /// Host pattern this override applies to. Supports exact hosts and `*.suffix` wildcards.
    pub pattern: String,

    /// Whether to verify matching upstream server certificates.
    pub verify: bool,
}

impl Default for TlsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            intercepted_ports: default_intercepted_ports(),
            bypass: Vec::new(),
            verify_upstream: true,
            block_quic_on_intercept: true,
            upstream_ca_cert: Vec::new(),
            scoped_upstream_ca_cert: Vec::new(),
            scoped_verify_upstream: Vec::new(),
            intercept_ca: InterceptCaConfig::default(),
            cache: CertCacheConfig::default(),
        }
    }
}

impl Default for CertCacheConfig {
    fn default() -> Self {
        Self {
            capacity: default_cache_capacity(),
            validity_hours: default_cert_validity_hours(),
        }
    }
}

fn default_intercepted_ports() -> Vec<u16> {
    vec![443]
}

fn default_cache_capacity() -> usize {
    1000
}

fn default_cert_validity_hours() -> u64 {
    24
}

//--------------------------------------------------------------------------------------------------
// Types: Networking — policy
//--------------------------------------------------------------------------------------------------

/// Action to take on traffic matched by a [`Rule`] (or a policy default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Action {
    /// Allow the traffic.
    Allow,
    /// Silently drop the traffic.
    Deny,
}

/// Direction a [`Rule`] applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Outbound: guest → destination.
    Egress,
    /// Inbound: peer → guest.
    Ingress,
    /// Either direction.
    Any,
}

/// Protocol filter for a [`Rule`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    /// TCP.
    Tcp,
    /// UDP.
    Udp,
    /// ICMPv4.
    Icmpv4,
    /// ICMPv6.
    Icmpv6,
}

/// Pre-defined destination category for a [`Destination::Group`] match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum DestinationGroup {
    /// Public internet — any address not in another category.
    Public,
    /// Loopback addresses (`127.0.0.0/8`, `::1`).
    Loopback,
    /// Private ranges (RFC 1918 / RFC 4193 ULA / CGN).
    Private,
    /// Link-local addresses, excluding the metadata IP.
    LinkLocal,
    /// Cloud metadata endpoint (`169.254.169.254`).
    Metadata,
    /// Multicast addresses (`224.0.0.0/4`, `ff00::/8`).
    Multicast,
    /// The sandbox host, reachable via the gateway IP.
    Host,
}

/// Traffic destination filter for a [`Rule`].
///
/// The `Cidr`, `Domain`, and `DomainSuffix` leaves carry their canonical
/// string form (e.g. `"10.0.0.0/8"`, `"example.com"`); the local network
/// engine re-parses and validates them into its richer internal types at
/// load time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(rename_all = "snake_case")]
pub enum Destination {
    /// Match any destination.
    Any,
    /// IP address or CIDR block (e.g. `"1.2.3.4"`, `"10.0.0.0/8"`).
    #[cfg_attr(feature = "utoipa", schema(value_type = String))]
    Cidr(#[cfg_attr(feature = "ts", ts(type = "string"))] IpNetwork),
    /// Exact domain name (e.g. `"example.com"`).
    Domain(String),
    /// Domain suffix — the apex and any subdomain of it.
    DomainSuffix(String),
    /// A pre-defined destination group.
    Group(DestinationGroup),
}

/// Inclusive guest-side port range for a [`Rule`] match.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct PortRange {
    /// Start port (inclusive).
    pub start: u16,
    /// End port (inclusive).
    pub end: u16,
}

/// A single egress/ingress policy rule. Evaluated first-match-wins per
/// direction.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct Rule {
    /// Direction this rule applies to.
    pub direction: Direction,
    /// Destination filter (direction-dependent interpretation).
    pub destination: Destination,
    /// Protocol set; empty matches any protocol.
    #[serde(default)]
    pub protocols: Vec<Protocol>,
    /// Guest-side port-range set; empty matches any port.
    #[serde(default)]
    pub ports: Vec<PortRange>,
    /// Action to take on a match.
    pub action: Action,
}

/// Egress/ingress network policy: an ordered [`Rule`] list plus a
/// per-direction default [`Action`]. Carried in [`NetworkSpec::policy`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct NetworkPolicy {
    /// Default action for egress traffic matching no rule. Default: `Deny`.
    #[serde(default = "action_deny")]
    pub default_egress: Action,
    /// Default action for ingress traffic matching no rule. Default: `Deny`.
    #[serde(default = "action_deny")]
    pub default_ingress: Action,
    /// Ordered rules, evaluated first-match-wins per direction.
    #[serde(default)]
    pub rules: Vec<Rule>,
}

/// Default [`Action`] (`Deny`) for a policy's per-direction defaults, so a
/// partially-specified policy fails closed.
fn action_deny() -> Action {
    Action::Deny
}

//--------------------------------------------------------------------------------------------------
// Types: Networking — DNS & interface
//--------------------------------------------------------------------------------------------------

/// DNS interception and filtering settings. Carried in [`NetworkSpec::dns`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct DnsConfig {
    /// Whether DNS-rebinding protection is enabled. Default: true.
    pub rebind_protection: bool,
    /// Upstream nameservers as `IP`, `IP:PORT`, `HOST`, or `HOST:PORT`
    /// strings. Empty falls back to the host's `/etc/resolv.conf`.
    pub nameservers: Vec<String>,
    /// Per-query timeout in milliseconds. Default: 5000.
    pub query_timeout_ms: u64,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            rebind_protection: true,
            nameservers: Vec::new(),
            query_timeout_ms: 5000,
        }
    }
}

/// Optional guest interface overrides. Unset fields are derived from the
/// sandbox slot by the local network engine. Carried in
/// [`NetworkSpec::interface`].
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "utoipa", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct InterfaceOverrides {
    /// Guest MAC address as six octets. Default: derived from slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac: Option<[u8; 6]>,
    /// Interface MTU. Default: 1500.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mtu: Option<u16>,
    /// Guest IPv4 address (e.g. `172.16.0.2`). Default: derived from slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub ipv4_address: Option<Ipv4Addr>,
    /// Guest IPv4 pool CIDR (e.g. `"172.16.0.0/12"`). Default: derived from slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub ipv4_pool: Option<Ipv4Network>,
    /// Guest IPv6 address. Default: derived from slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub ipv6_address: Option<Ipv6Addr>,
    /// Guest IPv6 pool CIDR. Default: derived from slot.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg_attr(feature = "utoipa", schema(value_type = Option<String>))]
    #[cfg_attr(feature = "ts", ts(type = "string | null"))]
    pub ipv6_pool: Option<Ipv6Network>,
}

fn empty_secret_value() -> Zeroizing<String> {
    Zeroizing::new(String::new())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn disk_image_format_from_extension() {
        assert_eq!(
            DiskImageFormat::from_extension("qcow2"),
            Some(DiskImageFormat::Qcow2)
        );
        assert_eq!(
            DiskImageFormat::from_extension("raw"),
            Some(DiskImageFormat::Raw)
        );
        assert_eq!(
            DiskImageFormat::from_extension("vmdk"),
            Some(DiskImageFormat::Vmdk)
        );
        assert_eq!(DiskImageFormat::from_extension("ext4"), None);
        assert_eq!(DiskImageFormat::from_extension(""), None);
    }

    #[test]
    fn sandbox_resources_deserialize_legacy_capacity_from_effective_values() {
        let resources: SandboxResources =
            serde_json::from_str(r#"{"cpus":4,"memory_mib":2048}"#).unwrap();

        assert_eq!(resources.cpus, 4);
        assert_eq!(resources.max_cpus, 4);
        assert_eq!(resources.memory_mib, 2048);
        assert_eq!(resources.max_memory_mib, 2048);
    }

    #[test]
    fn disk_image_format_display_roundtrip() {
        for format in [
            DiskImageFormat::Qcow2,
            DiskImageFormat::Raw,
            DiskImageFormat::Vmdk,
        ] {
            let rendered = format.to_string();
            let parsed: DiskImageFormat = rendered.parse().unwrap();
            assert_eq!(parsed, format);
        }
    }

    #[test]
    fn disk_image_format_from_str_unknown() {
        assert!("ext4".parse::<DiskImageFormat>().is_err());
    }

    #[test]
    fn log_source_effective_uses_default_user_program_sources() {
        assert_eq!(
            LogSource::effective(&[]),
            vec![LogSource::Stdout, LogSource::Stderr, LogSource::Output]
        );
    }

    #[test]
    fn log_source_effective_sorts_and_deduplicates_requested_sources() {
        assert_eq!(
            LogSource::effective(&[LogSource::System, LogSource::Stdout, LogSource::System]),
            vec![LogSource::Stdout, LogSource::System]
        );
    }

    #[test]
    fn rlimit_resource_parses_case_insensitively() {
        assert_eq!(
            RlimitResource::try_from("NOFILE").unwrap(),
            RlimitResource::Nofile
        );
        assert!(RlimitResource::try_from("bogus").is_err());
    }

    #[test]
    fn sandbox_policy_serde_roundtrip() {
        let policy = SandboxPolicy {
            ephemeral: true,
            max_duration_secs: Some(3600),
            idle_timeout_secs: Some(120),
        };

        let json = serde_json::to_string(&policy).unwrap();
        let decoded: SandboxPolicy = serde_json::from_str(&json).unwrap();

        assert!(decoded.ephemeral);
        assert_eq!(decoded.max_duration_secs, Some(3600));
        assert_eq!(decoded.idle_timeout_secs, Some(120));
    }

    #[test]
    fn sandbox_policy_defaults_to_persistent() {
        assert!(!SandboxPolicy::default().ephemeral);
    }

    #[test]
    fn sandbox_policy_deserializes_missing_ephemeral_as_persistent() {
        // `ephemeral` has a persistent default so partial policy payloads
        // deserialize to the conservative behavior.
        let decoded: SandboxPolicy =
            serde_json::from_str(r#"{"max_duration_secs":60,"idle_timeout_secs":null}"#).unwrap();
        assert!(!decoded.ephemeral);
        assert_eq!(decoded.max_duration_secs, Some(60));
    }

    #[test]
    fn sandbox_spec_default_uses_static_resource_defaults() {
        let spec = SandboxSpec::default();

        assert_eq!(spec.resources.cpus, DEFAULT_SANDBOX_CPUS);
        assert_eq!(spec.resources.memory_mib, DEFAULT_SANDBOX_MEMORY_MIB);
        assert_eq!(
            spec.runtime.metrics_sample_interval_ms,
            Some(DEFAULT_METRICS_SAMPLE_INTERVAL_MS)
        );
    }

    #[test]
    fn sandbox_log_level_roundtrips_lowercase_values() {
        for (input, expected) in [
            ("error", SandboxLogLevel::Error),
            ("warn", SandboxLogLevel::Warn),
            ("info", SandboxLogLevel::Info),
            ("debug", SandboxLogLevel::Debug),
            ("trace", SandboxLogLevel::Trace),
        ] {
            let parsed: SandboxLogLevel = input.parse().unwrap();
            assert_eq!(parsed, expected);
            assert_eq!(parsed.as_str(), input);
        }
    }
}
