//! Shared sandbox domain types.

use std::collections::BTreeMap;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::Value;

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
    Bind(
        /// Host path to bind mount.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        PathBuf,
    ),

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
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct OciRootfsSource {
    /// OCI image reference (e.g. `python`).
    pub reference: String,

    /// Writable overlay upper size in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upper_size_mib: Option<u32>,
}

/// Controls when an OCI registry is contacted for manifest freshness.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
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
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub enum VolumeKind {
    /// Directory-backed named volume mounted through virtiofs.
    Directory,

    /// Raw ext4 disk-image named volume mounted through virtio-blk.
    Disk,
}

/// Configuration for creating a named volume.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[cfg_attr(feature = "ts", ts(tag = "type"))]
pub enum VolumeMount {
    /// Bind mount a host directory into the guest.
    Bind {
        /// Host path to bind mount.
        #[cfg_attr(feature = "ts", ts(type = "string"))]
        host: PathBuf,
        /// Guest mount path.
        guest: String,
        /// Guest mount behavior.
        options: MountOptions,
        /// Guest-visible stat virtualization policy.
        stat_virtualization: StatVirtualization,
        /// Host permission propagation policy.
        host_permissions: HostPermissions,
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
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct NetworkSpec {
    /// Whether networking is enabled for this sandbox.
    pub enabled: bool,

    /// Guest interface overrides for the local network engine.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interface: Option<Value>,

    /// Host-to-guest port mappings.
    pub ports: Vec<PublishedPortSpec>,

    /// Egress and ingress policy subdocument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub policy: Option<Value>,

    /// DNS interception and filtering subdocument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Value>,

    /// TLS interception subdocument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls: Option<Value>,

    /// Secret injection subdocument.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Value>,

    /// Max concurrent guest connections.
    pub max_connections: Option<usize>,

    /// Whether to copy trusted host CAs into the guest at boot.
    pub trust_host_cas: bool,
}

/// A published port mapping between host and guest.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct HandoffInit {
    /// Init binary: absolute path inside the guest rootfs, or the literal `auto`.
    #[cfg_attr(feature = "ts", ts(type = "string"))]
    pub cmd: PathBuf,

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
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct SandboxSpec {
    /// Unique sandbox name.
    pub name: String,

    /// Root filesystem source.
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
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
#[serde(default)]
pub struct SandboxResources {
    /// Number of virtual CPUs.
    pub cpus: u8,

    /// Guest memory in MiB.
    pub memory_mib: u32,
}

/// Guest runtime options for a sandbox.
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct EnvVar {
    /// Environment variable name.
    pub key: String,

    /// Environment variable value.
    pub value: String,
}

/// Runtime log verbosity for sandbox specs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
            upper_size_mib: None,
        }
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

    /// Return the configured OCI upper size in MiB if this is an OCI rootfs.
    pub fn oci_upper_size_mib(&self) -> Option<u32> {
        match self {
            Self::Oci(oci) => oci.upper_size_mib,
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
        }
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
                quota_mib,
            } => {
                let mut map = serializer.serialize_map(Some(7))?;
                map.serialize_entry("type", "Bind")?;
                map.serialize_entry("host", host)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("options", options)?;
                map.serialize_entry("stat_virtualization", stat_virtualization)?;
                map.serialize_entry("host_permissions", host_permissions)?;
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
            } => {
                let mut map = serializer.serialize_map(Some(6))?;
                map.serialize_entry("type", "Named")?;
                map.serialize_entry("name", name)?;
                map.serialize_entry("guest", guest)?;
                map.serialize_entry("options", options)?;
                map.serialize_entry("stat_virtualization", stat_virtualization)?;
                map.serialize_entry("host_permissions", host_permissions)?;
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
                quota_mib,
            } => Self::Bind {
                host,
                guest,
                options: decode_mount_options(options, readonly),
                stat_virtualization,
                host_permissions,
                quota_mib,
            },
            VolumeMountHelper::Named {
                name,
                guest,
                options,
                readonly,
                stat_virtualization,
                host_permissions,
            } => Self::Named {
                name,
                guest,
                create: None,
                options: decode_mount_options(options, readonly),
                stat_virtualization,
                host_permissions,
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
                quota_mib,
            } => f
                .debug_struct("Bind")
                .field("host", host)
                .field("guest", guest)
                .field("options", options)
                .field("stat_virtualization", stat_virtualization)
                .field("host_permissions", host_permissions)
                .field("quota_mib", quota_mib)
                .finish(),
            Self::Named {
                name,
                guest,
                create,
                options,
                stat_virtualization,
                host_permissions,
            } => f
                .debug_struct("Named")
                .field("name", name)
                .field("guest", guest)
                .field("create", create)
                .field("options", options)
                .field("stat_virtualization", stat_virtualization)
                .field("host_permissions", host_permissions)
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

fn decode_mount_options(options: Option<MountOptions>, readonly: bool) -> MountOptions {
    options.unwrap_or(MountOptions {
        readonly,
        ..MountOptions::default()
    })
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
