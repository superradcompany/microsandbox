//! Shared sandbox domain types.

use std::path::PathBuf;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

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

//--------------------------------------------------------------------------------------------------
// Types: Lifecycle
//--------------------------------------------------------------------------------------------------

/// Sandbox lifecycle policy.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "ts", derive(ts_rs::TS))]
pub struct SandboxPolicy {
    /// Hard cap on total sandbox lifetime in seconds. `None` = run forever.
    pub max_duration_secs: Option<u64>,

    /// Idle timeout in seconds. `None` = no idle detection.
    pub idle_timeout_secs: Option<u64>,
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
            max_duration_secs: Some(3600),
            idle_timeout_secs: Some(120),
        };

        let json = serde_json::to_string(&policy).unwrap();
        let decoded: SandboxPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.max_duration_secs, Some(3600));
        assert_eq!(decoded.idle_timeout_secs, Some(120));
    }
}
