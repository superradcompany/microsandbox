//! The typed launch contract between the SDK and the `msb sandbox` process.
//!
//! [`LaunchConfig`] is the bulk of a sandbox's configuration. The SDK builds
//! it, serializes it as JSON, and hands it to `msb sandbox` over an inherited
//! file descriptor (see [`crate::vm::CONFIG_FD`]); the process deserializes it
//! and builds its [`crate::vm::Config`] from it. Only a few operator-readable
//! labels and the real inherited fds stay on the process argv. This keeps the
//! network config and secret-bearing env out of `ps` and `/proc/<pid>/cmdline`
//! — see issue #997.

use std::path::PathBuf;

use microsandbox_protocol::bootstrap::GuestBootstrap;
use microsandbox_types::{CpuPlacement, DeploymentProfile, PlacementProfile, VsockRouteSpec};
use serde::{Deserialize, Serialize};

use microsandbox_types::TransparentHugePagePolicy;

#[cfg(feature = "net")]
use microsandbox_network::config::NetworkConfig;

use crate::vm::{MetricsSlotHandoff, StartupCommand};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// The bulk `msb sandbox` configuration delivered over the config fd.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct LaunchConfig {
    /// Path to the sandbox database file.
    pub db_path: PathBuf,

    /// Timeout when acquiring a sandbox database connection from the pool.
    pub db_connect_timeout_secs: u64,

    /// Directory for log files.
    pub log_dir: PathBuf,

    /// Runtime directory (scripts, heartbeat).
    pub runtime_dir: PathBuf,

    /// Root directory holding every sandbox's persisted state.
    pub sandboxes_dir: PathBuf,

    /// Root directory holding ephemeral host-runtime artifacts.
    #[serde(default)]
    pub run_dir: PathBuf,

    /// Internal directory containing process-held CPU allocation leases.
    pub cpu_lease_dir: PathBuf,

    /// Internal directory containing process-held writeback pressure leases.
    pub writeback_lease_dir: PathBuf,

    /// Requested host CPU placement policy.
    pub cpu_placement: CpuPlacement,

    /// Host-defined profile name retained for diagnostics and missing-profile validation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_profile_name: Option<String>,

    /// Host-resolved profile definition; sandbox clients submit only the name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement_profile: Option<PlacementProfile>,

    /// Path to the Unix domain socket for the agent relay.
    pub agent_sock: PathBuf,

    /// Path to the libkrunfw shared library.
    pub libkrunfw_path: PathBuf,

    /// Guest transparent huge-page policy selected at boot.
    #[serde(default)]
    pub thp: TransparentHugePagePolicy,

    /// Per-writable-raw-disk hard budget for buffered host dirty data.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_writeback_limit_bytes: Option<u64>,

    /// Host-global dirty-credit pool shared fairly by live writable disks.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_writeback_pool_bytes: Option<u64>,

    /// User workload to start after boot, if any.
    pub startup: Option<StartupCommand>,

    /// Lifetime bounds for the sandbox.
    pub lifecycle: Lifecycle,

    /// Metrics sampling configuration and the host-reserved slot.
    pub metrics: MetricsConfig,

    /// Root filesystem source.
    pub rootfs: RootfsConfig,

    /// Additional virtio-fs mounts as `tag:host_path[:opts]`.
    pub mounts: Vec<String>,

    /// Disk-image volume mounts as `id:host_path:format[:ro]`.
    pub disks: Vec<String>,

    /// Path to the init binary in the guest.
    pub init_path: Option<PathBuf>,

    /// Typed one-shot configuration delivered to agentd over its console.
    pub bootstrap: GuestBootstrap,

    /// Path to the executable to run in the guest.
    pub exec_path: Option<PathBuf>,

    /// Arguments to pass to the executable.
    pub exec_args: Vec<String>,

    /// Network configuration. Present only when the `net` feature is on.
    #[cfg(feature = "net")]
    pub network: Option<NetworkConfig>,

    /// Host-runtime isolation profile enforced by backend implementations.
    #[cfg(feature = "net")]
    #[serde(default)]
    pub deployment_profile: DeploymentProfile,

    /// Sandbox slot for deterministic network address derivation.
    #[cfg(feature = "net")]
    pub sandbox_slot: u64,

    /// Host Unix sockets exposed through virtio-vsock.
    #[serde(default)]
    pub vsock: Vec<VsockRouteSpec>,

    /// Construction-only checkpoint restore source, if this launch is a clone/rollback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_restore: Option<CheckpointRestoreConfig>,
}

/// Pinned child-owned checkpoint closure delivered to the sandbox process.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRestoreConfig {
    /// Path to the complete eager checkpoint closure.
    pub closure: PathBuf,
    /// Expected algorithm-qualified composite checkpoint root.
    pub checkpoint_root: String,
    /// Stable source checkpoint identifier retained for diagnostics.
    pub checkpoint_id: String,
}

/// Lifetime bounds for the sandbox.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct Lifecycle {
    /// Hard cap on total sandbox lifetime in seconds.
    pub max_duration_secs: Option<u64>,

    /// Idle timeout in seconds.
    pub idle_timeout_secs: Option<u64>,
}

/// Metrics sampling configuration.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct MetricsConfig {
    /// Sampling interval in milliseconds.
    pub sample_interval_ms: u64,

    /// Disable sampling; overrides `sample_interval_ms`.
    pub disabled: bool,

    /// Host-reserved shared-memory slot, if metrics are enabled.
    pub slot: Option<MetricsSlotHandoff>,
}

/// Root filesystem source for the sandbox.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct RootfsConfig {
    /// Root filesystem path for direct passthrough mounts.
    pub path: Option<PathBuf>,

    /// Follow symlinks when resolving a bind (`path`) rootfs.
    ///
    /// Defaults to `false` (resolve following no symlink), matching the
    /// `--mount` protection for the caller/tenant-provided rootfs path.
    #[serde(default)]
    pub follow_root_symlinks: bool,

    /// Disk image file path for virtio-blk rootfs.
    pub disk: Option<PathBuf>,

    /// Disk image format (qcow2, raw, vmdk).
    pub disk_format: Option<String>,

    /// Mount the disk image as read-only.
    pub disk_readonly: bool,

    /// Complete oldest-to-head chain for a runtime-owned flat root disk.
    ///
    /// This is mutually exclusive with the single-file `disk` representation. It is used after
    /// checkpoint rollover has replaced the original raw root with a qcow2 successor.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disk_layers: Vec<RootfsUpperLayerConfig>,

    /// Whether the direct root disk is sandbox-owned and may be rolled over for checkpoints.
    ///
    /// User-supplied disk-image roots deliberately leave this false.
    #[serde(default)]
    pub disk_runtime_owned: bool,

    /// Writable upper block device for OCI rootfs overlay.
    pub upper: Option<PathBuf>,

    /// Upper disk image format ("raw", "qcow2"). Absent means raw — the
    /// managed `upper.ext4` fast path. Set for user-supplied disk-image
    /// root disks so the runner attaches with the right format.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upper_format: Option<String>,

    /// Complete oldest-to-head writable upper chain for a restored managed root.
    ///
    /// This is mutually exclusive with `upper`/`upper_format`. Every path is child-owned before
    /// the launch contract is published, and libkrun presents the chain as one virtio-blk device.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub upper_layers: Vec<RootfsUpperLayerConfig>,
}

/// One explicitly resolved member of a managed root upper chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RootfsUpperLayerConfig {
    /// Exact child-owned host path.
    pub path: PathBuf,
    /// On-disk format (`raw` or `qcow2`).
    pub format: String,
}
