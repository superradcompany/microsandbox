//! The typed launch contract between the SDK and the `msb machine` process.
//!
//! [`LaunchConfig`] is the bulk of a sandbox's configuration. The SDK builds
//! it, serializes it as JSON, and hands it to `msb machine` over an inherited
//! file descriptor (see [`CONFIG_FD`]); the process deserializes it
//! and builds its [`crate::vm::Config`] from it. Only a few operator-readable
//! labels and the real inherited fds stay on the process argv. This keeps the
//! network config and secret-bearing env out of `ps` and `/proc/<pid>/cmdline`
//! — see issue #997.

use std::path::PathBuf;

use super::compat;

use microsandbox_protocol::bootstrap::GuestBootstrap;
use microsandbox_types::{CpuPlacement, PlacementProfile, VsockRouteSpec};
use serde::{Deserialize, Serialize};

use microsandbox_types::TransparentHugePagePolicy;

#[cfg(feature = "net")]
use microsandbox_network::ResolvedNetworkConfig;
#[cfg(feature = "net")]
use microsandbox_types::DeploymentProfile;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Fixed fd carrying the bulk `msb machine` config as NUL-terminated argument records.
pub const CONFIG_FD: i32 = 96;
/// Fixed descriptor carrying sealed Linux local-branch memory into the child runtime.
pub const BRANCH_MEMORY_FD: i32 = 95;

/// Fixed fd used to pass the attached-parent watchdog pipe into `msb machine`.
pub const PARENT_WATCH_FD: i32 = 97;

/// Fixed fd used to pass startup JSON from `msb machine` to its launcher.
pub const STARTUP_FD: i32 = 98;

/// Fixed fd holding the inherited per-sandbox lifecycle ownership lock.
#[cfg(unix)]
pub const LIFECYCLE_LOCK_FD: i32 = 99;

/// Control byte sent by the owner to stop parent-watch monitoring without stopping the sandbox.
pub const PARENT_WATCH_DETACH: u8 = 1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Side-effect-free response to `msb __launch-protocol`.
#[derive(Debug, Serialize, Deserialize)]
pub struct LaunchCapabilities {
    /// Supported wire generations: 1 is the v0.6.17 boot contract; 2 adds explicit intent.
    pub protocols: Vec<u32>,
    /// Relaxed captured-object checks can independently require destination backing.
    /// Older probes omit this feature; ordinary protocol-2 launches are unchanged.
    #[serde(default)]
    pub required_restore_backing: bool,
}

/// Hidden CLI handoff describing the metrics slot the host reserved for this sandbox.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricsSlotHandoff {
    /// Name of the POSIX shared-memory object holding the registry.
    pub shm_name: String,
    /// Reserved slot index.
    pub slot: u32,
    /// Generation paired with the reservation.
    pub generation: u64,
}

/// User workload that the sandbox process should start after boot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StartupCommand {
    /// Path or command name to execute inside the guest.
    pub cmd: String,

    /// Arguments to pass to the command.
    pub args: Vec<String>,

    /// Environment variables as `KEY=VALUE` strings.
    pub env: Vec<String>,

    /// Working directory for the command.
    pub cwd: Option<String>,

    /// Guest user override for the command.
    pub user: Option<String>,
}

/// The bulk `msb machine` configuration delivered over the config fd.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LaunchConfig {
    /// Required execution intent. Restore intent must never be inferred from optional hints.
    pub execution: ExecutionIntent,

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

    /// Backend-resolved protected cache for explicit memory captures and restores.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub memory_cache_dir: Option<PathBuf>,

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

    /// Private volume intent resolved by the owning sandbox's launcher.
    /// Kept distinct from capture-eligible shared named disks.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owned_volumes: Vec<microsandbox_types::VolumeMount>,

    /// Isolated host-file mounts handled by the single-file backend.
    #[serde(default)]
    pub file_mounts: Vec<FileMountConfig>,

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

    /// Network launch configuration. Present only when the `net` feature is on.
    #[cfg(feature = "net")]
    pub network: Option<ResolvedNetworkConfig>,

    /// Host-runtime isolation profile enforced by backend implementations.
    #[cfg(feature = "net")]
    #[serde(default)]
    pub deployment_profile: DeploymentProfile,

    /// Sandbox slot for deterministic network address derivation.
    #[cfg(feature = "net")]
    pub sandbox_slot: u16,

    /// Host Unix sockets exposed through virtio-vsock.
    #[serde(default)]
    pub vsock: Vec<VsockRouteSpec>,

    /// Construction-only checkpoint restore source, if this launch is a clone/rollback.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checkpoint_restore: Option<CheckpointRestoreConfig>,
}

/// Pinned child-owned checkpoint closure delivered to the sandbox process.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CheckpointRestoreConfig {
    /// Require the sealed memory object inherited at BRANCH_MEMORY_FD, not a serialized path.
    /// Kept inside this strict envelope so an older runtime rejects it instead of cold booting.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub memory_descriptor: bool,
    /// Captured virtual gateway identity; never derives from the child's host slot.
    #[serde(default)]
    pub network_gateway_mac: Option<[u8; 6]>,
    /// Explicit external-resource failure policy; older launchers default to strict.
    #[serde(default)]
    pub external_mount_policy: microsandbox_types::ExternalMountRestorePolicy,
    /// Captured external mount topology; host paths come only from trusted launch mounts.
    #[serde(default)]
    pub external_mounts: Vec<ExternalMountRestoreBinding>,
    /// Additional disks intentionally retained without host backing: device ID to guest path.
    /// Kept in the strict restore envelope so older runtimes reject unsupported requests.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub unavailable_disks: std::collections::BTreeMap<String, String>,
    /// Restore a local branch handoff instead of a durable checkpoint closure.
    pub local_branch: bool,
    /// Require private CoW memory rather than eager restoration.
    /// Kept inside the strict restore contract: an unsupported mode must not become a boot.
    pub forked: bool,
    /// Path to the complete eager checkpoint closure.
    pub closure: PathBuf,
    /// Expected algorithm-qualified composite checkpoint root.
    pub checkpoint_root: String,
    /// Stable source checkpoint identifier retained for diagnostics.
    pub checkpoint_id: String,
}

/// One externally bound filesystem retained in a full restore's device topology.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMountRestoreBinding {
    /// Require backing even when captured-object validation is relaxed.
    /// Omitted for legacy semantics; older runtimes reject this explicit requirement.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub require_backing: bool,
    /// Exact captured virtio transport identity.
    pub device_id: String,
    /// Captured guest namespace and mount flags.
    pub mount: microsandbox_protocol::bootstrap::BootstrapDirMount,

    /// Captured synthetic file name, or `None` for a directory export.
    #[serde(default)]
    pub filename: Option<String>,
    /// User explicitly selected a destination binding through a volume declaration.
    pub remapped: bool,
    /// No destination mapping was selected; retain an error-serving filesystem backend.
    pub unavailable: bool,
}

/// Required process-construction intent, independent of any guest startup command.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionIntent {
    /// Construct a fresh guest from its disk/image state.
    #[default]
    Boot,
    /// Continue captured execution; a complete recognized restore source is mandatory.
    Restore,
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

/// Host-side configuration for one isolated file mount.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileMountConfig {
    /// `tag:host_path[:opts]` specification parsed by the runtime.
    pub mount: String,

    /// Filename presented at the root of the synthetic virtio-fs share.
    pub filename: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LaunchConfig {
    /// Decode and validate execution intent before allocating or starting a VM.
    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        let config: Self = serde_json::from_slice(bytes)
            .map_err(|error| format!("invalid launch config: {error}"))?;
        #[cfg(feature = "net")]
        if let Some(network) = &config.network {
            network
                .config()
                .secrets
                .validate()
                .map_err(|error| format!("invalid secret configuration: {error}"))?;
        }
        match (config.execution, config.checkpoint_restore.as_ref()) {
            (ExecutionIntent::Boot, None) => {}
            (ExecutionIntent::Restore, Some(restore)) => {
                if restore.closure.as_os_str().is_empty()
                    || (!restore.local_branch && restore.checkpoint_root.is_empty())
                    || restore.checkpoint_id.is_empty()
                {
                    return Err("restore requires a complete checkpoint source".into());
                }
                if restore.local_branch && (!restore.forked || !restore.checkpoint_root.is_empty())
                {
                    return Err(
                        "local branch requires private memory and no durable checkpoint root"
                            .into(),
                    );
                }
                if config.startup.is_some() {
                    return Err("restore cannot execute a fresh startup command".into());
                }
                if restore.memory_descriptor
                    && (!restore.local_branch || !cfg!(target_os = "linux"))
                {
                    return Err("memory descriptor requires a Linux local branch".into());
                }
            }
            _ => return Err("execution intent and checkpoint restore source disagree".into()),
        }
        Ok(config)
    }

    /// Decode current or previous v0.6.x process-launch JSON.
    ///
    /// Older environment-based bootstrap is translated at this boundary. An
    /// explicit typed bootstrap remains authoritative, including empty values.
    /// Missing previous lease policies inherit the process CPU placement and
    /// use lease directories derived from the caller's runtime artifact root.
    pub fn from_json(bytes: &[u8]) -> Result<Self, String> {
        let config = compat::decode(bytes)?;
        Self::decode(&serde_json::to_vec(&config).map_err(|e| e.to_string())?)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn required_backing_is_explicit_and_absent_from_legacy_mount_bindings() {
        let legacy = serde_json::json!({
            "device_id": "virtio_fs2", "mount": {"tag": "data", "guest_path": "/data", "flags": {}},
            "filename": null, "remapped": false, "unavailable": false
        });
        let mut binding: super::ExternalMountRestoreBinding =
            serde_json::from_value(legacy).unwrap();
        assert!(!binding.require_backing);
        assert!(
            serde_json::to_value(&binding)
                .unwrap()
                .get("require_backing")
                .is_none()
        );
        binding.require_backing = true;
        assert_eq!(
            serde_json::to_value(binding).unwrap()["require_backing"],
            true
        );
    }

    #[test]
    fn memory_descriptor_cannot_be_used_as_a_durable_or_cold_restore() {
        let mut value = restore_request();
        value["checkpoint_restore"]["memory_descriptor"] = true.into();
        assert!(decode(value.clone()).is_err());
        value["checkpoint_restore"]["local_branch"] = true.into();
        value["checkpoint_restore"]["checkpoint_root"] = "".into();
        assert_eq!(decode(value.clone()).is_ok(), cfg!(target_os = "linux"));
        value["execution"] = "boot".into();
        assert!(decode(value).is_err());
    }

    fn restore_request() -> serde_json::Value {
        serde_json::to_value(LaunchConfig {
            execution: ExecutionIntent::Restore,
            checkpoint_restore: Some(CheckpointRestoreConfig {
                memory_descriptor: false,
                network_gateway_mac: None,
                external_mount_policy: Default::default(),
                external_mounts: Vec::new(),
                unavailable_disks: Default::default(),
                local_branch: false,
                forked: true,
                closure: "/owned/child/restore".into(),
                checkpoint_root: "blake3:captured-root".into(),
                checkpoint_id: "captured".into(),
            }),
            ..Default::default()
        })
        .unwrap()
    }

    fn decode(value: serde_json::Value) -> Result<LaunchConfig, String> {
        LaunchConfig::decode(&serde_json::to_vec(&value).unwrap())
    }

    #[test]
    fn matching_boot_and_restore_intents_are_accepted() {
        assert!(decode(serde_json::to_value(LaunchConfig::default()).unwrap()).is_ok());
        let restored = decode(restore_request()).unwrap();
        assert!(restored.checkpoint_restore.unwrap().forked);
    }

    #[test]
    fn unsupported_or_missing_restore_never_becomes_boot() {
        for mutation in [
            "missing",
            "null",
            "unknown_outer",
            "unknown_nested",
            "unknown_intent",
            "boot",
        ] {
            let mut request = restore_request();
            match mutation {
                "missing" => {
                    request
                        .as_object_mut()
                        .unwrap()
                        .remove("checkpoint_restore");
                }
                "null" => request["checkpoint_restore"] = serde_json::Value::Null,
                "unknown_outer" => request["branch_restore"] = serde_json::json!({}),
                "unknown_nested" => request["checkpoint_restore"]["unsupported"] = true.into(),
                "unknown_intent" => request["execution"] = "future_restore".into(),
                "boot" => request["execution"] = "boot".into(),
                _ => unreachable!(),
            }
            assert!(decode(request).is_err(), "{mutation}");
        }
    }

    #[test]
    fn launch_requires_explicit_intent_and_memory_policy() {
        let mut request = restore_request();
        request.as_object_mut().unwrap().remove("execution");
        assert!(decode(request).is_err());
        let mut request = restore_request();
        request["checkpoint_restore"]
            .as_object_mut()
            .unwrap()
            .remove("forked");
        assert!(decode(request).is_err());
    }

    #[test]
    fn local_branch_requires_restore_and_private_memory_without_a_fake_root() {
        let mut request = restore_request();
        request["checkpoint_restore"]["local_branch"] = true.into();
        assert!(decode(request.clone()).is_err());
        request["checkpoint_restore"]["checkpoint_root"] = "".into();
        assert!(decode(request.clone()).is_ok());
        request["checkpoint_restore"]["forked"] = false.into();
        assert!(decode(request.clone()).is_err());
        request["checkpoint_restore"]["forked"] = true.into();
        request["execution"] = "boot".into();
        assert!(decode(request).is_err());
    }

    #[test]
    fn isolated_file_mount_survives_the_client_runner_handoff() {
        let config = LaunchConfig {
            file_mounts: vec![FileMountConfig {
                mount: "config:/host/secret.txt:ro,uid=1000,gid=1000".into(),
                filename: "secret.txt".into(),
            }],
            ..Default::default()
        };
        let encoded = serde_json::to_value(&config).unwrap();
        let decoded: LaunchConfig = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded.file_mounts[0].mount, config.file_mounts[0].mount);
        assert_eq!(decoded.file_mounts[0].filename, "secret.txt");
        assert!(decoded.mounts.is_empty());

        // An omitted additive field must not turn an ordinary directory into a file mount.
        let mut without_files = encoded;
        without_files.as_object_mut().unwrap().remove("file_mounts");
        let decoded: LaunchConfig = serde_json::from_value(without_files).unwrap();
        assert!(decoded.file_mounts.is_empty());
    }

    #[cfg(feature = "net")]
    #[test]
    fn network_slot_handoff_rejects_out_of_range_values() {
        let config = LaunchConfig {
            sandbox_slot: u16::MAX,
            ..Default::default()
        };
        let mut encoded = serde_json::to_value(&config).unwrap();
        let decoded: LaunchConfig = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded.sandbox_slot, u16::MAX);
        encoded["sandbox_slot"] = serde_json::json!(u32::from(u16::MAX) + 1);
        assert!(serde_json::from_value::<LaunchConfig>(encoded).is_err());
    }
}
