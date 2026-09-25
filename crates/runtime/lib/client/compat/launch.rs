//! Select process-launch readers and share fields across previous formats.

use std::path::{Path, PathBuf};

use microsandbox_protocol::bootstrap::GuestBootstrap;
#[cfg(feature = "net")]
use microsandbox_types::DeploymentProfile;
use microsandbox_types::compat::field::Field;
use microsandbox_types::{
    CpuPlacement, PlacementProfile, TransparentHugePagePolicy, VsockRouteSpec,
};
use serde::Deserialize;

#[cfg(feature = "net")]
use crate::client::compat::network;
use crate::client::compat::{v0_5_9, v0_6_10};
use crate::client::launch::{
    CheckpointRestoreConfig, ExecutionIntent, FileMountConfig, LaunchConfig, Lifecycle,
    MetricsConfig, RootfsConfig, StartupCommand,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

// Dispatch only on explicit execution intent. Never retry a malformed modern
// payload using the more permissive previous defaults.
#[derive(Default, Deserialize)]
struct Intent {
    #[serde(default)]
    execution: Field<serde::de::IgnoredAny>,
    #[serde(default)]
    bootstrap: Field<serde::de::IgnoredAny>,
    #[serde(default)]
    checkpoint_restore: Field<serde::de::IgnoredAny>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct PreviousLaunch {
    db_path: PathBuf,

    db_connect_timeout_secs: u64,

    log_dir: PathBuf,

    runtime_dir: PathBuf,

    sandboxes_dir: PathBuf,

    #[serde(default)]
    run_dir: PathBuf,

    #[serde(default)]
    cpu_lease_dir: Field<PathBuf>,

    #[serde(default)]
    writeback_lease_dir: Field<PathBuf>,

    #[serde(default)]
    cpu_placement: Field<CpuPlacement>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    placement_profile_name: Option<String>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    placement_profile: Option<PlacementProfile>,

    agent_sock: PathBuf,

    libkrunfw_path: PathBuf,

    #[serde(default)]
    thp: TransparentHugePagePolicy,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    memory_cache_dir: Option<PathBuf>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_writeback_limit_bytes: Option<u64>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    block_writeback_pool_bytes: Option<u64>,

    startup: Option<StartupCommand>,

    lifecycle: Lifecycle,

    metrics: MetricsConfig,

    rootfs: RootfsConfig,

    mounts: Vec<String>,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    owned_volumes: Vec<microsandbox_types::VolumeMount>,

    #[serde(default)]
    file_mounts: Vec<FileMountConfig>,

    disks: Vec<String>,

    init_path: Option<PathBuf>,

    #[serde(default)]
    pub(super) bootstrap: Field<GuestBootstrap>,

    exec_path: Option<PathBuf>,

    exec_args: Vec<String>,

    #[cfg(feature = "net")]
    network: Option<network::Network>,

    #[cfg(feature = "net")]
    #[serde(default)]
    deployment_profile: DeploymentProfile,

    #[cfg(feature = "net")]
    sandbox_slot: u16,

    #[serde(default)]
    vsock: Vec<VsockRouteSpec>,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    checkpoint_restore: Option<CheckpointRestoreConfig>,
    #[serde(default)]
    pub(super) env: Field<Vec<String>>,
    pub(super) workdir: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PreviousLaunch {
    pub(super) fn into_current(
        self,
        bootstrap: GuestBootstrap,
        allow_missing_leases: bool,
    ) -> Result<LaunchConfig, String> {
        let legacy_leases = allow_missing_leases
            && matches!(self.cpu_lease_dir, Field::Missing)
            && matches!(self.writeback_lease_dir, Field::Missing)
            && matches!(self.cpu_placement, Field::Missing);
        let (cpu_lease_dir, writeback_lease_dir, cpu_placement) = if legacy_leases {
            (PathBuf::new(), PathBuf::new(), CpuPlacement::Inherit)
        } else {
            (
                required(self.cpu_lease_dir, "cpu_lease_dir")?,
                required(self.writeback_lease_dir, "writeback_lease_dir")?,
                required(self.cpu_placement, "cpu_placement")?,
            )
        };
        #[cfg(feature = "net")]
        let network = self
            .network
            .map(|network| network.into_current(self.deployment_profile))
            .transpose()?;
        let mut launch = LaunchConfig {
            execution: ExecutionIntent::Boot,
            bootstrap,
            cpu_lease_dir,
            writeback_lease_dir,
            cpu_placement,
            #[cfg(feature = "net")]
            network,
            db_path: self.db_path,
            db_connect_timeout_secs: self.db_connect_timeout_secs,
            log_dir: self.log_dir,
            runtime_dir: self.runtime_dir,
            sandboxes_dir: self.sandboxes_dir,
            run_dir: self.run_dir,
            placement_profile_name: self.placement_profile_name,
            placement_profile: self.placement_profile,
            agent_sock: self.agent_sock,
            libkrunfw_path: self.libkrunfw_path,
            thp: self.thp,
            memory_cache_dir: self.memory_cache_dir,
            block_writeback_limit_bytes: self.block_writeback_limit_bytes,
            block_writeback_pool_bytes: self.block_writeback_pool_bytes,
            startup: self.startup,
            lifecycle: self.lifecycle,
            metrics: self.metrics,
            rootfs: self.rootfs,
            mounts: self.mounts,
            owned_volumes: self.owned_volumes,
            file_mounts: self.file_mounts,
            disks: self.disks,
            init_path: self.init_path,
            exec_path: self.exec_path,
            exec_args: self.exec_args,
            #[cfg(feature = "net")]
            deployment_profile: self.deployment_profile,
            #[cfg(feature = "net")]
            sandbox_slot: self.sandbox_slot,
            vsock: self.vsock,
            checkpoint_restore: self.checkpoint_restore,
        };
        if legacy_leases {
            let root = run_dir(&launch);
            if root.as_os_str().is_empty() {
                return Err("legacy launch configuration has no runtime artifact root".into());
            }
            launch.cpu_lease_dir = root.join("cpu-leases");
            launch.writeback_lease_dir = root.join("writeback-leases");
            launch.run_dir = root;
        }
        Ok(launch)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Decode current or previous launch JSON at the process boundary.
pub fn decode(bytes: &[u8]) -> Result<LaunchConfig, String> {
    let intent: Intent = serde_json::from_slice(bytes).map_err(|e| e.to_string())?;
    if matches!(intent.execution, Field::Present(_)) {
        return serde_json::from_slice(bytes).map_err(|e| e.to_string());
    }
    if matches!(intent.bootstrap, Field::Present(_)) {
        return v0_6_10::launch::decode(bytes);
    }
    v0_5_9::launch::decode(bytes)
}

/// Decode the legacy boot entry point without weakening the strict modern decoder.
pub fn decode_legacy(bytes: &[u8]) -> Result<LaunchConfig, String> {
    let intent: Intent =
        serde_json::from_slice(bytes).map_err(|_| "invalid legacy launch configuration")?;
    if matches!(intent.execution, Field::Present(_))
        || matches!(intent.checkpoint_restore, Field::Present(_))
    {
        return Err("legacy sandbox launcher accepts boot-only payloads; use machine for explicit execution intent".into());
    }
    let config = decode(bytes)?;
    if !config.rootfs.disk_layers.is_empty() || !config.rootfs.upper_layers.is_empty() {
        return Err("legacy sandbox launcher does not accept checkpoint disk chains".into());
    }
    Ok(config)
}

/// Read the common fields without selecting a bootstrap format.
pub(super) fn decode_previous(bytes: &[u8]) -> Result<PreviousLaunch, String> {
    let previous: PreviousLaunch = serde_json::from_slice(bytes).map_err(|e| {
        // Input may contain secrets. Preserve useful structural diagnostics only.
        if e.to_string().contains("duplicate field") {
            "duplicate launch configuration field".to_owned()
        } else {
            "invalid or conflicting previous launch configuration".to_owned()
        }
    })?;
    Ok(previous)
}

fn required<T>(field: Field<T>, name: &str) -> Result<T, String> {
    match field {
        Field::Present(value) => Ok(value),
        Field::Missing => Err(format!("missing launch field: {name}")),
    }
}

/// Use the same endpoint/home inference as the previous lifecycle guard.
fn run_dir(launch: &LaunchConfig) -> PathBuf {
    if !launch.run_dir.as_os_str().is_empty() {
        return launch.run_dir.clone();
    }
    if let Some(agent_dir) = launch.agent_sock.parent()
        && agent_dir.file_name().is_some_and(|name| name == "agent")
        && let Some(root) = agent_dir.parent()
        && root != Path::new("")
    {
        return root.to_path_buf();
    }
    launch
        .sandboxes_dir
        .parent()
        .filter(|home| !home.as_os_str().is_empty())
        .map(|home| home.join(microsandbox_utils::RUN_SUBDIR))
        .unwrap_or_default()
}
