//! Direct local execution branching through the existing control and restore paths.

use std::sync::Arc;
#[cfg(feature = "local")]
use std::{fs::File, path::Path};

#[cfg(feature = "local")]
use microsandbox_runtime::checkpoint::LocalBranchState;
#[cfg(feature = "local")]
use microsandbox_runtime::control::ControlRequest;
#[cfg(feature = "local")]
use microsandbox_runtime::launch::{CheckpointRestoreConfig, RootfsUpperLayerConfig};

use crate::backend::Backend;
#[cfg(feature = "local")]
use crate::backend::LocalBackend;
use crate::backend::sandbox::SandboxIdentity;
use crate::{MicrosandboxError, MicrosandboxResult};

use super::{Sandbox, SandboxBuilder, SandboxHandle};
#[cfg(feature = "local")]
use super::{SandboxConfig, SandboxStatus, modify};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Prepare a direct local branch with explicit child resource bindings.
pub struct BranchBuilder {
    backend: Arc<dyn Backend>,
    source: String,
    identity: SandboxIdentity,
    pub(crate) inner: SandboxBuilder,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Branch current execution into an independent local child using private CoW RAM.
    /// The source keeps its running/paused state; no durable full snapshot is created.
    pub fn branch(&self, name: impl Into<String>) -> BranchBuilder {
        BranchBuilder::new(
            self.backend().clone(),
            self.name(),
            self.identity(),
            name.into(),
        )
    }
}

impl SandboxHandle {
    /// Branch a running or user-paused local sandbox without connecting to its guest.
    pub fn branch(&self, name: impl Into<String>) -> BranchBuilder {
        BranchBuilder::new(
            self.backend.clone(),
            self.name(),
            self.identity(),
            name.into(),
        )
    }
}

impl BranchBuilder {
    fn new(
        backend: Arc<dyn Backend>,
        source: &str,
        identity: SandboxIdentity,
        name: String,
    ) -> Self {
        let mut inner = SandboxBuilder::new(name);
        inner.config.spec.mounts.clear();
        inner.config.spec.network.ports.clear();
        inner.config.spec.vsock = Default::default();
        inner.config.spec.runtime.user = None;
        Self {
            backend,
            source: source.into(),
            identity,
            inner,
        }
    }

    /// Capture source execution and start an independent child; preserve source running/paused state.
    pub async fn branch(mut self) -> MicrosandboxResult<Sandbox> {
        self.inner.validate_vsock_routes()?;
        if let Some(error) = self.inner.build_error.take() {
            return Err(error);
        }
        branch(self.backend, &self.source, self.identity, self.inner.config).await
    }

    /// Branch with the shared startup progress and task cancellation contract.
    #[cfg(feature = "local")]
    pub fn branch_with_progress(
        mut self,
    ) -> MicrosandboxResult<(
        crate::CreationProgressHandle,
        tokio::task::JoinHandle<MicrosandboxResult<Sandbox>>,
    )> {
        let (handle, sender) = crate::progress::channel();
        self.inner.config.creation_progress = Some(sender.downgrade());
        let task = tokio::spawn(async move {
            let result = self.branch().await;
            drop(sender);
            result
        });
        Ok((handle, task))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(not(feature = "local"))]
async fn branch(
    _backend: Arc<dyn Backend>,
    _source: &str,
    _identity: SandboxIdentity,
    _options: super::SandboxConfig,
) -> MicrosandboxResult<Sandbox> {
    Err(MicrosandboxError::InvalidConfig(
        "direct branching requires a local backend".into(),
    ))
}

#[cfg(feature = "local")]
async fn branch(
    backend: Arc<dyn Backend>,
    source: &str,
    identity: SandboxIdentity,
    options: SandboxConfig,
) -> MicrosandboxResult<Sandbox> {
    let name = options.spec.name.clone();
    super::validate_sandbox_name(&name)?;
    let local = backend.as_local().ok_or_else(|| {
        MicrosandboxError::InvalidConfig("direct branching requires a local backend".into())
    })?;
    let SandboxIdentity::Local(expected_id) = identity else {
        return Err(MicrosandboxError::InvalidConfig(
            "direct branching requires a local source".into(),
        ));
    };
    let run = {
        let _transition =
            LocalBackend::acquire_sandbox_transition_guard(&local.config().run_dir(), source)
                .await?;
        local.control_run_identity(source, expected_id).await?
    };
    let handle = backend.sandboxes().get(backend.clone(), source).await?;
    if handle.identity() != SandboxIdentity::Local(expected_id) {
        return Err(MicrosandboxError::SandboxReplaced {
            name: source.into(),
            expected: format!("local:{expected_id}"),
            actual: handle.id().to_string(),
        });
    }
    if !matches!(
        handle.status_snapshot(),
        SandboxStatus::Running | SandboxStatus::Paused
    ) {
        return Err(MicrosandboxError::InvalidConfig(
            "branch requires a running or user-paused source".into(),
        ));
    }
    let mut config = handle
        .active_config()?
        .unwrap_or(handle.config()?)
        .clone_for_persistence();
    if !options.restore_resources.inherit
        && (config.spec.network.outbound_proxy.is_some()
            || config.spec.network.secrets.is_some()
            || config.spec.network.tls.is_some()
            || config.spec.network.trust_host_cas)
    {
        return Err(MicrosandboxError::InvalidConfig(
            "source uses host-backed proxy, TLS or secret resources; explicit compatible authorization is required (or dangerously_inherit_resources for this local source)".into(),
        ));
    }
    // Inheritance never copies a source's writable disks into the child configuration.
    // Captured disk selection below materializes independent child-owned files instead.
    config.spec.mounts.clear();
    config.spec.mounts.extend(options.spec.mounts);
    if !options.restore_resources.inherit || !options.spec.network.ports.is_empty() {
        config.spec.network.ports = options.spec.network.ports;
    }
    if let Some(user) = options.spec.runtime.user {
        config.spec.runtime.user = Some(user);
    }
    config.restore_resources = options.restore_resources;
    if !config.restore_resources.inherit {
        // Retained guest streams reset; an omitted route grants no source host access.
        config.spec.vsock = Default::default();
    }
    for route in options.spec.vsock.routes {
        config.spec.vsock.routes.retain(|existing| {
            existing.port != route.port || existing.socket_type != route.socket_type
        });
        config.spec.vsock.routes.push(route);
    }
    config.external_mount_policy = options.external_mount_policy;
    config.creation_progress = options.creation_progress;
    let capabilities =
        modify::control_request_for_run(local, source, run, "{\"op\":\"capabilities\"}\n".into())
            .await?;
    if !capabilities.capabilities.is_some_and(|c| c.branch_create) {
        return Err(MicrosandboxError::Runtime(
            "source runtime does not support direct local branching".into(),
        ));
    }
    config.spec.name = name;
    config.replace_existing = false;
    config.spec.patches.clear();
    config.branch_source = Some(super::identity::BranchSource {
        name: source.into(),
        run,
    });
    config.suppress_launch_for_full_restore();
    backend
        .sandboxes()
        .create_detached(backend.clone(), config)
        .await
}

/// Called only after the ordinary create path reserves the child name and directory.
/// Retain this pin through spawn, until the runtime owns its independent mapping handle.
#[cfg(feature = "local")]
pub(crate) async fn capture_child(
    local: &LocalBackend,
    config: &mut SandboxConfig,
    source: &super::identity::BranchSource,
    child: &Path,
) -> MicrosandboxResult<File> {
    // Child reservation precedes capture; source transition ownership now excludes restart or
    // replacement until the exact selected generation has handed off its state.
    let _transition =
        LocalBackend::acquire_sandbox_transition_guard(&local.config().run_dir(), &source.name)
            .await?;
    local.validate_control_run(&source.name, source.run).await?;
    // Serialize with durable source captures so a child's ancestry describes its actual cut.
    let lineage = crate::snapshot::lineage::begin(local, &source.name).await?;
    config.snapshot_parent = lineage.parent.as_ref().map(ToString::to_string);
    let id = format!("branch_{:032x}", rand::random::<u128>());
    // Acquired before publication: source exit or another capture cannot create an unpinned
    // eviction window before this caller opens the completed memory file.
    let _handoff = microsandbox_runtime::checkpoint::LocalMemory::reserve(
        &local.cache_dir().join("memory"),
        &id,
    )?;
    tokio::fs::write(child.join(".branch-reservation"), &id).await?;
    let request = ControlRequest::BranchCreate {
        branch_id: id.clone(),
        child_name: config.spec.name.clone(),
        memory_cache_dir: local.cache_dir().join("memory"),
    };
    let response = modify::control_request_for_run(
        local,
        &source.name,
        source.run,
        format!("{}\n", serde_json::to_string(&request)?),
    )
    .await?;
    local.validate_control_run(&source.name, source.run).await?;
    lineage.validate_source(local, &source.name).await?;
    let closure = child.join(".branch-restore");
    if response.branch.as_ref() != Some(&closure) {
        return Err(MicrosandboxError::Runtime(
            "branch returned an unexpected handoff path".into(),
        ));
    }
    let state = LocalBranchState::open(&closure)?;
    if state.id != id {
        return Err(MicrosandboxError::Runtime("branch identity differs".into()));
    }
    let pin = state.memory.pin()?;
    config.spec.resources.cpus = state.vcpus;
    config.spec.resources.max_cpus = state.max_cpus;
    config.spec.resources.memory_mib = state.memory_mib;
    config.spec.resources.max_memory_mib = state.max_memory_mib;
    // The captured effective address wins over launch-time pools/defaults. Each user-mode
    // network stack is isolated; host listeners were rejected before source mutation.
    config.spec.network.interface = None;
    super::builder::apply_capture_network(config, &state.resources)?;
    let layout = match config.spec.image.oci_root_disk() {
        Some(super::RootDisk::Flat { .. }) => crate::snapshot::SnapshotRootDisk::Flat,
        Some(super::RootDisk::Tmpfs { size_mib }) => crate::snapshot::SnapshotRootDisk::Tmpfs {
            size_mib: *size_mib,
        },
        _ => crate::snapshot::SnapshotRootDisk::Managed,
    };
    let root_device = crate::snapshot::root_device(&layout);
    let root_disks = state
        .disks
        .iter()
        .filter(|disk| matches!(disk.device_id.as_str(), "vda" | "vdb"))
        .collect::<Vec<_>>();
    match root_disks.as_slice() {
        [] if matches!(layout, crate::snapshot::SnapshotRootDisk::Tmpfs { .. }) => {}
        [disk] if Some(disk.device_id.as_str()) == root_device => {
            disk.to_canonical_bytes()
                .map_err(|e| MicrosandboxError::SnapshotIntegrity(e.to_string()))?;
            if disk.pause_generation != state.pause_generation {
                return Err(MicrosandboxError::SnapshotIntegrity(
                    "branch disk epoch differs".into(),
                ));
            }
            let sources = disk
                .layers
                .iter()
                .map(|layer| RootfsUpperLayerConfig {
                    path: closure
                        .join("layers")
                        .join(format!("{}.{}", layer.layer_id, layer.format)),
                    format: layer.format.clone(),
                })
                .collect::<Vec<_>>();
            let size = disk
                .layers
                .last()
                .ok_or_else(|| MicrosandboxError::SnapshotIntegrity("branch disk is empty".into()))?
                .virtual_size;
            config.snapshot_upper_layers =
                crate::snapshot::adopt_local_branch_for_child(&sources, size, child, &layout)
                    .await?;
        }
        _ => {
            return Err(MicrosandboxError::SnapshotIntegrity(
                "branch disk closure differs from root layout".into(),
            ));
        }
    }
    let mounts = crate::snapshot::materialize_additional_disks(
        &state.disks,
        &state.resources,
        &closure,
        child,
        root_device,
        &config.restore_resources,
    )
    .await?;
    crate::snapshot::apply_additional_disks(config, mounts);
    config.checkpoint_restore = Some(CheckpointRestoreConfig {
        network_gateway_mac: microsandbox_runtime::checkpoint::captured_gateway_mac(
            &state.resources,
        )
        .map_err(MicrosandboxError::SnapshotIntegrity)?,
        external_mount_policy: config.external_mount_policy,
        external_mounts: Vec::new(),
        unavailable_disks: Default::default(),
        local_branch: true,
        forked: true,
        closure,
        checkpoint_root: String::new(),
        checkpoint_id: id,
    });
    config.forked = true;
    config.suppress_launch_for_full_restore();
    tokio::fs::remove_file(child.join(".branch-reservation")).await?;
    Ok(pin)
}
