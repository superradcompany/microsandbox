//! Direct local execution branching through the existing control and restore paths.

#[cfg(feature = "local")]
use std::path::Path;
use std::sync::Arc;

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
    guest_flush: microsandbox_types::GuestFlush,
    backend: Arc<dyn Backend>,
    source: String,
    identity: SandboxIdentity,
    pub(crate) inner: SandboxBuilder,
    record_integrity: bool,
}

/// Capture once and create independently owned children concurrently, returning input-order results.
pub struct BranchManyBuilder {
    guest_flush: microsandbox_types::GuestFlush,
    backend: Arc<dyn Backend>,
    source: String,
    identity: SandboxIdentity,
    pub(crate) inner: SandboxBuilder,
    record_integrity: bool,
    names: Vec<String>,
}

/// Result for one requested child. Other children are not rolled back on startup failure.
pub struct BranchOutcome {
    /// Requested child name.
    pub name: String,
    /// Started child, or its individual startup error.
    pub result: MicrosandboxResult<Sandbox>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Capture one point in time for all names; no durable snapshot is published.
    pub fn branch_many(
        &self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> BranchManyBuilder {
        BranchManyBuilder::new(self.branch(""), names)
    }

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
    /// Capture one point in time for all names without connecting to the source guest.
    pub fn branch_many(
        &self,
        names: impl IntoIterator<Item = impl Into<String>>,
    ) -> BranchManyBuilder {
        BranchManyBuilder::new(self.branch(""), names)
    }

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

impl BranchManyBuilder {
    fn new(inner: BranchBuilder, names: impl IntoIterator<Item = impl Into<String>>) -> Self {
        let BranchBuilder {
            guest_flush,
            backend,
            source,
            identity,
            inner,
            record_integrity,
        } = inner;
        Self {
            guest_flush,
            backend,
            source,
            identity,
            inner,
            record_integrity,
            names: names.into_iter().map(Into::into).collect(),
        }
    }

    /// Select optional guest writeback for the single shared capture.
    pub fn guest_flush(mut self, policy: microsandbox_types::GuestFlush) -> Self {
        self.guest_flush = policy;
        self
    }

    /// Apply disk content integrity to the single shared capture.
    pub fn record_integrity(mut self) -> Self {
        self.record_integrity = true;
        self
    }

    /// Validate the batch, capture once, and return one startup outcome per name.
    /// Validation/capture failures fail the batch; later child failures do not recapture.
    pub async fn branch(mut self) -> MicrosandboxResult<Vec<BranchOutcome>> {
        let options = self.inner.config.into_config();
        SandboxBuilder::validate_vsock_routes(&options)?;
        if let Some(error) = self.inner.build_error.take() {
            return Err(error);
        }
        super::branch_batch::branch_many(
            self.backend,
            &self.source,
            self.identity,
            options,
            self.record_integrity,
            self.names,
            self.guest_flush,
        )
        .await
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
        inner.config.spec.mounts = Some(Vec::new());
        inner.config.spec.network.ports = Some(Vec::new());
        inner.config.spec.vsock = Default::default();
        inner.config.spec.runtime.user = None;
        Self {
            backend,
            source: source.into(),
            identity,
            inner,
            record_integrity: false,
            guest_flush: microsandbox_types::GuestFlush::Auto,
        }
    }

    /// Require or skip optional guest writeback before this capture. Auto retains dirty RAM.
    pub fn guest_flush(mut self, policy: microsandbox_types::GuestFlush) -> Self {
        self.guest_flush = policy;
        self
    }

    /// Record disk content integrity for the captured layers. Off by default; RAM is not hashed.
    pub fn record_integrity(mut self) -> Self {
        self.record_integrity = true;
        self
    }

    /// Capture source execution and start an independent child; preserve source running/paused state.
    pub async fn branch(mut self) -> MicrosandboxResult<Sandbox> {
        let options = self.inner.config.into_config();
        SandboxBuilder::validate_vsock_routes(&options)?;
        if let Some(error) = self.inner.build_error.take() {
            return Err(error);
        }
        branch(
            self.backend,
            &self.source,
            self.identity,
            options,
            self.record_integrity,
            self.guest_flush,
        )
        .await
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
    _record_integrity: bool,
    _guest_flush: microsandbox_types::GuestFlush,
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
    record_integrity: bool,
    guest_flush: microsandbox_types::GuestFlush,
) -> MicrosandboxResult<Sandbox> {
    let config = prepare_branch(
        backend.clone(),
        source,
        identity,
        options,
        record_integrity,
        guest_flush,
    )
    .await?;
    backend
        .sandboxes()
        .create_detached(backend.clone(), config)
        .await
}

/// Resolve source configuration once, shared by single-child and explicit batch operations.
#[cfg(feature = "local")]
pub(super) async fn prepare_branch(
    backend: Arc<dyn Backend>,
    source: &str,
    identity: SandboxIdentity,
    options: SandboxConfig,
    record_integrity: bool,
    guest_flush: microsandbox_types::GuestFlush,
) -> MicrosandboxResult<SandboxConfig> {
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
    // Owned declarations contain no source host path. Retain them as the required inventory
    // until capture proves that every one has independent child backing; clear external mounts.
    config
        .spec
        .mounts
        .retain(|mount| matches!(mount, microsandbox_types::VolumeMount::Owned { .. }));
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
    if !capabilities
        .capabilities
        .is_some_and(|c| c.optional_disk_integrity)
    {
        return Err(MicrosandboxError::Runtime(
            "source runtime lacks optional disk integrity; restart with the matching runtime"
                .into(),
        ));
    }
    #[cfg(target_os = "linux")]
    if !capabilities.capabilities.is_some_and(|c| c.branch_memfd) {
        return Err(MicrosandboxError::Runtime("source runtime lacks the memory-descriptor branch handoff; restart with the matching runtime".into()));
    }
    config.spec.name = name;
    config.replace_existing = false;
    config.spec.patches.clear();
    config.branch_source = Some(super::identity::BranchSource {
        guest_flush: modify::capture_flush_policy(capabilities.capabilities, guest_flush, false)?,
        batch: None,
        record_integrity,
        name: source.into(),
        run,
    });
    config.suppress_launch_for_full_restore();
    Ok(config)
}

/// Called only after the ordinary create path reserves the child name and directory.
/// Retain this pin through spawn, until the runtime owns its independent mapping handle.
#[cfg(feature = "local")]
pub(crate) async fn capture_child(
    local: &LocalBackend,
    config: &mut SandboxConfig,
    source: &super::identity::BranchSource,
    child: &Path,
) -> MicrosandboxResult<Arc<microsandbox_runtime::checkpoint::LocalMemoryPin>> {
    if let Some(capture) = source.batch.as_ref().and_then(|batch| batch.get()) {
        let closure = child.join(".branch-restore");
        // Only local hardlinks and small directory metadata; no background copier may
        // outlive cancellation and race the create path's staging cleanup.
        crate::snapshot::stage_local_branch_closure(capture.staging.path(), &closure)?;
        config.snapshot_parent = capture.snapshot_parent.clone();
        capture.state.validate_files(&closure)?;
        return adopt_capture(config, child, closure, &capture.state, capture.pin.clone()).await;
    }
    let record_integrity = source.record_integrity;
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
    #[cfg(not(target_os = "linux"))]
    let request = ControlRequest::BranchCreate {
        guest_flush: source.guest_flush,
        record_integrity,
        branch_id: id.clone(),
        child_name: config.spec.name.clone(),
        memory_cache_dir: local.cache_dir().join("memory"),
    };
    #[cfg(target_os = "linux")]
    let memory = Some(microsandbox_runtime::memory_handoff::create()?);
    #[cfg(not(target_os = "linux"))]
    let memory: Option<std::fs::File> = None;
    #[cfg(target_os = "linux")]
    let request = ControlRequest::BranchCreateMemfd {
        guest_flush: source.guest_flush,
        record_integrity,
        branch_id: id.clone(),
        child_name: config.spec.name.clone(),
        memory_cache_dir: local.cache_dir().join("memory"),
        backing: None,
    };
    let response = modify::control_request_for_run_with_memory(
        local,
        &source.name,
        source.run,
        format!("{}\n", serde_json::to_string(&request)?),
        memory.as_ref(),
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
    let state = Arc::new(LocalBranchState::open(&closure)?);
    if state.id != id {
        return Err(MicrosandboxError::Runtime("branch identity differs".into()));
    }
    let pin = Arc::new(state.memory.pin_backing(memory.as_ref())?);
    if let Some(batch) = &source.batch {
        // Keep independent disk links before the first child can launch or fail. A sibling
        // never depends on that child's directory, and RAM is pinned rather than copied.
        let staging = tempfile::Builder::new()
            .prefix(".branch-batch-")
            .tempdir_in(local.sandboxes_dir())?;
        crate::snapshot::stage_local_branch_closure(&closure, staging.path())?;
        batch
            .publish(super::branch_batch::BatchCapture {
                staging,
                pin: pin.clone(),
                state: state.clone(),
                snapshot_parent: config.snapshot_parent.clone(),
            })
            .map_err(|_| {
                MicrosandboxError::Runtime("batch capture was already established".into())
            })?;
    }
    // The captured files and RAM are now independently retained. Child adoption
    // and readiness do not need to exclude later source lifecycle operations.
    drop(lineage);
    drop(_transition);
    tokio::fs::remove_file(child.join(".branch-reservation")).await?;
    adopt_capture(config, child, closure, &state, pin).await
}

#[cfg(feature = "local")]
async fn adopt_capture(
    config: &mut SandboxConfig,
    child: &Path,
    closure: std::path::PathBuf,
    state: &LocalBranchState,
    pin: Arc<microsandbox_runtime::checkpoint::LocalMemoryPin>,
) -> MicrosandboxResult<Arc<microsandbox_runtime::checkpoint::LocalMemoryPin>> {
    // Every sibling must retain the captured owned inventory, not just the child
    // that established the batch. External-resource choices cannot replace it.
    crate::snapshot::validate_owned_inventory(&config.spec.mounts, &state.owned_volumes)?;
    #[cfg(target_os = "linux")]
    if state.memory.memfd_lease.is_some() {
        config.branch_memory = Some(pin.clone());
    }
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
            // The shared state was decoded and validated before publication; do not
            // allocate a throwaway canonical manifest for every sibling.
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
    let mut mounts = crate::snapshot::materialize_owned_volumes(
        &state.owned_volumes,
        &closure,
        child,
        &config.restore_resources,
    )
    .await?;
    mounts.extend(
        crate::snapshot::materialize_additional_disks(
            &state.disks,
            &state.resources,
            &closure,
            child,
            root_device,
            &config.restore_resources,
        )
        .await?,
    );
    crate::snapshot::apply_additional_disks(config, mounts);
    config.checkpoint_restore = Some(CheckpointRestoreConfig {
        memory_descriptor: state.memory.memfd_lease.is_some(),
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
        checkpoint_id: state.id.clone(),
    });
    config.forked = true;
    config.suppress_launch_for_full_restore();
    Ok(pin)
}
