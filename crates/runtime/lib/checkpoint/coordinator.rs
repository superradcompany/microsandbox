//! Same-epoch checkpoint capture and root-last publication.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use microsandbox_agent_client::AgentClient;
use microsandbox_image::checkpoint::{
    CaptureIntent, CheckpointManifest, ContentRef, DeviceStateRef, LocalObjectStore,
    MemoryCaptureMode, MemoryExtent, MemoryExtentContent, MemoryManifest, ResourceDescriptor,
    ResourceTreatment,
};
use microsandbox_protocol::bootstrap::GuestBootstrap;
use microsandbox_protocol::core::{
    CoreError, Ready, WorkloadFreeze, WorkloadFrozen, WorkloadThaw, WorkloadThawed,
};
use microsandbox_protocol::message::{Message, MessageType};
use msb_krun::{
    GuestMemoryRange, IncrementalCaptureDecision, MemoryCaptureOptions, MemoryCapturePlan,
    MemoryCaptureSink,
};

use super::disk::ManagedRootDisk;
use crate::vm::VmConfig;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const TYPE_NET: u32 = 1;
const TYPE_BLOCK: u32 = 2;
const TYPE_RNG: u32 = 4;
const TYPE_VSOCK: u32 = 19;
pub(super) const TYPE_FS: u32 = 26;
const MEMORY_CHUNK_SIZE: usize = 2 * 1024 * 1024;
const WORKLOAD_CONTROL_TIMEOUT: Duration = Duration::from_secs(10);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Runtime-owned state needed to produce successive complete checkpoint generations.
pub(crate) struct CheckpointCoordinator {
    root: PathBuf,
    store: LocalObjectStore,
    runtime: tokio::runtime::Handle,
    agent_sock: PathBuf,
    root_disk: Option<ManagedRootDisk>,
    fs_resource_bindings: BTreeMap<String, BTreeMap<String, String>>,
    network_resource_binding: Option<String>,
    previous_memory: Option<MemoryManifest>,
}

/// Published checkpoint identity returned to the control executor.
#[derive(Clone, Debug)]
pub(crate) struct CheckpointResult {
    pub(crate) checkpoint_id: String,
    pub(crate) checkpoint_root: String,
    pub(crate) path: PathBuf,
    pub(crate) memory_mode: MemoryCaptureMode,
    pub(crate) memory_logical_bytes: u64,
    pub(crate) memory_emitted_bytes: u64,
}

/// Capture failure with the source disposition made explicit.
#[derive(Debug)]
pub(crate) struct CheckpointFailure {
    message: String,
    pub(crate) keep_paused: bool,
    pub(crate) published: Option<Box<CheckpointResult>>,
}

struct AdmittedResources {
    inventory: Vec<(u32, String)>,
    resources: Vec<ResourceDescriptor>,
}

struct PausedCapture {
    result: CheckpointResult,
    memory_plan: MemoryCapturePlan,
    memory_manifest: MemoryManifest,
}

struct FrozenWorkload {
    client: AgentClient,
    attempt_id: String,
    protocol_generation: u8,
    ready: Ready,
}

struct MemoryObjectSink<'a> {
    store: &'a LocalObjectStore,
    updates: Vec<MemoryExtent>,
    pending_bytes: Vec<u8>,
    pending_extents: Vec<PendingMemoryExtent>,
}

struct PendingMemoryExtent {
    start: u64,
    length: u64,
    object_offset: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CheckpointCoordinator {
    /// Open the per-runtime object store and managed root-disk state.
    pub(crate) fn open(
        runtime_dir: &Path,
        vm: &VmConfig,
        guest_bootstrap: &GuestBootstrap,
        runtime: tokio::runtime::Handle,
        agent_sock: &Path,
    ) -> Result<Self, String> {
        let root = runtime_dir.join("checkpoints");
        std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;
        let store = LocalObjectStore::open(runtime_dir.join("checkpoint-store"))
            .map_err(|error| error.to_string())?;
        let root_disk = ManagedRootDisk::open(runtime_dir, vm)?;
        let fs_resource_bindings = runtime_owned_fs_bindings(root_disk.is_some());
        let network_resource_binding = guest_bootstrap
            .network
            .as_ref()
            .map(serde_json::to_string)
            .transpose()
            .map_err(|error| format!("serialize effective guest network binding: {error}"))?;
        Ok(Self {
            root,
            store,
            runtime,
            agent_sock: agent_sock.to_path_buf(),
            root_disk,
            fs_resource_bindings,
            network_resource_binding,
            previous_memory: None,
        })
    }

    /// Capture and publish one complete same-epoch checkpoint, then restore source execution.
    pub(crate) fn capture(
        &mut self,
        vm: &msb_krun::VmControl,
        checkpoint_id: &str,
        intent: CaptureIntent,
    ) -> Result<CheckpointResult, CheckpointFailure> {
        validate_checkpoint_id(checkpoint_id).map_err(CheckpointFailure::before_pause)?;
        validate_vm_generation_state(vm.vm_generation_state())
            .map_err(CheckpointFailure::before_pause)?;
        let mut admitted = admit_resources(
            vm,
            &self.fs_resource_bindings,
            self.network_resource_binding.as_deref(),
        )
        .map_err(CheckpointFailure::before_pause)?;
        let final_path = self.root.join(checkpoint_id);
        if final_path.exists() {
            return Err(CheckpointFailure::before_pause(
                "checkpoint identity is already published",
            ));
        }
        let staging = self.root.join(format!(
            ".{checkpoint_id}.{}.staging",
            rand::random::<u64>()
        ));
        std::fs::create_dir(&staging).map_err(CheckpointFailure::before_pause)?;

        // The guest latch is acquired while vCPUs can still service agentd.
        // It remains held in captured guest memory so a restored child cannot
        // run application code before VM Generation ID activation completes.
        let workload = match self.freeze_workload(checkpoint_id) {
            Ok(workload) => workload,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&staging);
                return Err(CheckpointFailure::before_pause(error));
            }
        };
        admitted.resources.push(workload.resource_descriptor());

        let pause = match vm.pause() {
            Ok(pause) => pause,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&staging);
                return match self.thaw_workload(&workload) {
                    Ok(()) => Err(CheckpointFailure::before_pause(error)),
                    Err(thaw_error) => Err(CheckpointFailure::paused(format!(
                        "VM pause failed: {error}; workload thaw failed: {thaw_error}"
                    ))),
                };
            }
        };
        let paused = self.capture_paused(
            vm,
            checkpoint_id,
            intent,
            &admitted.inventory,
            admitted.resources,
            pause.get(),
            &staging,
            &final_path,
        );
        let captured = match paused {
            Ok(captured) => captured,
            Err(mut failure) => {
                if !failure.keep_paused
                    && let Err(error) = vm.resume(pause)
                {
                    failure.keep_paused = true;
                    failure.message = format!("{}; source resume failed: {error}", failure.message);
                } else if !failure.keep_paused
                    && let Err(error) = self.thaw_workload(&workload)
                {
                    failure.keep_paused = true;
                    failure.message = format!("{}; workload thaw failed: {error}", failure.message);
                    if let Err(pause_error) = vm.pause() {
                        failure.message = format!(
                            "{}; fail-closed VM re-pause failed: {pause_error}",
                            failure.message
                        );
                    }
                }
                if failure.published.is_none() {
                    let _ = std::fs::remove_dir_all(&staging);
                }
                return Err(failure);
            }
        };

        let baseline_published = match vm.publish_memory_capture(&captured.memory_plan) {
            Ok(_) => true,
            Err(error) => {
                tracing::warn!(%error, "checkpoint published without retaining memory baseline");
                let _ = vm.abandon_memory_capture(&captured.memory_plan);
                false
            }
        };
        if let Err(error) = vm.resume(pause) {
            return Err(CheckpointFailure {
                message: format!("checkpoint published but source resume failed: {error}"),
                keep_paused: true,
                published: Some(Box::new(captured.result)),
            });
        }
        if let Err(error) = self.thaw_workload(&workload) {
            let repause = vm.pause().err();
            let message = match repause {
                Some(pause_error) => format!(
                    "checkpoint published but workload thaw failed: {error}; fail-closed VM re-pause failed: {pause_error}"
                ),
                None => format!("checkpoint published but workload thaw failed: {error}"),
            };
            return Err(CheckpointFailure {
                message,
                keep_paused: true,
                published: Some(Box::new(captured.result)),
            });
        }
        if baseline_published {
            self.previous_memory = Some(captured.memory_manifest);
        } else {
            self.previous_memory = None;
        }
        Ok(captured.result)
    }

    fn freeze_workload(&self, attempt_id: &str) -> Result<FrozenWorkload, String> {
        let client = self
            .runtime
            .block_on(AgentClient::connect_with_timeout(
                &self.agent_sock,
                WORKLOAD_CONTROL_TIMEOUT,
            ))
            .map_err(|error| format!("connect workload latch: {error}"))?;
        let request = WorkloadFreeze {
            attempt_id: attempt_id.to_string(),
        };
        let reply = self
            .runtime
            .block_on(async {
                tokio::time::timeout(
                    WORKLOAD_CONTROL_TIMEOUT,
                    client.request(MessageType::WorkloadFreeze, &request),
                )
                .await
            })
            .map_err(|_| "workload freeze timed out".to_string())?
            .map_err(|error| format!("request workload freeze: {error}"))?;
        validate_workload_reply::<WorkloadFrozen>(
            reply,
            MessageType::WorkloadFrozen,
            attempt_id,
            |payload| &payload.attempt_id,
        )?;
        let protocol_generation = client.negotiated_version();
        let ready = client
            .ready()
            .map_err(|error| format!("read workload-agent identity: {error}"))?;
        Ok(FrozenWorkload {
            client,
            attempt_id: attempt_id.to_string(),
            protocol_generation,
            ready,
        })
    }

    fn thaw_workload(&self, workload: &FrozenWorkload) -> Result<(), String> {
        let request = WorkloadThaw {
            attempt_id: workload.attempt_id.clone(),
        };
        let reply = self
            .runtime
            .block_on(async {
                tokio::time::timeout(
                    WORKLOAD_CONTROL_TIMEOUT,
                    workload.client.request(MessageType::WorkloadThaw, &request),
                )
                .await
            })
            .map_err(|_| "workload thaw timed out".to_string())?
            .map_err(|error| format!("request workload thaw: {error}"))?;
        validate_workload_reply::<WorkloadThawed>(
            reply,
            MessageType::WorkloadThawed,
            &workload.attempt_id,
            |payload| &payload.attempt_id,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn capture_paused(
        &mut self,
        vm: &msb_krun::VmControl,
        checkpoint_id: &str,
        intent: CaptureIntent,
        inventory: &[(u32, String)],
        resources: Vec<ResourceDescriptor>,
        pause_generation: u64,
        staging: &Path,
        final_path: &Path,
    ) -> Result<PausedCapture, CheckpointFailure> {
        let execution = vm
            .capture_execution_state()
            .map_err(CheckpointFailure::resumable)?;
        if execution.pause_generation() != pause_generation {
            return Err(CheckpointFailure::resumable(
                "execution state belongs to another pause generation",
            ));
        }
        let execution_bytes = execution.encode().map_err(CheckpointFailure::resumable)?;
        let execution_id = self
            .store
            .put_bytes(&execution_bytes)
            .map_err(CheckpointFailure::resumable)?;
        self.store
            .link_into(&execution_id, staging)
            .map_err(CheckpointFailure::resumable)?;

        let mut device_refs = Vec::with_capacity(inventory.len());
        let mut disk_roots = Vec::new();
        for (device_type, device_id) in inventory {
            let bytes = if *device_type == TYPE_BLOCK && device_id == "vdb" {
                let disk = self.root_disk.as_mut().ok_or_else(|| {
                    CheckpointFailure::resumable(
                        "managed root block device has no rollover provider",
                    )
                })?;
                let rollover = disk
                    .rollover(vm, &self.runtime, staging, pause_generation)
                    .map_err(|error| CheckpointFailure {
                        message: error.to_string(),
                        keep_paused: error.keep_paused,
                        published: None,
                    })?;
                let manifest_bytes = rollover
                    .manifest
                    .to_canonical_bytes()
                    .map_err(CheckpointFailure::resumable)?;
                let manifest_id = self
                    .store
                    .put_bytes(&manifest_bytes)
                    .map_err(CheckpointFailure::resumable)?;
                self.store
                    .link_into(&manifest_id, staging)
                    .map_err(CheckpointFailure::resumable)?;
                disk_roots.push(manifest_id);
                rollover.device_state
            } else if *device_type == TYPE_BLOCK {
                vm.capture_block_device_state(device_id)
                    .and_then(|state| {
                        if state.pause_generation != pause_generation {
                            return Err(msb_krun::Error::Runtime(msb_krun::RuntimeError::Control(
                                "block state belongs to another pause generation".into(),
                            )));
                        }
                        state.encode().map_err(|error| {
                            msb_krun::Error::Runtime(msb_krun::RuntimeError::Control(
                                error.to_string(),
                            ))
                        })
                    })
                    .map_err(|error| {
                        CheckpointFailure::resumable(format!(
                            "capture block device {device_id}: {error}"
                        ))
                    })?
            } else {
                let state = vm
                    .capture_virtio_device_state(*device_type, device_id)
                    .map_err(|error| {
                        CheckpointFailure::resumable(format!(
                            "capture virtio device {device_id} (type {device_type}): {error}"
                        ))
                    })?;
                if state.pause_generation != pause_generation {
                    return Err(CheckpointFailure::resumable(
                        "virtio state belongs to another pause generation",
                    ));
                }
                state.encode().map_err(CheckpointFailure::resumable)?
            };
            let state_id = self
                .store
                .put_bytes(&bytes)
                .map_err(CheckpointFailure::resumable)?;
            self.store
                .link_into(&state_id, staging)
                .map_err(CheckpointFailure::resumable)?;
            device_refs.push(DeviceStateRef {
                device_type: *device_type,
                device_id: device_id.clone(),
                state: state_id,
            });
        }

        let (memory_plan, memory_mode, base_extents) =
            self.plan_memory(vm).map_err(CheckpointFailure::resumable)?;
        let mut sink = MemoryObjectSink {
            store: &self.store,
            updates: Vec::new(),
            pending_bytes: Vec::with_capacity(MEMORY_CHUNK_SIZE),
            pending_extents: Vec::new(),
        };
        let stats = match vm.capture_memory(
            &memory_plan,
            MemoryCaptureOptions::new(MEMORY_CHUNK_SIZE, true)
                .map_err(CheckpointFailure::resumable)?,
            &mut sink,
        ) {
            Ok(stats) => stats,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        let updates = match sink.finish() {
            Ok(updates) => updates,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        let extents = match overlay_extents(base_extents, updates) {
            Ok(extents) => extents,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        let memory_manifest = MemoryManifest {
            schema: "microsandbox.memory/1".into(),
            architecture: std::env::consts::ARCH.into(),
            guest_page_size: 4096,
            topology_generation: memory_plan.topology().get(),
            generation: memory_plan.generation().get(),
            capture_mode: memory_mode,
            pause_generation,
            extents,
        };
        let memory_bytes = match memory_manifest.to_canonical_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        // Packed sparse ranges can reference the same object many times. Link each immutable
        // object once so closure construction never rehashes or relinks it per guest extent.
        let mut linked_memory_objects = BTreeSet::new();
        for extent in &memory_manifest.extents {
            if let MemoryExtentContent::Object(content) = &extent.content
                && linked_memory_objects.insert(content.object.clone())
                && let Err(error) = self.store.link_into(&content.object, staging)
            {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        }
        let memory_id = match self.store.put_bytes(&memory_bytes) {
            Ok(id) => id,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        if let Err(error) = self.store.link_into(&memory_id, staging) {
            let _ = vm.abandon_memory_capture(&memory_plan);
            return Err(CheckpointFailure::resumable(error));
        }

        let checkpoint = CheckpointManifest {
            schema: "microsandbox.checkpoint/1".into(),
            checkpoint_id: checkpoint_id.into(),
            capture_intent: intent,
            architecture: std::env::consts::ARCH.into(),
            pause_generation,
            execution_state: execution_id,
            memory: memory_id,
            disks: disk_roots,
            devices: device_refs,
            resources,
            requires: Vec::new(),
        };
        let checkpoint_bytes = match checkpoint.to_canonical_bytes() {
            Ok(bytes) => bytes,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        let checkpoint_root = match self.store.put_bytes(&checkpoint_bytes) {
            Ok(id) => id,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        if let Err(error) = self.store.link_into(&checkpoint_root, staging) {
            let _ = vm.abandon_memory_capture(&memory_plan);
            return Err(CheckpointFailure::resumable(error));
        }
        if let Err(error) = publish_root_last(staging, final_path, &checkpoint_bytes) {
            let _ = vm.abandon_memory_capture(&memory_plan);
            return Err(CheckpointFailure::resumable(error));
        }

        Ok(PausedCapture {
            result: CheckpointResult {
                checkpoint_id: checkpoint_id.into(),
                checkpoint_root: checkpoint_root.to_string(),
                path: final_path.to_path_buf(),
                memory_mode,
                memory_logical_bytes: stats.logical_bytes,
                memory_emitted_bytes: stats.emitted_bytes,
            },
            memory_plan,
            memory_manifest,
        })
    }

    fn plan_memory(
        &self,
        vm: &msb_krun::VmControl,
    ) -> Result<(MemoryCapturePlan, MemoryCaptureMode, Vec<MemoryExtent>), String> {
        let Some(baseline) = vm.retained_memory_baseline() else {
            return vm
                .plan_full_memory_capture()
                .map(|plan| (plan, MemoryCaptureMode::Full, Vec::new()))
                .map_err(|error| error.to_string());
        };
        let Some(previous) = self.previous_memory.as_ref().filter(|previous| {
            previous.generation == baseline.generation().get()
                && previous.topology_generation == baseline.topology().get()
        }) else {
            return vm
                .plan_full_memory_capture()
                .map(|plan| (plan, MemoryCaptureMode::Full, Vec::new()))
                .map_err(|error| error.to_string());
        };
        match vm
            .plan_incremental_memory_capture(baseline)
            .map_err(|error| error.to_string())?
        {
            IncrementalCaptureDecision::Incremental(plan) => Ok((
                plan,
                MemoryCaptureMode::Incremental,
                previous.extents.clone(),
            )),
            IncrementalCaptureDecision::Complete { capture, .. } => {
                Ok((capture, MemoryCaptureMode::Full, Vec::new()))
            }
            IncrementalCaptureDecision::FullRequired(_) => vm
                .plan_full_memory_capture()
                .map(|plan| (plan, MemoryCaptureMode::Full, Vec::new()))
                .map_err(|error| error.to_string()),
        }
    }
}

impl CheckpointFailure {
    fn before_pause(error: impl fmt::Display) -> Self {
        Self {
            message: error.to_string(),
            keep_paused: false,
            published: None,
        }
    }

    fn paused(error: impl fmt::Display) -> Self {
        Self {
            message: error.to_string(),
            keep_paused: true,
            published: None,
        }
    }

    fn resumable(error: impl fmt::Display) -> Self {
        Self::before_pause(error)
    }
}

impl FrozenWorkload {
    fn resource_descriptor(&self) -> ResourceDescriptor {
        ResourceDescriptor {
            id: "guest:agentd".into(),
            kind: "agent".into(),
            treatment: ResourceTreatment::Serialize,
            binding: BTreeMap::from([
                (
                    "protocol_generation".into(),
                    self.protocol_generation.to_string(),
                ),
                ("agent_version".into(), self.ready.agent_version.clone()),
                ("boot_time_ns".into(), self.ready.boot_time_ns.to_string()),
                ("init_time_ns".into(), self.ready.init_time_ns.to_string()),
                ("ready_time_ns".into(), self.ready.ready_time_ns.to_string()),
            ]),
        }
    }
}

impl MemoryObjectSink<'_> {
    /// Publish the final partial content pack and return its exact guest-address projection.
    fn finish(mut self) -> io::Result<Vec<MemoryExtent>> {
        self.flush_pending()?;
        Ok(self.updates)
    }

    /// Store up to one bounded chunk containing bytes from multiple sparse guest ranges.
    fn flush_pending(&mut self) -> io::Result<()> {
        if self.pending_bytes.is_empty() {
            return Ok(());
        }
        let bytes = std::mem::take(&mut self.pending_bytes);
        let object = self
            .store
            .put_bytes(&bytes)
            .map_err(|error| io::Error::other(error.to_string()))?;
        self.updates
            .extend(self.pending_extents.drain(..).map(|extent| MemoryExtent {
                start: extent.start,
                length: extent.length,
                content: MemoryExtentContent::Object(ContentRef {
                    object: object.clone(),
                    object_offset: extent.object_offset,
                }),
            }));
        self.pending_bytes = Vec::with_capacity(MEMORY_CHUNK_SIZE);
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Display for CheckpointFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.message.fmt(formatter)
    }
}

impl std::error::Error for CheckpointFailure {}

impl MemoryCaptureSink for MemoryObjectSink<'_> {
    fn write_bytes(&mut self, range: GuestMemoryRange, bytes: &[u8]) -> io::Result<()> {
        if bytes.len() as u64 != range.length() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "memory sink range length does not match bytes",
            ));
        }

        if !self.pending_bytes.is_empty()
            && self.pending_bytes.len().saturating_add(bytes.len()) > MEMORY_CHUNK_SIZE
        {
            self.flush_pending()?;
        }
        if bytes.len() > MEMORY_CHUNK_SIZE {
            let object = self
                .store
                .put_bytes(bytes)
                .map_err(|error| io::Error::other(error.to_string()))?;
            self.updates.push(MemoryExtent {
                start: range.start(),
                length: range.length(),
                content: MemoryExtentContent::Object(ContentRef {
                    object,
                    object_offset: 0,
                }),
            });
            return Ok(());
        }

        let object_offset = self.pending_bytes.len() as u64;
        self.pending_bytes.extend_from_slice(bytes);
        self.pending_extents.push(PendingMemoryExtent {
            start: range.start(),
            length: range.length(),
            object_offset,
        });
        Ok(())
    }

    fn write_zero(&mut self, range: GuestMemoryRange) -> io::Result<()> {
        self.updates.push(MemoryExtent {
            start: range.start(),
            length: range.length(),
            content: MemoryExtentContent::Zero,
        });
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_workload_reply<T>(
    reply: Message,
    expected_type: MessageType,
    expected_attempt: &str,
    attempt_id: impl for<'a> Fn(&'a T) -> &'a str,
) -> Result<(), String>
where
    T: serde::de::DeserializeOwned,
{
    if reply.t == MessageType::CoreError {
        let error = reply
            .payload::<CoreError>()
            .map_err(|decode| format!("decode workload control error: {decode}"))?;
        return Err(format!("workload control rejected: {}", error.message));
    }
    if reply.t != expected_type {
        return Err(format!(
            "unexpected workload control reply {} (expected {})",
            reply.t.as_str(),
            expected_type.as_str()
        ));
    }
    let payload = reply
        .payload::<T>()
        .map_err(|error| format!("decode {}: {error}", expected_type.as_str()))?;
    if attempt_id(&payload) != expected_attempt {
        return Err("workload control reply belongs to another checkpoint attempt".into());
    }
    Ok(())
}

fn admit_resources(
    vm: &msb_krun::VmControl,
    fs_resource_bindings: &BTreeMap<String, BTreeMap<String, String>>,
    network_resource_binding: Option<&str>,
) -> Result<AdmittedResources, String> {
    let inventory = vm
        .virtio_device_inventory()
        .map_err(|error| error.to_string())?;
    let mut resources = Vec::with_capacity(inventory.len());
    for (device_type, device_id) in &inventory {
        if !vm
            .virtio_device_supports_quiesce(*device_type, device_id)
            .map_err(|error| error.to_string())?
        {
            return Err(format!(
                "resource {device_id} (virtio type {device_type}) cannot quiesce"
            ));
        }
        let fs_binding = if *device_type == TYPE_FS {
            Some(fs_resource_bindings.get(device_id).ok_or_else(|| {
                format!("active virtio-fs resource {device_id} has no handle-state provider")
            })?)
        } else {
            None
        };
        if *device_type == TYPE_BLOCK && !matches!(device_id.as_str(), "vda" | "vdb") {
            return Err(format!(
                "additional block resource {device_id} has no immutable-generation provider"
            ));
        }
        let treatment = match *device_type {
            TYPE_NET | TYPE_VSOCK | TYPE_FS => ResourceTreatment::Reconnect,
            TYPE_RNG => ResourceTreatment::Reset,
            _ => ResourceTreatment::Serialize,
        };
        let mut binding = BTreeMap::new();
        binding.insert("device_id".into(), device_id.clone());
        if *device_type == TYPE_NET {
            let network = network_resource_binding.ok_or_else(|| {
                format!("active network resource {device_id} has no effective guest binding")
            })?;
            binding.insert("guest_network".into(), network.into());
        }
        if let Some(fs_binding) = fs_binding {
            binding.extend(fs_binding.clone());
        }
        resources.push(ResourceDescriptor {
            id: format!("virtio:{device_type}:{device_id}"),
            kind: resource_kind(*device_type).into(),
            treatment,
            binding,
        });
    }
    Ok(AdmittedResources {
        inventory,
        resources,
    })
}

/// Require the guest-side generation driver before producing a checkpoint that promises full restore.
///
/// Merely attaching the host transport is insufficient: without a bound guest driver, a restored
/// child cannot acknowledge the fresh generation that gates workload thaw.
fn validate_vm_generation_state(state: Option<msb_krun::VmGenerationState>) -> Result<(), String> {
    let state = state.ok_or_else(|| {
        "VM Generation ID transport is unavailable for full checkpoints".to_string()
    })?;
    if state.driver_error {
        return Err("guest VM Generation ID driver reported a protocol error".to_string());
    }
    if !state.driver_ready {
        return Err("guest VM Generation ID driver is not ready for full checkpoints".to_string());
    }
    Ok(())
}

/// Describe the two filesystem transports owned by the runtime itself.
///
/// libkrun exposes transport identifiers rather than FUSE mount tags in its
/// device inventory. Microsandbox constructs filesystems in a fixed order:
/// the root/bootstrap transport first and `msb_runtime` second. A managed
/// block root may reconnect the first transport because it is only the
/// discarded init trampoline. The runtime share is likewise an explicitly
/// reconnectable host-control binding. Every later filesystem belongs to a
/// user mount and remains ineligible until its provider can preserve live
/// handles and object identity.
fn runtime_owned_fs_bindings(
    managed_block_root: bool,
) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut bindings = BTreeMap::new();
    if managed_block_root {
        bindings.insert(
            "virtio_fs0".into(),
            BTreeMap::from([
                ("guest_tag".into(), "/dev/root".into()),
                ("role".into(), "bootstrap_trampoline".into()),
            ]),
        );
    }
    bindings.insert(
        "virtio_fs1".into(),
        BTreeMap::from([
            (
                "guest_tag".into(),
                microsandbox_protocol::RUNTIME_FS_TAG.into(),
            ),
            ("role".into(), "runtime_control".into()),
        ]),
    );
    bindings
}

fn overlay_extents(
    mut base: Vec<MemoryExtent>,
    mut updates: Vec<MemoryExtent>,
) -> Result<Vec<MemoryExtent>, String> {
    updates.sort_by_key(|extent| extent.start);
    validate_non_overlapping(&updates)?;
    for update in updates {
        let update_end = update
            .start
            .checked_add(update.length)
            .ok_or_else(|| "memory update overflows".to_string())?;
        let mut next = Vec::with_capacity(base.len() + 1);
        for extent in base {
            let extent_end = extent
                .start
                .checked_add(extent.length)
                .ok_or_else(|| "memory base extent overflows".to_string())?;
            if extent_end <= update.start || extent.start >= update_end {
                next.push(extent);
                continue;
            }
            if extent.start < update.start {
                next.push(slice_extent(
                    &extent,
                    extent.start,
                    update.start - extent.start,
                ));
            }
            if extent_end > update_end {
                next.push(slice_extent(&extent, update_end, extent_end - update_end));
            }
        }
        next.push(update);
        next.sort_by_key(|extent| extent.start);
        base = next;
    }
    validate_non_overlapping(&base)?;
    Ok(coalesce_extents(base))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn slice_extent(extent: &MemoryExtent, start: u64, length: u64) -> MemoryExtent {
    let delta = start - extent.start;
    let content = match &extent.content {
        MemoryExtentContent::Zero => MemoryExtentContent::Zero,
        MemoryExtentContent::Object(content) => MemoryExtentContent::Object(ContentRef {
            object: content.object.clone(),
            object_offset: content.object_offset + delta,
        }),
    };
    MemoryExtent {
        start,
        length,
        content,
    }
}

fn validate_non_overlapping(extents: &[MemoryExtent]) -> Result<(), String> {
    let mut end = 0u64;
    for extent in extents {
        if extent.length == 0 || extent.start < end {
            return Err("memory extents are empty, overlapping, or unsorted".into());
        }
        end = extent
            .start
            .checked_add(extent.length)
            .ok_or_else(|| "memory extent overflows".to_string())?;
    }
    Ok(())
}

fn coalesce_extents(extents: Vec<MemoryExtent>) -> Vec<MemoryExtent> {
    let mut output: Vec<MemoryExtent> = Vec::with_capacity(extents.len());
    for extent in extents {
        let Some(previous) = output.last_mut() else {
            output.push(extent);
            continue;
        };
        let contiguous = previous.start + previous.length == extent.start;
        let compatible = match (&previous.content, &extent.content) {
            (MemoryExtentContent::Zero, MemoryExtentContent::Zero) => true,
            (MemoryExtentContent::Object(left), MemoryExtentContent::Object(right)) => {
                left.object == right.object
                    && left.object_offset + previous.length == right.object_offset
            }
            _ => false,
        };
        if contiguous && compatible {
            previous.length += extent.length;
        } else {
            output.push(extent);
        }
    }
    output
}

fn publish_root_last(staging: &Path, final_path: &Path, bytes: &[u8]) -> Result<(), String> {
    let root = staging.join("checkpoint.json");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&root)
        .map_err(|error| error.to_string())?;
    use std::io::Write as _;
    file.write_all(bytes).map_err(|error| error.to_string())?;
    file.sync_all().map_err(|error| error.to_string())?;
    // Windows cannot rename a directory while a child file remains open without delete sharing.
    // Close the durable root before atomically publishing its staging directory.
    drop(file);
    sync_directory(staging).map_err(|error| error.to_string())?;
    std::fs::rename(staging, final_path).map_err(|error| error.to_string())?;
    sync_directory(
        final_path
            .parent()
            .ok_or_else(|| "checkpoint path has no parent".to_string())?,
    )
    .map_err(|error| error.to_string())
}

fn validate_checkpoint_id(id: &str) -> Result<(), String> {
    if id.is_empty()
        || id.len() > 128
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err("checkpoint id must be 1-128 ASCII letters, digits, '-' or '_'".into());
    }
    Ok(())
}

fn resource_kind(device_type: u32) -> &'static str {
    match device_type {
        TYPE_NET => "network",
        TYPE_BLOCK => "block",
        TYPE_RNG => "rng",
        TYPE_VSOCK => "vsock",
        TYPE_FS => "virtiofs",
        _ => "virtio",
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    std::fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{
        MemoryObjectSink, overlay_extents, publish_root_last, runtime_owned_fs_bindings,
        validate_vm_generation_state, validate_workload_reply,
    };

    use microsandbox_image::checkpoint::{
        ContentRef, LocalObjectStore, MemoryExtent, MemoryExtentContent, ObjectId,
    };
    use microsandbox_protocol::core::{CoreError, CoreErrorKind, WorkloadFrozen};
    use microsandbox_protocol::message::{Message, MessageType};
    use msb_krun::{GuestMemoryRange, MemoryCaptureSink};

    #[test]
    fn incremental_updates_split_and_reuse_unchanged_object_ranges() {
        let original = ObjectId::from_bytes(b"original").unwrap();
        let changed = ObjectId::from_bytes(b"changed").unwrap();
        let base = vec![MemoryExtent {
            start: 0,
            length: 12,
            content: MemoryExtentContent::Object(ContentRef {
                object: original.clone(),
                object_offset: 0,
            }),
        }];
        let updates = vec![MemoryExtent {
            start: 4,
            length: 4,
            content: MemoryExtentContent::Object(ContentRef {
                object: changed.clone(),
                object_offset: 0,
            }),
        }];

        let result = overlay_extents(base, updates).unwrap();

        assert_eq!(result.len(), 3);
        assert_eq!(result[0].start, 0);
        assert_eq!(result[0].length, 4);
        assert_eq!(result[1].start, 4);
        assert_eq!(result[1].length, 4);
        assert_eq!(result[2].start, 8);
        assert_eq!(result[2].length, 4);
        assert!(matches!(
            &result[2].content,
            MemoryExtentContent::Object(content)
                if content.object == original && content.object_offset == 8
        ));
    }

    #[test]
    fn managed_root_admits_only_runtime_owned_filesystems() {
        let bindings = runtime_owned_fs_bindings(true);

        assert_eq!(bindings["virtio_fs0"]["guest_tag"], "/dev/root");
        assert_eq!(
            bindings["virtio_fs1"]["guest_tag"],
            microsandbox_protocol::RUNTIME_FS_TAG
        );
        assert!(!bindings.contains_key("virtio_fs2"));
    }

    #[test]
    fn full_checkpoint_requires_a_ready_generation_driver() {
        assert!(validate_vm_generation_state(None).is_err());
        assert!(
            validate_vm_generation_state(Some(msb_krun::VmGenerationState {
                driver_ready: false,
                driver_error: false,
                requested: None,
                processed: None,
            }))
            .is_err()
        );
        assert!(
            validate_vm_generation_state(Some(msb_krun::VmGenerationState {
                driver_ready: true,
                driver_error: true,
                requested: None,
                processed: None,
            }))
            .is_err()
        );
        assert!(
            validate_vm_generation_state(Some(msb_krun::VmGenerationState {
                driver_ready: true,
                driver_error: false,
                requested: None,
                processed: None,
            }))
            .is_ok()
        );
    }

    #[test]
    fn passthrough_root_is_not_treated_as_a_reconnectable_trampoline() {
        let bindings = runtime_owned_fs_bindings(false);

        assert!(!bindings.contains_key("virtio_fs0"));
        assert!(bindings.contains_key("virtio_fs1"));
    }

    #[test]
    fn root_last_publication_closes_the_root_before_renaming() {
        let temp = tempfile::tempdir().unwrap();
        let staging = temp.path().join("checkpoint.staging");
        let published = temp.path().join("checkpoint");
        std::fs::create_dir(&staging).unwrap();

        publish_root_last(&staging, &published, b"checkpoint-root").unwrap();

        assert!(!staging.exists());
        assert_eq!(
            std::fs::read(published.join("checkpoint.json")).unwrap(),
            b"checkpoint-root"
        );
    }

    #[test]
    fn sparse_memory_ranges_share_one_bounded_content_object() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(temp.path()).unwrap();
        let mut sink = MemoryObjectSink {
            store: &store,
            updates: Vec::new(),
            pending_bytes: Vec::new(),
            pending_extents: Vec::new(),
        };

        sink.write_bytes(GuestMemoryRange::new(0x1000, 3).unwrap(), b"abc")
            .unwrap();
        sink.write_zero(GuestMemoryRange::new(0x2000, 4).unwrap())
            .unwrap();
        sink.write_bytes(GuestMemoryRange::new(0x3000, 2).unwrap(), b"de")
            .unwrap();
        let mut extents = sink.finish().unwrap();
        extents.sort_by_key(|extent| extent.start);

        assert_eq!(extents.len(), 3);
        let MemoryExtentContent::Object(first) = &extents[0].content else {
            panic!("first range must reference packed bytes");
        };
        assert_eq!(first.object_offset, 0);
        assert!(matches!(extents[1].content, MemoryExtentContent::Zero));
        let MemoryExtentContent::Object(second) = &extents[2].content else {
            panic!("second range must reference packed bytes");
        };
        assert_eq!(second.object, first.object);
        assert_eq!(second.object_offset, 3);
        assert_eq!(
            std::fs::read(store.object_path(&first.object)).unwrap(),
            b"abcde"
        );
    }

    #[test]
    fn workload_reply_must_confirm_the_exact_attempt() {
        let reply = Message::with_payload(
            MessageType::WorkloadFrozen,
            7,
            &WorkloadFrozen {
                attempt_id: "checkpoint-42".into(),
            },
        )
        .unwrap();

        validate_workload_reply::<WorkloadFrozen>(
            reply,
            MessageType::WorkloadFrozen,
            "checkpoint-42",
            |payload| &payload.attempt_id,
        )
        .unwrap();

        let stale = Message::with_payload(
            MessageType::WorkloadFrozen,
            7,
            &WorkloadFrozen {
                attempt_id: "checkpoint-41".into(),
            },
        )
        .unwrap();
        assert!(
            validate_workload_reply::<WorkloadFrozen>(
                stale,
                MessageType::WorkloadFrozen,
                "checkpoint-42",
                |payload| &payload.attempt_id,
            )
            .is_err()
        );
    }

    #[test]
    fn workload_core_error_preserves_guest_diagnostic() {
        let reply = Message::with_payload(
            MessageType::CoreError,
            7,
            &CoreError {
                kind: CoreErrorKind::CapabilityUnavailable,
                message: "freezer unavailable".into(),
                offending_type: Some(MessageType::WorkloadFreeze.as_str().into()),
            },
        )
        .unwrap();

        let error = validate_workload_reply::<WorkloadFrozen>(
            reply,
            MessageType::WorkloadFrozen,
            "checkpoint-42",
            |payload| &payload.attempt_id,
        )
        .unwrap_err();
        assert!(error.contains("freezer unavailable"));
    }
}
