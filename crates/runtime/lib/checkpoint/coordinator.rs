//! Same-epoch checkpoint capture and root-last publication.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use microsandbox_agent_client::OptimizedAgentClient as AgentClient;
use microsandbox_image::checkpoint::{
    AdmittedObject, CaptureIntent, CaptureObjectBatch, CheckpointGeometry, CheckpointManifest,
    ContentRef, DeviceStateRef, LocalObjectStore, MemoryCaptureMode, MemoryExtent,
    MemoryExtentContent, MemoryManifest, ObjectId, ResourceDescriptor, ResourceTreatment,
};
use microsandbox_image::snapshot::{
    OwnedDirectoryPayload, OwnedMountSnapshot, OwnedVolumeCapture, OwnedVolumeData,
};
use microsandbox_protocol::bootstrap::GuestBootstrap;
use microsandbox_protocol::core::{
    CoreError, CoreErrorKind, Ready, WorkloadFailureDisposition, WorkloadFreeze, WorkloadFrozen,
    WorkloadThaw, WorkloadThawed, WorkloadTransportCredit, WorkloadTransportPosition,
};
use microsandbox_protocol::message::{Message, MessageType};
use msb_krun::{IncrementalCaptureDecision, MemoryCaptureOptions, MemoryCapturePlan};

use super::additional_disk::RuntimeOwnedAdditionalDisk;
use super::capture_pipeline::{MEMORY_OBJECT_PACK_SIZE, MemoryObjectSink};
use super::disk::RuntimeOwnedRootDisk;
use super::local_memory::{LocalMemoryCapture, LocalMemoryPin};
use crate::runner::workload_control::{InputGate, WorkloadControl};
use crate::vm::VmConfig;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const TYPE_NET: u32 = 1;
const TYPE_BLOCK: u32 = 2;
const TYPE_RNG: u32 = 4;
const TYPE_VSOCK: u32 = 19;
pub(super) const TYPE_FS: u32 = 26;
// Keep zero detection fine-grained so one live page does not force a large sparse range into the
// object store. Independently pack non-zero ranges into larger immutable objects to amortize
// hashing, fsync, directory publication, and restore-time object opens.
const MEMORY_SCAN_CHUNK_SIZE: usize = 2 * 1024 * 1024;
const WORKLOAD_CONTROL_TIMEOUT: Duration = Duration::from_secs(10);
const EXTERNAL_WORKLOAD_FREEZE_TIMEOUT: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Runtime-owned state needed to produce successive complete checkpoint generations.
pub(crate) struct CheckpointCoordinator {
    root: PathBuf,
    store: LocalObjectStore,
    runtime: tokio::runtime::Handle,
    agent_sock: PathBuf,
    workload_control: Arc<WorkloadControl>,
    root_disk: Option<RuntimeOwnedRootDisk>,
    additional_disks: BTreeMap<String, RuntimeOwnedAdditionalDisk>,
    owned_mounts: BTreeMap<String, OwnedMountSnapshot>,
    owned_directories: BTreeMap<String, microsandbox_filesystem::OwnedDirectoryCheckpoint>,
    unsupported_additional_disks: BTreeMap<String, String>,
    fs_resource_bindings: BTreeMap<String, BTreeMap<String, String>>,
    network_resource_binding: Option<BTreeMap<String, String>>,
    previous_memory: Option<MemoryManifest>,
    previous_memory_objects: Vec<AdmittedObject>,
    memory_cache: Option<super::MemoryCache>,
    cached_baseline: Option<(MemoryManifest, super::CachedMemory)>,
    local_cache_root: Option<PathBuf>,
    local_baseline: Option<LocalMemoryPin>,
    inherited_memory: Option<LocalMemoryPin>,
    boot_geometry: (u8, u8, u32, u32),
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
    freezer_unavailable: bool,
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
    memory_manifest: Option<MemoryManifest>,
    memory_objects: Vec<AdmittedObject>,
    local_memory: Option<LocalMemoryPin>,
    timings: PausedCaptureTimings,
}

#[derive(Default)]
struct PausedCaptureTimings {
    execution_us: u128,
    devices_us: u128,
    managed_disk_us: u128,
    memory_plan_us: u128,
    memory_capture_us: u128,
    memory_finish_us: u128,
    memory_paused_prepare_us: u128,
    guest_bytes_read: u64,
    unplugged_bytes_skipped: u64,
    extent_overlay_us: u128,
    memory_manifest_us: u128,
    checkpoint_publish_us: u128,
    pipeline_wait_us: u128,
    object_persist_worker_us: u128,
    object_packs: u64,
    peak_in_flight_bytes: usize,
    object_hashed_bytes: u64,
    object_linked_bytes: u64,
    object_copied_bytes: u64,
    object_directory_syncs: u64,
}

struct FrozenWorkload {
    external_mounts_synced: bool,
    // An empty request also acknowledges success. Retain exactly what was requested
    // so a later paused capture cannot mistake that acknowledgement for a root flush.
    synced_mounts: BTreeSet<String>,
    gate: InputGate,
    attempt_id: String,
    protocol_generation: u8,
    ready: Ready,
    host_input: WorkloadTransportPosition,
    input_credit: WorkloadTransportCredit,
    guest_bulk_bytes: u64,
}

/// Executor-owned resident pause. A recovery pause never acquires this public resume authority.
pub(crate) struct UserPause {
    generation: msb_krun::VmPauseGeneration,
    workload: Option<FrozenWorkload>,
    // A kernel-only resident pause still keeps unadmitted host input source-owned.
    input_gate: Option<InputGate>,
    pub(crate) capture_unavailable: Option<String>,
}

struct PendingDeviceState {
    device_type: u32,
    device_id: String,
    bytes: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CheckpointCoordinator {
    /// Establish a resident, user-owned pause without requiring snapshot resource admission.
    pub(crate) fn pause_user(
        &self,
        vm: &msb_krun::VmControl,
        attempt_id: &str,
        guest_flush: Option<microsandbox_types::GuestFlush>,
    ) -> Result<UserPause, CheckpointFailure> {
        if !vm.clock_sync_supported() {
            return Err(CheckpointFailure::before_pause(
                "guest kernel lacks clock-only resume support",
            ));
        }
        let required = guest_flush.is_some_and(|policy| policy.requires_writeback(false));
        let (workload, capture_unavailable) = match self
            .freeze_workload(vm, attempt_id, required, false)
        {
            Ok(workload) => (Some(workload), None),
            Err(error) if error.freezer_unavailable && !required => (None, Some(error.to_string())),
            Err(error) => return Err(error),
        };
        if required
            && let Some(workload) = &workload
            && !workload.covers(&self.flush_mounts(true, false))
        {
            return Err(recover_failed_freeze(
                attempt_id,
                "required guest filesystem flush failed; pause was not established".into(),
                || self.thaw_workload(workload),
                || vm.pause().map(|_| ()).map_err(|error| error.to_string()),
            ));
        }
        let input_gate = if workload.is_none() {
            Some(
                self.gate_input(Instant::now() + WORKLOAD_CONTROL_TIMEOUT)?
                    .0,
            )
        } else {
            None
        };
        match vm.pause() {
            Ok(generation) => Ok(UserPause {
                generation,
                workload,
                input_gate,
                capture_unavailable,
            }),
            Err(error) => {
                if let Some(workload) = workload {
                    return Err(recover_failed_freeze(
                        attempt_id,
                        error.to_string(),
                        || self.thaw_workload(&workload),
                        || vm.pause().map(|_| ()).map_err(|error| error.to_string()),
                    ));
                }
                if let Some(gate) = input_gate {
                    gate.release();
                }
                Err(CheckpointFailure::before_pause(error))
            }
        }
    }

    /// Resume this exact resident VM, processing clock correction before releasing workloads.
    pub(crate) fn resume_user(
        &self,
        vm: &msb_krun::VmControl,
        paused: &UserPause,
    ) -> Result<(), CheckpointFailure> {
        paused.validate(vm).map_err(CheckpointFailure::paused)?;
        let request = vm
            .request_clock_sync()
            .ok_or_else(|| CheckpointFailure::paused("clock-only resume request unavailable"))?;
        vm.resume(paused.generation)
            .map_err(CheckpointFailure::paused)?;
        let result = if vm.wait_vm_generation_processed(request, WORKLOAD_CONTROL_TIMEOUT)
            == Some(msb_krun::VmGenerationWaitOutcome::Processed)
        {
            match &paused.workload {
                Some(workload) => self.thaw_workload(workload),
                None => {
                    if let Some(gate) = &paused.input_gate {
                        gate.release();
                    }
                    Ok(())
                }
            }
        } else {
            Err("guest did not acknowledge resident resume clock correction".into())
        };
        result.map_err(|error| {
            let pause_error = vm.pause().err();
            CheckpointFailure::paused(format!(
                "resume recovery required: {error}; pause error: {pause_error:?}"
            ))
        })
    }

    pub(crate) fn compact(
        &mut self,
        vm: &msb_krun::VmControl,
        target: microsandbox_types::DiskCompactionTarget,
        layers: Option<usize>,
        dry_run: bool,
    ) -> Result<super::DiskCompactionResult, super::disk::RootDiskRolloverError> {
        super::compaction::compact_live(
            &mut self.root_disk,
            &mut self.additional_disks,
            &self.owned_mounts,
            vm,
            &self.runtime,
            &target,
            layers,
            dry_run,
        )
    }

    pub(crate) fn grow_root(
        &mut self,
        vm: &msb_krun::VmControl,
        size_bytes: u64,
    ) -> Result<crate::control::RootDiskGrowthResult, super::disk::RootDiskRolloverError> {
        use super::disk::RootDiskRolloverError as Failure;
        let started = Instant::now();
        let disk = self
            .root_disk
            .as_mut()
            .ok_or_else(|| Failure::pre_rebind("root is not runtime-owned"))?;
        let client = self
            .runtime
            .block_on(AgentClient::connect_with_timeout(
                &self.agent_sock,
                WORKLOAD_CONTROL_TIMEOUT,
            ))
            .map_err(Failure::pre_rebind)?;
        // Gate the protocol and validate ext4 before mutating either disk or recovery state.
        let request = microsandbox_protocol::core::RootDiskGrow { size_bytes };
        self.runtime
            .block_on(root_growth_request(
                &client,
                MessageType::RootDiskPrepare,
                &request,
            ))
            .map_err(Failure::pre_rebind)?;
        disk.begin_growth(size_bytes).map_err(Failure::pre_rebind)?;
        let paused_at = Instant::now();
        let pause = vm.pause().map_err(Failure::pre_rebind)?;
        if let Err(error) = vm.grow_block_capacity(disk.device_id(), size_bytes) {
            // The image may already be larger. Fence execution until restart reopens actual
            // capacity; retrying this target then completes the filesystem phase.
            return Err(Failure::post_journal(format!(
                "root block growth requires forward recovery: {error}"
            )));
        }
        vm.resume(pause).map_err(Failure::post_journal)?;
        let pause_us = paused_at.elapsed().as_micros() as u64;
        let guest_started = Instant::now();
        let state = self
            .runtime
            .block_on(root_growth_request(
                &client,
                MessageType::RootDiskGrow,
                &request,
            ))
            .map_err(|e| {
                Failure::pre_rebind(format!(
                    "block device grew; filesystem completion is pending, retry this target: {e}"
                ))
            })?;
        if state.filesystem_bytes != size_bytes || state.device_bytes < size_bytes {
            return Err(Failure::pre_rebind(
                "guest did not acknowledge the requested root capacity; retry to finish growth",
            ));
        }
        let guest_us = guest_started.elapsed().as_micros() as u64;
        disk.finish_growth().map_err(Failure::pre_rebind)?;
        Ok(crate::control::RootDiskGrowthResult {
            filesystem_bytes: state.filesystem_bytes,
            device_bytes: state.device_bytes,
            total_us: started.elapsed().as_micros() as u64,
            pause_us,
            guest_us,
        })
    }

    /// Open the per-runtime object store and managed root-disk state.
    pub(crate) fn open(
        runtime_dir: &Path,
        vm: &VmConfig,
        guest_bootstrap: &GuestBootstrap,
        runtime: tokio::runtime::Handle,
        agent_sock: &Path,
        workload_control: Arc<WorkloadControl>,
        owned_directories: BTreeMap<String, microsandbox_filesystem::OwnedDirectoryCheckpoint>,
    ) -> Result<Self, String> {
        let root = runtime_dir.join("checkpoints");
        std::fs::create_dir_all(&root).map_err(|error| error.to_string())?;
        let store = LocalObjectStore::open(runtime_dir.join("checkpoint-store"))
            .map_err(|error| error.to_string())?;
        let root_disk = RuntimeOwnedRootDisk::open(runtime_dir, vm)?;
        let additional_disks =
            RuntimeOwnedAdditionalDisk::open_all(&vm.disks, guest_bootstrap, runtime_dir)?;
        let owned_mounts = vm
            .owned_volumes
            .iter()
            .map(|mount| {
                let tag = microsandbox_types::owned_volume_mount_id(mount.guest());
                if !guest_bootstrap
                    .dir_mounts
                    .iter()
                    .any(|binding| binding.guest_path == mount.guest() && binding.tag == tag)
                    && !guest_bootstrap
                        .disk_mounts
                        .iter()
                        .any(|binding| binding.guest_path == mount.guest() && binding.id == tag)
                {
                    return Err(format!(
                        "owned mount {} has no matching guest binding",
                        mount.guest()
                    ));
                }
                Ok((
                    tag,
                    OwnedMountSnapshot::from_mount(mount).map_err(|error| error.to_string())?,
                ))
            })
            .collect::<Result<BTreeMap<_, _>, String>>()?;
        let unsupported_additional_disks = vm
            .disks
            .iter()
            .filter(|disk| disk.snapshot_owned && !additional_disks.contains_key(&disk.id))
            .map(|disk| (disk.id.clone(), format!("{:?}", disk.format)))
            .collect();
        let block_root =
            vm.rootfs_vmdk.is_some() || vm.rootfs_disk.is_some() || vm.rootfs_disk_spec.is_some();
        let mut fs_resource_bindings = runtime_owned_fs_bindings(block_root);
        fs_resource_bindings.extend(super::external_mounts::bindings(
            runtime_dir,
            vm,
            guest_bootstrap,
        )?);
        let network_resource_binding = guest_bootstrap
            .network
            .as_ref()
            .map(|network| -> Result<BTreeMap<String, String>, String> {
                #[cfg(feature = "net")]
                {
                    // Recapturing a child retains its original virtual gateway,
                    // not the child's independently allocated host slot.
                    let gateway = vm
                        .checkpoint_restore
                        .as_ref()
                        .and_then(|restore| restore.network_gateway_mac)
                        .unwrap_or_else(|| {
                            microsandbox_network::network::SmoltcpNetwork::default_gateway_mac(
                                vm.sandbox_slot,
                            )
                        });
                    Ok(BTreeMap::from([
                        (
                            "guest_network".into(),
                            serde_json::to_string(network).map_err(|error| error.to_string())?,
                        ),
                        (
                            "gateway_mac".into(),
                            serde_json::to_string(&gateway).map_err(|error| error.to_string())?,
                        ),
                    ]))
                }
                #[cfg(not(feature = "net"))]
                {
                    let _ = network;
                    Err("network capture requires the net feature".into())
                }
            })
            .transpose()
            .map_err(|error| format!("serialize effective guest network binding: {error}"))?;
        Ok(Self {
            root,
            store,
            runtime,
            agent_sock: agent_sock.to_path_buf(),
            workload_control,
            root_disk,
            additional_disks,
            owned_mounts,
            owned_directories,
            unsupported_additional_disks,
            fs_resource_bindings,
            network_resource_binding,
            previous_memory: None,
            previous_memory_objects: Vec::new(),
            memory_cache: if vm
                .checkpoint_restore
                .as_ref()
                .is_some_and(|restore| restore.forked)
            {
                Some(
                    super::MemoryCache::open(vm.memory_cache_dir.as_ref().ok_or_else(|| {
                        "CoW memory requires its backend-resolved cache directory".to_string()
                    })?)
                    .map_err(|error| error.to_string())?,
                )
            } else {
                None
            },
            cached_baseline: None,
            local_cache_root: vm.memory_cache_dir.clone(),
            local_baseline: None,
            inherited_memory: None,
            boot_geometry: (vm.vcpus, vm.max_cpus, vm.memory_mib, vm.max_memory_mib),
        })
    }

    /// Retain the admitted restore image before the VMM is constructed. Its parent's token is
    /// not usable here; the first capture binds this pin to the new VMM's construction token.
    pub(crate) fn inherit_local_memory(&mut self, memory: Option<LocalMemoryPin>) {
        self.inherited_memory = memory;
    }

    /// Seal the owned disk at a crash-consistent cut without capturing RAM or guest execution.
    pub(crate) fn capture_disk(
        &mut self,
        vm: &msb_krun::VmControl,
        checkpoint_id: &str,
        user_pause: Option<&UserPause>,
        guest_flush: Option<microsandbox_types::GuestFlush>,
    ) -> Result<crate::control::DiskCheckpointControlState, super::disk::RootDiskRolloverError>
    {
        use super::disk::RootDiskRolloverError as Failure;
        let started = Instant::now();
        validate_checkpoint_id(checkpoint_id).map_err(Failure::pre_rebind)?;
        if let Some(paused) = user_pause {
            paused.validate(vm).map_err(Failure::pre_rebind)?;
        }
        let disk = self.root_disk.as_ref().ok_or_else(|| {
            Failure::pre_rebind("disk-only capture requires an owned managed or flat root disk")
        })?;
        if disk.growth_pending() {
            return Err(Failure::pre_rebind(
                "complete pending root-disk growth before snapshotting",
            ));
        }
        // Absent policy preserves old clients' crash-consistent disk cut. New clients
        // explicitly send Auto, which requires root and owned-block guest writeback.
        let required = guest_flush.is_some_and(|policy| policy.requires_writeback(true));
        let required_mounts = self.flush_mounts(required, true);
        let acquired_workload;
        let workload = if self.owned_mounts.is_empty() && !required {
            None
        } else if let Some(paused) = user_pause {
            Some(paused.workload.as_ref().ok_or_else(|| {
                Failure::pre_rebind("capture requires a guest-flushed pause; resume and pause with --guest-flush required, or explicitly skip optional flushing")
            })?)
        } else {
            acquired_workload = self
                .freeze_workload(vm, checkpoint_id, required, true)
                .map_err(|error| {
                    if error.keep_paused {
                        Failure::post_journal(error)
                    } else {
                        Failure::pre_rebind(error)
                    }
                })?;
            Some(&acquired_workload)
        };
        if workload.is_some_and(|workload| !workload.covers(&required_mounts)) {
            if user_pause.is_none() {
                self.thaw_workload(workload.expect("checked workload"))
                    .map_err(Failure::post_journal)?;
            }
            return Err(Failure::pre_rebind(
                "capture requires an acknowledged guest filesystem flush at this pause; resume and pause with --guest-flush required, or explicitly skip optional flushing",
            ));
        }
        let path = self.root.join(checkpoint_id);
        if let Err(error) = std::fs::create_dir(&path) {
            if user_pause.is_none()
                && let Some(workload) = workload
            {
                self.thaw_workload(workload)
                    .map_err(Failure::post_journal)?;
            }
            return Err(Failure::pre_rebind(error));
        }
        let paused_at = Instant::now();
        let pause = match user_pause
            .map(|p| Ok(p.generation))
            .unwrap_or_else(|| vm.pause())
        {
            Ok(pause) => pause,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&path);
                if user_pause.is_none()
                    && let Some(workload) = workload
                {
                    self.thaw_workload(workload)
                        .map_err(Failure::post_journal)?;
                }
                return Err(Failure::pre_rebind(error));
            }
        };
        // Keep every owned provider quiesced until all bytes are sealed. No RAM scan or
        // execution serialization is needed for this cold-boot storage artifact.
        let result: Result<_, Failure> = (|| {
            if !self.owned_directories.is_empty() {
                std::fs::create_dir_all(path.join("owned")).map_err(Failure::pre_rebind)?;
            }
            let captured = self.root_disk.as_mut().expect("validated root").rollover(
                vm,
                &self.runtime,
                &path,
                pause.get(),
                false,
                false,
            )?;
            let mut owned_volumes = Vec::new();
            for (tag, mount) in &self.owned_mounts {
                let data = if let Some(directory) = self.owned_directories.get(tag) {
                    directory
                        .prepare_capture(&path.join("owned").join(tag))
                        .map_err(Failure::pre_rebind)?;
                    let device = self
                        .fs_resource_bindings
                        .iter()
                        .find(|(_, binding)| binding.get("guest_tag") == Some(tag))
                        .map(|(device, _)| device)
                        .ok_or_else(|| {
                            Failure::pre_rebind("owned directory lacks its transport")
                        })?;
                    vm.capture_virtio_device_state(TYPE_FS, device)
                        .map_err(Failure::pre_rebind)?;
                    owned_directory_data(directory.finish_capture().map_err(Failure::pre_rebind)?)
                        .map_err(Failure::pre_rebind)?
                } else {
                    let disk = self.additional_disks.get_mut(tag).ok_or_else(|| {
                        Failure::pre_rebind("owned disk lacks its capture provider")
                    })?;
                    let generation = disk
                        .capture(vm, &self.runtime, &path, pause.get(), false)?
                        .manifest;
                    OwnedVolumeData::Disk { generation }
                };
                owned_volumes.push(OwnedVolumeCapture {
                    mount_id: tag.clone(),
                    mount: mount.clone(),
                    data,
                });
            }
            Ok((captured, owned_volumes))
        })();
        for directory in self.owned_directories.values() {
            let _ = directory.cancel_capture();
        }
        if user_pause.is_none() && !result.as_ref().is_err_and(|e| e.keep_paused) {
            vm.resume(pause).map_err(Failure::post_journal)?;
            if let Some(workload) = workload
                && let Err(error) = self.thaw_workload(workload)
            {
                let _ = vm.pause();
                return Err(Failure::post_journal(error));
            }
        }
        let pause_us = paused_at.elapsed().as_micros();
        match result {
            Ok((captured, owned_volumes)) => {
                tracing::info!(target: "microsandbox_checkpoint_timing", operation = "capture_disk",
                    checkpoint_id, source_already_paused = user_pause.is_some(), pause_us,
                    total_us = started.elapsed().as_micros(), "disk-only checkpoint timing");
                Ok(crate::control::DiskCheckpointControlState {
                    checkpoint_id: checkpoint_id.into(),
                    path,
                    disk: captured.manifest,
                    owned_volumes,
                })
            }
            Err(error) => {
                // The runtime's forward journal owns any committed new head. Only discard the
                // unreturned immutable closure, never source layers or its recovery journal.
                let _ = std::fs::remove_dir_all(&path);
                Err(error)
            }
        }
    }

    /// Capture a same-epoch full checkpoint while preserving prior execution state.
    pub(crate) fn capture(
        &mut self,
        vm: &msb_krun::VmControl,
        checkpoint_id: &str,
        intent: CaptureIntent,
        user_pause: Option<&UserPause>,
        record_integrity: bool,
        guest_flush: Option<microsandbox_types::GuestFlush>,
    ) -> Result<CheckpointResult, CheckpointFailure> {
        self.capture_to(
            vm,
            checkpoint_id,
            intent,
            user_pause,
            None,
            None,
            record_integrity,
            guest_flush,
        )
    }

    /// Capture a local handoff directly, without publishing a portable RAM closure.
    // Keep borrowed capture inputs explicit; this entry point does not own or retain them.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn branch(
        &mut self,
        vm: &msb_krun::VmControl,
        id: &str,
        child_name: &str,
        reserved_cache: &Path,
        user_pause: Option<&UserPause>,
        memory_backing: Option<&std::fs::File>,
        record_integrity: bool,
        guest_flush: Option<microsandbox_types::GuestFlush>,
    ) -> Result<CheckpointResult, CheckpointFailure> {
        let cache = self.local_cache_root.as_ref().ok_or_else(|| {
            CheckpointFailure::before_pause("runtime has no backend-resolved memory cache")
        })?;
        // Reject unsupported hosts before freezing or rolling over the source disk.
        super::MemoryCache::open_namespace(cache.clone(), "branches")
            .map_err(CheckpointFailure::before_pause)?;
        if std::fs::canonicalize(cache).map_err(CheckpointFailure::before_pause)?
            != std::fs::canonicalize(reserved_cache).map_err(CheckpointFailure::before_pause)?
        {
            return Err(CheckpointFailure::before_pause(
                "branch handoff cache differs from the source runtime; use the source's original backend cache configuration",
            ));
        }
        validate_checkpoint_id(id).map_err(CheckpointFailure::before_pause)?;
        microsandbox_types::validate_sandbox_name(child_name)
            .map_err(CheckpointFailure::before_pause)?;
        // The SDK reserves a fresh child directory under this same backend. Never accept
        // caller-selected host paths, symlinked children, or an existing handoff destination.
        let source = self.root.parent().and_then(Path::parent).ok_or_else(|| {
            CheckpointFailure::before_pause("source storage has no sandbox parent")
        })?;
        let parent = source
            .parent()
            .ok_or_else(|| CheckpointFailure::before_pause("missing sandbox storage root"))?;
        let child = parent.join(child_name);
        if child == source
            || !std::fs::symlink_metadata(&child).is_ok_and(|m| m.file_type().is_dir())
        {
            return Err(CheckpointFailure::before_pause(
                "branch requires a reserved child directory",
            ));
        }
        let reservation = child.join(".branch-reservation");
        if !std::fs::symlink_metadata(&reservation)
            .is_ok_and(|m| m.file_type().is_file() && m.len() <= 128)
            || std::fs::read_to_string(&reservation).map_err(CheckpointFailure::before_pause)? != id
        {
            return Err(CheckpointFailure::before_pause(
                "child reservation does not match branch attempt",
            ));
        }
        let destination = child.join(".branch-restore");
        if std::fs::symlink_metadata(&destination).is_ok() {
            return Err(CheckpointFailure::before_pause(
                "child already has a branch handoff",
            ));
        }
        self.capture_to(
            vm,
            id,
            CaptureIntent::FullSnapshot,
            user_pause,
            Some(&destination),
            memory_backing,
            record_integrity,
            guest_flush,
        )
    }

    // Durable and local capture share one executor-owned boundary and its borrowed inputs.
    #[allow(clippy::too_many_arguments)]
    fn capture_to(
        &mut self,
        vm: &msb_krun::VmControl,
        checkpoint_id: &str,
        intent: CaptureIntent,
        user_pause: Option<&UserPause>,
        local_destination: Option<&Path>,
        _memory_backing: Option<&std::fs::File>,
        record_integrity: bool,
        guest_flush: Option<microsandbox_types::GuestFlush>,
    ) -> Result<CheckpointResult, CheckpointFailure> {
        // All RAM captures pass through this executor-owned method. Consume the construction
        // handoff before either durable or local capture can publish a newer token. Dirty
        // tracking has run since the pristine mapping was installed, not since this adoption.
        // Topology or tracking invalidation leaves no VMM token and selects full capture.
        if let Some(mut inherited) = self.inherited_memory.take()
            && let Some(baseline) = vm.retained_memory_baseline()
        {
            inherited.memory.generation = baseline.generation().get();
            inherited.memory.topology = baseline.topology().get();
            self.local_baseline = Some(inherited);
            tracing::info!("adopted inherited local memory baseline");
        }
        if let Some(paused) = user_pause {
            paused
                .validate(vm)
                .map_err(CheckpointFailure::before_pause)?;
            if let Some(reason) = &paused.capture_unavailable {
                return Err(CheckpointFailure::before_pause(reason));
            }
        }
        if self
            .root_disk
            .as_ref()
            .is_some_and(|disk| disk.growth_pending())
        {
            return Err(CheckpointFailure::before_pause(
                "complete pending root-disk growth before checkpointing",
            ));
        }
        let total_started = Instant::now();
        validate_checkpoint_id(checkpoint_id).map_err(CheckpointFailure::before_pause)?;
        validate_vm_generation_state(vm.vm_generation_state())
            .map_err(CheckpointFailure::before_pause)?;
        let admission_started = Instant::now();
        let mut admitted = admit_resources(
            vm,
            &self.fs_resource_bindings,
            &self.additional_disks,
            &self.unsupported_additional_disks,
            self.network_resource_binding.as_ref(),
        )
        .map_err(CheckpointFailure::before_pause)?;
        let admission_us = admission_started.elapsed().as_micros();
        let staging_started = Instant::now();
        let final_path = local_destination
            .map(Path::to_path_buf)
            .unwrap_or_else(|| self.root.join(checkpoint_id));
        if final_path.exists() {
            return Err(CheckpointFailure::before_pause(
                "checkpoint identity is already published",
            ));
        }
        let staging = final_path
            .parent()
            .ok_or_else(|| CheckpointFailure::before_pause("capture destination has no parent"))?
            .join(format!(
                ".{checkpoint_id}.{}.staging",
                rand::random::<u64>()
            ));
        std::fs::create_dir(&staging).map_err(CheckpointFailure::before_pause)?;
        let staging_us = staging_started.elapsed().as_micros();

        // Preparing an immutable baseline does not read live guest RAM. Keep this potentially
        // RAM-sized copy outside the freeze/pause window; dirty tracking continues until the
        // authoritative paused plan below. The executor owns this coordinator exclusively.
        let memory_prepare_started = Instant::now();
        let prepared_local_memory = if local_destination.is_some() {
            let baseline = self.local_baseline.as_ref().filter(|previous| {
                vm.retained_memory_baseline().is_some_and(|baseline| {
                    previous.memory.generation == baseline.generation().get()
                        && previous.memory.topology == baseline.topology().get()
                })
            });
            // Configured MiB excludes architecture-specific mappings (for example the x86
            // kernel mapping). Only an observed immutable generation gives an exact bound.
            let prepared = baseline
                .map(|baseline| baseline.capacity())
                .transpose()
                .and_then(|capacity| {
                    #[cfg(target_os = "linux")]
                    return LocalMemoryCapture::prepare_with_backing(
                        self.local_cache_root
                            .as_ref()
                            .expect("validated local cache"),
                        checkpoint_id,
                        baseline,
                        capacity,
                        _memory_backing,
                    );
                    #[cfg(not(target_os = "linux"))]
                    LocalMemoryCapture::prepare(
                        self.local_cache_root
                            .as_ref()
                            .expect("validated local cache"),
                        checkpoint_id,
                        baseline,
                        capacity,
                    )
                });
            let sink = match prepared {
                Ok(sink) => sink,
                Err(error) => {
                    let _ = std::fs::remove_dir_all(&staging);
                    return Err(CheckpointFailure::before_pause(error));
                }
            };
            Some(sink)
        } else {
            None
        };
        let memory_prepare_us = memory_prepare_started.elapsed().as_micros();
        if let Some(prepared) = &prepared_local_memory {
            tracing::info!(target: "microsandbox_checkpoint_timing", operation = "local_memory_prepare", prepare_us = prepared.prepare_us, baseline_bytes = prepared.baseline_bytes, reflink = prepared.reflink, ram_backed = prepared.ram_backed, "prepared immutable RAM backing before workload freeze");
        }

        // The guest latch is acquired while vCPUs can still service agentd.
        // It remains held in captured guest memory so a restored child cannot
        // run application code before VM Generation ID activation completes.
        // An already-paused source borrows its original latch and token: even a brief resume
        // here would invalidate the user's paused boundary and require another guest handshake.
        let required = guest_flush.is_some_and(|policy| policy.requires_writeback(false));
        let required_mounts = self.flush_mounts(required, false);
        let workload_unavailable_started = Instant::now();
        let freeze_started = Instant::now();
        let acquired_workload;
        let workload = match user_pause {
            Some(paused) => paused.workload.as_ref().expect("validated workload latch"),
            None => {
                acquired_workload = match self.freeze_workload(vm, checkpoint_id, required, false) {
                    Ok(workload) => workload,
                    Err(error) => {
                        let _ = std::fs::remove_dir_all(&staging);
                        return Err(error);
                    }
                };
                &acquired_workload
            }
        };
        let freeze_us = freeze_started.elapsed().as_micros();
        if !workload.covers(&required_mounts) {
            let _ = std::fs::remove_dir_all(&staging);
            if user_pause.is_none() {
                self.thaw_workload(workload)
                    .map_err(CheckpointFailure::paused)?;
            }
            return Err(CheckpointFailure::before_pause(
                "capture requires a clean guest writeback boundary at this pause; finish active filesystem uploads, or resume and pause with --guest-flush required",
            ));
        }
        admitted.resources.push(workload.resource_descriptor());

        let vm_pause_window_started = Instant::now();
        let pause_started = Instant::now();
        let pause = match user_pause
            .map(|paused| Ok(paused.generation))
            .unwrap_or_else(|| vm.pause())
        {
            Ok(pause) => pause,
            Err(error) => {
                let _ = std::fs::remove_dir_all(&staging);
                return match self.thaw_workload(workload) {
                    Ok(()) => Err(CheckpointFailure::before_pause(error)),
                    Err(thaw_error) => Err(CheckpointFailure::paused(format!(
                        "VM pause failed: {error}; workload thaw failed: {thaw_error}"
                    ))),
                };
            }
        };
        let pause_barrier_us = pause_started.elapsed().as_micros();
        let paused_capture_started = Instant::now();
        let paused = self.capture_paused(
            vm,
            checkpoint_id,
            intent,
            &admitted.inventory,
            admitted.resources,
            pause.get(),
            &staging,
            &final_path,
            local_destination.is_some(),
            prepared_local_memory,
            record_integrity,
        );
        let paused_capture_us = paused_capture_started.elapsed().as_micros();
        for directory in self.owned_directories.values() {
            let _ = directory.cancel_capture();
        }
        let captured = match paused {
            Ok(captured) => captured,
            Err(mut failure) => {
                if user_pause.is_none()
                    && !failure.keep_paused
                    && let Err(error) = vm.resume(pause)
                {
                    failure.keep_paused = true;
                    failure.message = format!("{}; source resume failed: {error}", failure.message);
                } else if user_pause.is_none()
                    && !failure.keep_paused
                    && let Err(error) = self.thaw_workload(workload)
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

        let baseline_started = Instant::now();
        let baseline_published = match vm.publish_memory_capture(&captured.memory_plan) {
            Ok(_) => true,
            Err(error) => {
                tracing::warn!(%error, "checkpoint published without retaining memory baseline");
                let _ = vm.abandon_memory_capture(&captured.memory_plan);
                false
            }
        };
        let baseline_publish_us = baseline_started.elapsed().as_micros();
        let resume_started = Instant::now();
        if user_pause.is_none()
            && let Err(error) = vm.resume(pause)
        {
            return Err(CheckpointFailure {
                freezer_unavailable: false,
                message: format!("checkpoint published but source resume failed: {error}"),
                keep_paused: true,
                published: Some(Box::new(captured.result)),
            });
        }
        let resume_us = resume_started.elapsed().as_micros();
        let vm_pause_window_us = vm_pause_window_started.elapsed().as_micros();
        let thaw_started = Instant::now();
        if user_pause.is_none()
            && let Err(error) = self.thaw_workload(workload)
        {
            let repause = vm.pause().err();
            let message = match repause {
                Some(pause_error) => format!(
                    "checkpoint published but workload thaw failed: {error}; fail-closed VM re-pause failed: {pause_error}"
                ),
                None => format!("checkpoint published but workload thaw failed: {error}"),
            };
            return Err(CheckpointFailure {
                freezer_unavailable: false,
                message,
                keep_paused: true,
                published: Some(Box::new(captured.result)),
            });
        }
        let thaw_us = thaw_started.elapsed().as_micros();
        let workload_unavailable_us = workload_unavailable_started.elapsed().as_micros();
        if let (Some(cache), Some(memory_manifest)) =
            (&self.memory_cache, &captured.memory_manifest)
        {
            // Source execution has resumed (unless explicitly user-paused). Read only the
            // completed immutable capture, never live RAM, while preparing child acceleration.
            let prepared = (|| -> Result<super::CachedMemory, String> {
                let bytes = memory_manifest
                    .to_canonical_bytes()
                    .map_err(|e| e.to_string())?;
                let identity = ObjectId::from_bytes(&bytes).map_err(|e| e.to_string())?;
                cache
                    .materialize_with_baseline(
                        memory_manifest,
                        &identity,
                        self.cached_baseline
                            .as_ref()
                            .map(|(manifest, cached)| (manifest, cached)),
                        |id| {
                            let mut bytes = Vec::new();
                            std::fs::File::open(self.store.object_path(id))?
                                .take(MEMORY_OBJECT_PACK_SIZE as u64 + 1)
                                .read_to_end(&mut bytes)?;
                            if bytes.len() > MEMORY_OBJECT_PACK_SIZE
                                || ObjectId::from_bytes(&bytes).map_err(io::Error::other)? != *id
                            {
                                return Err(io::Error::other(
                                    "memory object failed size/identity validation",
                                ));
                            }
                            Ok(bytes)
                        },
                    )
                    .map_err(|e| e.to_string())
            })();
            match prepared {
                Ok(cached) => {
                    tracing::info!(target: "microsandbox_checkpoint_timing", operation = "memory_cache", prepare_us = cached.prepare_us, cache_hit = cached.cache_hit, reflink = cached.reflink, "prepared immutable capture cache");
                    self.cached_baseline = Some((memory_manifest.clone(), cached));
                }
                Err(error) => {
                    // Publication already succeeded. Losing optional acceleration does not
                    // erase the artifact or turn its successful capture into a false failure.
                    tracing::warn!(%error, "checkpoint published without memory cache acceleration");
                }
            }
        }
        if baseline_published {
            self.previous_memory = captured.memory_manifest;
            self.previous_memory_objects = captured.memory_objects;
            self.local_baseline = captured.local_memory;
        } else {
            self.previous_memory = None;
            self.previous_memory_objects.clear();
            self.local_baseline = None;
        }
        tracing::info!(
            target: "microsandbox_checkpoint_timing",
            operation = "capture",
            source_already_paused = user_pause.is_some(),
            checkpoint_id,
            memory_prepare_us,
            memory_paused_prepare_us = captured.timings.memory_paused_prepare_us,
            memory_finish_us = captured.timings.memory_finish_us,
            memory_mode = ?captured.result.memory_mode,
            memory_logical_bytes = captured.result.memory_logical_bytes,
            memory_emitted_bytes = captured.result.memory_emitted_bytes,
            guest_bytes_read = captured.timings.guest_bytes_read,
            unplugged_bytes_skipped = captured.timings.unplugged_bytes_skipped,
            total_us = total_started.elapsed().as_micros(),
            admission_us,
            staging_us,
            freeze_us,
            pause_barrier_us,
            paused_capture_us,
            execution_us = captured.timings.execution_us,
            devices_us = captured.timings.devices_us,
            managed_disk_us = captured.timings.managed_disk_us,
            memory_plan_us = captured.timings.memory_plan_us,
            memory_capture_us = captured.timings.memory_capture_us,
            extent_overlay_us = captured.timings.extent_overlay_us,
            memory_manifest_us = captured.timings.memory_manifest_us,
            checkpoint_publish_us = captured.timings.checkpoint_publish_us,
            pipeline_wait_us = captured.timings.pipeline_wait_us,
            object_persist_worker_us = captured.timings.object_persist_worker_us,
            object_packs = captured.timings.object_packs,
            peak_in_flight_bytes = captured.timings.peak_in_flight_bytes,
            object_hashed_bytes = captured.timings.object_hashed_bytes,
            object_linked_bytes = captured.timings.object_linked_bytes,
            object_copied_bytes = captured.timings.object_copied_bytes,
            object_directory_syncs = captured.timings.object_directory_syncs,
            baseline_publish_us,
            resume_us,
            thaw_us,
            vm_pause_window_us,
            workload_unavailable_us,
            "checkpoint capture timing"
        );
        Ok(captured.result)
    }

    /// Build the exact filesystem coverage needed at this boundary. Host-backed directory
    /// synchronization remains mandatory; block-filesystem writeback follows the policy.
    fn flush_mounts(&self, required: bool, disk_only: bool) -> BTreeSet<String> {
        let mut mounts = self
            .fs_resource_bindings
            .values()
            .filter(|binding| {
                binding
                    .get("role")
                    .is_some_and(|role| role == "external_bind" || role == "owned_directory")
            })
            .filter_map(|binding| binding.get("guest_tag").cloned())
            .collect::<BTreeSet<_>>();
        let owned_disks = self
            .owned_mounts
            .values()
            .filter(|mount| {
                matches!(
                    mount.storage,
                    microsandbox_types::OwnedVolumeStorage::Disk { .. }
                )
            })
            .map(|mount| mount.guest.as_str());
        // Disk-only capture does not include independent named disks. Full Required
        // capture must flush them too, but merely owning a disk must not force a flush.
        let additional_disks = self
            .additional_disks
            .values()
            .filter(|_| !disk_only)
            .filter_map(|disk| disk.binding().get("guest_path"))
            .map(String::as_str);
        extend_block_flush_mounts(&mut mounts, required, owned_disks.chain(additional_disks));
        mounts
    }

    pub(crate) fn validate_paused_flush(
        &self,
        vm: &msb_krun::VmControl,
        pause: &UserPause,
        policy: microsandbox_types::GuestFlush,
    ) -> Result<(), String> {
        pause.validate(vm)?;
        if policy.requires_writeback(false)
            && !pause
                .workload
                .as_ref()
                .is_some_and(|workload| workload.covers(&self.flush_mounts(true, false)))
        {
            return Err("existing pause has no required guest-flush boundary; explicitly resume before pausing with --guest-flush required".into());
        }
        Ok(())
    }

    fn freeze_workload(
        &self,
        vm: &msb_krun::VmControl,
        attempt_id: &str,
        required: bool,
        disk_only: bool,
    ) -> Result<FrozenWorkload, CheckpointFailure> {
        // These are the bundled guest's capabilities, not a newly connected SDK client's
        // generation. Internal lifecycle work must not join the FIFO it is about to gate.
        let (protocol_generation, ready) = self
            .workload_control
            .ready()
            .map_err(CheckpointFailure::before_pause)?;
        if !MessageType::WorkloadFreeze.is_available_at(protocol_generation) {
            return Err(CheckpointFailure::before_pause(
                "guest protocol does not support workload freeze",
            ));
        }
        let gate_deadline = Instant::now() + WORKLOAD_CONTROL_TIMEOUT;
        let (gate, host_input) = self.gate_input(gate_deadline)?;
        let requested_mounts = self.flush_mounts(required, disk_only);
        let external_mount_tags = requested_mounts.iter().cloned().collect::<Vec<_>>();
        // Gating keeps its original deadline. The external-only request budget begins
        // after gating and includes freezer work, the guest's 20s flush, and output cut.
        let deadline = freeze_request_deadline(
            gate_deadline,
            Instant::now(),
            !external_mount_tags.is_empty(),
        );
        let mut workload = FrozenWorkload {
            external_mounts_synced: false,
            synced_mounts: BTreeSet::new(),
            gate,
            attempt_id: attempt_id.to_string(),
            protocol_generation,
            ready,
            host_input,
            input_credit: WorkloadTransportCredit::default(),
            guest_bulk_bytes: 0,
        };
        let request = WorkloadFreeze {
            external_mount_tags,
            attempt_id: attempt_id.to_string(),
            host_input,
        };
        let message = match Message::with_payload(MessageType::WorkloadFreeze, 0, &request) {
            Ok(message) => message,
            Err(error) => {
                // No lifecycle request has been admitted, so ordinary input can safely resume.
                workload.gate.release();
                return Err(CheckpointFailure::before_pause(error));
            }
        };
        let reply = self
            .runtime
            .block_on(async {
                tokio::time::timeout_at(
                    deadline.into(),
                    self.workload_control.request(message, attempt_id),
                )
                .await
            })
            .map_err(|_| "workload freeze timed out".to_string())
            .and_then(|reply| reply.map_err(|error| format!("request workload freeze: {error}")));
        if let Ok(reply) = &reply
            && let Some(reason) = unavailable_freezer_reason(reply, attempt_id)
        {
            // Explicit guest evidence says the freezer was never attempted.
            workload.gate.release();
            let mut error = CheckpointFailure::before_pause(reason);
            error.freezer_unavailable = true;
            return Err(error);
        }
        let result = reply.and_then(|reply| {
            let frozen = validate_workload_reply::<WorkloadFrozen>(
                reply,
                MessageType::WorkloadFrozen,
                attempt_id,
                |payload| &payload.attempt_id,
            )?;
            self.workload_control.update_credit(frozen.input_credit)?;
            self.runtime
                .block_on(async {
                    tokio::time::timeout_at(
                        deadline.into(),
                        self.workload_control
                            .wait_bulk_cut(frozen.guest_bulk_bytes_target),
                    )
                    .await
                })
                .map_err(|_| {
                    "guest output did not reach the frozen transport boundary".to_string()
                })??;
            Ok(frozen)
        });
        let frozen = result.map_err(|error| {
            recover_failed_freeze(
                attempt_id,
                error,
                || self.thaw_workload(&workload),
                || vm.pause().map(|_| ()).map_err(|error| error.to_string()),
            )
        })?;
        workload.input_credit = frozen.input_credit;
        workload.external_mounts_synced = frozen.external_mounts_synced;
        if frozen.external_mounts_synced {
            workload.synced_mounts = requested_mounts;
        }
        workload.guest_bulk_bytes = frozen.guest_bulk_bytes_target;
        Ok(workload)
    }

    /// Park both ordinary writers at complete records before taking their cumulative cut.
    fn gate_input(
        &self,
        deadline: Instant,
    ) -> Result<(InputGate, WorkloadTransportPosition), CheckpointFailure> {
        let gate = self.workload_control.gate();
        let result = self
            .runtime
            .block_on(async {
                tokio::time::timeout_at(deadline.into(), self.workload_control.parked_position())
                    .await
            })
            .map_err(|_| "host input did not reach a complete transport boundary".to_string())
            .and_then(|result| result);
        match result {
            Ok(position) => Ok((gate, position)),
            Err(error) => {
                gate.release();
                Err(CheckpointFailure::before_pause(error))
            }
        }
    }

    fn thaw_workload(&self, workload: &FrozenWorkload) -> Result<(), String> {
        let request = WorkloadThaw {
            attempt_id: workload.attempt_id.clone(),
            mode: microsandbox_protocol::core::WorkloadThawMode::Continue,
        };
        let message = Message::with_payload(MessageType::WorkloadThaw, 0, &request)
            .map_err(|error| error.to_string())?;
        let reply = self
            .runtime
            .block_on(async {
                tokio::time::timeout(
                    WORKLOAD_CONTROL_TIMEOUT,
                    self.workload_control.request(message, &workload.attempt_id),
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
        )?;
        // Only acknowledged thaw releases the source-owned FIFO. Dropping a failed capture
        // without reaching here leaves the helper fenced instead of implicitly flushing input.
        workload.gate.release();
        Ok(())
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
        local: bool,
        prepared_local_memory: Option<LocalMemoryCapture>,
        record_integrity: bool,
    ) -> Result<PausedCapture, CheckpointFailure> {
        let mut timings = PausedCaptureTimings::default();
        let batch = Arc::new(CaptureObjectBatch::new(
            self.store.clone(),
            if local {
                &[]
            } else {
                &self.previous_memory_objects
            },
        ));
        let devices_started = Instant::now();
        let mut pending_devices = Vec::with_capacity(inventory.len());
        let mut disk_roots = Vec::new();
        let mut local_disks = Vec::new();
        let mut owned_volumes = Vec::new();
        if !self.owned_directories.is_empty() {
            std::fs::create_dir_all(staging.join("owned")).map_err(CheckpointFailure::resumable)?;
        }
        for (tag, directory) in &self.owned_directories {
            directory
                .prepare_capture(&staging.join("owned").join(tag))
                .map_err(CheckpointFailure::resumable)?;
        }
        for (device_type, device_id) in inventory {
            let runtime_owned_root = self
                .root_disk
                .as_ref()
                .is_some_and(|disk| disk.device_id() == device_id);
            let bytes = if *device_type == TYPE_BLOCK && runtime_owned_root {
                let disk = self.root_disk.as_mut().ok_or_else(|| {
                    CheckpointFailure::resumable(
                        "managed root block device has no rollover provider",
                    )
                })?;
                let disk_started = Instant::now();
                let rollover = disk
                    .rollover(
                        vm,
                        &self.runtime,
                        staging,
                        pause_generation,
                        local,
                        record_integrity,
                    )
                    .map_err(|error| CheckpointFailure {
                        freezer_unavailable: false,
                        message: error.to_string(),
                        keep_paused: error.keep_paused,
                        published: None,
                    })?;
                timings.managed_disk_us += disk_started.elapsed().as_micros();
                if !local {
                    let manifest_bytes = rollover
                        .manifest
                        .to_canonical_bytes()
                        .map_err(CheckpointFailure::resumable)?;
                    let manifest_id = batch
                        .put_bytes(&manifest_bytes)
                        .map_err(CheckpointFailure::resumable)?;
                    batch
                        .link_into(&manifest_id, staging)
                        .map_err(CheckpointFailure::resumable)?;
                    disk_roots.push(manifest_id);
                }
                local_disks.push(rollover.manifest);
                rollover.device_state
            } else if *device_type == TYPE_BLOCK && self.additional_disks.contains_key(device_id) {
                let disk_started = Instant::now();
                let captured = self
                    .additional_disks
                    .get_mut(device_id)
                    .expect("registered additional disk was checked above")
                    .capture(
                        vm,
                        &self.runtime,
                        staging,
                        pause_generation,
                        record_integrity,
                    )
                    .map_err(|error| CheckpointFailure {
                        message: error.to_string(),
                        keep_paused: error.keep_paused,
                        published: None,
                        freezer_unavailable: false,
                    })?;
                timings.managed_disk_us += disk_started.elapsed().as_micros();
                if !local {
                    let bytes = captured
                        .manifest
                        .to_canonical_bytes()
                        .map_err(CheckpointFailure::resumable)?;
                    let id = batch
                        .put_bytes(&bytes)
                        .map_err(CheckpointFailure::resumable)?;
                    batch
                        .link_into(&id, staging)
                        .map_err(CheckpointFailure::resumable)?;
                    disk_roots.push(id);
                }
                local_disks.push(captured.manifest);
                captured.device_state
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
            pending_devices.push(PendingDeviceState {
                device_type: *device_type,
                device_id: device_id.clone(),
                bytes,
            });
        }
        for (tag, mount) in &self.owned_mounts {
            let data = if let Some(directory) = self.owned_directories.get(tag) {
                owned_directory_data(
                    directory
                        .finish_capture()
                        .map_err(CheckpointFailure::resumable)?,
                )
                .map_err(CheckpointFailure::resumable)?
            } else {
                let generation = local_disks
                    .iter()
                    .find(|disk| disk.device_id == *tag)
                    .ok_or_else(|| {
                        CheckpointFailure::resumable(format!("owned disk {tag} was not captured"))
                    })?
                    .clone();
                OwnedVolumeData::Disk { generation }
            };
            owned_volumes.push(OwnedVolumeCapture {
                mount_id: tag.clone(),
                mount: mount.clone(),
                data,
            });
        }
        let device_refs = if local {
            pending_devices
                .iter()
                .map(|device| {
                    Ok(DeviceStateRef {
                        device_type: device.device_type,
                        device_id: device.device_id.clone(),
                        state: put_local_object(staging, &device.bytes)?,
                    })
                })
                .collect::<Result<Vec<_>, String>>()
        } else {
            persist_device_states(&batch, staging, &pending_devices)
        }
        .map_err(CheckpointFailure::resumable)?;
        timings.devices_us = devices_started.elapsed().as_micros();

        // Device capture parks each worker. Capture interrupt-controller state
        // only after their final completions have been published; otherwise a
        // used queue could survive in RAM without its corresponding interrupt.
        // Execution capture must also precede RAM capture: KVM flushes its LPI
        // pending tables into guest RAM as part of this operation.
        let execution_started = Instant::now();
        let execution = vm
            .capture_execution_state()
            .map_err(CheckpointFailure::resumable)?;
        if execution.pause_generation() != pause_generation {
            return Err(CheckpointFailure::resumable(
                "execution state belongs to another pause generation",
            ));
        }
        let execution_bytes = execution.encode().map_err(CheckpointFailure::resumable)?;
        let execution_id = if local {
            put_local_object(staging, &execution_bytes).map_err(CheckpointFailure::resumable)?
        } else {
            let id = batch
                .put_bytes(&execution_bytes)
                .map_err(CheckpointFailure::resumable)?;
            batch
                .link_into(&id, staging)
                .map_err(CheckpointFailure::resumable)?;
            id
        };
        timings.execution_us = execution_started.elapsed().as_micros();

        if local {
            let memory_plan_started = Instant::now();
            let (memory_plan, incremental) = self
                .plan_local_memory(vm)
                .map_err(CheckpointFailure::resumable)?;
            timings.memory_plan_us = memory_plan_started.elapsed().as_micros();
            let captured = (|| {
                let prepare_started = Instant::now();
                let baseline = if incremental {
                    self.local_baseline.as_ref()
                } else {
                    None
                };
                let expected = baseline.map(|base| (base.memory.generation, base.memory.topology));
                // A topology change or a Complete/FullRequired plan invalidates the prepared
                // delta. Never apply a full capture to a copied baseline with stale geometry.
                let mut sink = match prepared_local_memory {
                    Some(prepared) if prepared.baseline() == expected => prepared,
                    Some(mut prepared)
                        if expected.is_none()
                            && prepared.baseline().is_some_and(|(_, topology)| {
                                topology == memory_plan.topology().get()
                            }) =>
                    {
                        prepared
                            .reset_to_full()
                            .map_err(CheckpointFailure::resumable)?;
                        prepared
                    }
                    previous => {
                        // A different topology invalidates both bytes and the RAM reservation.
                        // Release it before preparing an unbounded, disk-backed complete cut.
                        drop(previous);
                        let capacity = baseline
                            .map(|baseline| baseline.capacity())
                            .transpose()
                            .map_err(CheckpointFailure::resumable)?;
                        LocalMemoryCapture::prepare(
                            self.local_cache_root
                                .as_ref()
                                .expect("validated local cache"),
                            checkpoint_id,
                            baseline,
                            capacity,
                        )
                        .map_err(CheckpointFailure::resumable)?
                    }
                };
                timings.memory_paused_prepare_us = prepare_started.elapsed().as_micros();
                let reflink = sink.reflink;
                let started = Instant::now();
                let stats = vm
                    .capture_memory(
                        &memory_plan,
                        MemoryCaptureOptions::new(MEMORY_SCAN_CHUNK_SIZE, true)
                            .map_err(CheckpointFailure::resumable)?,
                        &mut sink,
                    )
                    .map_err(CheckpointFailure::resumable)?;
                timings.memory_capture_us = started.elapsed().as_micros();
                let finish_started = Instant::now();
                let memory = sink
                    .finish(memory_plan.generation().get(), memory_plan.topology().get())
                    .map_err(CheckpointFailure::resumable)?;
                timings.memory_finish_us = finish_started.elapsed().as_micros();
                timings.guest_bytes_read = stats.guest_bytes_read;
                timings.unplugged_bytes_skipped = stats.unplugged_bytes_skipped;
                let state = super::LocalBranchState {
                    id: checkpoint_id.into(),
                    architecture: std::env::consts::ARCH.into(),
                    pause_generation,
                    execution_state: execution_id,
                    devices: device_refs,
                    resources,
                    disks: local_disks,
                    owned_volumes,
                    memory: memory.memory.clone(),
                    vcpus: self.boot_geometry.0,
                    max_cpus: self.boot_geometry.1,
                    memory_mib: self.boot_geometry.2,
                    max_memory_mib: self.boot_geometry.3,
                };
                let bytes = serde_json::to_vec(&state).map_err(CheckpointFailure::resumable)?;
                // This handoff has no snapshot root or RAM object manifest. Child-owned disk
                // links and bounded metadata are installed before acknowledging the capture.
                std::fs::write(staging.join("branch.json"), bytes)
                    .map_err(CheckpointFailure::resumable)?;
                std::fs::rename(staging, final_path).map_err(CheckpointFailure::resumable)?;
                tracing::info!(target: "microsandbox_checkpoint_timing", operation = "local_memory_capture", incremental, reflink, capture_us = timings.memory_capture_us, paused_prepare_us = timings.memory_paused_prepare_us, finish_us = timings.memory_finish_us, guest_bytes_read = stats.guest_bytes_read, unplugged_bytes_skipped = stats.unplugged_bytes_skipped);
                Ok((memory, stats))
            })();
            let (memory, stats) = match captured {
                Ok(captured) => captured,
                Err(error) => {
                    let _ = vm.abandon_memory_capture(&memory_plan);
                    return Err(error);
                }
            };
            return Ok(PausedCapture {
                result: CheckpointResult {
                    checkpoint_id: checkpoint_id.into(),
                    checkpoint_root: String::new(),
                    path: final_path.into(),
                    memory_mode: if incremental {
                        MemoryCaptureMode::Incremental
                    } else {
                        MemoryCaptureMode::Full
                    },
                    memory_logical_bytes: stats.logical_bytes,
                    memory_emitted_bytes: stats.emitted_bytes,
                },
                memory_plan,
                memory_manifest: None,
                memory_objects: Vec::new(),
                local_memory: Some(memory),
                timings,
            });
        }

        let memory_plan_started = Instant::now();
        let (memory_plan, memory_mode, base_extents) =
            self.plan_memory(vm).map_err(CheckpointFailure::resumable)?;
        timings.memory_plan_us = memory_plan_started.elapsed().as_micros();
        let mut sink = match MemoryObjectSink::new(Arc::clone(&batch)) {
            Ok(sink) => sink,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        let memory_capture_started = Instant::now();
        let stats = match vm.capture_memory(
            &memory_plan,
            MemoryCaptureOptions::new(MEMORY_SCAN_CHUNK_SIZE, true)
                .map_err(CheckpointFailure::resumable)?,
            &mut sink,
        ) {
            Ok(stats) => stats,
            Err(error) => {
                // Stop/join queued writers before the caller can remove this capture's staging.
                drop(sink);
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        let (updates, pipeline_stats) = match sink.finish() {
            Ok(result) => result,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        timings.memory_capture_us = memory_capture_started.elapsed().as_micros();
        timings.guest_bytes_read = stats.guest_bytes_read;
        timings.unplugged_bytes_skipped = stats.unplugged_bytes_skipped;
        timings.pipeline_wait_us = pipeline_stats.wait_us;
        timings.object_persist_worker_us = pipeline_stats.persist_us;
        timings.object_packs = pipeline_stats.packs;
        timings.peak_in_flight_bytes = pipeline_stats.peak_in_flight_bytes;
        let extent_overlay_started = Instant::now();
        let extents = match overlay_extents(base_extents, updates) {
            Ok(extents) => extents,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        timings.extent_overlay_us = extent_overlay_started.elapsed().as_micros();
        let memory_manifest_started = Instant::now();
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
            if let MemoryExtentContent::Object(content) = &extent.content {
                linked_memory_objects.insert(content.object.clone());
            }
        }
        let linked_memory_objects = linked_memory_objects.into_iter().collect::<Vec<_>>();
        if let Err(error) = parallel_link_objects(&batch, staging, &linked_memory_objects) {
            let _ = vm.abandon_memory_capture(&memory_plan);
            return Err(CheckpointFailure::resumable(error));
        }
        let memory_id = match batch.put_bytes(&memory_bytes) {
            Ok(id) => id,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        if let Err(error) = batch.link_into(&memory_id, staging) {
            let _ = vm.abandon_memory_capture(&memory_plan);
            return Err(CheckpointFailure::resumable(error));
        }
        timings.memory_manifest_us = memory_manifest_started.elapsed().as_micros();

        let checkpoint_publish_started = Instant::now();
        let checkpoint = CheckpointManifest {
            schema: "microsandbox.checkpoint/1".into(),
            checkpoint_id: checkpoint_id.into(),
            capture_intent: intent,
            architecture: std::env::consts::ARCH.into(),
            geometry: CheckpointGeometry {
                vcpus: self.boot_geometry.0,
                max_vcpus: self.boot_geometry.1.max(self.boot_geometry.0),
                memory_mib: self.boot_geometry.2,
                max_memory_mib: self.boot_geometry.3.max(self.boot_geometry.2),
            },
            pause_generation,
            execution_state: execution_id,
            memory: memory_id,
            disks: disk_roots,
            owned_volumes,
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
        let checkpoint_root = match batch.put_bytes(&checkpoint_bytes) {
            Ok(id) => id,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        if let Err(error) = batch.link_into(&checkpoint_root, staging) {
            let _ = vm.abandon_memory_capture(&memory_plan);
            return Err(CheckpointFailure::resumable(error));
        }
        let memory_objects = match batch
            .retained_objects(&linked_memory_objects)
            .and_then(|objects| batch.finish().map(|_| objects))
        {
            Ok(objects) => objects,
            Err(error) => {
                let _ = vm.abandon_memory_capture(&memory_plan);
                return Err(CheckpointFailure::resumable(error));
            }
        };
        let object_stats = batch.stats();
        timings.object_hashed_bytes = object_stats.hashed_bytes;
        timings.object_linked_bytes = object_stats.linked_bytes;
        timings.object_copied_bytes = object_stats.copied_bytes;
        timings.object_directory_syncs = object_stats.directory_syncs;
        if let Err(error) = publish_root_last(staging, final_path, &checkpoint_bytes) {
            let _ = vm.abandon_memory_capture(&memory_plan);
            return Err(CheckpointFailure::resumable(error));
        }
        timings.checkpoint_publish_us = checkpoint_publish_started.elapsed().as_micros();

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
            memory_manifest: Some(memory_manifest),
            memory_objects,
            local_memory: None,
            timings,
        })
    }

    fn plan_local_memory(
        &self,
        vm: &msb_krun::VmControl,
    ) -> Result<(MemoryCapturePlan, bool), String> {
        if let (Some(baseline), Some(previous)) =
            (vm.retained_memory_baseline(), self.local_baseline.as_ref())
            && previous.memory.generation == baseline.generation().get()
            && previous.memory.topology == baseline.topology().get()
        {
            match vm
                .plan_incremental_memory_capture(baseline)
                .map_err(|e| e.to_string())?
            {
                IncrementalCaptureDecision::Incremental(plan) => return Ok((plan, true)),
                IncrementalCaptureDecision::Complete { capture, .. } => {
                    return Ok((capture, false));
                }
                IncrementalCaptureDecision::FullRequired(_) => {}
            }
        }
        vm.plan_full_memory_capture()
            .map(|plan| (plan, false))
            .map_err(|e| e.to_string())
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

impl FrozenWorkload {
    fn covers(&self, required: &BTreeSet<String>) -> bool {
        required.is_empty()
            || (self.external_mounts_synced && required.is_subset(&self.synced_mounts))
    }
}

impl UserPause {
    fn validate(&self, vm: &msb_krun::VmControl) -> Result<(), String> {
        if vm.execution_state() != Some(msb_krun::VmExecutionState::Paused(self.generation)) {
            return Err("user pause no longer owns the current VM execution boundary".into());
        }
        if self.workload.is_none() && self.capture_unavailable.is_none() {
            return Err("user pause has no prepared workload latch for full capture".into());
        }
        Ok(())
    }
}

impl CheckpointFailure {
    fn before_pause(error: impl fmt::Display) -> Self {
        Self {
            message: error.to_string(),
            freezer_unavailable: false,
            keep_paused: false,
            published: None,
        }
    }

    fn paused(error: impl fmt::Display) -> Self {
        Self {
            message: error.to_string(),
            freezer_unavailable: false,
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
                    "external_mounts_synced".into(),
                    self.external_mounts_synced.to_string(),
                ),
                ("attempt_id".into(), self.attempt_id.clone()),
                (
                    "protocol_generation".into(),
                    self.protocol_generation.to_string(),
                ),
                ("agent_version".into(), self.ready.agent_version.clone()),
                ("boot_time_ns".into(), self.ready.boot_time_ns.to_string()),
                ("init_time_ns".into(), self.ready.init_time_ns.to_string()),
                ("ready_time_ns".into(), self.ready.ready_time_ns.to_string()),
                // Restore the negotiated physical transport as well as the agent identity.
                (
                    "ready".into(),
                    serde_json::to_string(&self.ready).expect("Ready is serializable"),
                ),
                (
                    "transport_host_input".into(),
                    serde_json::to_string(&self.host_input)
                        .expect("input position is serializable"),
                ),
                (
                    "transport_input_credit".into(),
                    serde_json::to_string(&self.input_credit)
                        .expect("input credit is serializable"),
                ),
                (
                    "transport_guest_bulk_bytes".into(),
                    self.guest_bulk_bytes.to_string(),
                ),
            ]),
        }
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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn freeze_request_deadline(
    gate_deadline: Instant,
    gate_completed: Instant,
    external_mounts: bool,
) -> Instant {
    if external_mounts {
        gate_completed + EXTERNAL_WORKLOAD_FREEZE_TIMEOUT
    } else {
        gate_deadline
    }
}

async fn root_growth_request(
    client: &AgentClient,
    message_type: MessageType,
    request: &microsandbox_protocol::core::RootDiskGrow,
) -> Result<microsandbox_protocol::core::RootDiskState, String> {
    let reply = tokio::time::timeout(
        Duration::from_secs(120),
        client.request(message_type, request),
    )
    .await
    .map_err(|_| "guest root growth timed out".to_string())?
    .map_err(|e| e.to_string())?;
    if reply.t == MessageType::CoreError {
        return Err(reply
            .payload::<CoreError>()
            .map_err(|e| e.to_string())?
            .message);
    }
    if reply.t != MessageType::RootDiskState {
        return Err("unexpected root growth response".into());
    }
    reply.payload().map_err(|e| e.to_string())
}

/// Only new, scoped evidence of no attempted freeze permits a capability fallback.
fn unavailable_freezer_reason(reply: &Message, attempt_id: &str) -> Option<String> {
    if reply.t != MessageType::CoreError {
        return None;
    }
    let error = reply.payload::<CoreError>().ok()?;
    let detail = error.workload_failure?;
    (error.kind == CoreErrorKind::CapabilityUnavailable
        && error.offending_type.as_deref() == Some(MessageType::WorkloadFreeze.as_str())
        && detail.attempt_id == attempt_id
        && detail.disposition == WorkloadFailureDisposition::Unavailable)
        .then_some(error.message)
}

fn recover_failed_freeze(
    attempt_id: &str,
    error: String,
    thaw: impl FnOnce() -> Result<(), String>,
    pause: impl FnOnce() -> Result<(), String>,
) -> CheckpointFailure {
    match thaw() {
        Ok(()) => CheckpointFailure::before_pause(error),
        Err(thaw_error) => {
            // Stop further guest progress if possible, and fence host mutations even if the
            // hypervisor pause itself fails. Never turn uncertainty into a running disposition.
            let pause_status = match pause() {
                Ok(()) => "VM paused".to_string(),
                Err(error) => format!("VM pause also failed: {error}"),
            };
            CheckpointFailure::paused(format!(
                "attempt {attempt_id}: {error}; workload recovery required: {thaw_error}; {pause_status}"
            ))
        }
    }
}

fn validate_workload_reply<T>(
    reply: Message,
    expected_type: MessageType,
    expected_attempt: &str,
    attempt_id: impl for<'a> Fn(&'a T) -> &'a str,
) -> Result<T, String>
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
    Ok(payload)
}

fn owned_directory_data(
    snapshot: microsandbox_filesystem::OwnedDirectorySnapshot,
) -> Result<OwnedVolumeData, String> {
    let descriptor = snapshot
        .descriptor_bytes()
        .map_err(|error| error.to_string())?;
    Ok(OwnedVolumeData::Directory {
        descriptor: OwnedDirectoryPayload {
            digest: snapshot.digest().map_err(|error| error.to_string())?,
            bytes: descriptor.len() as u64,
        },
        files: snapshot
            .payloads()
            .into_iter()
            .map(|payload| OwnedDirectoryPayload {
                digest: payload.digest,
                bytes: payload.bytes,
            })
            .collect(),
    })
}

fn admit_resources(
    vm: &msb_krun::VmControl,
    fs_resource_bindings: &BTreeMap<String, BTreeMap<String, String>>,
    additional_disks: &BTreeMap<String, RuntimeOwnedAdditionalDisk>,
    unsupported_additional_disks: &BTreeMap<String, String>,
    network_resource_binding: Option<&BTreeMap<String, String>>,
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
        if *device_type == TYPE_BLOCK
            && !matches!(device_id.as_str(), "vda" | "vdb")
            && !additional_disks.contains_key(device_id)
        {
            if let Some(format) = unsupported_additional_disks.get(device_id) {
                return Err(format!(
                    "managed block resource {device_id} uses unsupported checkpoint format {format}; additional disk capture supports standalone raw and qcow2"
                ));
            }
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
        if *device_type == TYPE_BLOCK
            && let Some(disk) = additional_disks.get(device_id)
        {
            binding.extend(disk.binding().clone());
        }
        if *device_type == TYPE_NET {
            let network = network_resource_binding.ok_or_else(|| {
                format!("active network resource {device_id} has no effective guest binding")
            })?;
            binding.extend(network.clone());
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
    if !state.clock_sync_supported {
        return Err("guest kernel lacks clock-aware activation required for full checkpoints; restart with the updated kernel".to_string());
    }
    Ok(())
}

/// Describe the two filesystem transports owned by the runtime itself.
///
/// libkrun exposes transport identifiers rather than FUSE mount tags in its
/// device inventory. Microsandbox constructs filesystems in a fixed order:
/// the root/bootstrap transport first and `msb_runtime` second. A block
/// root may reconnect the first transport because it is only the
/// discarded init trampoline. The runtime share is likewise an explicitly
/// reconnectable host-control binding. Every later filesystem belongs to a
/// user mount and remains ineligible until its provider can preserve live
/// handles and object identity.
fn runtime_owned_fs_bindings(block_root: bool) -> BTreeMap<String, BTreeMap<String, String>> {
    let mut bindings = BTreeMap::new();
    if block_root {
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
    base.sort_by_key(|extent| extent.start);
    updates.sort_by_key(|extent| extent.start);
    validate_non_overlapping(&base)?;
    validate_non_overlapping(&updates)?;
    // Consume each old range once. A suffix split by an update remains at the
    // front for the next update; object offsets are retained by slice_extent.
    let mut pending = std::collections::VecDeque::from(base);
    let mut output = Vec::with_capacity(pending.len() + updates.len());
    for update in updates {
        let update_end = update.start + update.length;
        while let Some(extent) = pending.front() {
            if extent.start >= update_end {
                break;
            }
            let extent = pending.pop_front().expect("front was present");
            let extent_end = extent.start + extent.length;
            if extent_end <= update.start {
                output.push(extent);
                continue;
            }
            if extent.start < update.start {
                output.push(slice_extent(
                    &extent,
                    extent.start,
                    update.start - extent.start,
                ));
            }
            if extent_end > update_end {
                pending.push_front(slice_extent(&extent, update_end, extent_end - update_end));
                break;
            }
        }
        output.push(update);
    }
    output.extend(pending);
    validate_non_overlapping(&output)?;
    Ok(coalesce_extents(output))
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Guest writeback is separate from draining/sealing the host block backends. A full
/// capture retains dirty pages in RAM; a disk-only Skip accepts a crash-consistent cut.
/// Neither an owned disk nor a virtiofs mount should implicitly add a root flush.
fn extend_block_flush_mounts<'a>(
    mounts: &mut BTreeSet<String>,
    required: bool,
    disks: impl Iterator<Item = &'a str>,
) {
    if required {
        mounts.insert("path:/".into());
        mounts.extend(disks.map(|guest| format!("path:{guest}")));
    }
}

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

/// Persist independent device envelopes concurrently after every device has reached the same
/// paused epoch. Immutable-object publication is thread-safe, and the returned vector retains the
/// inventory order required by the checkpoint manifest.
/// Local handoffs reuse the state codecs and object paths, but make no crash-recovery promise.
/// Only bounded CPU/device state reaches this helper; RAM goes straight to its mmap backing.
fn put_local_object(staging: &Path, bytes: &[u8]) -> Result<ObjectId, String> {
    let id = ObjectId::from_bytes(bytes).map_err(|e| e.to_string())?;
    let store = LocalObjectStore::open(staging).map_err(|e| e.to_string())?;
    let path = store.object_path(&id);
    std::fs::create_dir_all(path.parent().expect("confined object parent"))
        .map_err(|e| e.to_string())?;
    std::fs::write(path, bytes).map_err(|e| e.to_string())?;
    Ok(id)
}

fn persist_device_states(
    store: &CaptureObjectBatch,
    staging: &Path,
    pending: &[PendingDeviceState],
) -> Result<Vec<DeviceStateRef>, String> {
    if pending.is_empty() {
        return Ok(Vec::new());
    }
    let workers = parallel_worker_count(pending.len());
    let chunk_size = pending.len().div_ceil(workers);
    std::thread::scope(|scope| {
        let handles = pending
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    chunk
                        .iter()
                        .map(|state| {
                            let id = store.put_bytes(&state.bytes).map_err(|error| {
                                format!("store device state {}: {error}", state.device_id)
                            })?;
                            store.link_into(&id, staging).map_err(|error| {
                                format!("link device state {}: {error}", state.device_id)
                            })?;
                            Ok(DeviceStateRef {
                                device_type: state.device_type,
                                device_id: state.device_id.clone(),
                                state: id,
                            })
                        })
                        .collect::<Result<Vec<_>, String>>()
                })
            })
            .collect::<Vec<_>>();
        let mut refs = Vec::with_capacity(pending.len());
        for handle in handles {
            refs.extend(
                handle
                    .join()
                    .map_err(|_| "device-state persistence worker panicked".to_string())??,
            );
        }
        Ok(refs)
    })
}

/// Link independent immutable memory objects concurrently, reusing this batch's inode ownership.
fn parallel_link_objects(
    store: &CaptureObjectBatch,
    staging: &Path,
    objects: &[ObjectId],
) -> Result<(), String> {
    if objects.is_empty() {
        return Ok(());
    }
    let workers = parallel_worker_count(objects.len());
    let chunk_size = objects.len().div_ceil(workers);
    std::thread::scope(|scope| {
        let handles = objects
            .chunks(chunk_size)
            .map(|chunk| {
                scope.spawn(move || {
                    for object in chunk {
                        store
                            .link_into(object, staging)
                            .map_err(|error| format!("link memory object {object}: {error}"))?;
                    }
                    Ok::<(), String>(())
                })
            })
            .collect::<Vec<_>>();
        for handle in handles {
            handle
                .join()
                .map_err(|_| "memory-object link worker panicked".to_string())??;
        }
        Ok(())
    })
}

fn parallel_worker_count(items: usize) -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(1)
        .min(8)
        .min(items.max(1))
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
        FrozenWorkload, MemoryObjectSink, PendingDeviceState, WorkloadControl, overlay_extents,
        persist_device_states, publish_root_last, runtime_owned_fs_bindings,
        validate_vm_generation_state, validate_workload_reply,
    };
    use std::collections::BTreeSet;

    use microsandbox_image::checkpoint::{
        CaptureObjectBatch, ContentRef, LocalObjectStore, MemoryExtent, MemoryExtentContent,
        ObjectId,
    };
    use microsandbox_protocol::core::{
        CoreError, CoreErrorKind, Ready, WorkloadFrozen, WorkloadTransportCredit,
        WorkloadTransportPosition,
    };
    use microsandbox_protocol::message::{Message, MessageType};
    use msb_krun::{GuestMemoryRange, MemoryCaptureSink};
    use std::sync::Arc;

    #[test]
    fn block_writeback_follows_policy_without_weakening_directory_barriers() {
        use microsandbox_types::GuestFlush::{Auto, Required, Skip};
        for (policy, disk_only, flush_blocks) in [
            (Auto, true, true),
            (Required, true, true),
            (Skip, true, false),
            (Auto, false, false),
            (Required, false, true),
            (Skip, false, false),
        ] {
            for directories in [
                BTreeSet::new(),
                BTreeSet::from(["owned_files".into(), "external_data".into()]),
            ] {
                let mut mounts = directories.clone();
                super::extend_block_flush_mounts(
                    &mut mounts,
                    policy.requires_writeback(disk_only),
                    ["/data"].into_iter(),
                );
                let mut expected = directories;
                if flush_blocks {
                    expected.extend(["path:/".into(), "path:/data".into()]);
                }
                assert_eq!(mounts, expected, "{policy:?}, disk_only={disk_only}");
            }
        }
    }

    #[test]
    fn external_flush_budget_starts_after_gate_without_extending_ordinary_control() {
        let start = std::time::Instant::now();
        let gate_deadline = start + super::WORKLOAD_CONTROL_TIMEOUT;
        let gate_completed = start + std::time::Duration::from_secs(4);
        assert_eq!(
            super::freeze_request_deadline(gate_deadline, gate_completed, false),
            gate_deadline
        );
        let external = super::freeze_request_deadline(gate_deadline, gate_completed, true);
        assert_eq!(
            external.duration_since(gate_completed),
            std::time::Duration::from_secs(30)
        );
        assert!(external > gate_completed + std::time::Duration::from_secs(20));
        assert_eq!(
            super::WORKLOAD_CONTROL_TIMEOUT,
            std::time::Duration::from_secs(10)
        );
    }

    #[test]
    fn flush_acknowledgement_proves_only_the_requested_filesystems() {
        let control = WorkloadControl::new();
        let mut workload = FrozenWorkload {
            external_mounts_synced: true,
            synced_mounts: BTreeSet::new(),
            gate: control.gate(),
            attempt_id: "flush-proof".into(),
            protocol_generation: 9,
            ready: Ready::default(),
            host_input: WorkloadTransportPosition::default(),
            input_credit: WorkloadTransportCredit::default(),
            guest_bulk_bytes: 0,
        };
        let root = BTreeSet::from(["path:/".into()]);
        let owned = BTreeSet::from(["path:/".into(), "path:/data".into()]);
        assert!(workload.covers(&BTreeSet::new()));
        assert!(
            !workload.covers(&root),
            "empty success must not masquerade as root writeback"
        );
        workload.synced_mounts = root.clone();
        assert!(workload.covers(&root));
        assert!(!workload.covers(&owned));
        workload.synced_mounts = owned.clone();
        assert!(workload.covers(&root));
        assert!(workload.covers(&owned));
        workload.external_mounts_synced = false;
        assert!(
            !workload.covers(&owned),
            "requested coverage without success is not proof"
        );
        workload.gate.release();
    }

    #[test]
    fn unavailable_freezer_requires_explicit_matching_evidence() {
        use microsandbox_protocol::core::{WorkloadFailure, WorkloadFailureDisposition};
        let mut error = CoreError {
            kind: CoreErrorKind::CapabilityUnavailable,
            message: "missing freezer".into(),
            offending_type: Some(MessageType::WorkloadFreeze.as_str().into()),
            workload_failure: None,
        };
        let check = |error: &CoreError| {
            let reply = Message::with_payload(MessageType::CoreError, 7, error).unwrap();
            super::unavailable_freezer_reason(&reply, "a").is_some()
        };
        assert!(!check(&error), "older agent errors are ambiguous");
        for disposition in [
            WorkloadFailureDisposition::RecoveryRequired,
            WorkloadFailureDisposition::Unknown,
        ] {
            error.workload_failure = Some(WorkloadFailure {
                attempt_id: "a".into(),
                disposition,
            });
            assert!(!check(&error));
        }
        error.workload_failure.as_mut().unwrap().disposition =
            WorkloadFailureDisposition::Unavailable;
        assert!(check(&error));
        error.workload_failure.as_mut().unwrap().attempt_id = "b".into();
        assert!(!check(&error));
        error.workload_failure.as_mut().unwrap().attempt_id = "a".into();
        error.offending_type = Some(MessageType::WorkloadThaw.as_str().into());
        assert!(!check(&error));
        error.offending_type = Some(MessageType::WorkloadFreeze.as_str().into());
        error.kind = CoreErrorKind::InvalidSession;
        assert!(!check(&error));
    }

    #[test]
    fn failed_freeze_returns_running_only_after_confirmed_recovery() {
        let failure = super::recover_failed_freeze(
            "a",
            "lost reply".into(),
            || Ok(()),
            || panic!("must not pause after thaw"),
        );
        assert!(!failure.keep_paused);
        for pause_fails in [false, true] {
            let failure = super::recover_failed_freeze(
                "a",
                "lost reply".into(),
                || Err("thaw failed".into()),
                || {
                    if pause_fails {
                        Err("pause failed".into())
                    } else {
                        Ok(())
                    }
                },
            );
            assert!(failure.keep_paused);
            assert!(failure.message.contains("attempt a"));
            assert!(failure.message.contains("recovery required"));
            assert_eq!(failure.message.contains("pause also failed"), pause_fails);
        }
    }

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
    fn incremental_merge_matches_byte_oracle_for_fragmented_ranges() {
        let original = ObjectId::from_bytes(b"base").unwrap();
        let changed = ObjectId::from_bytes(b"update").unwrap();
        // Independent per-byte oracle includes holes, zero ranges, nonzero
        // object offsets, unsorted input, and updates spanning multiple ranges.
        let expand = |extents: &[MemoryExtent]| {
            let mut bytes = vec![None; 256];
            for extent in extents {
                for delta in 0..extent.length {
                    bytes[(extent.start + delta) as usize] = Some(match &extent.content {
                        MemoryExtentContent::Zero => (None, 0),
                        MemoryExtentContent::Object(content) => {
                            (Some(content.object.clone()), content.object_offset + delta)
                        }
                    });
                }
            }
            bytes
        };
        let mut seed = 7u64;
        for _ in 0..1000 {
            let mut make = |object: &ObjectId| {
                let mut ranges = Vec::new();
                let mut start = 0;
                while start < 256 {
                    seed = seed.wrapping_mul(6364136223846793005).wrapping_add(1);
                    let length = (1 + (seed >> 32) % 17).min(256 - start);
                    if !seed.is_multiple_of(5) {
                        ranges.push(MemoryExtent {
                            start,
                            length,
                            content: if seed.is_multiple_of(3) {
                                MemoryExtentContent::Zero
                            } else {
                                MemoryExtentContent::Object(ContentRef {
                                    object: object.clone(),
                                    object_offset: 1024 + start,
                                })
                            },
                        });
                    }
                    start += length;
                }
                ranges.reverse();
                ranges
            };
            let base = make(&original);
            let updates = make(&changed);
            let mut expected = expand(&base);
            for (slot, update) in expected.iter_mut().zip(expand(&updates)) {
                if update.is_some() {
                    *slot = update;
                }
            }
            assert_eq!(expand(&overlay_extents(base, updates).unwrap()), expected);
        }
        let zero = |start, length| MemoryExtent {
            start,
            length,
            content: MemoryExtentContent::Zero,
        };
        assert!(overlay_extents(vec![zero(0, 8), zero(4, 8)], vec![]).is_err());
        assert!(overlay_extents(vec![], vec![zero(u64::MAX, 2)]).is_err());
        assert!(overlay_extents(vec![], vec![zero(0, 0)]).is_err());
        assert!(overlay_extents(vec![], vec![zero(0, 8), zero(4, 8)]).is_err());
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
                driver_ready: true,
                driver_error: false,
                clock_sync_supported: false,
                requested: None,
                processed: None,
            }))
            .unwrap_err()
            .contains("clock-aware")
        );
        assert!(
            validate_vm_generation_state(Some(msb_krun::VmGenerationState {
                driver_ready: false,
                driver_error: false,
                clock_sync_supported: false,
                requested: None,
                processed: None,
            }))
            .is_err()
        );
        assert!(
            validate_vm_generation_state(Some(msb_krun::VmGenerationState {
                driver_ready: true,
                driver_error: true,
                clock_sync_supported: true,
                requested: None,
                processed: None,
            }))
            .is_err()
        );
        assert!(
            validate_vm_generation_state(Some(msb_krun::VmGenerationState {
                driver_ready: true,
                driver_error: false,
                clock_sync_supported: true,
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
        let batch = Arc::new(CaptureObjectBatch::new(store.clone(), &[]));
        let mut sink = MemoryObjectSink::new(Arc::clone(&batch)).unwrap();

        sink.write_bytes(GuestMemoryRange::new(0x1000, 3).unwrap(), b"abc")
            .unwrap();
        sink.write_zero(GuestMemoryRange::new(0x2000, 4).unwrap())
            .unwrap();
        sink.write_bytes(GuestMemoryRange::new(0x3000, 2).unwrap(), b"de")
            .unwrap();
        let (mut extents, _) = sink.finish().unwrap();
        batch.finish().unwrap();
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
    fn parallel_device_persistence_preserves_inventory_order() {
        let temp = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(temp.path().join("store")).unwrap();
        let staging = temp.path().join("checkpoint");
        std::fs::create_dir(&staging).unwrap();
        let pending = (0..16)
            .map(|index| PendingDeviceState {
                device_type: index,
                device_id: format!("device-{index:02}"),
                bytes: vec![index as u8; 4096],
            })
            .collect::<Vec<_>>();

        let batch = CaptureObjectBatch::new(store.clone(), &[]);
        let persisted = persist_device_states(&batch, &staging, &pending).unwrap();
        batch.finish().unwrap();

        assert_eq!(persisted.len(), pending.len());
        for (index, state) in persisted.iter().enumerate() {
            assert_eq!(state.device_type, index as u32);
            assert_eq!(state.device_id, format!("device-{index:02}"));
            assert_eq!(
                std::fs::read(store.object_path(&state.state)).unwrap(),
                vec![index as u8; 4096]
            );
        }
    }

    #[test]
    fn captured_agent_descriptor_retains_transport_debt() {
        let control = WorkloadControl::new();
        let workload = FrozenWorkload {
            external_mounts_synced: false,
            synced_mounts: BTreeSet::new(),
            gate: control.gate(),
            attempt_id: "checkpoint-42".into(),
            protocol_generation: 9,
            ready: Ready {
                workload_transport_barrier_version: Some(
                    microsandbox_protocol::core::WORKLOAD_TRANSPORT_BARRIER_VERSION,
                ),
                ..Ready::default()
            },
            host_input: WorkloadTransportPosition {
                control_bytes: 90_000_000,
                control_frames: 4_000,
                bulk_bytes: 100_000_000,
                bulk_frames: 5_000,
            },
            input_credit: WorkloadTransportCredit {
                control_bytes: 90_000_128,
                control_frames: 4_002,
                bulk_bytes: 100_000_256,
                bulk_frames: 5_003,
            },
            guest_bulk_bytes: 123_456_789,
        };
        let descriptor = workload.resource_descriptor();
        let position: WorkloadTransportPosition =
            serde_json::from_str(&descriptor.binding["transport_host_input"]).unwrap();
        let credit: WorkloadTransportCredit =
            serde_json::from_str(&descriptor.binding["transport_input_credit"]).unwrap();
        assert_eq!(position, workload.host_input);
        assert_eq!(credit, workload.input_credit);
        assert_eq!(
            descriptor.binding["transport_guest_bulk_bytes"],
            "123456789"
        );
        // Publication does not release queued source input. Only confirmed thaw does.
        assert!(control.gated());
        workload.gate.release();
    }

    #[test]
    fn workload_reply_must_confirm_the_exact_attempt() {
        let reply = Message::with_payload(
            MessageType::WorkloadFrozen,
            7,
            &WorkloadFrozen {
                external_mounts_synced: false,
                attempt_id: "checkpoint-42".into(),
                guest_bulk_bytes_target: 0,
                input_credit: WorkloadTransportCredit::default(),
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
                external_mounts_synced: false,
                attempt_id: "checkpoint-41".into(),
                guest_bulk_bytes_target: 0,
                input_credit: WorkloadTransportCredit::default(),
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
                workload_failure: None,
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
