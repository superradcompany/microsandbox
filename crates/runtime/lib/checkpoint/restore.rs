//! Eager construction-only reconstruction from a validated checkpoint closure.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;
use std::time::Instant;

use microsandbox_image::checkpoint::{
    CheckpointClosure, CheckpointGeometry, MemoryExtentContent, ObjectId, ResourceDescriptor,
    ResourceTreatment,
};
use microsandbox_protocol::core::{
    Ready, WORKLOAD_TRANSPORT_BARRIER_VERSION, WorkloadTransportCredit, WorkloadTransportPosition,
};
use microsandbox_protocol::message::{MessageType, PROTOCOL_VERSION};

use super::coordinator::TYPE_FS;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_EXECUTION_STATE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DEVICE_STATE_BYTES: u64 = 1024 * 1024;
const MAX_FS_DEVICE_STATE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_MEMORY_OBJECT_BYTES: u64 = 32 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fully admitted checkpoint state ready to install during [`msb_krun::Vm::enter`].
pub(crate) struct PreparedCheckpointRestore {
    geometry: CheckpointGeometry,
    execution: msb_krun::ExecutionState,
    devices: Vec<PreparedDeviceRestore>,
    memory: Option<CheckpointMemoryRestore>,
    local_memory: Option<msb_krun::PrivateMemoryBacking>,
    local_disks: Option<super::local_disk::LocalDiskAdmissions>,
    agent: RestoredAgentState,
}

/// Agent identity and latch attempt restored with the guest memory image.
pub(crate) struct RestoredAgentState {
    /// Exact inherited RAM pin, handed once to the child's capture coordinator.
    pub(crate) inherited_memory: Option<super::local_memory::LocalMemoryPin>,
    /// Host-only backend reconstruction diagnostics, populated before activation.
    pub(crate) external_mount_reports: Vec<ExternalMountReport>,
    /// Protocol generation spoken by the captured agent.
    pub(crate) protocol_generation: u8,
    /// Cached ready payload used for post-activation client handshakes.
    pub(crate) ready: Ready,
    /// Checkpoint attempt that owns the captured workload freeze.
    pub(crate) attempt_id: String,
    /// Complete host input admitted before the captured freeze acknowledgement.
    pub(crate) host_input: WorkloadTransportPosition,
    /// Absolute guest grants, including debt retained by inherited stdin.
    pub(crate) input_credit: WorkloadTransportCredit,
    /// Complete dedicated guest bulk output observed before capture.
    pub(crate) guest_bulk_bytes_target: u64,
}

/// One external backend's reconstruction report, shared only within the destination runtime.
pub(crate) struct ExternalMountReport {
    pub(crate) guest_path: String,
    pub(crate) unavailable: Option<String>,
    pub(crate) stale_inodes: std::sync::Arc<std::sync::Mutex<Vec<u64>>>,
}

enum PreparedDeviceRestore {
    Block {
        device_id: String,
        state: msb_krun::BlockDeviceState,
    },
    Virtio(msb_krun::VirtioDeviceState),
}

struct CheckpointMemoryRestore {
    closure: CheckpointClosure,
    progress: Option<crate::startup_progress::StartupProgressCallback>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PreparedCheckpointRestore {
    /// Captured additional block devices in transport order, including unmapped ones.
    pub(crate) fn additional_blocks(&self) -> Vec<(&str, &msb_krun::BlockDeviceState)> {
        let mut blocks: Vec<_> = self
            .devices
            .iter()
            .filter_map(|device| match device {
                PreparedDeviceRestore::Block { device_id, state }
                    if !matches!(device_id.as_str(), "vda" | "vdb") =>
                {
                    Some((device_id.as_str(), state))
                }
                _ => None,
            })
            .collect();
        blocks.sort_by_key(|(_, state)| state.transport.irq_line);
        blocks
    }

    /// Seed the journal while this runtime retains the exact admitted immutable files.
    pub(crate) fn seed_root_disk(
        &self,
        runtime_dir: &std::path::Path,
        vm: &crate::vm::VmConfig,
    ) -> Result<(), String> {
        if let Some(memory) = &self.memory {
            super::disk::seed_restored_root_disk(runtime_dir, vm, &memory.closure)?;
        } else if let Some(admitted) = &self.local_disks {
            super::disk::seed_local_root_disk(runtime_dir, vm, admitted)?;
        }
        Ok(())
    }

    /// Decode a local handoff and pin its RAM before constructing any guest mappings.
    pub(crate) fn open_local(
        root: PathBuf,
        expected_id: &str,
        memory_descriptor: bool,
    ) -> Result<Self, String> {
        let state = super::LocalBranchState::open(&root).map_err(|e| e.to_string())?;
        if state.id != expected_id {
            return Err("local branch identity differs".into());
        }
        let local_disks = super::local_disk::LocalDiskAdmissions::open(&root, &state.disks)
            .map_err(|e| e.to_string())?;
        let read = |id: &ObjectId, limit| {
            super::LocalBranchState::read_object(&root, id, limit).map_err(|e| e.to_string())
        };
        let execution = msb_krun::ExecutionState::decode(&read(
            &state.execution_state,
            MAX_EXECUTION_STATE_BYTES,
        )?)
        .map_err(|e| e.to_string())?;
        if execution.pause_generation() != state.pause_generation {
            return Err("branch execution epoch differs".into());
        }
        let devices = decode_devices(&state.devices, state.pause_generation, read)?;
        let resource = state
            .resources
            .iter()
            .find(|r| r.id == "guest:agentd")
            .ok_or("branch has no captured agent identity")?;
        let mut agent = parse_restored_agent_resource(resource, &state.id)?;
        if memory_descriptor != state.memory.memfd_lease.is_some() {
            return Err("branch memory descriptor differs from handoff".into());
        }
        #[cfg(target_os = "linux")]
        let transferred = if memory_descriptor {
            use std::os::fd::FromRawFd;
            // The strict launcher contract reserves this descriptor; consume it exactly once.
            // Check existence before constructing an owned File, including manual invocations.
            if unsafe { libc::fcntl(crate::launch::BRANCH_MEMORY_FD, libc::F_GETFD) } < 0 {
                return Err("missing inherited branch memory".into());
            }
            Some(unsafe { std::fs::File::from_raw_fd(crate::launch::BRANCH_MEMORY_FD) })
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        let transferred = None;
        let pin = state
            .memory
            .pin_backing(transferred.as_ref())
            .map_err(|e| e.to_string())?;
        let file = pin.file().try_clone().map_err(|e| e.to_string())?;
        agent.inherited_memory = Some(pin);
        let regions = state
            .memory
            .regions
            .into_iter()
            .map(|region| msb_krun::PrivateMemoryRegion {
                guest_address: region.guest_address,
                length: region.length,
                file_offset: region.file_offset,
            })
            .collect();
        let backing = msb_krun::PrivateMemoryBacking::new(file, regions)
            .map_err(|e| e.to_string())?
            .with_capture_baseline();
        Ok(Self {
            geometry: CheckpointGeometry {
                vcpus: state.vcpus,
                max_vcpus: state.max_cpus.max(state.vcpus),
                memory_mib: state.memory_mib,
                max_memory_mib: state.max_memory_mib.max(state.memory_mib),
            },
            execution,
            devices,
            memory: None,
            local_memory: Some(backing),
            local_disks,
            agent,
        })
    }

    /// Resolve and decode every construction-time state envelope before building the VM.
    pub(crate) fn open(root: PathBuf, expected_root: &str) -> Result<Self, String> {
        let total_started = Instant::now();
        let expected = ObjectId::new(expected_root).map_err(|error| error.to_string())?;
        let closure_started = Instant::now();
        let closure = CheckpointClosure::open(root, Some(&expected))
            .map_err(|error| format!("validate checkpoint closure: {error}"))?;
        let closure_open_us = closure_started.elapsed().as_micros();
        let pause_generation = closure.checkpoint().pause_generation;
        let agent_started = Instant::now();
        let agent = parse_restored_agent(&closure)?;
        let agent_parse_us = agent_started.elapsed().as_micros();

        let execution_started = Instant::now();
        let execution_bytes = closure
            .read_object(
                &closure.checkpoint().execution_state,
                MAX_EXECUTION_STATE_BYTES,
            )
            .map_err(|error| format!("read checkpoint execution state: {error}"))?;
        let execution = msb_krun::ExecutionState::decode(&execution_bytes)
            .map_err(|error| format!("decode checkpoint execution state: {error}"))?;
        if execution.pause_generation() != pause_generation {
            return Err("execution state does not belong to the checkpoint epoch".into());
        }
        let execution_us = execution_started.elapsed().as_micros();

        let devices_started = Instant::now();
        let devices = decode_devices(
            &closure.checkpoint().devices,
            pause_generation,
            |id, limit| closure.read_object(id, limit).map_err(|e| e.to_string()),
        )?;
        let devices_us = devices_started.elapsed().as_micros();
        tracing::info!(
            target: "microsandbox_checkpoint_timing",
            operation = "restore_prepare",
            checkpoint_id = closure.checkpoint().checkpoint_id,
            total_us = total_started.elapsed().as_micros(),
            closure_open_us,
            agent_parse_us,
            execution_us,
            devices_us,
            device_count = devices.len(),
            memory_extent_count = closure.memory().extents.len(),
            "checkpoint restore preparation timing"
        );

        Ok(Self {
            geometry: closure.checkpoint().geometry,
            execution,
            devices,
            memory: Some(CheckpointMemoryRestore {
                closure,
                progress: None,
            }),
            local_memory: None,
            local_disks: None,
            agent,
        })
    }

    /// Validate the launcher configuration before preparing RAM backing or entering the VM.
    pub(crate) fn validate_geometry(&self, config: &crate::vm::VmConfig) -> Result<(), String> {
        let requested = CheckpointGeometry {
            vcpus: config.vcpus,
            max_vcpus: config.max_cpus.max(config.vcpus),
            memory_mib: config.memory_mib,
            max_memory_mib: config.max_memory_mib.max(config.memory_mib),
        };
        if requested != self.geometry {
            return Err("restore VM construction geometry differs from captured geometry".into());
        }
        Ok(())
    }

    /// Install all restore sources and leave the VM at an explicit activation gate.
    pub(crate) fn install(
        self,
        vm: &mut msb_krun::Vm,
        cache_root: Option<PathBuf>,
        progress: crate::startup_progress::StartupProgressCallback,
    ) -> Result<RestoredAgentState, String> {
        vm.set_execution_restore(self.execution);
        if let Some(backing) = self.local_memory {
            vm.set_private_memory_backing(backing);
        } else if let Some(root) = cache_root {
            let closure = &self
                .memory
                .as_ref()
                .expect("durable restore memory")
                .closure;
            let cache = super::MemoryCache::open(root)
                .map_err(|e| e.to_string())?
                .with_progress(progress);
            let cached = cache
                .materialize_parallel(
                    closure.memory(),
                    &closure.checkpoint().memory,
                    |id, bytes| {
                        closure
                            .read_object_into(id, MAX_MEMORY_OBJECT_BYTES, bytes)
                            .map_err(io::Error::other)
                    },
                )
                .map_err(|e| e.to_string())?;
            tracing::info!(
                cache_hit = cached.cache_hit,
                prepare_us = cached.prepare_us,
                "prepared private memory backing"
            );
            let regions = cached
                .regions
                .into_iter()
                .map(|region| msb_krun::PrivateMemoryRegion {
                    guest_address: region.guest_address,
                    length: region.length,
                    file_offset: region.file_offset,
                })
                .collect();
            let backing = msb_krun::PrivateMemoryBacking::new(cached.file, regions)
                .map_err(|e| e.to_string())?;
            vm.set_private_memory_backing(backing);
        } else {
            let mut memory = self.memory.expect("durable restore memory");
            memory.progress = Some(progress);
            vm.set_memory_restore(memory);
        }
        for device in self.devices {
            match device {
                PreparedDeviceRestore::Block { device_id, state } => {
                    vm.add_block_device_restore(device_id, state);
                }
                PreparedDeviceRestore::Virtio(state) => vm.add_virtio_device_restore(state),
            }
        }
        vm.set_start_paused(true);
        Ok(self.agent)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl msb_krun::VmMemoryRestoreSource for CheckpointMemoryRestore {
    fn restore(&mut self, target: &mut dyn msb_krun::VmMemoryRestoreTarget) -> io::Result<()> {
        let total_started = Instant::now();
        let mut zero_write_us = 0u128;
        let mut zero_bytes = 0u64;
        let mut guest_write_us = 0u128;
        let mut guest_object_bytes = 0u64;
        let mut object_extent_count = 0usize;
        let mut objects: BTreeMap<ObjectId, Vec<(msb_krun::GuestMemoryRange, u64)>> =
            BTreeMap::new();
        for extent in &self.closure.memory().extents {
            let range = msb_krun::GuestMemoryRange::new(extent.start, extent.length)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            match &extent.content {
                MemoryExtentContent::Zero => {
                    let write_started = Instant::now();
                    target.write_zero(range)?;
                    zero_write_us += write_started.elapsed().as_micros();
                    zero_bytes = zero_bytes.saturating_add(range.length());
                }
                MemoryExtentContent::Object(content) => {
                    object_extent_count += 1;
                    objects
                        .entry(content.object.clone())
                        .or_default()
                        .push((range, content.object_offset));
                }
            }
        }

        // Read and identity-check each packed object exactly once with bounded read-ahead.
        // Guest ranges are disjoint and only this construction thread writes them; workers
        // never obtain guest-memory access or permit activation before verification completes.
        // Count required object-backed slices, not untouched capacity or bytes verified
        // speculatively by reader threads. The existing observer coalesces these updates.
        let total_bytes = objects
            .values()
            .flatten()
            .map(|(range, _)| range.length())
            .sum();
        let report_progress = |completed_bytes| {
            if let Some(progress) = &self.progress {
                progress(crate::startup_progress::StartupProgress {
                    phase: crate::startup_progress::StartupPhase::PreparingSnapshot,
                    completed_bytes,
                    total_bytes: Some(total_bytes),
                });
            }
        };
        report_progress(0);
        let object_count = objects.len();
        let pipeline = super::object_pipeline::consume_verified_objects(
            objects,
            |id, bytes| {
                self.closure
                    .read_object_into(id, MAX_MEMORY_OBJECT_BYTES, bytes)
                    .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))
            },
            |extents, bytes| {
                for (range, offset) in extents {
                    let start = usize::try_from(offset).map_err(|_| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "memory object offset is too large",
                        )
                    })?;
                    let length = usize::try_from(range.length()).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "memory extent is too large")
                    })?;
                    let end = start.checked_add(length).ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "memory object slice overflows")
                    })?;
                    let slice = bytes.get(start..end).ok_or_else(|| {
                        io::Error::new(
                            io::ErrorKind::InvalidData,
                            "memory object slice exceeds verified bytes",
                        )
                    })?;
                    let write_started = Instant::now();
                    target.write_bytes(range, slice)?;
                    guest_write_us += write_started.elapsed().as_micros();
                    guest_object_bytes = guest_object_bytes.saturating_add(range.length());
                }
                report_progress(guest_object_bytes);
                Ok(())
            },
        )?;
        tracing::info!(
            target: "microsandbox_checkpoint_timing",
            operation = "restore_memory",
            total_us = total_started.elapsed().as_micros(),
            object_read_us = pipeline.read_us + pipeline.hash_us,
            object_io_worker_us = pipeline.read_us,
            object_hash_worker_us = pipeline.hash_us,
            object_pipeline_us = pipeline.elapsed_us,
            guest_write_us,
            zero_write_us,
            object_count,
            object_extent_count,
            object_bytes = pipeline.object_bytes,
            guest_object_bytes,
            zero_bytes,
            "checkpoint memory restore timing"
        );
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Restore diagnostics
//--------------------------------------------------------------------------------------------------

impl RestoredAgentState {
    /// Atomically publish health after backend reconstruction and before public activation.
    pub(crate) fn publish_mount_warnings(
        &self,
        runtime_dir: &std::path::Path,
    ) -> Result<(), String> {
        use std::io::Write;
        let warnings = self.external_mount_reports.iter().filter_map(|report| {
            let stale_inodes = report.stale_inodes.lock().unwrap().clone();
            let reason = match &report.unavailable {
                Some(reason) => reason.clone(),
                None if !stale_inodes.is_empty() => "captured objects are missing, replaced, or changed; backend requests for their retained handles return ESTALE (clean cached reads may still succeed)".into(),
                None => return None,
            };
            Some(microsandbox_types::ExternalMountWarning { guest_path: report.guest_path.clone(), reason, stale_inodes })
        }).collect::<Vec<_>>();
        // The guest can write /.msb (runtime_dir); these host-authored diagnostics
        // must live outside that share so resumed code cannot erase the warning.
        let sandbox_dir = runtime_dir
            .parent()
            .ok_or("runtime has no host-only parent")?;
        let mut file = tempfile::NamedTempFile::new_in(sandbox_dir).map_err(|e| e.to_string())?;
        file.write_all(&serde_json::to_vec(&warnings).map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        // These warnings are diagnostics, not recovery state. Readers need a complete atomic
        // replacement, but a disk flush must not delay guest activation. Closing the handle
        // before replacement also permits renaming on Windows; TempPath cleans up on failure.
        let path = file.into_temp_path();
        super::replace_file(&path, &sandbox_dir.join("restore-mount-warnings.json"))
            .map_err(|e| e.to_string())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn decode_devices(
    references: &[microsandbox_image::checkpoint::DeviceStateRef],
    pause_generation: u64,
    mut read: impl FnMut(&ObjectId, u64) -> Result<Vec<u8>, String>,
) -> Result<Vec<PreparedDeviceRestore>, String> {
    let mut devices = Vec::with_capacity(references.len());
    for device in references {
        let max_state_bytes = if device.device_type == TYPE_FS {
            MAX_FS_DEVICE_STATE_BYTES
        } else {
            MAX_DEVICE_STATE_BYTES
        };
        let bytes = read(&device.state, max_state_bytes)
            .map_err(|error| format!("read checkpoint device {}: {error}", device.device_id))?;
        if device.device_type == 2 {
            let state = msb_krun::BlockDeviceState::decode(&bytes).map_err(|error| {
                format!(
                    "decode checkpoint block device {}: {error}",
                    device.device_id
                )
            })?;
            if state.pause_generation != pause_generation {
                return Err(format!(
                    "block device {} does not belong to the checkpoint epoch",
                    device.device_id
                ));
            }
            devices.push(PreparedDeviceRestore::Block {
                device_id: device.device_id.clone(),
                state,
            });
        } else {
            let state = msb_krun::VirtioDeviceState::decode(&bytes).map_err(|error| {
                format!(
                    "decode checkpoint virtio device {}: {error}",
                    device.device_id
                )
            })?;
            if state.pause_generation != pause_generation || state.device_id != device.device_id {
                return Err(format!(
                    "virtio device {} does not belong to the checkpoint binding/epoch",
                    device.device_id
                ));
            }
            devices.push(PreparedDeviceRestore::Virtio(state));
        }
    }
    Ok(devices)
}

fn parse_restored_agent(closure: &CheckpointClosure) -> Result<RestoredAgentState, String> {
    let resource = closure
        .checkpoint()
        .resources
        .iter()
        .find(|resource| resource.id == "guest:agentd")
        .ok_or_else(|| "checkpoint has no serialized guest agent identity".to_string())?;
    parse_restored_agent_resource(resource, &closure.checkpoint().checkpoint_id)
}

fn parse_restored_agent_resource(
    resource: &ResourceDescriptor,
    checkpoint_id: &str,
) -> Result<RestoredAgentState, String> {
    if resource.kind != "agent" || resource.treatment != ResourceTreatment::Serialize {
        return Err("checkpoint guest agent has an incompatible resource treatment".into());
    }
    let value = |key: &str| {
        resource
            .binding
            .get(key)
            .ok_or_else(|| format!("checkpoint guest agent is missing {key}"))
    };
    let protocol_generation = value("protocol_generation")?
        .parse::<u8>()
        .map_err(|error| {
            format!("checkpoint guest agent has invalid protocol generation: {error}")
        })?;
    if protocol_generation > PROTOCOL_VERSION
        || !MessageType::WorkloadThaw.is_available_at(protocol_generation)
    {
        return Err(format!(
            "checkpoint guest agent protocol generation {protocol_generation} is unsupported"
        ));
    }

    let ready: Ready = serde_json::from_str(value("ready")?)
        .map_err(|error| format!("checkpoint guest readiness is invalid: {error}"))?;
    if ready.workload_transport_barrier_version != Some(WORKLOAD_TRANSPORT_BARRIER_VERSION) {
        return Err("checkpoint guest has an unsupported development transport-credit contract; recreate the full snapshot with a matching build".into());
    }
    let host_input: WorkloadTransportPosition =
        serde_json::from_str(value("transport_host_input")?)
            .map_err(|error| format!("checkpoint host input position is invalid: {error}"))?;
    let input_credit: WorkloadTransportCredit =
        serde_json::from_str(value("transport_input_credit")?)
            .map_err(|error| format!("checkpoint input credit is invalid: {error}"))?;
    if host_input.control_bytes > input_credit.control_bytes
        || host_input.control_frames > input_credit.control_frames
        || host_input.bulk_bytes > input_credit.bulk_bytes
        || host_input.bulk_frames > input_credit.bulk_frames
    {
        return Err("checkpoint transport input exceeds captured credit".into());
    }
    let guest_bulk_bytes_target = value("transport_guest_bulk_bytes")?
        .parse::<u64>()
        .map_err(|error| format!("checkpoint guest bulk position is invalid: {error}"))?;
    if ready.bulk_transport.is_none() && guest_bulk_bytes_target != 0 {
        return Err("combined checkpoint has a dedicated guest bulk counter".into());
    }
    Ok(RestoredAgentState {
        inherited_memory: None,
        external_mount_reports: Vec::new(),
        protocol_generation,
        ready,
        host_input,
        input_credit,
        guest_bulk_bytes_target,
        attempt_id: resource
            .binding
            .get("attempt_id")
            .cloned()
            .unwrap_or_else(|| checkpoint_id.into()),
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn agent_resource(protocol_generation: u8) -> ResourceDescriptor {
        ResourceDescriptor {
            id: "guest:agentd".into(),
            kind: "agent".into(),
            treatment: ResourceTreatment::Serialize,
            binding: BTreeMap::from([
                (
                    "protocol_generation".into(),
                    protocol_generation.to_string(),
                ),
                ("agent_version".into(), "0.6.16-test".into()),
                ("boot_time_ns".into(), "10".into()),
                ("init_time_ns".into(), "20".into()),
                ("ready_time_ns".into(), "30".into()),
                (
                    "transport_host_input".into(),
                    serde_json::to_string(&WorkloadTransportPosition::default()).unwrap(),
                ),
                (
                    "transport_input_credit".into(),
                    serde_json::to_string(&WorkloadTransportCredit::default()).unwrap(),
                ),
                ("transport_guest_bulk_bytes".into(), "0".into()),
                (
                    "ready".into(),
                    serde_json::to_string(&Ready {
                        agent_version: "0.6.16-test".into(),
                        boot_time_ns: 10,
                        init_time_ns: 20,
                        ready_time_ns: 30,
                        workload_transport_barrier_version: Some(
                            WORKLOAD_TRANSPORT_BARRIER_VERSION,
                        ),
                        ..Default::default()
                    })
                    .unwrap(),
                ),
            ]),
        }
    }

    #[test]
    fn parses_attempt_scoped_agent_restore_identity() {
        let restored =
            parse_restored_agent_resource(&agent_resource(PROTOCOL_VERSION), "checkpoint-attempt")
                .unwrap();

        assert_eq!(restored.protocol_generation, PROTOCOL_VERSION);
        assert_eq!(restored.attempt_id, "checkpoint-attempt");
        assert_eq!(restored.ready.agent_version, "0.6.16-test");
        assert_eq!(restored.ready.boot_time_ns, 10);
        assert_eq!(restored.ready.init_time_ns, 20);
        assert_eq!(restored.ready.ready_time_ns, 30);
    }

    #[test]
    fn mount_warnings_are_published_outside_the_guest_runtime_share() {
        let sandbox = tempfile::tempdir().unwrap();
        let runtime = sandbox.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        let mut restored =
            parse_restored_agent_resource(&agent_resource(PROTOCOL_VERSION), "attempt").unwrap();
        restored
            .external_mount_reports
            .push(super::ExternalMountReport {
                guest_path: "/external".into(),
                unavailable: Some("export unavailable".into()),
                stale_inodes: Default::default(),
            });
        restored.publish_mount_warnings(&runtime).unwrap();
        assert!(!runtime.join("restore-mount-warnings.json").exists());
        let warnings: Vec<microsandbox_types::ExternalMountWarning> = serde_json::from_slice(
            &std::fs::read(sandbox.path().join("restore-mount-warnings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].guest_path, "/external");
        // Writing the guest-visible lookalike cannot replace the host's record.
        std::fs::write(runtime.join("restore-mount-warnings.json"), b"[]").unwrap();
        let retained: Vec<microsandbox_types::ExternalMountWarning> = serde_json::from_slice(
            &std::fs::read(sandbox.path().join("restore-mount-warnings.json")).unwrap(),
        )
        .unwrap();
        assert_eq!(retained, warnings);
        // A later healthy activation replaces old warnings, including an empty result.
        restored.external_mount_reports.clear();
        restored.publish_mount_warnings(&runtime).unwrap();
        let bytes = std::fs::read(sandbox.path().join("restore-mount-warnings.json")).unwrap();
        assert_eq!(bytes, b"[]");
        assert_eq!(std::fs::read_dir(sandbox.path()).unwrap().count(), 2);
    }

    #[test]
    fn rejects_agent_generation_without_workload_thaw() {
        let error = parse_restored_agent_resource(&agent_resource(8), "checkpoint-attempt")
            .err()
            .unwrap();

        assert!(error.contains("protocol generation 8 is unsupported"));
    }

    #[test]
    fn rejects_development_snapshot_with_stdin_charged_to_control() {
        let mut resource = agent_resource(PROTOCOL_VERSION);
        let mut ready: Ready = serde_json::from_str(&resource.binding["ready"]).unwrap();
        ready.workload_transport_barrier_version = Some(1);
        resource
            .binding
            .insert("ready".into(), serde_json::to_string(&ready).unwrap());
        let error = parse_restored_agent_resource(&resource, "old-development-cut")
            .err()
            .unwrap();
        assert!(error.contains("unsupported development transport-credit contract"));
    }

    #[test]
    fn rejects_reconstructed_agent_resource() {
        let mut resource = agent_resource(PROTOCOL_VERSION);
        resource.treatment = ResourceTreatment::Reconnect;

        let error = parse_restored_agent_resource(&resource, "checkpoint-attempt")
            .err()
            .unwrap();

        assert!(error.contains("incompatible resource treatment"));
    }

    #[test]
    fn rejects_development_capture_without_proven_transport_position() {
        let mut resource = agent_resource(PROTOCOL_VERSION);
        resource.binding.remove("transport_host_input");
        assert!(
            parse_restored_agent_resource(&resource, "attempt")
                .err()
                .unwrap()
                .contains("transport_host_input")
        );
    }

    #[test]
    fn rejects_transport_debt_beyond_captured_grants() {
        let mut resource = agent_resource(PROTOCOL_VERSION);
        resource.binding.insert(
            "transport_host_input".into(),
            serde_json::to_string(&WorkloadTransportPosition {
                control_bytes: 1,
                ..Default::default()
            })
            .unwrap(),
        );
        assert!(
            parse_restored_agent_resource(&resource, "attempt")
                .err()
                .unwrap()
                .contains("exceeds captured credit")
        );
    }

    #[test]
    fn combined_transport_accepts_input_bulk_counter_but_not_dedicated_output_cut() {
        let mut resource = agent_resource(PROTOCOL_VERSION);
        resource.binding.insert(
            "transport_host_input".into(),
            serde_json::to_string(&WorkloadTransportPosition {
                bulk_bytes: 32,
                bulk_frames: 1,
                ..Default::default()
            })
            .unwrap(),
        );
        resource.binding.insert(
            "transport_input_credit".into(),
            serde_json::to_string(&WorkloadTransportCredit {
                bulk_bytes: 64,
                bulk_frames: 2,
                ..Default::default()
            })
            .unwrap(),
        );
        assert_eq!(
            parse_restored_agent_resource(&resource, "attempt")
                .unwrap()
                .host_input
                .bulk_bytes,
            32
        );
        resource
            .binding
            .insert("transport_guest_bulk_bytes".into(), "1".into());
        assert!(
            parse_restored_agent_resource(&resource, "attempt")
                .err()
                .unwrap()
                .contains("dedicated guest bulk counter")
        );
    }
}
