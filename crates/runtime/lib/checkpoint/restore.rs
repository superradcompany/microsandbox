//! Eager construction-only reconstruction from a validated checkpoint closure.

use std::collections::BTreeMap;
use std::io;
use std::path::PathBuf;

use microsandbox_image::checkpoint::{
    CheckpointClosure, MemoryExtentContent, ObjectId, ResourceDescriptor, ResourceTreatment,
};
use microsandbox_protocol::core::Ready;
use microsandbox_protocol::message::{MessageType, PROTOCOL_VERSION};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_EXECUTION_STATE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DEVICE_STATE_BYTES: u64 = 1024 * 1024;
const MAX_MEMORY_OBJECT_BYTES: u64 = 2 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fully admitted checkpoint state ready to install during [`msb_krun::Vm::enter`].
pub(crate) struct PreparedCheckpointRestore {
    execution: msb_krun::ExecutionState,
    devices: Vec<PreparedDeviceRestore>,
    memory: CheckpointMemoryRestore,
    agent: RestoredAgentState,
}

/// Agent identity and latch attempt restored with the guest memory image.
pub(crate) struct RestoredAgentState {
    /// Protocol generation spoken by the captured agent.
    pub(crate) protocol_generation: u8,
    /// Cached ready payload used for post-activation client handshakes.
    pub(crate) ready: Ready,
    /// Checkpoint attempt that owns the captured workload freeze.
    pub(crate) attempt_id: String,
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
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PreparedCheckpointRestore {
    /// Resolve and decode every construction-time state envelope before building the VM.
    pub(crate) fn open(root: PathBuf, expected_root: &str) -> Result<Self, String> {
        let expected = ObjectId::new(expected_root).map_err(|error| error.to_string())?;
        let closure = CheckpointClosure::open(root, Some(&expected))
            .map_err(|error| format!("validate checkpoint closure: {error}"))?;
        let pause_generation = closure.checkpoint().pause_generation;
        let agent = parse_restored_agent(&closure)?;

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

        let mut devices = Vec::with_capacity(closure.checkpoint().devices.len());
        for device in &closure.checkpoint().devices {
            let bytes = closure
                .read_object(&device.state, MAX_DEVICE_STATE_BYTES)
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
                if state.pause_generation != pause_generation || state.device_id != device.device_id
                {
                    return Err(format!(
                        "virtio device {} does not belong to the checkpoint binding/epoch",
                        device.device_id
                    ));
                }
                devices.push(PreparedDeviceRestore::Virtio(state));
            }
        }

        Ok(Self {
            execution,
            devices,
            memory: CheckpointMemoryRestore { closure },
            agent,
        })
    }

    /// Install all restore sources and leave the VM at an explicit activation gate.
    pub(crate) fn install(self, vm: &mut msb_krun::Vm) -> RestoredAgentState {
        vm.set_execution_restore(self.execution);
        vm.set_memory_restore(self.memory);
        for device in self.devices {
            match device {
                PreparedDeviceRestore::Block { device_id, state } => {
                    vm.add_block_device_restore(device_id, state);
                }
                PreparedDeviceRestore::Virtio(state) => vm.add_virtio_device_restore(state),
            }
        }
        vm.set_start_paused(true);
        self.agent
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl msb_krun::VmMemoryRestoreSource for CheckpointMemoryRestore {
    fn restore(&mut self, target: &mut dyn msb_krun::VmMemoryRestoreTarget) -> io::Result<()> {
        let mut objects: BTreeMap<ObjectId, Vec<(msb_krun::GuestMemoryRange, u64)>> =
            BTreeMap::new();
        for extent in &self.closure.memory().extents {
            let range = msb_krun::GuestMemoryRange::new(extent.start, extent.length)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
            match &extent.content {
                MemoryExtentContent::Zero => target.write_zero(range)?,
                MemoryExtentContent::Object(content) => {
                    objects
                        .entry(content.object.clone())
                        .or_default()
                        .push((range, content.object_offset));
                }
            }
        }

        // Read and identity-check each packed object exactly once, write all of its referenced
        // guest ranges, then release the small object buffer. This fuses integrity with the
        // unavoidable restore pass without retaining a RAM-sized cache.
        for (id, extents) in objects {
            let bytes = self
                .closure
                .read_object(&id, MAX_MEMORY_OBJECT_BYTES)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
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
                target.write_bytes(range, slice)?;
            }
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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
    let parse_u64 = |key: &str| {
        value(key)?
            .parse::<u64>()
            .map_err(|error| format!("checkpoint guest agent has invalid {key}: {error}"))
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

    Ok(RestoredAgentState {
        protocol_generation,
        ready: Ready {
            boot_time_ns: parse_u64("boot_time_ns")?,
            init_time_ns: parse_u64("init_time_ns")?,
            ready_time_ns: parse_u64("ready_time_ns")?,
            agent_version: value("agent_version")?.clone(),
        },
        attempt_id: checkpoint_id.into(),
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
    fn rejects_agent_generation_without_workload_thaw() {
        let error = parse_restored_agent_resource(&agent_resource(7), "checkpoint-attempt")
            .err()
            .unwrap();

        assert!(error.contains("protocol generation 7 is unsupported"));
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
}
