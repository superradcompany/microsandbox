//! Bounded process-local branch handoff, deliberately distinct from a full snapshot.

use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

use microsandbox_image::checkpoint::{
    DeviceStateRef, DiskGenerationManifest, LocalObjectStore, ObjectId, ResourceDescriptor,
};
use serde::{Deserialize, Serialize};

use super::local_memory::LocalMemory;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Same-epoch local execution handoff. RAM has no portable object representation here.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalBranchState {
    /// Unique capture attempt, shared with the workload freeze latch.
    pub id: String,
    /// Host architecture required by the captured execution.
    pub architecture: String,
    /// Shared CPU/device/RAM pause boundary.
    pub pause_generation: u64,
    /// Encoded CPU and interrupt-controller state.
    pub execution_state: ObjectId,
    /// Existing device state encodings.
    pub devices: Vec<DeviceStateRef>,
    /// Existing resource bindings, including the captured agent identity.
    pub resources: Vec<ResourceDescriptor>,
    /// Complete sealed disk generations.
    pub disks: Vec<DiskGenerationManifest>,
    /// Required owned storage. Older strict local handoff readers reject this field.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub owned_volumes: Vec<microsandbox_image::snapshot::OwnedVolumeCapture>,
    /// Complete, immutable, mmap-ready RAM; never a partial memory manifest.
    pub memory: LocalMemory,
    /// Boot CPU count and configured capacity, not a mutable guest online count.
    pub vcpus: u8,
    /// Maximum CPU count used for device construction.
    pub max_cpus: u8,
    /// Boot RAM geometry in MiB.
    pub memory_mib: u32,
    /// Configured hotplug capacity in MiB.
    pub max_memory_mib: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalBranchState {
    /// Read bounded handoff metadata; ordinary snapshot readers never recognize this file.
    pub fn open(root: &Path) -> io::Result<Self> {
        let bytes = read_bounded(&root.join("branch.json"), 16 * 1024 * 1024)?;
        let state: Self = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
        if state.architecture != std::env::consts::ARCH {
            return Err(io::Error::other("branch architecture differs"));
        }
        for disk in &state.disks {
            disk.validate().map_err(io::Error::other)?;
            if disk.pause_generation != state.pause_generation {
                return Err(io::Error::other(
                    "branch disk belongs to a different pause epoch",
                ));
            }
        }
        state.validate_files(root)?;
        microsandbox_image::snapshot::validate_owned_volumes(&state.owned_volumes)
            .map_err(io::Error::other)?;
        microsandbox_image::snapshot::validate_owned_resources(
            &state.owned_volumes,
            &state.resources,
        )
        .map_err(io::Error::other)?;
        for volume in &state.owned_volumes {
            if let microsandbox_image::snapshot::OwnedVolumeData::Disk { generation } = &volume.data
                && (generation.pause_generation != state.pause_generation
                    || !state.disks.contains(generation))
            {
                return Err(io::Error::other(
                    "owned disk is absent from the branch capture epoch",
                ));
            }
        }
        microsandbox_image::snapshot::verify_owned_directory_payloads(root, &state.owned_volumes)
            .map_err(io::Error::other)?;
        Ok(state)
    }

    /// Check one child's file bindings against already decoded immutable capture metadata.
    /// The SDK may share decoded metadata within a batch; each VM still opens and admits
    /// its own handoff independently through `open` at the runtime boundary.
    pub fn validate_files(&self, root: &Path) -> io::Result<()> {
        for disk in &self.disks {
            for layer in &disk.layers {
                let path = root
                    .join("layers")
                    .join(format!("{}.{}", layer.layer_id, layer.format));
                let metadata = std::fs::symlink_metadata(path)?;
                if !metadata.is_file() || metadata.len() != layer.file_size {
                    return Err(io::Error::other("branch disk file type or length differs"));
                }
            }
        }
        Ok(())
    }

    /// Read an existing bounded state object, checking its recorded identity.
    pub fn read_object(root: &Path, id: &ObjectId, limit: u64) -> io::Result<Vec<u8>> {
        let store = LocalObjectStore::open(root).map_err(io::Error::other)?;
        let bytes = read_bounded(&store.object_path(id), limit)?;
        if ObjectId::from_bytes(&bytes).map_err(io::Error::other)? != *id {
            return Err(io::Error::other("branch state object differs"));
        }
        Ok(bytes)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn read_bounded(path: &Path, limit: u64) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)?.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(io::Error::other("local state exceeds size bound"));
    }
    Ok(bytes)
}
