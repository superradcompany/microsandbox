//! Strict resolver for one self-contained composite-checkpoint closure.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};

use sha2::{Digest as _, Sha256};

use super::{
    CheckpointManifest, DiskGenerationManifest, DiskLayerRef, MemoryExtentContent, MemoryManifest,
    ObjectId, sparse_file_integrity,
};
use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const CHECKPOINT_ROOT_FILE: &str = "checkpoint.json";
const MAX_MANIFEST_BYTES: u64 = 8 * 1024 * 1024;
const MAX_EXECUTION_STATE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_DEVICE_STATE_BYTES: u64 = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A validated, self-contained checkpoint closure rooted at a published directory.
///
/// Opening verifies the canonical root and every transitively referenced manifest, object slice,
/// and disk layer. Later restore reads still verify object identities so replacing bytes between
/// admission and consumption fails closed.
#[derive(Clone, Debug)]
pub struct CheckpointClosure {
    root: PathBuf,
    root_id: ObjectId,
    checkpoint: CheckpointManifest,
    memory: MemoryManifest,
    disks: Vec<DiskGenerationManifest>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CheckpointClosure {
    /// Open and validate a published checkpoint closure.
    pub fn open(root: impl Into<PathBuf>, expected_root: Option<&ObjectId>) -> ImageResult<Self> {
        let root = root.into();
        let metadata = std::fs::symlink_metadata(&root)?;
        if !metadata.file_type().is_dir() {
            return checkpoint_error("checkpoint root is not a directory");
        }

        let root_bytes =
            read_regular_bounded(&root.join(CHECKPOINT_ROOT_FILE), MAX_MANIFEST_BYTES)?;
        let root_id = ObjectId::from_bytes(&root_bytes)?;
        if expected_root.is_some_and(|expected| expected != &root_id) {
            return Err(ImageError::DigestMismatch {
                digest: root_id.to_string(),
                expected: expected_root.expect("checked Some").to_string(),
                actual: root_id.to_string(),
            });
        }
        let checkpoint = CheckpointManifest::from_bytes(&root_bytes)?;
        if checkpoint.architecture != std::env::consts::ARCH {
            return checkpoint_error(format!(
                "checkpoint architecture {} cannot restore on {}",
                checkpoint.architecture,
                std::env::consts::ARCH
            ));
        }

        let memory_bytes = read_object_verified(&root, &checkpoint.memory, MAX_MANIFEST_BYTES)?;
        let memory = MemoryManifest::from_bytes(&memory_bytes)?;
        if memory.architecture != checkpoint.architecture
            || memory.pause_generation != checkpoint.pause_generation
        {
            return checkpoint_error("memory state does not belong to the checkpoint epoch");
        }
        validate_memory_objects(&root, &memory)?;

        // Execution/device codecs perform their own bounded semantic decoding in the runtime. At
        // this layer we still prove that every named immutable object exists and matches its id.
        read_object_verified(
            &root,
            &checkpoint.execution_state,
            MAX_EXECUTION_STATE_BYTES,
        )?;
        for device in &checkpoint.devices {
            read_object_verified(&root, &device.state, MAX_DEVICE_STATE_BYTES)?;
        }

        let mut disks = Vec::with_capacity(checkpoint.disks.len());
        let mut volumes = BTreeSet::new();
        for disk_id in &checkpoint.disks {
            let bytes = read_object_verified(&root, disk_id, MAX_MANIFEST_BYTES)?;
            let disk = DiskGenerationManifest::from_bytes(&bytes)?;
            if disk.pause_generation != checkpoint.pause_generation {
                return checkpoint_error("disk generation does not belong to the checkpoint epoch");
            }
            if !volumes.insert(disk.volume_id.clone()) {
                return checkpoint_error("checkpoint repeats a logical disk volume");
            }
            validate_disk_layers(&root, &disk)?;
            disks.push(disk);
        }

        Ok(Self {
            root,
            root_id,
            checkpoint,
            memory,
            disks,
        })
    }

    /// Return the immutable root identity computed from canonical `checkpoint.json` bytes.
    pub fn root_id(&self) -> &ObjectId {
        &self.root_id
    }

    /// Return the validated composite manifest.
    pub fn checkpoint(&self) -> &CheckpointManifest {
        &self.checkpoint
    }

    /// Return the complete logical memory generation.
    pub fn memory(&self) -> &MemoryManifest {
        &self.memory
    }

    /// Return the validated disk generations.
    pub fn disks(&self) -> &[DiskGenerationManifest] {
        &self.disks
    }

    /// Read and reverify one immutable object, bounded by `max_len`.
    pub fn read_object(&self, id: &ObjectId, max_len: u64) -> ImageResult<Vec<u8>> {
        read_object_verified(&self.root, id, max_len)
    }

    /// Return the confined path of a validated disk layer.
    pub fn disk_layer_path(&self, layer: &DiskLayerRef) -> PathBuf {
        self.root
            .join("layers")
            .join(format!("{}.{}", layer.layer_id, layer.format))
    }

    /// Stream and verify every immutable memory payload referenced by the logical generation.
    ///
    /// Restore normally fuses this check with copying bytes into guest memory. Explicit artifact
    /// verification uses this method when no restore read is available to amortize the work.
    pub fn verify_memory_objects(&self) -> ImageResult<()> {
        let mut verified = BTreeSet::new();
        for extent in &self.memory.extents {
            let MemoryExtentContent::Object(content) = &extent.content else {
                continue;
            };
            if verified.insert(content.object.clone()) {
                verify_object_streaming(&self.root, &content.object)?;
            }
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_memory_objects(root: &Path, memory: &MemoryManifest) -> ImageResult<()> {
    let mut verified = BTreeSet::new();
    for extent in &memory.extents {
        let MemoryExtentContent::Object(content) = &extent.content else {
            continue;
        };
        let path = object_path(root, &content.object);
        if verified.insert(content.object.clone()) {
            // Payload verification is fused with the inevitable restore read. Admission only
            // proves member shape and range bounds, avoiding a second full RAM pass.
            open_regular(&path)?;
        }
        let size = std::fs::metadata(&path)?.len();
        let end = content
            .object_offset
            .checked_add(extent.length)
            .ok_or_else(|| checkpoint_error_value("memory object slice overflows"))?;
        if end > size {
            return checkpoint_error("memory extent exceeds its immutable object");
        }
    }
    Ok(())
}

fn validate_disk_layers(root: &Path, disk: &DiskGenerationManifest) -> ImageResult<()> {
    for layer in &disk.layers {
        let path = root
            .join("layers")
            .join(format!("{}.{}", layer.layer_id, layer.format));
        let metadata = std::fs::symlink_metadata(&path)?;
        if !metadata.file_type().is_file() {
            return checkpoint_error("checkpoint disk layer is not a regular file");
        }
        let integrity = sparse_file_integrity(&path)?;
        if integrity.root != layer.integrity_root {
            return Err(ImageError::DigestMismatch {
                digest: layer.layer_id.clone(),
                expected: layer.integrity_root.clone(),
                actual: integrity.root,
            });
        }
    }
    Ok(())
}

fn read_object_verified(root: &Path, id: &ObjectId, max_len: u64) -> ImageResult<Vec<u8>> {
    let path = object_path(root, id);
    let mut file = open_regular(&path)?;
    let length = file.metadata()?.len();
    if length > max_len {
        return checkpoint_error(format!("checkpoint object exceeds {max_len} bytes"));
    }
    let length = usize::try_from(length)
        .map_err(|_| checkpoint_error_value("checkpoint object exceeds host limits"))?;
    let mut bytes = Vec::with_capacity(length);
    file.read_to_end(&mut bytes)?;
    let actual = ObjectId::from_bytes(&bytes)?;
    if &actual != id {
        return Err(ImageError::DigestMismatch {
            digest: id.to_string(),
            expected: id.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(bytes)
}

fn verify_object_streaming(root: &Path, id: &ObjectId) -> ImageResult<()> {
    let mut file = open_regular(&object_path(root, id))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    let actual = format!("sha256:{}", hex::encode(hasher.finalize()));
    if actual != id.as_str() {
        return Err(ImageError::DigestMismatch {
            digest: id.to_string(),
            expected: id.to_string(),
            actual,
        });
    }
    Ok(())
}

fn read_regular_bounded(path: &Path, max_len: u64) -> ImageResult<Vec<u8>> {
    let mut file = open_regular(path)?;
    let length = file.metadata()?.len();
    if length > max_len {
        return checkpoint_error(format!("checkpoint manifest exceeds {max_len} bytes"));
    }
    let mut bytes = Vec::with_capacity(length as usize);
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn open_regular(path: &Path) -> ImageResult<File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if !metadata.file_type().is_file() {
        return checkpoint_error(format!(
            "checkpoint member is not a regular file: {}",
            path.display()
        ));
    }
    Ok(File::open(path)?)
}

fn object_path(root: &Path, id: &ObjectId) -> PathBuf {
    let encoded = id
        .as_str()
        .strip_prefix("sha256:")
        .expect("ObjectId validates its algorithm");
    root.join("objects")
        .join("sha256")
        .join(&encoded[..2])
        .join(encoded)
}

fn checkpoint_error<T>(message: impl Into<String>) -> ImageResult<T> {
    Err(checkpoint_error_value(message))
}

fn checkpoint_error_value(message: impl Into<String>) -> ImageError {
    ImageError::ManifestParse(format!("checkpoint closure: {}", message.into()))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::checkpoint::{
        CaptureIntent, ContentRef, DeviceStateRef, MemoryCaptureMode, MemoryExtent,
        ResourceDescriptor, ResourceTreatment,
    };

    fn fixture() -> (tempfile::TempDir, ObjectId) {
        let directory = tempfile::tempdir().unwrap();
        let store = super::super::LocalObjectStore::open(directory.path()).unwrap();
        let memory_bytes = b"memory";
        let memory_object = store.put_bytes(memory_bytes).unwrap();
        let memory = MemoryManifest {
            schema: "microsandbox.memory/1".into(),
            architecture: std::env::consts::ARCH.into(),
            guest_page_size: 4096,
            topology_generation: 1,
            generation: 1,
            capture_mode: MemoryCaptureMode::Full,
            pause_generation: 7,
            extents: vec![MemoryExtent {
                start: 0,
                length: memory_bytes.len() as u64,
                content: MemoryExtentContent::Object(ContentRef {
                    object: memory_object,
                    object_offset: 0,
                }),
            }],
        };
        let memory_id = store
            .put_bytes(&memory.to_canonical_bytes().unwrap())
            .unwrap();
        let execution_id = store.put_bytes(b"execution").unwrap();
        let device_id = store.put_bytes(b"device").unwrap();
        let checkpoint = CheckpointManifest {
            schema: "microsandbox.checkpoint/1".into(),
            checkpoint_id: "checkpoint".into(),
            capture_intent: CaptureIntent::ResumableSnapshot,
            architecture: std::env::consts::ARCH.into(),
            pause_generation: 7,
            execution_state: execution_id,
            memory: memory_id,
            disks: Vec::new(),
            devices: vec![DeviceStateRef {
                device_type: 4,
                device_id: "rng".into(),
                state: device_id,
            }],
            resources: vec![ResourceDescriptor {
                id: "virtio:4:rng".into(),
                kind: "rng".into(),
                treatment: ResourceTreatment::Reset,
                binding: BTreeMap::new(),
            }],
            requires: Vec::new(),
        };
        let root_bytes = checkpoint.to_canonical_bytes().unwrap();
        let root_id = ObjectId::from_bytes(&root_bytes).unwrap();
        std::fs::write(directory.path().join(CHECKPOINT_ROOT_FILE), root_bytes).unwrap();
        (directory, root_id)
    }

    #[test]
    fn opens_complete_valid_closure() {
        let (directory, expected) = fixture();

        let closure = CheckpointClosure::open(directory.path(), Some(&expected)).unwrap();

        assert_eq!(closure.root_id(), &expected);
        assert_eq!(closure.memory().pause_generation, 7);
    }

    #[test]
    fn rejects_replaced_memory_object() {
        let (directory, expected) = fixture();
        let checkpoint = CheckpointManifest::from_bytes(
            &std::fs::read(directory.path().join(CHECKPOINT_ROOT_FILE)).unwrap(),
        )
        .unwrap();
        let memory = MemoryManifest::from_bytes(
            &read_object_verified(directory.path(), &checkpoint.memory, MAX_MANIFEST_BYTES)
                .unwrap(),
        )
        .unwrap();
        let MemoryExtentContent::Object(content) = &memory.extents[0].content else {
            panic!("fixture uses object memory");
        };
        std::fs::write(object_path(directory.path(), &content.object), b"changed").unwrap();

        let closure = CheckpointClosure::open(directory.path(), Some(&expected)).unwrap();
        let error = closure
            .read_object(&content.object, MAX_MANIFEST_BYTES)
            .unwrap_err();

        assert!(matches!(error, ImageError::DigestMismatch { .. }));
    }

    #[test]
    fn explicit_verification_detects_replaced_memory_object() {
        let (directory, expected) = fixture();
        let closure = CheckpointClosure::open(directory.path(), Some(&expected)).unwrap();
        let MemoryExtentContent::Object(content) = &closure.memory().extents[0].content else {
            panic!("fixture uses object memory");
        };
        std::fs::write(object_path(directory.path(), &content.object), b"changed").unwrap();

        let error = closure.verify_memory_objects().unwrap_err();

        assert!(matches!(error, ImageError::DigestMismatch { .. }));
    }
}
