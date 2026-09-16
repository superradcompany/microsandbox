//! Strict resolver for one self-contained composite-checkpoint closure.

use std::collections::BTreeSet;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Instant;

use sha2::{Digest as _, Sha256};

use super::admitted_disk::AdmittedDiskLayers;
use super::{
    CheckpointManifest, DiskGenerationManifest, DiskLayerRef, MemoryExtentContent, MemoryManifest,
    ObjectId,
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
    admitted_disks: AdmittedDiskLayers,
}

/// Separate wall times for loading and verifying one checkpoint object.
#[derive(Clone, Copy, Debug, Default)]
pub struct CheckpointObjectReadTiming {
    /// File open, allocation or buffer growth, and read time in microseconds.
    pub read_us: u128,
    /// Identity verification time in microseconds.
    pub hash_us: u128,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CheckpointClosure {
    /// Inspect the bounded, identity-verified root for construction planning, not payload admission.
    /// The child closure must still be fully opened before its contents are consumed.
    pub fn inspect_manifest(
        root: &Path,
        expected_root: Option<&ObjectId>,
    ) -> ImageResult<CheckpointManifest> {
        read_checkpoint_root(root, expected_root).map(|(_, manifest)| manifest)
    }

    /// Open and validate a checkpoint closure for restore on this host architecture.
    pub fn open(root: impl Into<PathBuf>, expected_root: Option<&ObjectId>) -> ImageResult<Self> {
        Self::open_inner(root.into(), expected_root, true)
    }

    /// Open and validate a checkpoint closure without requiring host architecture compatibility.
    ///
    /// Inspection, verification, and archive transport use this path. Construction must use
    /// [`open`](Self::open) so an incompatible checkpoint cannot reach restore.
    pub fn open_portable(
        root: impl Into<PathBuf>,
        expected_root: Option<&ObjectId>,
    ) -> ImageResult<Self> {
        Self::open_inner(root.into(), expected_root, false)
    }

    fn open_inner(
        root: PathBuf,
        expected_root: Option<&ObjectId>,
        require_host_architecture: bool,
    ) -> ImageResult<Self> {
        let (root_id, checkpoint) = read_checkpoint_root(&root, expected_root)?;
        if require_host_architecture && checkpoint.architecture != std::env::consts::ARCH {
            return checkpoint_error(format!(
                "checkpoint architecture {} cannot restore on {}",
                checkpoint.architecture,
                std::env::consts::ARCH
            ));
        }

        let memory_bytes = read_object_verified(&root, &checkpoint.memory, MAX_MANIFEST_BYTES)?;
        crate::snapshot::verify_owned_directory_payloads(&root, &checkpoint.owned_volumes)?;
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
        let mut admitted_disks = AdmittedDiskLayers::default();
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
            for layer in &disk.layers {
                let path = disk_layer_path(&root, layer);
                if open_regular(&path)?.metadata()?.len() != layer.file_size {
                    return checkpoint_error("disk layer length differs from captured file size");
                }
                if let Some(expected) = &layer.integrity_root {
                    admitted_disks.admit(&path, expected)?;
                }
            }
            disks.push(disk);
        }
        for volume in &checkpoint.owned_volumes {
            if let crate::snapshot::OwnedVolumeData::Disk { generation } = &volume.data
                && !disks.contains(generation)
            {
                return checkpoint_error("owned disk is absent from the checkpoint closure");
            }
        }

        Ok(Self {
            root,
            root_id,
            checkpoint,
            memory,
            disks,
            admitted_disks,
        })
    }

    /// Return the immutable root identity computed from canonical `checkpoint.json` bytes.
    pub fn root_id(&self) -> &ObjectId {
        &self.root_id
    }

    /// Root of this verified immutable closure.
    pub fn root(&self) -> &Path {
        &self.root
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

    /// Load and verify one object into reusable storage, without changing its identity contract.
    /// The buffer must not be consumed when this method fails.
    pub fn read_object_into(
        &self,
        id: &ObjectId,
        max_len: u64,
        bytes: &mut Vec<u8>,
    ) -> ImageResult<CheckpointObjectReadTiming> {
        read_object_verified_into(&self.root, id, max_len, bytes)
    }

    /// Return the confined path of a validated disk layer.
    pub fn disk_layer_path(&self, layer: &DiskLayerRef) -> PathBuf {
        disk_layer_path(&self.root, layer)
    }

    /// Reuse a disk root only while the candidate is the exact unchanged admitted file.
    /// Copies, rewritten qcow headers, replaced names, and uncached layers return no reusable root.
    /// A later explicit integrity capture may compute one. Retained file handles are bounded.
    pub fn reused_disk_integrity(&self, path: &Path) -> ImageResult<Option<String>> {
        self.admitted_disks
            .reuse_for(path)
            .map(|root| root.map(str::to_owned))
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

fn read_checkpoint_root(
    root: &Path,
    expected_root: Option<&ObjectId>,
) -> ImageResult<(ObjectId, CheckpointManifest)> {
    if !std::fs::symlink_metadata(root)?.file_type().is_dir() {
        return checkpoint_error("checkpoint root is not a directory");
    }
    let bytes = read_regular_bounded(&root.join(CHECKPOINT_ROOT_FILE), MAX_MANIFEST_BYTES)?;
    let id = ObjectId::from_bytes(&bytes)?;
    if let Some(expected) = expected_root.filter(|expected| *expected != &id) {
        return Err(ImageError::DigestMismatch {
            digest: id.to_string(),
            expected: expected.to_string(),
            actual: id.to_string(),
        });
    }
    Ok((id, CheckpointManifest::from_bytes(&bytes)?))
}

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

fn disk_layer_path(root: &Path, layer: &DiskLayerRef) -> PathBuf {
    root.join("layers")
        .join(format!("{}.{}", layer.layer_id, layer.format))
}

fn read_object_verified(root: &Path, id: &ObjectId, max_len: u64) -> ImageResult<Vec<u8>> {
    let mut bytes = Vec::new();
    read_object_verified_into(root, id, max_len, &mut bytes)?;
    Ok(bytes)
}

fn read_object_verified_into(
    root: &Path,
    id: &ObjectId,
    max_len: u64,
    bytes: &mut Vec<u8>,
) -> ImageResult<CheckpointObjectReadTiming> {
    let started = Instant::now();
    let path = object_path(root, id);
    let mut file = open_regular(&path)?;
    let length = file.metadata()?.len();
    if length > max_len {
        return checkpoint_error(format!("checkpoint object exceeds {max_len} bytes"));
    }
    let length = usize::try_from(length)
        .map_err(|_| checkpoint_error_value("checkpoint object exceeds host limits"))?;
    // Keep the initialized buffer between packs. Unlike clear + resize this does not zero
    // an entire reused pack before the file read overwrites it. A growing file cannot make
    // read_to_end allocate beyond the admitted object bound.
    bytes.resize(length, 0);
    file.read_exact(bytes)?;
    if file.read(&mut [0u8; 1])? != 0 {
        return checkpoint_error("checkpoint object changed length during read");
    }
    let read_us = started.elapsed().as_micros();
    let hash_started = Instant::now();
    let actual = ObjectId::from_bytes(bytes)?;
    if &actual != id {
        return Err(ImageError::DigestMismatch {
            digest: id.to_string(),
            expected: id.to_string(),
            actual: actual.to_string(),
        });
    }
    Ok(CheckpointObjectReadTiming {
        read_us,
        hash_us: hash_started.elapsed().as_micros(),
    })
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

    #[test]
    fn reusable_object_reader_checks_each_identity_and_reuses_allocation() {
        let directory = tempfile::tempdir().unwrap();
        let store = super::super::LocalObjectStore::open(directory.path()).unwrap();
        let first = store.put_bytes(b"first payload").unwrap();
        let second = store.put_bytes(b"next payload!").unwrap();
        let mut buffer = Vec::with_capacity(64);
        let allocation = buffer.as_ptr();
        read_object_verified_into(directory.path(), &first, 64, &mut buffer).unwrap();
        assert_eq!(buffer, b"first payload");
        read_object_verified_into(directory.path(), &second, 64, &mut buffer).unwrap();
        assert_eq!(buffer, b"next payload!");
        assert_eq!(buffer.as_ptr(), allocation);
        assert!(read_object_verified_into(directory.path(), &first, 4, &mut buffer).is_err());
        std::fs::write(store.object_path(&second), b"bad payload!!").unwrap();
        assert!(matches!(
            read_object_verified_into(directory.path(), &second, 64, &mut buffer),
            Err(ImageError::DigestMismatch { .. })
        ));
    }

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
            capture_intent: CaptureIntent::FullSnapshot,
            geometry: crate::checkpoint::CheckpointGeometry {
                vcpus: 1,
                max_vcpus: 1,
                memory_mib: 128,
                max_memory_mib: 128,
            },
            architecture: std::env::consts::ARCH.into(),
            pause_generation: 7,
            execution_state: execution_id,
            memory: memory_id,
            disks: Vec::new(),
            owned_volumes: Vec::new(),
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
    fn manifest_inspection_does_not_substitute_for_payload_admission() {
        let (directory, root) = fixture();
        let manifest = CheckpointClosure::inspect_manifest(directory.path(), Some(&root)).unwrap();
        std::fs::remove_file(super::object_path(
            directory.path(),
            &manifest.execution_state,
        ))
        .unwrap();
        assert!(CheckpointClosure::inspect_manifest(directory.path(), Some(&root)).is_ok());
        assert!(CheckpointClosure::open(directory.path(), Some(&root)).is_err());
        let wrong = ObjectId::from_bytes(b"wrong root").unwrap();
        assert!(CheckpointClosure::inspect_manifest(directory.path(), Some(&wrong)).is_err());
    }

    #[test]
    fn optional_disk_integrity_retains_length_checks_and_detects_opted_in_corruption() {
        use crate::checkpoint::{
            DiskGenerationManifest, DiskLayerRef, LocalObjectStore, sparse_file_integrity,
        };
        for record_integrity in [false, true] {
            let (directory, root) = fixture();
            let mut checkpoint =
                CheckpointClosure::inspect_manifest(directory.path(), Some(&root)).unwrap();
            let store = LocalObjectStore::open(directory.path()).unwrap();
            std::fs::create_dir(directory.path().join("layers")).unwrap();
            let path = directory.path().join("layers/base.raw");
            std::fs::write(&path, [17; 4096]).unwrap();
            let disk = DiskGenerationManifest {
                schema: "microsandbox.disk-generation/1".into(),
                volume_id: "volume".into(),
                device_id: "vdb".into(),
                generation: 1,
                pause_generation: checkpoint.pause_generation,
                head: "base".into(),
                layers: vec![DiskLayerRef {
                    layer_id: "base".into(),
                    format: "raw".into(),
                    virtual_size: 4096,
                    file_size: 4096,
                    predecessor: None,
                    integrity_root: record_integrity
                        .then(|| sparse_file_integrity(&path).unwrap().root),
                }],
            };
            checkpoint.disks = vec![
                store
                    .put_bytes(&disk.to_canonical_bytes().unwrap())
                    .unwrap(),
            ];
            std::fs::write(
                directory.path().join(CHECKPOINT_ROOT_FILE),
                checkpoint.to_canonical_bytes().unwrap(),
            )
            .unwrap();
            assert!(CheckpointClosure::open(directory.path(), None).is_ok());
            // Same-length content changes are intentionally only detectable when opted in.
            std::fs::write(&path, [18; 4096]).unwrap();
            assert_eq!(
                CheckpointClosure::open(directory.path(), None).is_err(),
                record_integrity
            );
            std::fs::write(&path, [17; 4095]).unwrap();
            let error = CheckpointClosure::open(directory.path(), None)
                .err()
                .unwrap()
                .to_string();
            assert!(error.contains("length"), "{error}");
        }
    }

    #[test]
    fn opens_complete_valid_closure() {
        let (directory, expected) = fixture();

        let closure = CheckpointClosure::open(directory.path(), Some(&expected)).unwrap();

        assert_eq!(closure.root_id(), &expected);
        assert_eq!(closure.memory().pause_generation, 7);
    }

    #[test]
    fn deep_closure_admission_keeps_file_handles_bounded() {
        #[cfg(unix)]
        if std::env::var_os("MSB_TEST_DEEP_ADMISSION_LOW_FD").is_none() {
            use std::os::unix::process::CommandExt;

            // Isolate the process-wide limit from concurrently running tests. The old one-FD-
            // per-layer implementation cannot admit these 512 files with only 64 descriptors.
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .args([
                    "--exact",
                    "checkpoint::resolver::tests::deep_closure_admission_keeps_file_handles_bounded",
                    "--nocapture",
                ])
                .env("MSB_TEST_DEEP_ADMISSION_LOW_FD", "1");
            // SAFETY: the pre-exec callback only invokes async-signal-safe libc resource-limit
            // operations; it does not allocate or acquire locks in the forked child.
            unsafe {
                child.pre_exec(|| {
                    let mut limit = std::mem::zeroed::<libc::rlimit>();
                    if libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    limit.rlim_cur = limit.rlim_max.min(64);
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "low-FD admission failed: {}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
            return;
        }

        let (directory, _) = fixture();
        let store = super::super::LocalObjectStore::open(directory.path()).unwrap();
        let root_path = directory.path().join(CHECKPOINT_ROOT_FILE);
        let mut checkpoint =
            CheckpointManifest::from_bytes(&std::fs::read(&root_path).unwrap()).unwrap();
        std::fs::create_dir_all(directory.path().join("layers")).unwrap();
        let mut paths = Vec::new();
        // Each volume stays inside the existing 256-layer manifest limit. Disk header codecs
        // are runtime concerns: this resolver fixture exercises byte admission and membership.
        for volume in 0..2 {
            let mut layers = Vec::new();
            for index in 0..256 {
                let layer_id = format!("volume_{volume}_layer_{index}");
                let format = if index == 0 { "raw" } else { "qcow2" };
                let path = directory
                    .path()
                    .join("layers")
                    .join(format!("{layer_id}.{format}"));
                std::fs::write(&path, [0x55]).unwrap();
                let integrity_root = super::super::sparse_file_integrity(&path).unwrap().root;
                layers.push(DiskLayerRef {
                    file_size: 1,
                    layer_id,
                    format: format.into(),
                    virtual_size: 4096,
                    predecessor: (index > 0)
                        .then(|| format!("volume_{volume}_layer_{}", index - 1)),
                    integrity_root: Some(integrity_root),
                });
                paths.push(path);
            }
            let disk = DiskGenerationManifest {
                schema: "microsandbox.disk-generation/1".into(),
                volume_id: format!("volume_{volume}"),
                device_id: format!("device_{volume}"),
                generation: 1,
                head: layers.last().unwrap().layer_id.clone(),
                layers,
                pause_generation: checkpoint.pause_generation,
            };
            checkpoint.disks.push(
                store
                    .put_bytes(&disk.to_canonical_bytes().unwrap())
                    .unwrap(),
            );
        }
        let bytes = checkpoint.to_canonical_bytes().unwrap();
        let root = ObjectId::from_bytes(&bytes).unwrap();
        std::fs::write(&root_path, bytes).unwrap();

        let closure = CheckpointClosure::open(directory.path(), Some(&root)).unwrap();
        assert_eq!(closure.disks().len(), 2);
        assert!(closure.disks().iter().all(|disk| disk.layers.len() == 256));
        let reusable = paths
            .iter()
            .filter(|path| closure.reused_disk_integrity(path).unwrap().is_some())
            .count();
        assert_eq!(reusable, 32);
        drop(closure);

        // A layer outside the retained receipt set must still be verified during admission.
        std::fs::write(paths.last().unwrap(), [0xAA]).unwrap();
        assert!(matches!(
            CheckpointClosure::open(directory.path(), Some(&root)),
            Err(ImageError::DigestMismatch { .. })
        ));
    }

    #[test]
    fn portable_open_separates_integrity_from_restore_architecture() {
        let (directory, _expected) = fixture();
        let root_path = directory.path().join(CHECKPOINT_ROOT_FILE);
        let mut checkpoint =
            CheckpointManifest::from_bytes(&std::fs::read(&root_path).unwrap()).unwrap();
        checkpoint.architecture = "another-architecture".into();
        let memory_path = object_path(directory.path(), &checkpoint.memory);
        let mut memory = MemoryManifest::from_bytes(&std::fs::read(&memory_path).unwrap()).unwrap();
        memory.architecture = checkpoint.architecture.clone();
        let store = super::super::LocalObjectStore::open(directory.path()).unwrap();
        checkpoint.memory = store
            .put_bytes(&memory.to_canonical_bytes().unwrap())
            .unwrap();
        let root_bytes = checkpoint.to_canonical_bytes().unwrap();
        let expected = ObjectId::from_bytes(&root_bytes).unwrap();
        std::fs::write(root_path, root_bytes).unwrap();

        CheckpointClosure::open_portable(directory.path(), Some(&expected)).unwrap();
        let error = CheckpointClosure::open(directory.path(), Some(&expected)).unwrap_err();
        assert!(error.to_string().contains("cannot restore"));
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
