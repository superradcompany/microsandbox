//! Crash-safe local immutable-object storage.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::SystemTime;

use sha2::{Digest as _, Sha256};

use crate::error::{ImageError, ImageResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const FILE_MERKLE_LEAF_SIZE: usize = 64 * 1024;
const MERKLE_LEAF_DOMAIN: &[u8] = b"microsandbox.checkpoint-file/1\0leaf\0";
const MERKLE_PARENT_DOMAIN: &[u8] = b"microsandbox.checkpoint-file/1\0parent\0";
const MERKLE_ROOT_DOMAIN: &[u8] = b"microsandbox.checkpoint-file/1\0root\0";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::snapshot::disk::ObjectId;

/// Filesystem-backed content-addressed object store.
#[derive(Clone, Debug)]
pub struct LocalObjectStore {
    root: PathBuf,
    ownership: Arc<StoreOwnership>,
}

#[derive(Debug, Default)]
struct StoreOwnership {
    publication: Mutex<()>,
}

/// A verified immutable inode identity in a live runtime's owned object store.
///
/// This receipt is neither serializable nor constructible from a path, and is scoped to its store
/// instance. The owning runtime must retain its published object names and never mutate their bytes.
/// Reuse opens and pins the exact inode only for the active operation, checking identity and stamp;
/// missing, replaced or modified members fail closed. Retaining generations therefore costs no FD
/// per object. Unadmitted stores/imports still verify payloads instead of trusting these receipts.
#[derive(Clone, Debug)]
pub struct AdmittedObject {
    id: ObjectId,
    path: PathBuf,
    stamp: ObjectStamp,
    ownership: Arc<StoreOwnership>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ObjectStamp {
    identity: (u64, u64),
    length: u64,
    modified: SystemTime,
}

/// Capture-local object publication with deferred directory durability, but durable file data.
///
/// Finish this batch before publishing any manifest root. Existing `LocalObjectStore::put_bytes`
/// keeps its immediate durability contract; only this explicitly scoped API batches directory sync.
pub struct CaptureObjectBatch {
    store: LocalObjectStore,
    admitted: Mutex<BTreeMap<ObjectId, AdmittedObject>>,
    directories: Mutex<BTreeSet<PathBuf>>,
    hashed_bytes: AtomicU64,
    linked_bytes: AtomicU64,
    copied_bytes: AtomicU64,
    directory_syncs: AtomicU64,
}

/// Actual work performed by a capture object batch, independent of its logical RAM size.
#[derive(Clone, Copy, Debug, Default)]
pub struct CaptureObjectBatchStats {
    /// Bytes hashed to create or admit immutable objects.
    pub hashed_bytes: u64,
    /// Bytes referenced by newly installed closure links, including copy fallbacks.
    pub linked_bytes: u64,
    /// Bytes physically copied when hardlinks were unavailable.
    pub copied_bytes: u64,
    /// Directory durability barriers issued by this batch.
    pub directory_syncs: u64,
}

/// Sparse-aware immutable identity of one physical layer file.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SparseFileIntegrity {
    /// BLAKE3 Merkle root.
    pub root: String,
    /// Logical file length bound by the root.
    pub logical_size: u64,
}

struct MerkleAccumulator {
    levels: Vec<Option<[u8; 32]>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalObjectStore {
    /// Open or create a local object store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> ImageResult<Self> {
        let root = root.into();
        std::fs::create_dir_all(root.join("objects").join("sha256"))?;
        Ok(Self {
            root,
            ownership: Arc::new(StoreOwnership::default()),
        })
    }

    /// Store exact bytes durably and return their immutable identity.
    pub fn put_bytes(&self, bytes: &[u8]) -> ImageResult<ObjectId> {
        let id = ObjectId::from_bytes(bytes)?;
        let path = self.object_path(&id);
        if path.exists() {
            self.verify_existing(&id, &path)?;
            sync_directories_through(path.parent().expect("object parent"), &self.root)?;
            return Ok(id);
        }
        let parent = path.parent().expect("object path has a parent");
        std::fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".{}.{}.tmp", id.hex(), rand::random::<u64>()));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        let published = publish_object_file(&temporary, &path, &self.ownership);
        let _ = std::fs::remove_file(&temporary);
        if !published? {
            self.verify_existing(&id, &path)?;
        }
        sync_directories_through(parent, &self.root)?;
        Ok(id)
    }

    /// Return the confined path of a stored object.
    pub fn object_path(&self, id: &ObjectId) -> PathBuf {
        let encoded = id.hex();
        self.root
            .join("objects")
            .join("sha256")
            .join(&encoded[..2])
            .join(encoded)
    }

    /// Link one existing object into a self-contained checkpoint closure.
    pub fn link_into(&self, id: &ObjectId, closure_root: &Path) -> ImageResult<PathBuf> {
        let source = self.object_path(id);
        self.verify_existing(id, &source)?;
        let encoded = id.hex();
        let target = closure_root
            .join("objects")
            .join("sha256")
            .join(&encoded[..2])
            .join(encoded);
        if target.exists() {
            self.verify_existing(id, &target)?;
            return Ok(target);
        }
        let parent = target.parent().expect("closure object has a parent");
        std::fs::create_dir_all(parent)?;
        match std::fs::hard_link(&source, &target) {
            Ok(()) => {}
            Err(_) => {
                std::fs::copy(&source, &target)?;
                // `FlushFileBuffers`, used by `sync_all` on Windows, requires a handle opened
                // with write access even though the immutable bytes are already complete.
                let sync_result = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&target)
                    .and_then(|file| file.sync_all());
                if let Err(error) = sync_result {
                    let _ = std::fs::remove_file(&target);
                    return Err(error.into());
                }
            }
        }
        sync_directories_through(parent, closure_root)?;
        Ok(target)
    }

    fn verify_existing(&self, id: &ObjectId, path: &Path) -> ImageResult<()> {
        let mut file = File::open(path)?;
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
                digest: id.as_str().into(),
                expected: id.as_str().into(),
                actual,
            });
        }
        Ok(())
    }
}

impl CaptureObjectBatch {
    /// Start a new batch, retaining only explicitly supplied previous-generation capabilities.
    pub fn new(store: LocalObjectStore, previous: &[AdmittedObject]) -> Self {
        let admitted = previous
            .iter()
            .filter(|object| Arc::ptr_eq(&object.ownership, &store.ownership))
            .map(|object| (object.id.clone(), object.clone()))
            .collect();
        Self {
            store,
            admitted: Mutex::new(admitted),
            directories: Mutex::new(BTreeSet::new()),
            hashed_bytes: AtomicU64::new(0),
            linked_bytes: AtomicU64::new(0),
            copied_bytes: AtomicU64::new(0),
            directory_syncs: AtomicU64::new(0),
        }
    }

    /// Hash new bytes once and store durable file data. Directory entries commit at `finish`.
    pub fn put_bytes(&self, bytes: &[u8]) -> ImageResult<ObjectId> {
        let id = ObjectId::from_bytes(bytes)?;
        self.hashed_bytes
            .fetch_add(bytes.len() as u64, Ordering::Relaxed);
        if let Some(object) = self.admitted.lock().unwrap().get(&id).cloned() {
            object.validate()?;
            return Ok(id);
        }
        let path = self.store.object_path(&id);
        if path.exists() {
            self.admit(&id)?;
            // Also sync the path of an object left by a previously interrupted batch.
            self.record_directories(path.parent().unwrap(), &self.store.root);
            return Ok(id);
        }
        let parent = path.parent().expect("object parent");
        std::fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".{}.{}.tmp", id.hex(), rand::random::<u64>()));
        let result = (|| -> ImageResult<AdmittedObject> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);
            if publish_object_file(&temporary, &path, &self.store.ownership)? {
                self.open_admitted(id.clone(), path.clone())
            } else {
                self.admit(&id)
            }
        })();
        let _ = std::fs::remove_file(&temporary);
        let object = result?;
        self.admitted.lock().unwrap().insert(id.clone(), object);
        self.record_directories(parent, &self.store.root);
        Ok(id)
    }

    /// Link admitted bytes without rehashing the generation's complete inherited RAM payload.
    pub fn link_into(&self, id: &ObjectId, closure_root: &Path) -> ImageResult<PathBuf> {
        // A receipt itself is not sufficient authority to read bytes. Pin/check it once below;
        // avoid the redundant open that admitting an already-owned receipt would otherwise do.
        let known = self.admitted.lock().unwrap().get(id).cloned();
        let object = match known {
            Some(object) => object,
            None => self.admit(id)?,
        };
        let pinned = object.pin()?;
        let encoded = id.hex();
        let target = closure_root
            .join("objects")
            .join("sha256")
            .join(&encoded[..2])
            .join(encoded);
        let parent = target.parent().expect("closure object parent");
        std::fs::create_dir_all(parent)?;
        if target.exists() {
            // Existing targets are not automatically part of this batch's ownership. Retain
            // the checked public behavior, except for the exact already-admitted inode.
            let file = File::open(&target)?;
            if ObjectStamp::read(&file)? != object.stamp {
                self.verify_and_sync_target(id, &target)?;
            }
        } else {
            match std::fs::hard_link(&object.path, &target) {
                Ok(()) => {
                    if ObjectStamp::read(&File::open(&target)?)? != object.stamp {
                        let _ = std::fs::remove_file(&target);
                        return Err(
                            std::io::Error::other("admitted object path was replaced").into()
                        );
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    self.verify_and_sync_target(id, &target)?;
                }
                Err(_) => {
                    // Copy the retained inode, not a potentially replaced path. Positioned
                    // reads avoid shared cursor races when several closures reuse one object.
                    copy_admitted_object(&object, &pinned, &target)?;
                    self.copied_bytes
                        .fetch_add(object.stamp.length, Ordering::Relaxed);
                }
            }
            object.validate_pin(&pinned)?;
            self.linked_bytes
                .fetch_add(object.stamp.length, Ordering::Relaxed);
        }
        self.record_directories(parent, closure_root);
        Ok(target)
    }

    fn verify_and_sync_target(&self, id: &ObjectId, path: &Path) -> ImageResult<()> {
        // A pre-existing independent copy may have been written without a durability barrier.
        // Verify and sync the very same open file, rather than hashing one path then flushing a
        // replacement. Windows requires write access for FlushFileBuffers.
        #[cfg(unix)]
        let file = File::open(path)?;
        #[cfg(windows)]
        let file = OpenOptions::new().read(true).write(true).open(path)?;
        let stamp = ObjectStamp::read(&file)?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0; 1024 * 1024];
        let mut offset = 0;
        loop {
            let count = read_object_at(&file, &mut buffer, offset)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            offset += count as u64;
        }
        self.hashed_bytes.fetch_add(offset, Ordering::Relaxed);
        let actual = format!("sha256:{}", hex::encode(hasher.finalize()));
        if actual != id.as_str() {
            return Err(ImageError::DigestMismatch {
                digest: id.to_string(),
                expected: id.to_string(),
                actual,
            });
        }
        file.sync_all()?;
        if ObjectStamp::read(&file)? != stamp || ObjectStamp::read(&File::open(path)?)? != stamp {
            return Err(std::io::Error::other("closure object changed during verification").into());
        }
        Ok(())
    }

    /// Make every new directory entry durable before its caller publishes a root descriptor.
    /// Call only after all batch writers have joined. A failed sync leaves the set available for retry.
    pub fn finish(&self) -> ImageResult<CaptureObjectBatchStats> {
        let mut directories = self.directories.lock().unwrap();
        let mut ordered = directories.iter().collect::<Vec<_>>();
        ordered.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
        for path in ordered {
            #[cfg(unix)]
            {
                File::open(path)?.sync_all()?;
                self.directory_syncs.fetch_add(1, Ordering::Relaxed);
            }
            #[cfg(not(unix))]
            let _ = path;
        }
        directories.clear();
        Ok(self.stats())
    }

    /// Retain exactly the next generation's referenced receipts without keeping object FDs open.
    pub fn retained_objects(&self, ids: &[ObjectId]) -> ImageResult<Vec<AdmittedObject>> {
        ids.iter().map(|id| self.admit(id)).collect()
    }

    /// Read counters without adding timing or content-verification work.
    pub fn stats(&self) -> CaptureObjectBatchStats {
        CaptureObjectBatchStats {
            hashed_bytes: self.hashed_bytes.load(Ordering::Relaxed),
            linked_bytes: self.linked_bytes.load(Ordering::Relaxed),
            copied_bytes: self.copied_bytes.load(Ordering::Relaxed),
            directory_syncs: self.directory_syncs.load(Ordering::Relaxed),
        }
    }

    fn admit(&self, id: &ObjectId) -> ImageResult<AdmittedObject> {
        if let Some(object) = self.admitted.lock().unwrap().get(id).cloned() {
            object.validate()?;
            return Ok(object);
        }
        let object = self.open_admitted(id.clone(), self.store.object_path(id))?;
        let pinned = object.pin()?;
        let mut hasher = Sha256::new();
        let mut buffer = vec![0; 1024 * 1024];
        let mut offset = 0;
        loop {
            let count = read_object_at(&pinned, &mut buffer, offset)?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
            offset += count as u64;
        }
        self.hashed_bytes.fetch_add(offset, Ordering::Relaxed);
        let actual = format!("sha256:{}", hex::encode(hasher.finalize()));
        if actual != id.as_str() {
            return Err(ImageError::DigestMismatch {
                digest: id.to_string(),
                expected: id.to_string(),
                actual,
            });
        }
        object.validate_pin(&pinned)?;
        self.admitted
            .lock()
            .unwrap()
            .insert(id.clone(), object.clone());
        Ok(object)
    }

    fn open_admitted(&self, id: ObjectId, path: PathBuf) -> ImageResult<AdmittedObject> {
        let file = File::open(&path)?;
        let stamp = ObjectStamp::read(&file)?;
        Ok(AdmittedObject {
            id,
            path,
            stamp,
            ownership: Arc::clone(&self.store.ownership),
        })
    }

    fn record_directories(&self, path: &Path, stop: &Path) {
        let mut directories = self.directories.lock().unwrap();
        for directory in path.ancestors() {
            directories.insert(directory.to_path_buf());
            if directory == stop {
                break;
            }
        }
    }
}

impl AdmittedObject {
    fn validate(&self) -> ImageResult<()> {
        self.pin().map(|_| ())
    }

    fn pin(&self) -> ImageResult<File> {
        let file = File::open(&self.path)?;
        self.validate_pin(&file)?;
        Ok(file)
    }

    fn validate_pin(&self, file: &File) -> ImageResult<()> {
        if ObjectStamp::read(file)? != self.stamp {
            return Err(std::io::Error::other("admitted immutable object was modified").into());
        }
        Ok(())
    }
}

impl ObjectStamp {
    fn read(file: &File) -> std::io::Result<Self> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(std::io::Error::other(
                "immutable object is not a regular file",
            ));
        }
        #[cfg(unix)]
        let identity = {
            use std::os::unix::fs::MetadataExt;
            (metadata.dev(), metadata.ino())
        };
        #[cfg(windows)]
        let identity = {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::Storage::FileSystem::{
                BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
            };
            let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::uninit();
            // SAFETY: the file owns a valid handle and the API initializes the output on success.
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
                return Err(std::io::Error::last_os_error());
            }
            let info = unsafe { info.assume_init() };
            (
                u64::from(info.dwVolumeSerialNumber),
                (u64::from(info.nFileIndexHigh) << 32) | u64::from(info.nFileIndexLow),
            )
        };
        Ok(Self {
            identity,
            length: metadata.len(),
            modified: metadata.modified()?,
        })
    }
}

impl MerkleAccumulator {
    fn new(height: u32) -> Self {
        Self {
            levels: vec![None; height as usize + 1],
        }
    }

    fn push_subtree(&mut self, mut height: u32, mut hash: [u8; 32]) {
        loop {
            let slot = &mut self.levels[height as usize];
            match slot.take() {
                Some(left) => {
                    hash = hash_parent(&left, &hash);
                    height += 1;
                }
                None => {
                    *slot = Some(hash);
                    return;
                }
            }
        }
    }

    fn finish(mut self, height: u32) -> [u8; 32] {
        self.levels[height as usize]
            .take()
            .expect("complete Merkle tree has one root")
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn publish_object_file(
    temporary: &Path,
    path: &Path,
    ownership: &StoreOwnership,
) -> std::io::Result<bool> {
    // Atomic no-replace publication keeps admitted inode bindings stable for concurrent writers.
    match std::fs::hard_link(temporary, path) {
        Ok(()) => Ok(true),
        Err(_) if path.exists() => Ok(false),
        Err(_) => {
            // Some filesystems do not support hardlinks. All writers in this runtime's store
            // share the fallback namespace lock; it covers only the final check and rename.
            let _publication = ownership.publication.lock().unwrap();
            if path.exists() {
                return Ok(false);
            }
            std::fs::rename(temporary, path)?;
            Ok(true)
        }
    }
}

fn read_object_at(file: &File, bytes: &mut [u8], offset: u64) -> std::io::Result<usize> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::FileExt;
        file.read_at(bytes, offset)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::FileExt;
        file.seek_read(bytes, offset)
    }
}

fn copy_admitted_object(object: &AdmittedObject, source: &File, target: &Path) -> ImageResult<()> {
    let mut destination = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(target)?;
    let result = (|| -> ImageResult<()> {
        let mut buffer = vec![0; 1024 * 1024];
        let mut offset = 0;
        while offset < object.stamp.length {
            let length = buffer.len().min((object.stamp.length - offset) as usize);
            let count = read_object_at(source, &mut buffer[..length], offset)?;
            if count == 0 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "immutable object was truncated",
                )
                .into());
            }
            destination.write_all(&buffer[..count])?;
            offset += count as u64;
        }
        object.validate_pin(source)?;
        destination.sync_all()?;
        Ok(())
    })();
    drop(destination);
    if result.is_err() {
        let _ = std::fs::remove_file(target);
    }
    result
}

fn sync_directories_through(path: &Path, stop: &Path) -> ImageResult<()> {
    #[cfg(unix)]
    {
        let mut current = Some(path);
        while let Some(directory) = current {
            File::open(directory)?.sync_all()?;
            if directory == stop {
                break;
            }
            current = directory.parent();
        }
    }
    #[cfg(not(unix))]
    let _ = (path, stop);
    Ok(())
}

/// Compute a sparse-aware fixed-leaf Merkle root without reading unallocated holes.
pub fn sparse_file_integrity(path: &Path) -> ImageResult<SparseFileIntegrity> {
    let started = std::time::Instant::now();
    let mut file = File::open(path)?;
    let logical_size = file.metadata()?.len();
    let logical_leaves = logical_size.div_ceil(FILE_MERKLE_LEAF_SIZE as u64).max(1);
    let tree_leaves = logical_leaves.next_power_of_two();
    let tree_height = tree_leaves.trailing_zeros();
    let zero_roots = zero_subtree_roots(tree_height);
    let allocation_map = microsandbox_utils::extent::ExtentMap::scan_file(&file)?;
    let ranges = allocated_leaf_ranges(allocation_map.as_ref(), logical_size, logical_leaves);
    let mut accumulator = MerkleAccumulator::new(tree_height);
    let mut cursor = 0u64;
    let mut buffer = vec![0u8; FILE_MERKLE_LEAF_SIZE];
    let mut read_bytes = 0u64;
    let mut read_leaves = 0u64;

    for (start, end) in ranges {
        push_zero_range(&mut accumulator, &zero_roots, cursor, start);
        for leaf in start..end {
            let offset = leaf * FILE_MERKLE_LEAF_SIZE as u64;
            let readable = logical_size
                .saturating_sub(offset)
                .min(FILE_MERKLE_LEAF_SIZE as u64) as usize;
            buffer.fill(0);
            file.seek(SeekFrom::Start(offset))?;
            file.read_exact(&mut buffer[..readable])?;
            read_bytes += readable as u64;
            read_leaves += 1;
            accumulator.push_subtree(0, hash_leaf(&buffer));
        }
        cursor = end;
    }
    push_zero_range(&mut accumulator, &zero_roots, cursor, tree_leaves);

    let mut root = blake3::Hasher::new();
    root.update(MERKLE_ROOT_DOMAIN);
    root.update(&logical_size.to_le_bytes());
    root.update(&(FILE_MERKLE_LEAF_SIZE as u32).to_le_bytes());
    root.update(&tree_height.to_le_bytes());
    root.update(&accumulator.finish(tree_height));
    tracing::info!(target: "microsandbox_checkpoint_timing", operation = "disk_hash", logical_bytes = logical_size, read_bytes, read_leaves, hash_us = started.elapsed().as_micros(), "sealed disk integrity timing");
    Ok(SparseFileIntegrity {
        root: format!("blake3:{}", root.finalize().to_hex()),
        logical_size,
    })
}

fn allocated_leaf_ranges(
    map: Option<&microsandbox_utils::extent::ExtentMap>,
    logical_size: u64,
    logical_leaves: u64,
) -> Vec<(u64, u64)> {
    if logical_size == 0 {
        return Vec::new();
    }
    let Some(map) = map else {
        return vec![(0, logical_leaves)];
    };
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for (offset, length) in &map.extents {
        let start = offset / FILE_MERKLE_LEAF_SIZE as u64;
        let end = offset
            .saturating_add(*length)
            .div_ceil(FILE_MERKLE_LEAF_SIZE as u64)
            .min(logical_leaves);
        if end <= start {
            continue;
        }
        match ranges.last_mut() {
            Some((_, previous_end)) if start <= *previous_end => {
                *previous_end = (*previous_end).max(end);
            }
            _ => ranges.push((start, end)),
        }
    }
    ranges
}

fn zero_subtree_roots(height: u32) -> Vec<[u8; 32]> {
    let mut roots = vec![hash_leaf(&vec![0u8; FILE_MERKLE_LEAF_SIZE])];
    for level in 1..=height {
        let child = roots[level as usize - 1];
        roots.push(hash_parent(&child, &child));
    }
    roots
}

fn push_zero_range(
    accumulator: &mut MerkleAccumulator,
    zero_roots: &[[u8; 32]],
    mut start: u64,
    end: u64,
) {
    while start < end {
        let remaining_height = 63 - (end - start).leading_zeros();
        let alignment_height = if start == 0 {
            remaining_height
        } else {
            start.trailing_zeros().min(remaining_height)
        };
        accumulator.push_subtree(alignment_height, zero_roots[alignment_height as usize]);
        start += 1u64 << alignment_height;
    }
}

fn hash_leaf(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MERKLE_LEAF_DOMAIN);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

fn hash_parent(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(MERKLE_PARENT_DOMAIN);
    hasher.update(left);
    hasher.update(right);
    *hasher.finalize().as_bytes()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capture_batch_reuses_owned_objects_and_syncs_each_directory_once() {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(directory.path().join("store")).unwrap();
        let first = CaptureObjectBatch::new(store.clone(), &[]);
        let id = first.put_bytes(b"captured immutable RAM").unwrap();
        first
            .link_into(&id, &directory.path().join("first"))
            .unwrap();
        let stats = first.finish().unwrap();
        assert_eq!(
            stats.hashed_bytes, 22,
            "new objects must not be rehashed when linked"
        );
        let retained = first.retained_objects(std::slice::from_ref(&id)).unwrap();
        let second = CaptureObjectBatch::new(store, &retained);
        second
            .link_into(&id, &directory.path().join("second"))
            .unwrap();
        second
            .link_into(&id, &directory.path().join("second"))
            .unwrap();
        let stats = second.finish().unwrap();
        assert_eq!(stats.hashed_bytes, 0);
        assert_eq!(stats.linked_bytes, 22);
        #[cfg(unix)]
        assert_eq!(
            stats.directory_syncs, 4,
            "prefix, algorithm, objects and closure directories"
        );
        assert_eq!(
            second.finish().unwrap().directory_syncs,
            stats.directory_syncs
        );
    }

    #[test]
    fn capture_batch_checks_unadmitted_data_and_pinned_copy_keeps_exact_inode() {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(directory.path().join("store")).unwrap();
        let id = store.put_bytes(b"original").unwrap();
        let batch = CaptureObjectBatch::new(store.clone(), &[]);
        batch
            .link_into(&id, &directory.path().join("first"))
            .unwrap();
        assert_eq!(batch.stats().hashed_bytes, 8);
        let admitted = batch
            .retained_objects(std::slice::from_ref(&id))
            .unwrap()
            .remove(0);
        let pinned = admitted.pin().unwrap();
        // An active operation's pin is sufficient for a copy even if its original entry is
        // unlinked. A later operation must refuse: the runtime no longer owns that name.
        std::fs::remove_file(store.object_path(&id)).unwrap();
        let target = directory.path().join("pinned-copy");
        copy_admitted_object(&admitted, &pinned, &target).unwrap();
        assert_eq!(std::fs::read(target).unwrap(), b"original");
        assert!(
            batch
                .link_into(&id, &directory.path().join("second"))
                .is_err()
        );

        let corrupt_id = store.put_bytes(b"must be checked").unwrap();
        std::fs::write(store.object_path(&corrupt_id), b"corrupted").unwrap();
        let fresh = CaptureObjectBatch::new(store, &[]);
        assert!(
            fresh
                .link_into(&corrupt_id, &directory.path().join("bad"))
                .is_err()
        );
    }

    #[test]
    fn capture_batch_rejects_replaced_or_modified_admitted_inodes() {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(directory.path().join("store")).unwrap();
        let batch = CaptureObjectBatch::new(store.clone(), &[]);
        let id = batch.put_bytes(b"original").unwrap();
        let path = store.object_path(&id);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, b"replaced").unwrap();
        assert!(
            batch
                .link_into(&id, &directory.path().join("replaced"))
                .is_err()
        );

        let other = batch.put_bytes(b"another object").unwrap();
        // Length change is portable and reliably visible even on coarse timestamp filesystems.
        std::fs::write(store.object_path(&other), b"short").unwrap();
        assert!(
            batch
                .link_into(&other, &directory.path().join("mutated"))
                .is_err()
        );
        assert!(batch.put_bytes(b"another object").is_err());
    }

    #[test]
    fn capture_batch_directory_failure_does_not_report_durable_completion() {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(directory.path().join("store")).unwrap();
        let batch = CaptureObjectBatch::new(store.clone(), &[]);
        let id = batch
            .put_bytes(b"durable data pending publication")
            .unwrap();
        let closure = directory.path().join("closure");
        batch.link_into(&id, &closure).unwrap();
        #[cfg(unix)]
        {
            std::fs::remove_dir_all(&closure).unwrap();
            assert!(batch.finish().is_err());
        }
        assert!(!closure.join("checkpoint.json").exists());
        assert!(store.object_path(&id).is_file());
    }

    #[test]
    fn existing_independent_closure_copies_are_verified_before_reuse() {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(directory.path().join("store")).unwrap();
        let batch = CaptureObjectBatch::new(store.clone(), &[]);
        let id = batch.put_bytes(b"original").unwrap();
        let closure = directory.path().join("closure");
        let target = LocalObjectStore::open(&closure).unwrap().object_path(&id);
        std::fs::create_dir_all(target.parent().unwrap()).unwrap();
        // A separate inode, initially written without sync_all, must not inherit source admission.
        std::fs::write(&target, b"original").unwrap();
        batch.link_into(&id, &closure).unwrap();
        assert_eq!(batch.stats().hashed_bytes, 16);
        batch.finish().unwrap();
        std::fs::write(&target, b"modified").unwrap();
        assert!(batch.link_into(&id, &closure).is_err());
        assert_eq!(
            std::fs::read(&target).unwrap(),
            b"modified",
            "never delete a pre-existing target on verification failure"
        );
        assert_eq!(std::fs::read(store.object_path(&id)).unwrap(), b"original");
    }

    #[test]
    fn concurrent_checked_and_batched_writers_keep_the_winning_inode() {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(directory.path().join("store")).unwrap();
        let batch = Arc::new(CaptureObjectBatch::new(store.clone(), &[]));
        let gate = std::sync::Barrier::new(8);
        let payload = vec![7; 65536];
        std::thread::scope(|scope| {
            let handles = (0..8)
                .map(|index| {
                    let gate = &gate;
                    let payload = &payload;
                    let batch = &batch;
                    let store = &store;
                    scope.spawn(move || {
                        gate.wait();
                        if index % 2 == 0 {
                            store.put_bytes(payload)
                        } else {
                            batch.put_bytes(payload)
                        }
                        .unwrap()
                    })
                })
                .collect::<Vec<_>>();
            let expected = ObjectId::from_bytes(&payload).unwrap();
            for handle in handles {
                assert_eq!(handle.join().unwrap(), expected);
            }
        });
        let id = ObjectId::from_bytes(&payload).unwrap();
        batch
            .link_into(&id, &directory.path().join("closure"))
            .unwrap();
        batch.finish().unwrap();
        let stamp = ObjectStamp::read(&File::open(store.object_path(&id)).unwrap()).unwrap();
        assert_eq!(batch.retained_objects(&[id]).unwrap()[0].stamp, stamp);
    }

    #[test]
    #[ignore = "opt-in old/new object-store experiment; prints measured times, not a CI latency threshold"]
    fn capture_store_full_incremental_experiment() {
        const COUNT: usize = 16;
        const SIZE: usize = 1024 * 1024;
        const DELTA: usize = 4096;
        let directory = tempfile::tempdir().unwrap();
        let payloads = (0..COUNT)
            .map(|index| vec![index as u8 + 1; SIZE])
            .collect::<Vec<_>>();
        let changed = vec![255; DELTA];
        for round in 0..3 {
            let old =
                LocalObjectStore::open(directory.path().join(format!("old-{round}"))).unwrap();
            let started = std::time::Instant::now();
            let mut old_ids = Vec::new();
            for bytes in &payloads {
                let id = old.put_bytes(bytes).unwrap();
                old.link_into(&id, &directory.path().join(format!("old-full-{round}")))
                    .unwrap();
                old_ids.push(id);
            }
            let old_full_us = started.elapsed().as_micros();
            let started = std::time::Instant::now();
            old_ids.push(old.put_bytes(&changed).unwrap());
            for id in &old_ids {
                old.link_into(id, &directory.path().join(format!("old-delta-{round}")))
                    .unwrap();
            }
            let old_delta_us = started.elapsed().as_micros();

            let new =
                LocalObjectStore::open(directory.path().join(format!("new-{round}"))).unwrap();
            let full = CaptureObjectBatch::new(new.clone(), &[]);
            let started = std::time::Instant::now();
            let mut new_ids = Vec::new();
            for bytes in &payloads {
                let id = full.put_bytes(bytes).unwrap();
                full.link_into(&id, &directory.path().join(format!("new-full-{round}")))
                    .unwrap();
                new_ids.push(id);
            }
            let full_stats = full.finish().unwrap();
            let receipts = full.retained_objects(&new_ids).unwrap();
            let new_full_us = started.elapsed().as_micros();
            let delta = CaptureObjectBatch::new(new, &receipts);
            let started = std::time::Instant::now();
            new_ids.push(delta.put_bytes(&changed).unwrap());
            for id in &new_ids {
                delta
                    .link_into(id, &directory.path().join(format!("new-delta-{round}")))
                    .unwrap();
            }
            let delta_stats = delta.finish().unwrap();
            let new_delta_us = started.elapsed().as_micros();
            assert_eq!(
                old_ids, new_ids,
                "the optimized publication preserves content identities"
            );
            assert_eq!(full_stats.hashed_bytes, (COUNT * SIZE) as u64);
            assert_eq!(
                delta_stats.hashed_bytes, DELTA as u64,
                "inherited payload must not be read again"
            );
            #[cfg(unix)]
            {
                assert!(full_stats.directory_syncs <= (2 * (COUNT + 3)) as u64);
                assert!(delta_stats.directory_syncs <= (COUNT + 8) as u64);
            }
            // Old byte/sync counts follow the unchanged checked public path's exact loop; new
            // counts come from runtime counters. Timings are measured; no speed ratio is asserted.
            println!(
                "{}",
                serde_json::json!({
                    "experiment": "capture_object_store", "round": round,
                    "baseline_bytes": COUNT * SIZE, "changed_bytes": DELTA,
                    "old_full_us": old_full_us, "new_full_us": new_full_us,
                    "old_incremental_us": old_delta_us, "new_incremental_us": new_delta_us,
                    "old_full_expected_hashed_bytes": 2 * COUNT * SIZE,
                    "old_incremental_expected_hashed_bytes": COUNT * SIZE + 2 * DELTA,
                    "new_full_hashed_bytes": full_stats.hashed_bytes,
                    "new_incremental_hashed_bytes": delta_stats.hashed_bytes,
                    "new_full_directory_syncs": full_stats.directory_syncs,
                    "new_incremental_directory_syncs": delta_stats.directory_syncs
                })
            );
        }
    }

    #[test]
    fn admission_receipts_do_not_escape_their_store_lifetime() {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(directory.path()).unwrap();
        let first = CaptureObjectBatch::new(store.clone(), &[]);
        let id = first.put_bytes(b"payload").unwrap();
        let receipts = first.retained_objects(std::slice::from_ref(&id)).unwrap();
        first.finish().unwrap();
        // Opening the same path does not confer the old runtime's ownership. Re-admit bytes.
        let reopened =
            CaptureObjectBatch::new(LocalObjectStore::open(directory.path()).unwrap(), &receipts);
        reopened
            .retained_objects(std::slice::from_ref(&id))
            .unwrap();
        assert_eq!(reopened.stats().hashed_bytes, 7);
    }

    #[cfg(unix)]
    #[test]
    fn retained_receipts_fit_low_fd_budget() {
        const CHILD: &str = "MSB_STORE_LOW_FD_TEST_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let result = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "checkpoint::store::tests::retained_receipts_fit_low_fd_budget",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(result.success());
            return;
        }
        // Set a low limit only in this isolated test process, never in the parallel test runner.
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, limit.as_mut_ptr()) },
            0
        );
        let mut limit = unsafe { limit.assume_init() };
        limit.rlim_cur = limit.rlim_cur.min(64);
        assert_eq!(unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) }, 0);
        let directory = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(directory.path().join("store")).unwrap();
        let first = CaptureObjectBatch::new(store.clone(), &[]);
        let ids = (0_u32..512)
            .map(|index| first.put_bytes(&index.to_le_bytes()).unwrap())
            .collect::<Vec<_>>();
        first.finish().unwrap();
        let receipts = first.retained_objects(&ids).unwrap();
        drop(first);
        let second = CaptureObjectBatch::new(store, &receipts);
        for id in &ids {
            second
                .link_into(id, &directory.path().join("closure"))
                .unwrap();
        }
        assert_eq!(second.finish().unwrap().hashed_bytes, 0);
    }

    #[test]
    fn identical_objects_are_reused_and_linked_into_a_closure() {
        let directory = tempfile::tempdir().unwrap();
        let store = LocalObjectStore::open(directory.path().join("store")).unwrap();
        let first = store.put_bytes(b"same bytes").unwrap();
        let second = store.put_bytes(b"same bytes").unwrap();
        assert_eq!(first, second);

        let linked = store
            .link_into(&first, &directory.path().join("checkpoint"))
            .unwrap();
        assert_eq!(std::fs::read(linked).unwrap(), b"same bytes");
    }

    #[test]
    fn sparse_integrity_does_not_depend_on_hole_allocation() {
        let directory = tempfile::tempdir().unwrap();
        let sparse = directory.path().join("sparse.raw");
        let dense = directory.path().join("dense.raw");
        let sparse_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&sparse)
            .unwrap();
        microsandbox_utils::extent::mark_sparse(&sparse_file).unwrap();
        sparse_file.set_len(8 * 1024 * 1024).unwrap();
        sparse_file.sync_all().unwrap();
        std::fs::write(&dense, vec![0u8; 8 * 1024 * 1024]).unwrap();

        assert_eq!(
            sparse_file_integrity(&sparse).unwrap(),
            sparse_file_integrity(&dense).unwrap()
        );
    }
}
