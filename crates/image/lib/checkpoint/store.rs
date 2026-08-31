//! Crash-safe local immutable-object storage.

use std::fmt;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
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

/// Algorithm-qualified immutable object identity.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct ObjectId(String);

/// Filesystem-backed content-addressed object store.
#[derive(Clone, Debug)]
pub struct LocalObjectStore {
    root: PathBuf,
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

impl ObjectId {
    /// Compute an identity from exact bytes.
    pub fn from_bytes(bytes: &[u8]) -> ImageResult<Self> {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        Self::new(format!("sha256:{}", hex::encode(hasher.finalize())))
    }

    /// Parse and validate an algorithm-qualified identity.
    pub fn new(value: impl Into<String>) -> ImageResult<Self> {
        let value = value.into();
        let Some(encoded) = value.strip_prefix("sha256:") else {
            return Err(ImageError::ManifestParse(
                "object identity must use sha256".into(),
            ));
        };
        if encoded.len() != 64
            || !encoded
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(ImageError::ManifestParse(format!(
                "invalid object identity: {value}"
            )));
        }
        Ok(Self(value))
    }

    /// Return the qualified identity.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn hex(&self) -> &str {
        self.0.strip_prefix("sha256:").expect("validated identity")
    }
}

impl LocalObjectStore {
    /// Open or create a local object store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> ImageResult<Self> {
        let root = root.into();
        std::fs::create_dir_all(root.join("objects").join("sha256"))?;
        Ok(Self { root })
    }

    /// Store exact bytes durably and return their immutable identity.
    pub fn put_bytes(&self, bytes: &[u8]) -> ImageResult<ObjectId> {
        let id = ObjectId::from_bytes(bytes)?;
        let path = self.object_path(&id);
        if path.exists() {
            self.verify_existing(&id, &path)?;
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
        match std::fs::rename(&temporary, &path) {
            Ok(()) => {}
            Err(_error) if path.exists() => {
                let _ = std::fs::remove_file(&temporary);
                self.verify_existing(&id, &path)?;
                return Ok(id);
            }
            Err(error) => {
                let _ = std::fs::remove_file(&temporary);
                return Err(error.into());
            }
        }
        sync_parent(parent)?;
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
            return Ok(target);
        }
        let parent = target.parent().expect("closure object has a parent");
        std::fs::create_dir_all(parent)?;
        match std::fs::hard_link(&source, &target) {
            Ok(()) => {}
            Err(_) => {
                std::fs::copy(&source, &target)?;
                File::open(&target)?.sync_all()?;
            }
        }
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

impl fmt::Display for ObjectId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(formatter)
    }
}

impl TryFrom<String> for ObjectId {
    type Error = ImageError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl From<ObjectId> for String {
    fn from(value: ObjectId) -> Self {
        value.0
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn sync_parent(path: &Path) -> ImageResult<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

/// Compute a sparse-aware fixed-leaf Merkle root without reading unallocated holes.
pub fn sparse_file_integrity(path: &Path) -> ImageResult<SparseFileIntegrity> {
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
