//! Snapshot content verification.

use std::fs::{File, OpenOptions};
use std::io;
use std::io::{Read, Seek, SeekFrom};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::{MicrosandboxError, MicrosandboxResult, Operation, UnsupportedReason};
use microsandbox_image::snapshot::{FILE_MERKLE_BLAKE3_LEAF_SIZE, SnapshotState, UpperIntegrity};
use microsandbox_utils::extent::ExtentMap;
use rayon::prelude::*;
use sha2::{Digest as _, Sha256};

use super::Snapshot;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MERKLE_LEAF_DOMAIN: &[u8] = b"msb-file-merkle-blake3-v1\0leaf\0";
const MERKLE_PARENT_DOMAIN: &[u8] = b"msb-file-merkle-blake3-v1\0parent\0";
const MERKLE_ROOT_DOMAIN: &[u8] = b"msb-file-merkle-blake3-v1\0root\0";
const MERKLE_READ_BATCH: usize = 8 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result of explicit snapshot verification.
#[derive(Debug, Clone)]
pub struct SnapshotVerifyReport {
    /// Snapshot manifest digest.
    pub digest: String,
    /// Artifact directory.
    pub path: PathBuf,
    /// Upper-layer content verification result.
    pub upper: UpperVerifyStatus,
}

/// Upper-layer content verification result.
#[derive(Debug, Clone)]
pub enum UpperVerifyStatus {
    /// The snapshot intentionally has no persistent payload integrity.
    NotRecorded,
    /// Recorded content integrity matched the computed digest.
    Verified {
        /// Digest algorithm.
        algorithm: String,
        /// Matching digest or Merkle root.
        digest: String,
    },
}

/// Streaming binary-tree accumulator. Zero gaps are inserted as complete
/// subtrees, keeping all-hole work logarithmic in the logical file size.
struct MerkleAccumulator {
    nodes: Vec<Option<[u8; 32]>>,
    processed_leaves: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct VerificationSourceIdentity {
    len: u64,
    modified: Option<SystemTime>,
    #[cfg(unix)]
    device: u64,
    #[cfg(unix)]
    inode: u64,
    #[cfg(unix)]
    changed_seconds: i64,
    #[cfg(unix)]
    changed_nanos: i64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl MerkleAccumulator {
    fn new(tree_height: u32) -> Self {
        Self {
            nodes: vec![None; tree_height as usize + 1],
            processed_leaves: 0,
        }
    }

    fn push_subtree(&mut self, height: u32, hash: [u8; 32]) {
        let width = 1u64 << height;
        debug_assert_eq!(self.processed_leaves % width, 0);

        let mut level = height as usize;
        let mut node = hash;
        while let Some(left) = self.nodes[level].take() {
            node = hash_parent(&left, &node);
            level += 1;
        }
        self.nodes[level] = Some(node);
        self.processed_leaves += width;
    }

    fn finish(mut self, tree_height: u32) -> [u8; 32] {
        debug_assert_eq!(self.nodes.iter().filter(|node| node.is_some()).count(), 1);
        self.nodes[tree_height as usize]
            .take()
            .expect("a complete Merkle tree has one root")
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) async fn verify_snapshot(snap: &Snapshot) -> MicrosandboxResult<SnapshotVerifyReport> {
    let SnapshotState::File(file_state) = &snap.manifest().state else {
        return Err(MicrosandboxError::unsupported(
            Operation::SnapshotOps,
            UnsupportedReason::NotAvailable(
                "checkpoint-state snapshot verification is not available".into(),
            ),
        ));
    };
    let Some(expected) = file_state.upper.integrity.as_ref() else {
        return Ok(SnapshotVerifyReport {
            digest: snap.digest().to_string(),
            path: snap.path().to_path_buf(),
            upper: UpperVerifyStatus::NotRecorded,
        });
    };

    let upper_path = snap.path().join(&file_state.upper.file);
    let payload = open_verification_source(&upper_path)?;
    let before = verification_source_identity(&payload.metadata()?);
    let actual = match expected {
        UpperIntegrity::Sha256 { .. } => {
            compute_sha256_integrity_from_file(payload.try_clone()?).await?
        }
        UpperIntegrity::SparseSha256V1 { .. } => {
            compute_legacy_sparse_integrity_from_file(payload.try_clone()?).await?
        }
        UpperIntegrity::FileMerkleBlake3V1 { .. } => {
            compute_merkle_integrity_from_file(payload.try_clone()?).await?
        }
    };
    ensure_verification_source_unchanged(&payload, &upper_path, &before)?;

    if actual != *expected {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "upper integrity mismatch: descriptor={}, file={}",
            expected.value(),
            actual.value()
        )));
    }

    Ok(SnapshotVerifyReport {
        digest: snap.digest().to_string(),
        path: snap.path().to_path_buf(),
        upper: UpperVerifyStatus::Verified {
            algorithm: expected.algorithm().into(),
            digest: actual.value().into(),
        },
    })
}

pub(super) async fn compute_merkle_integrity(path: &Path) -> MicrosandboxResult<UpperIntegrity> {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || merkle_integrity_blocking(&path))
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("snapshot integrity task: {error}")))?
        .map_err(Into::into)
}

/// Compute current integrity through a handle the caller has already confined
/// and pinned. This is used by downgrade so source and target algorithms bind
/// the same inode rather than reopening a mutable path.
pub(super) async fn compute_merkle_integrity_from_file(
    file: File,
) -> MicrosandboxResult<UpperIntegrity> {
    tokio::task::spawn_blocking(move || merkle_integrity_from_file(file))
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("snapshot integrity task: {error}")))?
        .map_err(Into::into)
}

/// Compute the released sparse-SHA representation through a file handle that
/// the caller has already confined and pinned.
pub(super) async fn compute_legacy_sparse_integrity_from_file(
    file: File,
) -> MicrosandboxResult<UpperIntegrity> {
    tokio::task::spawn_blocking(move || legacy_sparse_integrity_from_file(file))
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("snapshot integrity task: {error}")))?
        .map_err(Into::into)
}

pub(super) fn open_verification_source(path: &Path) -> MicrosandboxResult<File> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "snapshot payload is not a confined regular file: {}",
            path.display()
        )));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW);
    let file = options.open(path)?;
    if !file.metadata()?.is_file() {
        return Err(MicrosandboxError::SnapshotIntegrity(format!(
            "snapshot payload is not a regular file: {}",
            path.display()
        )));
    }
    Ok(file)
}

pub(super) fn verification_source_identity(
    metadata: &std::fs::Metadata,
) -> VerificationSourceIdentity {
    VerificationSourceIdentity {
        len: metadata.len(),
        modified: metadata.modified().ok(),
        #[cfg(unix)]
        device: metadata.dev(),
        #[cfg(unix)]
        inode: metadata.ino(),
        #[cfg(unix)]
        changed_seconds: metadata.ctime(),
        #[cfg(unix)]
        changed_nanos: metadata.ctime_nsec(),
    }
}

pub(super) fn ensure_verification_source_unchanged(
    file: &File,
    path: &Path,
    before: &VerificationSourceIdentity,
) -> MicrosandboxResult<()> {
    let handle_after = verification_source_identity(&file.metadata()?);
    let path_metadata = std::fs::symlink_metadata(path)?;
    if path_metadata.file_type().is_symlink() || !path_metadata.is_file() {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "snapshot payload binding changed during verification".into(),
        ));
    }
    let path_after = verification_source_identity(&path_metadata);
    if &handle_after != before || &path_after != before {
        return Err(MicrosandboxError::SnapshotIntegrity(
            "snapshot payload changed during verification".into(),
        ));
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: BLAKE3 Merkle Helpers
//--------------------------------------------------------------------------------------------------

fn merkle_integrity_blocking(path: &Path) -> io::Result<UpperIntegrity> {
    merkle_integrity_from_file(File::open(path)?)
}

fn merkle_integrity_from_file(mut file: File) -> io::Result<UpperIntegrity> {
    let logical_size = file.metadata()?.len();
    let leaf_size = u64::from(FILE_MERKLE_BLAKE3_LEAF_SIZE);
    let logical_leaf_count = logical_size.div_ceil(leaf_size).max(1);
    let tree_leaf_count = logical_leaf_count.next_power_of_two();
    let tree_height = tree_leaf_count.trailing_zeros();
    let zero_roots = zero_subtree_roots(tree_height);
    let allocation_map = ExtentMap::scan_file(&file)?;
    let ranges = allocated_leaf_ranges(allocation_map.as_ref(), logical_size, logical_leaf_count);

    let mut accumulator = MerkleAccumulator::new(tree_height);
    // Allocate the read batch only when at least one leaf is backed by data,
    // and reuse it across fragmented ranges.
    let mut buffer = Vec::new();
    let mut cursor = 0u64;
    for (start, end) in ranges {
        push_zero_range(&mut accumulator, &zero_roots, cursor, start);
        hash_leaf_range(
            &mut file,
            logical_size,
            start,
            end,
            &mut buffer,
            &mut accumulator,
        )?;
        cursor = end;
    }
    push_zero_range(&mut accumulator, &zero_roots, cursor, tree_leaf_count);

    let top = accumulator.finish(tree_height);
    let mut root_hasher = blake3::Hasher::new();
    root_hasher.update(MERKLE_ROOT_DOMAIN);
    root_hasher.update(&logical_size.to_le_bytes());
    root_hasher.update(&FILE_MERKLE_BLAKE3_LEAF_SIZE.to_le_bytes());
    root_hasher.update(&tree_height.to_le_bytes());
    root_hasher.update(&top);
    Ok(UpperIntegrity::FileMerkleBlake3V1 {
        root: format!("blake3:{}", root_hasher.finalize().to_hex()),
        logical_size,
        leaf_size: FILE_MERKLE_BLAKE3_LEAF_SIZE,
    })
}

fn allocated_leaf_ranges(
    map: Option<&ExtentMap>,
    logical_size: u64,
    logical_leaf_count: u64,
) -> Vec<(u64, u64)> {
    if logical_size == 0 {
        return Vec::new();
    }
    let Some(map) = map else {
        return vec![(0, logical_leaf_count)];
    };

    let leaf_size = u64::from(FILE_MERKLE_BLAKE3_LEAF_SIZE);
    let mut ranges: Vec<(u64, u64)> = Vec::new();
    for (offset, len) in &map.extents {
        let start = offset / leaf_size;
        let end = offset
            .saturating_add(*len)
            .div_ceil(leaf_size)
            .min(logical_leaf_count);
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

fn hash_leaf_range(
    file: &mut File,
    logical_size: u64,
    start: u64,
    end: u64,
    buffer: &mut Vec<u8>,
    accumulator: &mut MerkleAccumulator,
) -> io::Result<()> {
    let leaf_size = FILE_MERKLE_BLAKE3_LEAF_SIZE as usize;
    let leaves_per_batch = (MERKLE_READ_BATCH / leaf_size).max(1);
    buffer.resize(leaves_per_batch * leaf_size, 0);
    let mut leaf = start;

    while leaf < end {
        let batch_leaves = (end - leaf).min(leaves_per_batch as u64) as usize;
        let batch_bytes = batch_leaves * leaf_size;
        let offset = leaf * leaf_size as u64;
        let readable = logical_size.saturating_sub(offset).min(batch_bytes as u64) as usize;
        buffer[..batch_bytes].fill(0);
        file.seek(SeekFrom::Start(offset))?;
        file.read_exact(&mut buffer[..readable])?;

        let hashes: Vec<[u8; 32]> = buffer[..batch_bytes]
            .par_chunks_exact(leaf_size)
            .map(hash_leaf)
            .collect();
        for hash in hashes {
            accumulator.push_subtree(0, hash);
        }
        leaf += batch_leaves as u64;
    }
    Ok(())
}

fn push_zero_range(
    accumulator: &mut MerkleAccumulator,
    zero_roots: &[[u8; 32]],
    mut start: u64,
    end: u64,
) {
    while start < end {
        let remaining = end - start;
        let remaining_height = 63 - remaining.leading_zeros();
        let alignment_height = if start == 0 {
            remaining_height
        } else {
            start.trailing_zeros().min(remaining_height)
        };
        accumulator.push_subtree(alignment_height, zero_roots[alignment_height as usize]);
        start += 1u64 << alignment_height;
    }
}

fn zero_subtree_roots(tree_height: u32) -> Vec<[u8; 32]> {
    let zero_leaf = vec![0u8; FILE_MERKLE_BLAKE3_LEAF_SIZE as usize];
    let mut roots = vec![hash_leaf(&zero_leaf)];
    for height in 1..=tree_height {
        let child = roots[height as usize - 1];
        roots.push(hash_parent(&child, &child));
    }
    roots
}

fn hash_leaf(bytes: &[u8]) -> [u8; 32] {
    debug_assert_eq!(bytes.len(), FILE_MERKLE_BLAKE3_LEAF_SIZE as usize);
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
// Functions: Legacy SHA Helpers
//--------------------------------------------------------------------------------------------------

async fn compute_sha256_integrity_from_file(file: File) -> MicrosandboxResult<UpperIntegrity> {
    tokio::task::spawn_blocking(move || sha256_integrity_from_file(file))
        .await
        .map_err(|error| MicrosandboxError::Custom(format!("snapshot integrity task: {error}")))?
        .map_err(Into::into)
}

fn sha256_integrity_from_file(mut file: File) -> io::Result<UpperIntegrity> {
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1024 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(UpperIntegrity::Sha256 {
        digest: format!("sha256:{}", hex::encode(hasher.finalize())),
    })
}

fn legacy_sparse_integrity_from_file(mut file: File) -> io::Result<UpperIntegrity> {
    let len = file.metadata()?.len();

    let mut hasher = Sha256::new();
    hasher.update(b"msb-sparse-sha256-v1\0");
    hasher.update(len.to_le_bytes());

    match ExtentMap::scan_file(&file)? {
        Some(map) => {
            let mut offset = 0u64;
            for (start, extent_len) in &map.extents {
                if *start > offset {
                    hash_zeroes(start - offset, &mut hasher);
                }
                hash_extent(&mut file, *start, *extent_len, &mut hasher)?;
                offset = start + extent_len;
            }
            if offset < len {
                hash_zeroes(len - offset, &mut hasher);
            }
        }
        None => {
            file.seek(SeekFrom::Start(0))?;
            let mut buffer = vec![0u8; 1024 * 1024];
            loop {
                let read = file.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                hasher.update(&buffer[..read]);
            }
        }
    }

    Ok(UpperIntegrity::SparseSha256V1 {
        digest: format!("sha256:{}", hex::encode(hasher.finalize())),
    })
}

fn hash_extent(file: &mut File, offset: u64, len: u64, hasher: &mut Sha256) -> io::Result<()> {
    const BUFFER_SIZE: usize = 1024 * 1024;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut hashed = 0u64;

    file.seek(SeekFrom::Start(offset))?;
    while hashed < len {
        let wanted = (len - hashed).min(BUFFER_SIZE as u64) as usize;
        let read = file.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF mid-extent",
            ));
        }
        hasher.update(&buffer[..read]);
        hashed += read as u64;
    }
    Ok(())
}

fn hash_zeroes(mut len: u64, hasher: &mut Sha256) {
    static ZEROES: [u8; 1024 * 1024] = [0; 1024 * 1024];
    while len > 0 {
        let chunk = len.min(ZEROES.len() as u64) as usize;
        hasher.update(&ZEROES[..chunk]);
        len -= chunk as u64;
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;
    use std::io::{Seek, SeekFrom, Write};

    use super::*;

    #[test]
    fn merkle_integrity_is_stable_and_detects_data_changes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upper.ext4");
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.set_len(64 * 1024 * 1024).unwrap();
        file.seek(SeekFrom::Start(8 * 1024 * 1024)).unwrap();
        file.write_all(b"hello").unwrap();
        drop(file);

        let first = merkle_integrity_blocking(&path).unwrap();
        let second = merkle_integrity_blocking(&path).unwrap();
        assert_eq!(first.algorithm(), "msb-file-merkle-blake3-v1");
        assert_eq!(first, second);

        let mut file = OpenOptions::new().write(true).open(&path).unwrap();
        file.seek(SeekFrom::Start(8 * 1024 * 1024)).unwrap();
        file.write_all(b"HELLO").unwrap();
        drop(file);

        assert_ne!(first, merkle_integrity_blocking(&path).unwrap());
    }

    #[test]
    fn holes_and_allocated_zeroes_have_the_same_merkle_root() {
        let dir = tempfile::tempdir().unwrap();
        let sparse = dir.path().join("sparse.bin");
        let dense = dir.path().join("dense.bin");
        OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&sparse)
            .unwrap()
            .set_len(4 * 1024 * 1024)
            .unwrap();
        std::fs::write(&dense, vec![0u8; 4 * 1024 * 1024]).unwrap();

        assert_eq!(
            merkle_integrity_blocking(&sparse).unwrap(),
            merkle_integrity_blocking(&dense).unwrap()
        );
    }

    #[test]
    fn empty_file_has_a_stable_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.bin");
        std::fs::write(&path, []).unwrap();

        let first = merkle_integrity_blocking(&path).unwrap();
        assert_eq!(first, merkle_integrity_blocking(&path).unwrap());
        assert_eq!(
            first.value(),
            "blake3:1f44fec2aa3a7a1725f0f626b0599c99526f5a1e7f2817cd50b695597bce05fa"
        );
        assert!(matches!(
            first,
            UpperIntegrity::FileMerkleBlake3V1 {
                logical_size: 0,
                leaf_size: FILE_MERKLE_BLAKE3_LEAF_SIZE,
                ..
            }
        ));
    }

    #[test]
    fn partial_leaf_matches_golden_root() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial.bin");
        std::fs::write(&path, b"hello").unwrap();

        let integrity = merkle_integrity_blocking(&path).unwrap();
        assert_eq!(
            integrity.value(),
            "blake3:733a84a145df6c2139c33096e7584c1d8f42b0b981ec7e847b1bf6db73bec941"
        );
    }

    #[test]
    fn verification_identity_detects_mutation_after_hash_input_is_pinned() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upper.ext4");
        std::fs::write(&path, b"before").unwrap();
        let file = open_verification_source(&path).unwrap();
        let before = verification_source_identity(&file.metadata().unwrap());

        let mut writer = OpenOptions::new().append(true).open(&path).unwrap();
        writer.write_all(b" after").unwrap();
        writer.sync_all().unwrap();

        let error = ensure_verification_source_unchanged(&file, &path, &before).unwrap_err();
        assert!(error.to_string().contains("changed during verification"));
    }
}
