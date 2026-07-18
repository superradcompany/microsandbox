//! Reusable flat ext4 rootfs materialization from cached per-layer EROFS artifacts.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use sha2::{Digest as Sha2Digest, Sha256};

use crate::cache::lock::{flock_unlock, lock_exclusive, open_lock_file};
use crate::erofs::{ErofsEntryKind, ErofsReader};
use crate::ext4::{EXT4_ROOTFS_MATERIALIZER_ABI, Ext4RootfsOptions, materialize_ext4_rootfs};
use crate::path_bytes::path_bytes;
use crate::tree::{
    DataSpool, DeviceNode, DirectoryNode, FileData, FileTree, RegularFileId, RegularFileNode,
    SymlinkNode, TreeNode, merge_layers_with_provenance,
};
use crate::{Digest, FlatRootfsRef, GlobalCache, ImageError, ImageResult, Platform};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const FLAT_REF_SCHEMA: u32 = 1;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Materialize and publish a flat rootfs from the image's cached EROFS layers.
pub(crate) fn materialize_flat_rootfs(
    cache: &GlobalCache,
    manifest_digest: &Digest,
    layer_diff_ids: &[Digest],
    platform: &Platform,
    force: bool,
) -> ImageResult<FlatRootfsRef> {
    let (derivation_digest, derivation_bytes) =
        flat_derivation_digest(manifest_digest, layer_diff_ids, platform);
    if !force
        && let Some(reference) = cache.read_flat_ref(manifest_digest)?
        && reference.derivation_digest == derivation_digest.to_string()
    {
        return Ok(reference);
    }

    let lock_file = open_lock_file(&cache.flat_lock_path(&derivation_digest))?;
    lock_exclusive(&lock_file)?;
    let _lock_guard = scopeguard::guard(lock_file, |file| {
        let _ = flock_unlock(&file);
    });
    if !force
        && let Some(reference) = cache.read_flat_ref(manifest_digest)?
        && reference.derivation_digest == derivation_digest.to_string()
    {
        return Ok(reference);
    }

    let work_dir = cache.flat_work_dir(&derivation_digest);
    std::fs::create_dir_all(&work_dir).map_err(|source| ImageError::Cache {
        path: work_dir.clone(),
        source,
    })?;
    let _work_guard = scopeguard::guard((), |_| {
        let _ = std::fs::remove_dir_all(&work_dir);
    });
    let spool_path = work_dir.join("merged.spool");
    let mut spool = DataSpool::new(&spool_path).map_err(ImageError::Io)?;
    let mut layers = Vec::with_capacity(layer_diff_ids.len());
    for diff_id in layer_diff_ids {
        let layer_path = cache.layer_erofs_path(diff_id);
        layers.push(read_erofs_layer(&layer_path, &mut spool).map_err(|source| {
            ImageError::Materialize {
                digest: diff_id.to_string(),
                message: "failed to reconstruct cached EROFS layer for flat materialization"
                    .to_string(),
                source: Some(Box::new(source)),
            }
        })?);
    }
    let (tree, _) = merge_layers_with_provenance(layers);

    let candidate = work_dir.join("rootfs.raw.part");
    let artifact = materialize_ext4_rootfs(
        &candidate,
        tree,
        &Ext4RootfsOptions {
            derivation_digest: derivation_bytes,
            ..Ext4RootfsOptions::default()
        },
    )
    .map_err(|error| ImageError::Materialize {
        digest: manifest_digest.to_string(),
        message: format!("flat ext4 materialization failed: {error}"),
        source: Some(Box::new(error)),
    })?;
    let artifact_digest: Digest = format!("sha256:{}", hex::encode(artifact.sha256))
        .parse()
        .map_err(|_| ImageError::ManifestParse("invalid flat artifact digest".to_string()))?;
    cache.publish_flat_blob(&candidate, &artifact_digest, artifact.virtual_size_bytes)?;

    let reference = FlatRootfsRef {
        schema: FLAT_REF_SCHEMA,
        manifest_digest: manifest_digest.to_string(),
        derivation_digest: derivation_digest.to_string(),
        artifact_digest: artifact_digest.to_string(),
        materializer_abi: artifact.materializer_abi,
        uuid: hex::encode(artifact.uuid),
        virtual_size_bytes: artifact.virtual_size_bytes,
        inode_count: artifact.inode_count,
        content_bytes: artifact.content_bytes,
    };
    cache.write_flat_ref(manifest_digest, &reference)?;
    Ok(reference)
}

fn flat_derivation_digest(
    manifest_digest: &Digest,
    layer_diff_ids: &[Digest],
    platform: &Platform,
) -> (Digest, [u8; 32]) {
    let mut hasher = Sha256::new();
    hasher.update(b"microsandbox.flat-rootfs\0");
    hasher.update(EXT4_ROOTFS_MATERIALIZER_ABI.to_le_bytes());
    hasher.update(b"\0");
    hasher.update(platform.os.to_string().as_bytes());
    hasher.update(b"/");
    hasher.update(platform.arch.to_string().as_bytes());
    if let Some(variant) = &platform.variant {
        hasher.update(b"/");
        hasher.update(variant.as_bytes());
    }
    hasher.update(b"\0");
    hasher.update(manifest_digest.to_string().as_bytes());
    for diff_id in layer_diff_ids {
        hasher.update(b"\0");
        hasher.update(diff_id.to_string().as_bytes());
    }
    let bytes: [u8; 32] = hasher.finalize().into();
    let digest = format!("sha256:{}", hex::encode(bytes)).parse().unwrap();
    (digest, bytes)
}

fn read_erofs_layer(path: &Path, spool: &mut DataSpool) -> std::io::Result<FileTree> {
    let file = std::fs::File::open(path)?;
    let mut reader = ErofsReader::new(file)?;
    let mut tree = FileTree::new();
    let mut hardlinks: HashMap<u32, (RegularFileId, FileData)> = HashMap::new();
    reader.walk_entries::<std::io::Error, _>(|reader, entry| {
        let node = match entry.kind {
            ErofsEntryKind::RegularFile => {
                let (id, data) = if let Some((id, data)) = hardlinks.get(&entry.nid) {
                    (*id, data.clone())
                } else {
                    let offset = spool.current_offset();
                    let mut contents = reader.file_data_reader(entry.nid)?;
                    let mut buffer = [0u8; 64 * 1024];
                    let mut written = 0u64;
                    loop {
                        let len = contents.read(&mut buffer)?;
                        if len == 0 {
                            break;
                        }
                        spool.write_chunk(&buffer[..len])?;
                        written += len as u64;
                    }
                    if written != entry.size {
                        return Err(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "EROFS regular-file length changed while reconstructing layer",
                        ));
                    }
                    let id = RegularFileId::new();
                    let data = spool.data_ref(offset, written);
                    hardlinks.insert(entry.nid, (id, data.clone()));
                    (id, data)
                };
                TreeNode::RegularFile(RegularFileNode {
                    id,
                    metadata: entry.metadata,
                    xattrs: entry.xattrs,
                    data,
                    nlink: 1,
                })
            }
            ErofsEntryKind::Directory => {
                let mut directory = DirectoryNode::new(entry.metadata);
                directory.xattrs = entry.xattrs;
                TreeNode::Directory(directory)
            }
            ErofsEntryKind::Symlink => TreeNode::Symlink(SymlinkNode {
                metadata: entry.metadata,
                target: reader.read_link_by_nid(entry.nid)?,
            }),
            ErofsEntryKind::CharDevice | ErofsEntryKind::BlockDevice => {
                let (major, minor) = entry.rdev.ok_or_else(|| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "EROFS device entry is missing major/minor",
                    )
                })?;
                let device = DeviceNode {
                    metadata: entry.metadata,
                    major,
                    minor,
                };
                if entry.kind == ErofsEntryKind::CharDevice {
                    TreeNode::CharDevice(device)
                } else {
                    TreeNode::BlockDevice(device)
                }
            }
            ErofsEntryKind::Fifo => TreeNode::Fifo(entry.metadata),
            ErofsEntryKind::Socket => TreeNode::Socket(entry.metadata),
        };
        tree.insert(path_bytes(&entry.path), node)
            .map_err(std::io::Error::other)
    })?;
    Ok(tree)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{InodeMetadata, RegularFileNode};

    #[test]
    fn derivation_changes_with_layer_order() {
        let manifest: Digest = format!("sha256:{}", "a".repeat(64)).parse().unwrap();
        let first: Digest = format!("sha256:{}", "b".repeat(64)).parse().unwrap();
        let second: Digest = format!("sha256:{}", "c".repeat(64)).parse().unwrap();
        let platform = Platform::host_linux();

        assert_ne!(
            flat_derivation_digest(&manifest, &[first.clone(), second.clone()], &platform).0,
            flat_derivation_digest(&manifest, &[second, first], &platform).0
        );
    }

    #[test]
    fn materializes_cached_erofs_layers_into_flat_blob_and_ref() {
        let directory = tempfile::tempdir().unwrap();
        let cache = GlobalCache::new(directory.path()).unwrap();
        let manifest: Digest = format!("sha256:{}", "d".repeat(64)).parse().unwrap();
        let diff_id: Digest = format!("sha256:{}", "e".repeat(64)).parse().unwrap();
        let mut tree = FileTree::new();
        tree.insert(
            b"etc/message",
            TreeNode::RegularFile(RegularFileNode {
                id: RegularFileId::new(),
                metadata: InodeMetadata::default(),
                xattrs: Vec::new(),
                data: FileData::Memory(b"flat-rootfs".to_vec()),
                nlink: 1,
            }),
        )
        .unwrap();
        crate::erofs::write_erofs(&tree, &cache.layer_erofs_path(&diff_id)).unwrap();

        let reference = materialize_flat_rootfs(
            &cache,
            &manifest,
            &[diff_id],
            &Platform::host_linux(),
            false,
        )
        .unwrap();
        let artifact_digest: Digest = reference.artifact_digest.parse().unwrap();
        assert_eq!(reference.content_bytes, b"flat-rootfs".len() as u64);
        assert_eq!(reference.inode_count, 3);
        assert_eq!(reference.virtual_size_bytes, 256 * 1024 * 1024);
        assert!(cache.flat_blob_path(&artifact_digest).exists());
        assert_eq!(cache.read_flat_ref(&manifest).unwrap(), Some(reference));
    }
}
