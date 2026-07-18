//! Pure-Rust materialization of a merged OCI tree into a deterministic ext4 root filesystem.

use std::path::Path;

use super::formatter::{Ext4Error, Ext4FormatOptions, format_ext4_rootfs_with_tree_and_uuid};
use crate::tree::FileTree;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Version of the on-disk materializer behavior implemented by this module.
pub const EXT4_ROOTFS_MATERIALIZER_ABI: u32 = 1;

/// Default raw rootfs size used until cache-level canonical sizing is wired.
const DEFAULT_ROOTFS_SIZE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Profile-v1 journal size: 64 MiB with 4 KiB filesystem blocks.
const DEFAULT_ROOTFS_JOURNAL_BLOCKS: u32 = 16_384;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options that define deterministic ext4 rootfs output.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ext4RootfsOptions {
    /// Virtual size of the generated raw filesystem image.
    pub size_bytes: u64,

    /// Number of 4 KiB blocks reserved for the internal journal.
    pub journal_blocks: u32,

    /// Canonical derivation digest for the manifest, platform and filesystem profile.
    ///
    /// The first 16 bytes seed the filesystem UUID after RFC 4122 variant/version normalization.
    pub derivation_digest: [u8; 32],
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for Ext4RootfsOptions {
    fn default() -> Self {
        Self {
            size_bytes: DEFAULT_ROOTFS_SIZE_BYTES,
            journal_blocks: DEFAULT_ROOTFS_JOURNAL_BLOCKS,
            derivation_digest: [0u8; 32],
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Materialize a merged OCI tree into a deterministic raw ext4 filesystem.
///
/// This is a host-only pure-Rust operation. It does not mount the image or invoke an external
/// formatter. The output file is fully synchronized before this function returns.
pub fn materialize_ext4_rootfs(
    path: &Path,
    tree: FileTree,
    options: &Ext4RootfsOptions,
) -> Result<(), Ext4Error> {
    let format_options = Ext4FormatOptions {
        size_bytes: options.size_bytes,
        journal_blocks: options.journal_blocks,
    };
    let uuid = deterministic_uuid(&options.derivation_digest);

    format_ext4_rootfs_with_tree_and_uuid(path, &format_options, tree, uuid)?;

    // Rootfs artifacts enter a shared cache, unlike ephemeral upper creation. Durably persist the
    // complete candidate before a later cache transaction can hash and atomically publish it.
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)?
        .sync_all()?;

    Ok(())
}

fn deterministic_uuid(digest: &[u8; 32]) -> [u8; 16] {
    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&digest[..16]);
    uuid[6] = (uuid[6] & 0x0f) | 0x40;
    uuid[8] = (uuid[8] & 0x3f) | 0x80;
    uuid
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::{Read, Seek, SeekFrom};

    use super::*;
    use crate::tree::{FileData, InodeMetadata, RegularFileNode, TreeNode, Xattr};

    const TEST_SIZE_BYTES: u64 = 128 * 1024 * 1024;
    const TEST_JOURNAL_BLOCKS: u32 = 1024;

    fn test_options(digest: [u8; 32]) -> Ext4RootfsOptions {
        Ext4RootfsOptions {
            size_bytes: TEST_SIZE_BYTES,
            journal_blocks: TEST_JOURNAL_BLOCKS,
            derivation_digest: digest,
        }
    }

    fn inode_table_block() -> u64 {
        // One 128 MiB group: superblock block, one GDT block, reserved GDT headroom, then
        // block and inode bitmaps. This mirrors profile-v1 group-zero geometry.
        1 + 1 + super::super::layout::RESERVED_GDT_BLOCKS as u64 + 2
    }

    fn read_inode(path: &Path, inode: u32) -> Vec<u8> {
        let offset = inode_table_block() * 4096 + u64::from(inode - 1) * 256;
        let mut file = std::fs::File::open(path).unwrap();
        file.seek(SeekFrom::Start(offset)).unwrap();
        let mut bytes = vec![0u8; 256];
        file.read_exact(&mut bytes).unwrap();
        bytes
    }

    fn le_u16(bytes: &[u8], offset: usize) -> u16 {
        u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
    }

    fn le_u32(bytes: &[u8], offset: usize) -> u32 {
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }

    fn regular_file(id: crate::tree::RegularFileId) -> RegularFileNode {
        RegularFileNode {
            id,
            metadata: InodeMetadata {
                uid: 0x12345,
                gid: 0x23456,
                mode: 0o4750,
                mtime: 1_800_000_000,
                mtime_nsec: 123_456_789,
            },
            xattrs: Vec::new(),
            data: FileData::Memory(b"rootfs-data".to_vec()),
            nlink: 1,
        }
    }

    #[test]
    fn deterministic_uuid_has_rfc4122_version_and_variant() {
        let digest = [0xff; 32];
        let uuid = deterministic_uuid(&digest);

        assert_eq!(uuid[6] >> 4, 4);
        assert_eq!(uuid[8] >> 6, 2);
        assert_eq!(&uuid[..6], &[0xff; 6]);
    }

    #[test]
    fn materializer_preserves_inode_metadata_and_hardlinks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rootfs.raw");
        let mut tree = FileTree::new();
        let file = regular_file(crate::tree::RegularFileId::new());
        tree.insert(b"usr/bin/tool", TreeNode::RegularFile(file.clone()))
            .unwrap();
        tree.insert(b"usr/bin/tool-link", TreeNode::RegularFile(file))
            .unwrap();

        materialize_ext4_rootfs(&path, tree, &test_options([7u8; 32])).unwrap();

        // Intermediate directories consume inodes 11 and 12; the hardlinked file is inode 13.
        let inode = read_inode(&path, 13);
        assert_eq!(le_u16(&inode, 0x00), 0o100000 | 0o4750);
        assert_eq!(le_u16(&inode, 0x02), 0x2345);
        assert_eq!(le_u16(&inode, 0x78), 0x0001);
        assert_eq!(le_u16(&inode, 0x18), 0x3456);
        assert_eq!(le_u16(&inode, 0x7a), 0x0002);
        assert_eq!(le_u16(&inode, 0x1a), 2);
        assert_eq!(le_u32(&inode, 0x10), 1_800_000_000);
        assert_eq!(le_u32(&inode, 0x88) >> 2, 123_456_789);
    }

    #[test]
    fn materializer_is_byte_deterministic_for_same_inputs() {
        let dir = tempfile::tempdir().unwrap();
        let first_path = dir.path().join("first.raw");
        let second_path = dir.path().join("second.raw");
        let mut tree = FileTree::new();
        tree.insert(
            b"payload",
            TreeNode::RegularFile(regular_file(crate::tree::RegularFileId::new())),
        )
        .unwrap();
        let options = test_options([9u8; 32]);

        materialize_ext4_rootfs(&first_path, tree.clone(), &options).unwrap();
        materialize_ext4_rootfs(&second_path, tree, &options).unwrap();

        let mut first = std::fs::File::open(first_path).unwrap();
        let mut second = std::fs::File::open(second_path).unwrap();
        let mut first_buf = vec![0u8; 1024 * 1024];
        let mut second_buf = vec![0u8; 1024 * 1024];
        loop {
            let first_len = first.read(&mut first_buf).unwrap();
            let second_len = second.read(&mut second_buf).unwrap();
            assert_eq!(first_len, second_len);
            assert_eq!(&first_buf[..first_len], &second_buf[..second_len]);
            if first_len == 0 {
                break;
            }
        }
    }

    #[test]
    fn materializer_links_external_xattr_block_from_inode() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rootfs.raw");
        let mut tree = FileTree::new();
        let mut file = regular_file(crate::tree::RegularFileId::new());
        file.xattrs.push(Xattr {
            name: b"security.capability".to_vec(),
            value: (0u8..128).collect(),
        });
        tree.insert(b"usr/bin/tool", TreeNode::RegularFile(file))
            .unwrap();

        materialize_ext4_rootfs(&path, tree, &test_options([11u8; 32])).unwrap();

        let inode = read_inode(&path, 13);
        let xattr_block = u64::from(le_u32(&inode, 0x68)) | (u64::from(le_u16(&inode, 0x76)) << 32);
        assert_ne!(xattr_block, 0);
        let mut image = std::fs::File::open(&path).unwrap();
        image.seek(SeekFrom::Start(xattr_block * 4096)).unwrap();
        let mut block = vec![0u8; 4096];
        image.read_exact(&mut block).unwrap();
        assert_eq!(le_u32(&block, 0), 0xEA02_0000);
        assert_eq!(block[33], 6);
        assert_eq!(&block[48..58], b"capability");
    }
}
