//! Construction and validation of ext4's reserved group-descriptor inode.
//!
//! The resize inode deliberately uses the legacy double-indirect mapping expected by the Linux
//! kernel and e2fsprogs. It owns the primary reserved-GDT blocks and their sparse-super backup
//! copies; these blocks are filesystem metadata even though ext4 accounts for them through inode 7.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use super::format::{
    EXT4_BLOCK_SIZE, EXT4_INODE_SIZE, EXT4_MIN_EXTRA_ISIZE, EXT4_RESIZE_INO, S_IFREG,
    sparse_super_group,
};
use super::formatter::Ext4Error;
use super::layout::{GroupGeometry, get_le16, get_le32, inode_checksum, put_le16, put_le32};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `i_block[EXT2_DIND_BLOCK]` within a classic ext inode.
const DOUBLE_INDIRECT_BLOCK_OFFSET: usize = 0x28 + 13 * 4;

/// Number of 32-bit block pointers in one 4 KiB indirect block.
const POINTERS_PER_BLOCK: u32 = EXT4_BLOCK_SIZE / 4;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct ResizePointerBlocks {
    double_indirect_pointers: Vec<u32>,
    reserved_blocks: Vec<(u64, Vec<u8>)>,
}

struct ResizeInodeContents {
    inode: Vec<u8>,
    double_indirect: Vec<u8>,
    reserved_blocks: Vec<(u64, Vec<u8>)>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Write a complete, e2fsprogs-compatible resize inode and its indirect blocks.
pub(super) fn write_resize_inode(
    file: &mut (impl Write + Seek),
    geometry: &GroupGeometry,
    inode_table_block: u64,
    double_indirect_block: u64,
    csum_seed: u32,
    num_groups: u32,
) -> Result<(), Ext4Error> {
    let contents = build_resize_inode(geometry, double_indirect_block, csum_seed, num_groups)?;

    write_block(file, double_indirect_block, &contents.double_indirect)?;
    for (block, block_contents) in contents.reserved_blocks {
        write_block(file, block, &block_contents)?;
    }

    let inode_offset = inode_table_block * u64::from(EXT4_BLOCK_SIZE)
        + u64::from(EXT4_RESIZE_INO - 1) * u64::from(EXT4_INODE_SIZE);
    file.seek(SeekFrom::Start(inode_offset))?;
    file.write_all(&contents.inode)?;
    Ok(())
}

/// Validate inode 7 and every reserved-GDT pointer against the current filesystem geometry.
pub(super) fn validate_resize_inode(
    file: &mut File,
    geometry: &GroupGeometry,
    inode_table_block: u64,
    csum_seed: u32,
    num_groups: u32,
    num_blocks: u64,
) -> Result<u64, Ext4Error> {
    let inode_offset = inode_table_block * u64::from(EXT4_BLOCK_SIZE)
        + u64::from(EXT4_RESIZE_INO - 1) * u64::from(EXT4_INODE_SIZE);
    let mut inode = vec![0u8; EXT4_INODE_SIZE as usize];
    file.seek(SeekFrom::Start(inode_offset))?;
    file.read_exact(&mut inode)?;

    let stored_checksum =
        u32::from(get_le16(&inode, 0x7C)) | (u32::from(get_le16(&inode, 0x82)) << 16);
    if inode_checksum(csum_seed, EXT4_RESIZE_INO, get_le32(&inode, 0x64), &inode) != stored_checksum
    {
        return Err(unsupported("resize inode checksum mismatch"));
    }
    if get_le16(&inode, 0x00) != S_IFREG | 0o600
        || get_le16(&inode, 0x1A) != 1
        || get_le32(&inode, 0x20) != 0
    {
        return Err(unsupported(
            "resize inode has invalid mode, links, or flags",
        ));
    }

    for index in 0..15 {
        if index != 13 && get_le32(&inode, 0x28 + index * 4) != 0 {
            return Err(unsupported("resize inode uses blocks outside i_block[13]"));
        }
    }

    let double_indirect_block = u64::from(get_le32(&inode, DOUBLE_INDIRECT_BLOCK_OFFSET));
    if double_indirect_block == 0 || double_indirect_block >= num_blocks {
        return Err(unsupported(
            "resize inode double-indirect block is out of bounds",
        ));
    }

    let expected_size = resize_inode_size();
    let stored_size = u64::from(get_le32(&inode, 0x04)) | (u64::from(get_le32(&inode, 0x6C)) << 32);
    if stored_size != expected_size {
        return Err(unsupported("resize inode has an invalid logical size"));
    }

    let expected_owned_blocks = resize_inode_owned_blocks(geometry.reserved_gdt_blocks, num_groups);
    let stored_sectors = u64::from(get_le32(&inode, 0x1C));
    if stored_sectors != expected_owned_blocks * u64::from(EXT4_BLOCK_SIZE / 512) {
        return Err(unsupported("resize inode block accounting is inconsistent"));
    }

    let mut double_indirect = vec![0u8; EXT4_BLOCK_SIZE as usize];
    file.seek(SeekFrom::Start(
        double_indirect_block * u64::from(EXT4_BLOCK_SIZE),
    ))?;
    file.read_exact(&mut double_indirect)?;

    let expected = build_resize_pointer_blocks(geometry, num_groups)?;
    for (index, expected_block) in expected.double_indirect_pointers.iter().enumerate() {
        if get_le32(&double_indirect, index * 4) != *expected_block {
            return Err(unsupported(format!(
                "resize inode double-indirect pointer {index} is invalid"
            )));
        }
    }
    for (block, expected_contents) in expected.reserved_blocks {
        let mut contents = vec![0u8; EXT4_BLOCK_SIZE as usize];
        file.seek(SeekFrom::Start(block * u64::from(EXT4_BLOCK_SIZE)))?;
        file.read_exact(&mut contents)?;
        if contents != expected_contents {
            return Err(unsupported(format!(
                "reserved GDT pointer block {block} is invalid"
            )));
        }
    }

    Ok(double_indirect_block)
}

fn build_resize_inode(
    geometry: &GroupGeometry,
    double_indirect_block: u64,
    csum_seed: u32,
    num_groups: u32,
) -> Result<ResizeInodeContents, Ext4Error> {
    let pointers = build_resize_pointer_blocks(geometry, num_groups)?;
    let mut double_indirect = vec![0u8; EXT4_BLOCK_SIZE as usize];
    for (index, block) in pointers.double_indirect_pointers.iter().enumerate() {
        put_le32(&mut double_indirect, index * 4, *block);
    }

    let mut inode = vec![0u8; EXT4_INODE_SIZE as usize];
    let size = resize_inode_size();
    put_le16(&mut inode, 0x00, S_IFREG | 0o600);
    put_le32(&mut inode, 0x04, size as u32);
    put_le16(&mut inode, 0x1A, 1);
    let sectors = resize_inode_owned_blocks(geometry.reserved_gdt_blocks, num_groups)
        * u64::from(EXT4_BLOCK_SIZE / 512);
    put_le32(
        &mut inode,
        0x1C,
        u32::try_from(sectors)
            .map_err(|_| Ext4Error::Layout("resize inode block count exceeds u32".to_string()))?,
    );
    put_le32(
        &mut inode,
        DOUBLE_INDIRECT_BLOCK_OFFSET,
        u32::try_from(double_indirect_block).map_err(|_| {
            Ext4Error::Layout("resize inode double-indirect block exceeds u32".to_string())
        })?,
    );
    put_le32(&mut inode, 0x6C, (size >> 32) as u32);
    put_le16(&mut inode, 0x80, EXT4_MIN_EXTRA_ISIZE);

    let checksum = inode_checksum(csum_seed, EXT4_RESIZE_INO, 0, &inode);
    put_le16(&mut inode, 0x7C, checksum as u16);
    put_le16(&mut inode, 0x82, (checksum >> 16) as u16);

    Ok(ResizeInodeContents {
        inode,
        double_indirect,
        reserved_blocks: pointers.reserved_blocks,
    })
}

fn build_resize_pointer_blocks(
    geometry: &GroupGeometry,
    num_groups: u32,
) -> Result<ResizePointerBlocks, Ext4Error> {
    if geometry.gdt_blocks + geometry.reserved_gdt_blocks > POINTERS_PER_BLOCK {
        return Err(Ext4Error::Layout(
            "GDT span exceeds resize inode double-indirect capacity".to_string(),
        ));
    }

    let mut double_indirect_pointers = vec![0u32; POINTERS_PER_BLOCK as usize];
    let mut reserved_blocks = Vec::with_capacity(geometry.reserved_gdt_blocks as usize);
    let backup_groups = (1..num_groups)
        .filter(|group| sparse_super_group(*group))
        .collect::<Vec<_>>();

    for reserved_offset in 0..geometry.reserved_gdt_blocks {
        let primary_block = 1 + geometry.gdt_blocks + reserved_offset;
        let pointer_index = geometry.gdt_blocks + reserved_offset;
        double_indirect_pointers[pointer_index as usize] = primary_block;

        let mut contents = vec![0u8; EXT4_BLOCK_SIZE as usize];
        for (index, group) in backup_groups.iter().enumerate() {
            let backup_block = u64::from(primary_block)
                + u64::from(*group) * u64::from(super::format::EXT4_BLOCKS_PER_GROUP);
            let backup_block = u32::try_from(backup_block).map_err(|_| {
                Ext4Error::Layout("reserved GDT backup block exceeds u32".to_string())
            })?;
            put_le32(&mut contents, index * 4, backup_block);
        }
        reserved_blocks.push((u64::from(primary_block), contents));
    }

    Ok(ResizePointerBlocks {
        double_indirect_pointers,
        reserved_blocks,
    })
}

fn resize_inode_size() -> u64 {
    let pointers = u64::from(POINTERS_PER_BLOCK);
    (pointers * pointers + pointers + 12) * u64::from(EXT4_BLOCK_SIZE)
}

fn resize_inode_owned_blocks(reserved_gdt_blocks: u32, num_groups: u32) -> u64 {
    let backups = (1..num_groups)
        .filter(|group| sparse_super_group(*group))
        .count() as u64;
    1 + u64::from(reserved_gdt_blocks) * (1 + backups)
}

fn write_block(
    file: &mut (impl Write + Seek),
    block: u64,
    contents: &[u8],
) -> Result<(), Ext4Error> {
    file.seek(SeekFrom::Start(block * u64::from(EXT4_BLOCK_SIZE)))?;
    file.write_all(contents)?;
    Ok(())
}

fn unsupported(message: impl Into<String>) -> Ext4Error {
    Ext4Error::Unsupported(message.into())
}
