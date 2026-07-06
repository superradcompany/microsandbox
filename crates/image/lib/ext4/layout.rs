//! Shared ext4 on-disk layout math, bitmap builders, descriptor building, and metadata checksums used by both the formatter and the offline grow resizer.
//!
//! Everything here is expressed over [`GroupGeometry`] so the formatter (which computes geometry from format options) and the resizer (which recovers geometry from an existing
//! superblock) produce byte-identical per-group metadata.

use std::io::{self, Seek, SeekFrom, Write};

use super::format::{
    EXT4_BG_INODE_ZEROED, EXT4_BLOCK_SIZE, EXT4_BLOCKS_PER_GROUP, EXT4_DESC_SIZE,
    EXT4_INODES_PER_GROUP, sparse_super_group,
};
use crate::crc32c;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Blocks reserved after the GDT for future offline growth. With 64-byte descriptors each reserved block holds 64 more group descriptors, so 256 blocks x 64 descriptors x
/// 128 MiB/group gives roughly 2 TiB of total filesystem size before an image must be recreated.
pub(super) const RESERVED_GDT_BLOCKS: u32 = 256;

/// Maximum image size supported while writing physical block locations through ext4's low 32-bit fields.
pub(super) const MAX_BLOCKS: u64 = u32::MAX as u64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Block-group geometry of a formatter-produced image. All per-group metadata block positions derive from these five values.
pub(super) struct GroupGeometry {
    /// Total 4 KiB blocks in the image.
    pub(super) num_blocks: u64,

    /// Blocks currently occupied by group descriptors.
    pub(super) gdt_blocks: u32,

    /// Blocks reserved after the GDT for future growth. `gdt_blocks + reserved_gdt_blocks` is invariant across grows so existing group metadata never moves.
    pub(super) reserved_gdt_blocks: u32,

    /// Blocks occupied by one group's inode table.
    pub(super) inode_table_blocks: u32,
}

/// Per-group statistics baked into a 64-byte group descriptor.
pub(super) struct GroupDescStats {
    pub(super) free_blocks: u32,
    pub(super) free_inodes: u32,
    pub(super) used_dirs: u32,
    pub(super) block_bitmap_csum: u32,
    pub(super) inode_bitmap_csum: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl GroupGeometry {
    pub(super) fn group_start_block(&self, group: u32) -> u64 {
        group as u64 * EXT4_BLOCKS_PER_GROUP as u64
    }

    pub(super) fn blocks_in_group(&self, group: u32) -> u32 {
        let group_start = self.group_start_block(group);
        std::cmp::min(
            EXT4_BLOCKS_PER_GROUP as u64,
            self.num_blocks.saturating_sub(group_start),
        ) as u32
    }

    pub(super) fn group_has_backup_super(&self, group: u32) -> bool {
        group == 0 || sparse_super_group(group)
    }

    pub(super) fn group_leading_overhead_blocks(&self, group: u32) -> u32 {
        if self.group_has_backup_super(group) {
            1 + self.gdt_blocks + self.reserved_gdt_blocks
        } else {
            0
        }
    }

    pub(super) fn group_block_bitmap_block(&self, group: u32) -> u64 {
        self.group_start_block(group) + self.group_leading_overhead_blocks(group) as u64
    }

    pub(super) fn group_inode_bitmap_block(&self, group: u32) -> u64 {
        self.group_block_bitmap_block(group) + 1
    }

    pub(super) fn group_inode_table_block(&self, group: u32) -> u64 {
        self.group_inode_bitmap_block(group) + 1
    }

    pub(super) fn group_metadata_blocks(&self, group: u32) -> u32 {
        self.group_leading_overhead_blocks(group) + 2 + self.inode_table_blocks
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Bitmaps
//--------------------------------------------------------------------------------------------------

/// Block bitmap for a group with no data allocations: per-group metadata is marked used and the padding bits past the end of a partial final group are permanently set.
pub(super) fn build_block_bitmap_base(geo: &GroupGeometry, group: u32) -> Vec<u8> {
    let mut bitmap = vec![0u8; EXT4_BLOCK_SIZE as usize];

    for bit in 0..geo.group_metadata_blocks(group) {
        bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
    }

    let blocks_in_group = geo.blocks_in_group(group);
    for bit in blocks_in_group..EXT4_BLOCKS_PER_GROUP {
        bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
    }

    bitmap
}

/// Inode bitmap with the first `used_inodes` bits set. The bitmap consumes only the first inodes-per-group bits; the remaining padding bits in the block stay permanently set.
pub(super) fn build_inode_bitmap_base(used_inodes: u32) -> Vec<u8> {
    let mut bitmap = vec![0u8; EXT4_BLOCK_SIZE as usize];
    for bit in 0..used_inodes {
        bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
    }
    for bit in EXT4_INODES_PER_GROUP..(EXT4_BLOCK_SIZE * 8) {
        bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
    }
    bitmap
}

pub(super) fn count_used_bits(bitmap: &[u8], bits: usize) -> usize {
    let full_bytes = bits / 8;
    let mut used: usize = bitmap[..full_bytes]
        .iter()
        .map(|b| b.count_ones() as usize)
        .sum();

    // Count remaining bits in the partial last byte.
    let remaining = bits % 8;
    if remaining > 0 {
        let mask = (1u8 << remaining) - 1;
        used += (bitmap[full_bytes] & mask).count_ones() as usize;
    }
    used
}

//--------------------------------------------------------------------------------------------------
// Functions: Descriptors
//--------------------------------------------------------------------------------------------------

/// Build one 64-byte group descriptor with the same field set and flags the formatter writes, including the descriptor checksum.
pub(super) fn build_group_descriptor(
    geo: &GroupGeometry,
    group: u32,
    stats: &GroupDescStats,
    csum_seed: u32,
) -> [u8; EXT4_DESC_SIZE as usize] {
    let mut desc = [0u8; EXT4_DESC_SIZE as usize];
    let bb = geo.group_block_bitmap_block(group);
    let ib = geo.group_inode_bitmap_block(group);
    let it = geo.group_inode_table_block(group);

    put_le32(&mut desc, 0x00, bb as u32);
    put_le32(&mut desc, 0x04, ib as u32);
    put_le32(&mut desc, 0x08, it as u32);
    put_le16(&mut desc, 0x0C, stats.free_blocks as u16);
    put_le16(&mut desc, 0x0E, stats.free_inodes as u16);
    put_le16(&mut desc, 0x10, stats.used_dirs as u16);
    put_le16(&mut desc, 0x12, EXT4_BG_INODE_ZEROED);
    put_le16(&mut desc, 0x18, stats.block_bitmap_csum as u16);
    put_le16(&mut desc, 0x1A, stats.inode_bitmap_csum as u16);
    put_le16(&mut desc, 0x1C, stats.free_inodes as u16);
    put_le32(&mut desc, 0x20, (bb >> 32) as u32);
    put_le32(&mut desc, 0x24, (ib >> 32) as u32);
    put_le32(&mut desc, 0x28, (it >> 32) as u32);
    put_le16(&mut desc, 0x2C, (stats.free_blocks >> 16) as u16);
    put_le16(&mut desc, 0x2E, (stats.free_inodes >> 16) as u16);
    put_le16(&mut desc, 0x30, (stats.used_dirs >> 16) as u16);
    put_le16(&mut desc, 0x32, (stats.free_inodes >> 16) as u16);
    put_le16(&mut desc, 0x38, (stats.block_bitmap_csum >> 16) as u16);
    put_le16(&mut desc, 0x3A, (stats.inode_bitmap_csum >> 16) as u16);
    let checksum = gdt_checksum(csum_seed, group, &desc);
    put_le16(&mut desc, 0x1E, checksum);

    desc
}

//--------------------------------------------------------------------------------------------------
// Functions: Checksums
//--------------------------------------------------------------------------------------------------

/// GDT entry checksum (16-bit). `desc` must have its checksum field (offset 0x1E) zeroed.
pub(super) fn gdt_checksum(csum_seed: u32, group: u32, desc: &[u8]) -> u16 {
    let mut crc = crc32c::crc32c_raw(csum_seed, &group.to_le_bytes());
    crc = crc32c::crc32c_raw(crc, desc);
    (crc & 0xFFFF) as u16
}

/// Inode checksum (32-bit, split across lo/hi in the inode).
pub(super) fn inode_checksum(
    csum_seed: u32,
    inum: u32,
    generation: u32,
    inode_bytes: &[u8],
) -> u32 {
    let mut crc = crc32c::crc32c_raw(csum_seed, &inum.to_le_bytes());
    crc = crc32c::crc32c_raw(crc, &generation.to_le_bytes());
    crc = crc32c::crc32c_raw(crc, &inode_bytes[..0x7C]);
    crc = crc32c::crc32c_raw(crc, &[0u8; 2]);
    crc = crc32c::crc32c_raw(crc, &inode_bytes[0x7E..0x82]);
    crc = crc32c::crc32c_raw(crc, &[0u8; 2]);
    crc = crc32c::crc32c_raw(crc, &inode_bytes[0x84..]);
    crc
}

/// Bitmap checksum (block bitmap or inode bitmap), computed over the first `checksum_len` bytes of the in-memory bitmap and stored in the corresponding GDT fields.
pub(super) fn bitmap_checksum(csum_seed: u32, bitmap: &[u8], checksum_len: usize) -> u32 {
    crc32c::crc32c_raw(csum_seed, &bitmap[..checksum_len])
}

/// Directory block checksum.
pub(super) fn dir_block_checksum(csum_seed: u32, inum: u32, generation: u32, data: &[u8]) -> u32 {
    let mut crc = crc32c::crc32c_raw(csum_seed, &inum.to_le_bytes());
    crc = crc32c::crc32c_raw(crc, &generation.to_le_bytes());
    crc = crc32c::crc32c_raw(crc, data);
    crc
}

/// Superblock checksum: CRC32C over the 1020 bytes preceding the `s_checksum` field.
pub(super) fn superblock_checksum(sb: &[u8]) -> u32 {
    crc32c::crc32c_raw(0xFFFF_FFFF, &sb[..0x3FC])
}

//--------------------------------------------------------------------------------------------------
// Functions: Writers
//--------------------------------------------------------------------------------------------------

/// Write a 1024-byte backup superblock at the given group's first byte.
pub(super) fn write_backup_superblock_at(
    file: &mut (impl Write + Seek),
    group_start_block: u64,
    sb_block: &[u8],
) -> io::Result<()> {
    file.seek(SeekFrom::Start(group_start_block * EXT4_BLOCK_SIZE as u64))?;
    file.write_all(sb_block)?;
    Ok(())
}

/// Write GDT at block (group_start_block + 1).
pub(super) fn write_gdt_at(
    file: &mut (impl Write + Seek),
    group_start_block: u64,
    gdt: &[u8],
) -> io::Result<()> {
    let offset = (group_start_block + 1) * EXT4_BLOCK_SIZE as u64;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(gdt)?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Byte helpers
//--------------------------------------------------------------------------------------------------

pub(super) fn put_le16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}

pub(super) fn put_le32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

pub(super) fn put_be32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_be_bytes());
}

pub(super) fn get_le16(buf: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([buf[off], buf[off + 1]])
}

pub(super) fn get_le32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub(super) fn get_be32(buf: &[u8], off: usize) -> u32 {
    u32::from_be_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}
