//! Offline grow-only resizer for ext4 upper images produced by this crate's formatter.
//!
//! The resizer parses and strictly validates the primary superblock (it refuses anything the formatter did not write), then appends whole block groups: per-group bitmaps, backup
//! superblock + GDT copies in new sparse_super groups, descriptors appended to the primary GDT and every backup GDT, and finally the updated primary superblock. Because the
//! formatter reserves `RESERVED_GDT_BLOCKS` after the GDT, descriptors can extend into that reserved span without moving any existing metadata: `gdt_blocks +
//! s_reserved_gdt_blocks` stays constant across grows.
//!
//! Images whose guest was stopped without unmounting carry `EXT4_FEATURE_INCOMPAT_RECOVER` plus a pending jbd2 log; those are recovered first (see the [`jbd2`](super::jbd2)
//! module) and then grown as clean images.

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use super::format::{
    EXT4_BG_INODE_ZEROED, EXT4_BLOCK_SIZE, EXT4_BLOCKS_PER_GROUP, EXT4_DESC_SIZE, EXT4_EH_MAGIC,
    EXT4_EXTENTS_FL, EXT4_FEATURE_COMPAT_DIR_INDEX, EXT4_FEATURE_COMPAT_EXT_ATTR,
    EXT4_FEATURE_COMPAT_HAS_JOURNAL, EXT4_FEATURE_COMPAT_RESIZE_INODE, EXT4_FEATURE_INCOMPAT_64BIT,
    EXT4_FEATURE_INCOMPAT_EXTENTS, EXT4_FEATURE_INCOMPAT_FILETYPE, EXT4_FEATURE_INCOMPAT_RECOVER,
    EXT4_FEATURE_RO_COMPAT_DIR_NLINK, EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE,
    EXT4_FEATURE_RO_COMPAT_HUGE_FILE, EXT4_FEATURE_RO_COMPAT_LARGE_FILE,
    EXT4_FEATURE_RO_COMPAT_METADATA_CSUM, EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER, EXT4_FIRST_INO,
    EXT4_INODE_SIZE, EXT4_INODES_PER_GROUP, EXT4_JOURNAL_INO, EXT4_LOG_BLOCK_SIZE, EXT4_ROOT_INO,
    EXT4_SB_ERROR_COUNT_OFFSET, EXT4_SB_OVERHEAD_BLOCKS_OFFSET, EXT4_SUPER_MAGIC,
    sparse_super_group,
};
use super::formatter::{Ext4Error, mark_sparse};
use super::jbd2;
use super::layout::{
    GroupDescStats, GroupGeometry, MAX_BLOCKS, bitmap_checksum, build_block_bitmap_base,
    build_group_descriptor, build_inode_bitmap_base, count_used_bits, dir_block_checksum,
    gdt_checksum, get_le16, get_le32, inode_checksum, put_le16, put_le32, superblock_checksum,
    write_backup_superblock_at, write_gdt_at,
};
use super::resize_inode::{validate_resize_inode, write_resize_inode};
use crate::crc32c;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Byte offset of the 1024-byte superblock within the image.
const SB_OFFSET: u64 = 1024;

/// On-disk superblock size.
const SB_SIZE: usize = 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result of a successful offline grow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrowOutcome {
    /// 4 KiB block count before the grow.
    pub old_blocks: u64,

    /// 4 KiB block count after the grow.
    pub new_blocks: u64,

    /// Block group count before the grow.
    pub old_groups: u32,

    /// Block group count after the grow.
    pub new_groups: u32,
}

/// Superblock and primary GDT state parsed from an image and validated to match exactly what
/// this crate's formatter writes.
struct ParsedImage {
    /// Raw 1024-byte primary superblock.
    sb: Vec<u8>,

    /// Raw primary GDT descriptors (num_groups x 64 bytes). Left empty when `needs_recovery` is set, since the deep GDT validation that fills it only runs on clean images.
    gdt: Vec<u8>,

    /// `EXT4_FEATURE_INCOMPAT_RECOVER` was set: the guest never unmounted, so the jbd2 log must be replayed before the image can be trusted or grown.
    needs_recovery: bool,

    num_blocks: u64,
    num_groups: u32,
    gdt_blocks: u32,
    reserved_gdt_blocks: u32,
    inode_table_blocks: u32,
    csum_seed: u32,
    free_blocks: u64,
    free_inodes: u32,
    overhead_blocks: u32,
    resize_inode_block: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ParsedImage {
    fn geometry(&self) -> GroupGeometry {
        GroupGeometry {
            num_blocks: self.num_blocks,
            gdt_blocks: self.gdt_blocks,
            reserved_gdt_blocks: self.reserved_gdt_blocks,
            inode_table_blocks: self.inode_table_blocks,
        }
    }

    /// Largest block count this image can grow to in place: every group needs a descriptor, and
    /// descriptors must fit within the blocks already set aside for the GDT (allocated +
    /// reserved), since the data that follows them cannot be moved offline.
    fn max_growable_blocks(&self) -> u64 {
        let descs_per_block = (EXT4_BLOCK_SIZE / EXT4_DESC_SIZE as u32) as u64;
        let capacity_groups =
            (self.gdt_blocks as u64 + self.reserved_gdt_blocks as u64) * descs_per_block;
        (capacity_groups * EXT4_BLOCKS_PER_GROUP as u64).min(MAX_BLOCKS)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Grow the formatter-produced ext4 image at `path` to `new_size_bytes`.
///
/// Shrinking and no-op sizes are refused, the size must be a 4 KiB multiple, and the new group
/// descriptors must fit within the image's existing GDT capacity (see
/// [`Ext4Error::ExceedsGdtCapacity`]).
///
/// Images left dirty by a hard guest stop (`EXT4_FEATURE_INCOMPAT_RECOVER` set) have their jbd2
/// log replayed and the flag cleared everywhere before growing; any journal inconsistency aborts
/// with the image untouched.
///
/// Publish ordering: all new-group metadata, backup superblocks, backup GDTs, and resize-inode
/// metadata are written and fsynced before the primary superblock advertises the larger geometry.
/// This is not a transactional rollback boundary: if the in-place grow returns an error or the
/// process is interrupted, callers must discard and recreate the artifact rather than use it.
pub fn grow_image(path: &Path, new_size_bytes: u64) -> Result<GrowOutcome, Ext4Error> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let mut img = parse_and_validate(&mut file)?;

    // Replay the journal before anything else: growing with a pending log would let the next kernel mount replay stale transactions over the appended GDT entries. After a
    // successful replay the image must re-validate as a clean formatter image (the deep GDT checks were skipped on the dirty parse).
    if img.needs_recovery {
        replay_journal_and_clear_recover(&mut file, &img)?;
        img = parse_and_validate(&mut file)?;
        if img.needs_recovery {
            return Err(unsupported("journal recovery left the RECOVER flag set"));
        }
    }

    let block_size = EXT4_BLOCK_SIZE as u64;
    if !new_size_bytes.is_multiple_of(block_size) {
        return Err(Ext4Error::InvalidSize(format!(
            "image size must be aligned to {block_size} bytes"
        )));
    }
    let new_blocks = new_size_bytes / block_size;
    if new_blocks > MAX_BLOCKS {
        return Err(Ext4Error::TooLarge {
            requested_blocks: new_blocks,
            max_blocks: MAX_BLOCKS,
        });
    }
    if new_blocks <= img.num_blocks {
        return Err(Ext4Error::InvalidSize(format!(
            "cannot grow image from {} to {} bytes: the new size must be larger than the current size",
            img.num_blocks * block_size,
            new_size_bytes
        )));
    }
    if new_blocks > img.max_growable_blocks() {
        return Err(Ext4Error::ExceedsGdtCapacity {
            requested_bytes: new_size_bytes,
            max_size_bytes: img.max_growable_blocks() * block_size,
        });
    }

    let new_groups = new_blocks.div_ceil(EXT4_BLOCKS_PER_GROUP as u64) as u32;
    let descs_per_block = EXT4_BLOCK_SIZE / EXT4_DESC_SIZE as u32;
    let new_gdt_blocks = new_groups.div_ceil(descs_per_block);

    // Descriptors may extend into the reserved GDT span, but `gdt_blocks + reserved` stays
    // constant so no existing per-group metadata moves.
    let gdt_span = img.gdt_blocks + img.reserved_gdt_blocks;
    let new_reserved = gdt_span - new_gdt_blocks;

    let new_geo = GroupGeometry {
        num_blocks: new_blocks,
        gdt_blocks: new_gdt_blocks,
        reserved_gdt_blocks: new_reserved,
        inode_table_blocks: img.inode_table_blocks,
    };

    // Same partial-final-group rule as the formatter: a new group must be able to hold its
    // own metadata.
    for group in img.num_groups..new_groups {
        let blocks_in_group = new_geo.blocks_in_group(group);
        let metadata_blocks = new_geo.group_metadata_blocks(group);
        if blocks_in_group < metadata_blocks {
            return Err(Ext4Error::InvalidSize(format!(
                "block group {group} has {blocks_in_group} blocks but needs at least {metadata_blocks} metadata blocks; choose a size that leaves either no partial group or a larger final group"
            )));
        }
    }

    mark_sparse(&file)?;
    file.set_len(new_size_bytes)?;

    let mut gdt = img.gdt.clone();
    let mut total_free = img.free_blocks;
    let mut overhead = img.overhead_blocks as u64;

    // If the old final group was partial, the padding bits past its old end become real free
    // blocks: clear them in its bitmap and refresh its descriptor.
    let old_last = img.num_groups - 1;
    let old_geo = img.geometry();
    let old_last_blocks = old_geo.blocks_in_group(old_last);
    let new_last_blocks = new_geo.blocks_in_group(old_last);
    let mut extended_last_bitmap: Option<Vec<u8>> = None;
    if new_last_blocks > old_last_blocks {
        let mut bitmap = read_block_at(&mut file, old_geo.group_block_bitmap_block(old_last))?;
        for bit in old_last_blocks..new_last_blocks {
            bitmap[(bit / 8) as usize] &= !(1 << (bit % 8));
        }
        let bb_csum = bitmap_checksum(img.csum_seed, &bitmap, EXT4_BLOCK_SIZE as usize);
        let delta = new_last_blocks - old_last_blocks;

        let off = old_last as usize * EXT4_DESC_SIZE as usize;
        let desc = &mut gdt[off..off + EXT4_DESC_SIZE as usize];
        let free_blocks =
            (get_le16(desc, 0x0C) as u32 | ((get_le16(desc, 0x2C) as u32) << 16)) + delta;
        put_le16(desc, 0x0C, free_blocks as u16);
        put_le16(desc, 0x2C, (free_blocks >> 16) as u16);
        put_le16(desc, 0x18, bb_csum as u16);
        put_le16(desc, 0x38, (bb_csum >> 16) as u16);
        put_le16(desc, 0x1E, 0);
        let checksum = gdt_checksum(img.csum_seed, old_last, desc);
        put_le16(desc, 0x1E, checksum);

        total_free += delta as u64;
        extended_last_bitmap = Some(bitmap);
    }

    // New groups: bitmaps on disk, descriptors in memory. Inode tables stay sparse zeros,
    // matching the formatter's EXT4_BG_INODE_ZEROED groups.
    for group in img.num_groups..new_groups {
        let block_bitmap = build_block_bitmap_base(&new_geo, group);
        let inode_bitmap = build_inode_bitmap_base(0);
        write_block_at(
            &mut file,
            new_geo.group_block_bitmap_block(group),
            &block_bitmap,
        )?;
        write_block_at(
            &mut file,
            new_geo.group_inode_bitmap_block(group),
            &inode_bitmap,
        )?;

        let free_blocks = new_geo.blocks_in_group(group) - new_geo.group_metadata_blocks(group);
        let stats = GroupDescStats {
            free_blocks,
            free_inodes: EXT4_INODES_PER_GROUP,
            used_dirs: 0,
            block_bitmap_csum: bitmap_checksum(
                img.csum_seed,
                &block_bitmap,
                EXT4_BLOCK_SIZE as usize,
            ),
            inode_bitmap_csum: bitmap_checksum(
                img.csum_seed,
                &inode_bitmap,
                (EXT4_INODES_PER_GROUP / 8) as usize,
            ),
        };
        gdt.extend_from_slice(&build_group_descriptor(
            &new_geo,
            group,
            &stats,
            img.csum_seed,
        ));

        total_free += free_blocks as u64;
        overhead += new_geo.group_metadata_blocks(group) as u64;
    }

    let added_groups = new_groups - img.num_groups;
    let mut new_sb = img.sb.clone();
    put_le32(&mut new_sb, 0x00, new_groups * EXT4_INODES_PER_GROUP);
    put_le32(&mut new_sb, 0x04, new_blocks as u32);
    put_le32(&mut new_sb, 0x150, (new_blocks >> 32) as u32);
    put_le32(&mut new_sb, 0x0C, total_free as u32);
    put_le32(&mut new_sb, 0x158, (total_free >> 32) as u32);
    put_le32(
        &mut new_sb,
        0x10,
        img.free_inodes + added_groups * EXT4_INODES_PER_GROUP,
    );
    put_le16(&mut new_sb, 0xCE, new_reserved as u16);
    put_le32(&mut new_sb, EXT4_SB_OVERHEAD_BLOCKS_OFFSET, overhead as u32);
    let new_sb_csum = superblock_checksum(&new_sb);
    put_le32(&mut new_sb, 0x3FC, new_sb_csum);

    // Phase 1: everything invisible while the old primary superblock is in place — new-group
    // bitmaps (written above), descriptors appended past the old end of the primary GDT, and
    // every backup superblock + GDT copy.
    let old_gdt_len = img.num_groups as usize * EXT4_DESC_SIZE as usize;
    file.seek(SeekFrom::Start(EXT4_BLOCK_SIZE as u64 + old_gdt_len as u64))?;
    file.write_all(&gdt[old_gdt_len..])?;

    for group in 1..new_groups {
        if !sparse_super_group(group) {
            continue;
        }
        let mut backup_sb = new_sb.clone();
        put_le16(&mut backup_sb, 0x5A, group as u16);
        let backup_sb_csum = superblock_checksum(&backup_sb);
        put_le32(&mut backup_sb, 0x3FC, backup_sb_csum);
        write_backup_superblock_at(&mut file, new_geo.group_start_block(group), &backup_sb)?;
        write_gdt_at(&mut file, new_geo.group_start_block(group), &gdt)?;
    }
    // Consuming reserved headroom shifts the live pointer range in inode 7. Rebuild the complete
    // structure after all descriptor copies are in place so no consumed GDT block is overwritten.
    write_resize_inode(
        &mut file,
        &new_geo,
        new_geo.group_inode_table_block(0),
        img.resize_inode_block,
        img.csum_seed,
        new_groups,
    )?;
    file.sync_all()?;

    // Phase 2: the only pre-publish writes visible at the old size (the old final group's
    // bitmap padding and free count). A tear here still leaves the old superblock intact and
    // the drift is limited to that one group's padding bits and free count.
    if let Some(bitmap) = &extended_last_bitmap {
        write_block_at(
            &mut file,
            old_geo.group_block_bitmap_block(old_last),
            bitmap,
        )?;
        let off = old_last as usize * EXT4_DESC_SIZE as usize;
        file.seek(SeekFrom::Start(EXT4_BLOCK_SIZE as u64 + off as u64))?;
        file.write_all(&gdt[off..off + EXT4_DESC_SIZE as usize])?;
        file.sync_all()?;
    }

    // Phase 3: publish the grow by rewriting the primary superblock last.
    file.seek(SeekFrom::Start(SB_OFFSET))?;
    file.write_all(&new_sb)?;
    file.sync_all()?;

    Ok(GrowOutcome {
        old_blocks: img.num_blocks,
        new_blocks,
        old_groups: img.num_groups,
        new_groups,
    })
}

/// Validate a newly materialized rootfs without mounting it or trusting host filesystem tools.
pub(super) fn validate_rootfs_image(path: &Path) -> Result<(), Ext4Error> {
    let mut file = File::open(path)?;
    let img = parse_and_validate(&mut file)?;
    if img.needs_recovery {
        return Err(unsupported(
            "new rootfs unexpectedly requires journal recovery",
        ));
    }
    let geometry = img.geometry();
    let mut total_free_blocks = 0u64;
    let mut total_free_inodes = 0u64;

    for group in 0..img.num_groups {
        let descriptor =
            &img.gdt[group as usize * EXT4_DESC_SIZE as usize..][..EXT4_DESC_SIZE as usize];
        let block_bitmap = read_block_at(&mut file, geometry.group_block_bitmap_block(group))?;
        let inode_bitmap = read_block_at(&mut file, geometry.group_inode_bitmap_block(group))?;
        validate_group_bitmaps(&img, group, descriptor, &block_bitmap, &inode_bitmap)?;

        let used_blocks = count_used_bits(&block_bitmap, geometry.blocks_in_group(group) as usize);
        total_free_blocks += u64::from(geometry.blocks_in_group(group)) - used_blocks as u64;
        let used_inodes = count_used_bits(&inode_bitmap, EXT4_INODES_PER_GROUP as usize);
        total_free_inodes += u64::from(EXT4_INODES_PER_GROUP) - used_inodes as u64;

        for local_inode in 0..EXT4_INODES_PER_GROUP {
            if inode_bitmap[(local_inode / 8) as usize] & (1 << (local_inode % 8)) == 0 {
                continue;
            }
            let inode_number = group * EXT4_INODES_PER_GROUP + local_inode + 1;
            if inode_number < EXT4_FIRST_INO
                && inode_number != EXT4_ROOT_INO
                && inode_number != EXT4_JOURNAL_INO
            {
                continue;
            }
            validate_allocated_inode(
                &mut file,
                &img,
                group,
                local_inode,
                inode_number,
                &block_bitmap,
            )?;
        }
    }

    if total_free_blocks != img.free_blocks || total_free_inodes != u64::from(img.free_inodes) {
        return Err(unsupported(
            "superblock free-space counters do not match bitmaps",
        ));
    }
    validate_resize_inode(
        &mut file,
        &geometry,
        geometry.group_inode_table_block(0),
        img.csum_seed,
        img.num_groups,
        img.num_blocks,
    )?;
    validate_backup_metadata(&mut file, &img)?;
    Ok(())
}

/// Parse the primary superblock and GDT, refusing anything that does not match exactly what this
/// crate's formatter writes (geometry, feature masks, per-group layout, checksums).
fn parse_and_validate(file: &mut File) -> Result<ParsedImage, Ext4Error> {
    let file_len = file.metadata()?.len();
    if file_len < SB_OFFSET + SB_SIZE as u64 {
        return Err(unsupported("file too small to contain an ext4 superblock"));
    }

    let mut sb = vec![0u8; SB_SIZE];
    file.seek(SeekFrom::Start(SB_OFFSET))?;
    file.read_exact(&mut sb)?;

    if get_le16(&sb, 0x38) != EXT4_SUPER_MAGIC {
        return Err(unsupported("bad superblock magic"));
    }
    if superblock_checksum(&sb) != get_le32(&sb, 0x3FC) {
        return Err(unsupported("superblock checksum mismatch"));
    }

    let compat = get_le32(&sb, 0x5C);
    let incompat = get_le32(&sb, 0x60);
    let ro_compat = get_le32(&sb, 0x64);
    let expected_compat = EXT4_FEATURE_COMPAT_HAS_JOURNAL
        | EXT4_FEATURE_COMPAT_EXT_ATTR
        | EXT4_FEATURE_COMPAT_RESIZE_INODE
        | EXT4_FEATURE_COMPAT_DIR_INDEX;
    let expected_incompat = EXT4_FEATURE_INCOMPAT_FILETYPE
        | EXT4_FEATURE_INCOMPAT_EXTENTS
        | EXT4_FEATURE_INCOMPAT_64BIT;
    let expected_ro_compat = EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER
        | EXT4_FEATURE_RO_COMPAT_LARGE_FILE
        | EXT4_FEATURE_RO_COMPAT_HUGE_FILE
        | EXT4_FEATURE_RO_COMPAT_DIR_NLINK
        | EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE
        | EXT4_FEATURE_RO_COMPAT_METADATA_CSUM;
    // Acceptance rule: exactly the formatter's masks, with one exception — INCOMPAT_RECOVER may additionally be set, because every upper that was ever mounted carries it (the
    // guest does not unmount on stop). RECOVER images get their journal replayed by grow_image before the deep validation below ever runs on them.
    let needs_recovery = incompat & EXT4_FEATURE_INCOMPAT_RECOVER != 0;
    if compat != expected_compat
        || incompat & !EXT4_FEATURE_INCOMPAT_RECOVER != expected_incompat
        || ro_compat != expected_ro_compat
    {
        return Err(unsupported(format!(
            "feature flags do not match this crate's formatter (compat={compat:#x}, incompat={incompat:#x}, ro_compat={ro_compat:#x})"
        )));
    }

    let checks: [(bool, &str); 14] = [
        (get_le32(&sb, 0x4C) == 1, "unexpected revision level"),
        (
            get_le32(&sb, 0x18) == EXT4_LOG_BLOCK_SIZE,
            "unexpected block size",
        ),
        (
            get_le32(&sb, 0x1C) == EXT4_LOG_BLOCK_SIZE,
            "unexpected cluster size",
        ),
        (
            get_le32(&sb, 0x20) == EXT4_BLOCKS_PER_GROUP,
            "unexpected blocks per group",
        ),
        (
            get_le32(&sb, 0x24) == EXT4_BLOCKS_PER_GROUP,
            "unexpected clusters per group",
        ),
        (
            get_le32(&sb, 0x28) == EXT4_INODES_PER_GROUP,
            "unexpected inodes per group",
        ),
        (
            get_le16(&sb, 0x58) == EXT4_INODE_SIZE,
            "unexpected inode size",
        ),
        (
            get_le16(&sb, 0xFE) == EXT4_DESC_SIZE,
            "unexpected group descriptor size",
        ),
        (get_le32(&sb, 0x14) == 0, "unexpected first data block"),
        (
            get_le32(&sb, 0x54) == EXT4_FIRST_INO,
            "unexpected first inode",
        ),
        (get_le16(&sb, 0x5A) == 0, "not a primary superblock"),
        (sb[0x175] == 1, "unexpected metadata checksum type"),
        (
            sb[0x174] == 0 && get_le32(&sb, 0x104) == 0,
            "unexpected flex_bg/meta_bg layout",
        ),
        (
            get_le32(&sb, EXT4_SB_ERROR_COUNT_OFFSET) == 0,
            "superblock error count is nonzero",
        ),
    ];
    for (ok, message) in checks {
        if !ok {
            return Err(unsupported(message));
        }
    }
    // The kernel signals pending recovery via INCOMPAT_RECOVER and leaves s_state at 1 (valid) even across a hard stop, so any other value — error bits set or the valid bit
    // cleared — means damage that journal replay cannot repair.
    if get_le16(&sb, 0x3A) != 1 {
        return Err(unsupported("filesystem state is not clean (s_state != 1)"));
    }

    let num_blocks = get_le32(&sb, 0x04) as u64 | ((get_le32(&sb, 0x150) as u64) << 32);
    if num_blocks == 0 || num_blocks > MAX_BLOCKS {
        return Err(unsupported("implausible block count"));
    }
    if file_len != num_blocks * EXT4_BLOCK_SIZE as u64 {
        return Err(unsupported(
            "file length does not match superblock block count",
        ));
    }

    let num_groups = num_blocks.div_ceil(EXT4_BLOCKS_PER_GROUP as u64) as u32;
    if get_le32(&sb, 0x00) != num_groups * EXT4_INODES_PER_GROUP {
        return Err(unsupported("inode count does not match group count"));
    }

    let reserved_gdt_blocks = get_le16(&sb, 0xCE) as u32;
    let gdt_blocks =
        (num_groups as u64 * EXT4_DESC_SIZE as u64).div_ceil(EXT4_BLOCK_SIZE as u64) as u32;
    let inode_table_blocks =
        (EXT4_INODES_PER_GROUP as u64 * EXT4_INODE_SIZE as u64 / EXT4_BLOCK_SIZE as u64) as u32;

    let mut uuid = [0u8; 16];
    uuid.copy_from_slice(&sb[0x68..0x78]);
    let csum_seed = crc32c::crc32c_raw(0xFFFF_FFFF, &uuid);

    let img = ParsedImage {
        num_blocks,
        num_groups,
        gdt_blocks,
        reserved_gdt_blocks,
        inode_table_blocks,
        csum_seed,
        free_blocks: get_le32(&sb, 0x0C) as u64 | ((get_le32(&sb, 0x158) as u64) << 32),
        free_inodes: get_le32(&sb, 0x10),
        overhead_blocks: get_le32(&sb, EXT4_SB_OVERHEAD_BLOCKS_OFFSET),
        resize_inode_block: 0,
        gdt: Vec::new(),
        needs_recovery,
        sb,
    };

    let geo = img.geometry();
    if (geo.group_metadata_blocks(0) as u64) > geo.blocks_in_group(0) as u64 {
        return Err(unsupported("group 0 metadata does not fit its group"));
    }

    // Until the journal is replayed the on-disk descriptors may be stale or torn mid-checkpoint — exactly what replay repairs — so the deep validation below only runs on a
    // clean image; grow_image replays and re-parses before growing.
    if img.needs_recovery {
        return Ok(img);
    }

    // A non-empty orphan list needs inode-level processing (truncating/deleting inodes that were unlinked while open) that this resizer does not implement.
    if get_le32(&img.sb, 0xE8) != 0 {
        return Err(unsupported("filesystem has a pending orphan inode list"));
    }

    // Every existing descriptor must place its group's metadata exactly where the formatter's
    // layout does and carry a valid checksum; anything else means the image is not ours.
    let mut gdt = vec![0u8; img.num_groups as usize * EXT4_DESC_SIZE as usize];
    file.seek(SeekFrom::Start(EXT4_BLOCK_SIZE as u64))?;
    file.read_exact(&mut gdt)?;
    for group in 0..img.num_groups {
        let desc = &gdt[group as usize * EXT4_DESC_SIZE as usize..][..EXT4_DESC_SIZE as usize];
        let bb = get_le32(desc, 0x00) as u64 | ((get_le32(desc, 0x20) as u64) << 32);
        let ib = get_le32(desc, 0x04) as u64 | ((get_le32(desc, 0x24) as u64) << 32);
        let it = get_le32(desc, 0x08) as u64 | ((get_le32(desc, 0x28) as u64) << 32);
        if bb != geo.group_block_bitmap_block(group)
            || ib != geo.group_inode_bitmap_block(group)
            || it != geo.group_inode_table_block(group)
        {
            return Err(unsupported(format!(
                "group {group} metadata is not at the expected location"
            )));
        }
        if get_le16(desc, 0x12) != EXT4_BG_INODE_ZEROED {
            return Err(unsupported(format!("group {group} has unexpected flags")));
        }
        let mut desc_copy = desc.to_vec();
        put_le16(&mut desc_copy, 0x1E, 0);
        if gdt_checksum(img.csum_seed, group, &desc_copy) != get_le16(desc, 0x1E) {
            return Err(unsupported(format!(
                "group {group} descriptor checksum mismatch"
            )));
        }
    }

    let resize_inode_block = validate_resize_inode(
        file,
        &geo,
        geo.group_inode_table_block(0),
        img.csum_seed,
        img.num_groups,
        img.num_blocks,
    )?;

    Ok(ParsedImage {
        gdt,
        resize_inode_block,
        ..img
    })
}

/// Replay the pending jbd2 log, then clear `EXT4_FEATURE_INCOMPAT_RECOVER` from the primary and every backup superblock.
///
/// The journal is fully validated before its first write (see [`jbd2::recover_journal`]) and the backup superblocks are validated up front too, so an inconsistent image is
/// refused untouched. The write ordering is crash-safe: replayed blocks are fsynced, then the jbd2 superblock is reset to empty, then RECOVER is cleared — a tear at any point
/// leaves an image that the next attempt recovers to the same end state (replaying an already-emptied journal is a no-op).
fn replay_journal_and_clear_recover(file: &mut File, img: &ParsedImage) -> Result<(), Ext4Error> {
    let geo = img.geometry();
    let journal = jbd2::locate_journal(file, geo.group_inode_table_block(0), img.csum_seed)?;
    if journal.start_block + journal.len_blocks as u64 > img.num_blocks {
        return Err(unsupported("journal extent extends beyond the filesystem"));
    }
    let mut fs_uuid = [0u8; 16];
    fs_uuid.copy_from_slice(&img.sb[0x68..0x78]);

    let backup_groups: Vec<u32> = (1..img.num_groups)
        .filter(|g| sparse_super_group(*g))
        .collect();
    for &group in &backup_groups {
        read_superblock_at(
            file,
            geo.group_start_block(group) * EXT4_BLOCK_SIZE as u64,
            &format!("group {group} backup"),
        )?;
    }

    jbd2::recover_journal(file, &journal, &fs_uuid, img.num_blocks)?;

    // Replay may rewrite block 0 — the primary superblock is journaled metadata like any other — so re-read it before clearing the flag.
    let mut sb = read_superblock_at(file, SB_OFFSET, "primary")?;
    clear_recover_flag(&mut sb);
    file.seek(SeekFrom::Start(SB_OFFSET))?;
    file.write_all(&sb)?;

    // The kernel only ever sets RECOVER in the primary, but replay could have landed a journaled copy in a backup group; clear wherever it appears so the stored masks end up
    // uniformly clean.
    for &group in &backup_groups {
        let offset = geo.group_start_block(group) * EXT4_BLOCK_SIZE as u64;
        let mut backup = read_superblock_at(file, offset, &format!("group {group} backup"))?;
        if get_le32(&backup, 0x60) & EXT4_FEATURE_INCOMPAT_RECOVER != 0 {
            clear_recover_flag(&mut backup);
            file.seek(SeekFrom::Start(offset))?;
            file.write_all(&backup)?;
        }
    }
    file.sync_all()?;

    Ok(())
}

/// Read a 1024-byte superblock at `offset`, refusing bad magic or checksum.
fn read_superblock_at(file: &mut File, offset: u64, label: &str) -> Result<Vec<u8>, Ext4Error> {
    let mut sb = vec![0u8; SB_SIZE];
    file.seek(SeekFrom::Start(offset))?;
    file.read_exact(&mut sb)?;
    if get_le16(&sb, 0x38) != EXT4_SUPER_MAGIC || superblock_checksum(&sb) != get_le32(&sb, 0x3FC) {
        return Err(unsupported(format!(
            "{label} superblock has a bad magic or checksum"
        )));
    }
    Ok(sb)
}

fn clear_recover_flag(sb: &mut [u8]) {
    let incompat = get_le32(sb, 0x60) & !EXT4_FEATURE_INCOMPAT_RECOVER;
    put_le32(sb, 0x60, incompat);
    let checksum = superblock_checksum(sb);
    put_le32(sb, 0x3FC, checksum);
}

fn unsupported(message: impl Into<String>) -> Ext4Error {
    Ext4Error::Unsupported(message.into())
}

fn validate_group_bitmaps(
    img: &ParsedImage,
    group: u32,
    descriptor: &[u8],
    block_bitmap: &[u8],
    inode_bitmap: &[u8],
) -> Result<(), Ext4Error> {
    let geometry = img.geometry();
    let expected_block_checksum =
        get_le16(descriptor, 0x18) as u32 | (u32::from(get_le16(descriptor, 0x38)) << 16);
    let expected_inode_checksum =
        get_le16(descriptor, 0x1A) as u32 | (u32::from(get_le16(descriptor, 0x3A)) << 16);
    if bitmap_checksum(img.csum_seed, block_bitmap, EXT4_BLOCK_SIZE as usize)
        != expected_block_checksum
        || bitmap_checksum(
            img.csum_seed,
            inode_bitmap,
            (EXT4_INODES_PER_GROUP / 8) as usize,
        ) != expected_inode_checksum
    {
        return Err(unsupported(format!(
            "group {group} bitmap checksum mismatch"
        )));
    }

    let blocks_in_group = geometry.blocks_in_group(group);
    for bit in 0..geometry.group_metadata_blocks(group) {
        if block_bitmap[(bit / 8) as usize] & (1 << (bit % 8)) == 0 {
            return Err(unsupported(format!(
                "group {group} metadata block {bit} is marked free"
            )));
        }
    }
    for bit in blocks_in_group..EXT4_BLOCKS_PER_GROUP {
        if block_bitmap[(bit / 8) as usize] & (1 << (bit % 8)) == 0 {
            return Err(unsupported(format!(
                "group {group} block-bitmap padding is marked free"
            )));
        }
    }
    for bit in EXT4_INODES_PER_GROUP..(EXT4_BLOCK_SIZE * 8) {
        if inode_bitmap[(bit / 8) as usize] & (1 << (bit % 8)) == 0 {
            return Err(unsupported(format!(
                "group {group} inode-bitmap padding is marked free"
            )));
        }
    }

    let free_blocks =
        u32::from(get_le16(descriptor, 0x0C)) | (u32::from(get_le16(descriptor, 0x2C)) << 16);
    let free_inodes =
        u32::from(get_le16(descriptor, 0x0E)) | (u32::from(get_le16(descriptor, 0x2E)) << 16);
    if free_blocks as usize
        != blocks_in_group as usize - count_used_bits(block_bitmap, blocks_in_group as usize)
        || free_inodes as usize
            != EXT4_INODES_PER_GROUP as usize
                - count_used_bits(inode_bitmap, EXT4_INODES_PER_GROUP as usize)
    {
        return Err(unsupported(format!(
            "group {group} free-space counters do not match bitmaps"
        )));
    }
    Ok(())
}

fn validate_allocated_inode(
    file: &mut File,
    img: &ParsedImage,
    group: u32,
    local_inode: u32,
    inode_number: u32,
    _block_bitmap: &[u8],
) -> Result<(), Ext4Error> {
    let inode_offset = img.geometry().group_inode_table_block(group) * EXT4_BLOCK_SIZE as u64
        + u64::from(local_inode) * u64::from(EXT4_INODE_SIZE);
    let mut inode = vec![0u8; EXT4_INODE_SIZE as usize];
    file.seek(SeekFrom::Start(inode_offset))?;
    file.read_exact(&mut inode)?;
    let stored_checksum =
        u32::from(get_le16(&inode, 0x7C)) | (u32::from(get_le16(&inode, 0x82)) << 16);
    if inode_checksum(img.csum_seed, inode_number, get_le32(&inode, 0x64), &inode)
        != stored_checksum
    {
        return Err(unsupported(format!(
            "inode {inode_number} checksum mismatch"
        )));
    }
    if get_le16(&inode, 0) == 0 {
        return Err(unsupported(format!(
            "allocated inode {inode_number} has no mode"
        )));
    }

    if get_le32(&inode, 0x20) & EXT4_EXTENTS_FL != 0 {
        validate_inode_extent_tree(file, img, inode_number, &inode)?;
    }
    let xattr_block = u64::from(get_le32(&inode, 0x68)) | (u64::from(get_le16(&inode, 0x76)) << 32);
    if xattr_block != 0 {
        validate_external_xattrs(file, img, xattr_block, inode_number)?;
    }
    if get_le32(&inode, 0xA0) == 0xEA02_0000 {
        validate_xattr_entries(&inode[0xA4..], 0xA4, inode.len(), inode_number)?;
    }
    Ok(())
}

fn validate_inode_extent_tree(
    file: &mut File,
    img: &ParsedImage,
    inode_number: u32,
    inode: &[u8],
) -> Result<(), Ext4Error> {
    let root = &inode[0x28..0x64];
    if get_le16(root, 0) != EXT4_EH_MAGIC {
        return Err(unsupported(format!(
            "inode {inode_number} has bad extent magic"
        )));
    }
    let entries = usize::from(get_le16(root, 2));
    let max = usize::from(get_le16(root, 4));
    let depth = get_le16(root, 6);
    if entries > max || max > 4 || depth > 1 {
        return Err(unsupported(format!(
            "inode {inode_number} has invalid extent header"
        )));
    }
    if depth == 0 {
        validate_extent_entries(img, inode_number, &root[12..], entries)
    } else {
        if entries != 1 {
            return Err(unsupported(format!(
                "inode {inode_number} has an unsupported extent index fanout"
            )));
        }
        let leaf_block = u64::from(get_le32(root, 16)) | (u64::from(get_le16(root, 20)) << 32);
        if leaf_block >= img.num_blocks {
            return Err(unsupported(format!(
                "inode {inode_number} extent leaf is out of bounds"
            )));
        }
        let leaf = read_block_at(file, leaf_block)?;
        let tail = EXT4_BLOCK_SIZE as usize - 4;
        if get_le32(&leaf, tail)
            != dir_block_checksum(
                img.csum_seed,
                inode_number,
                get_le32(inode, 0x64),
                &leaf[..tail],
            )
            || get_le16(&leaf, 0) != EXT4_EH_MAGIC
            || get_le16(&leaf, 6) != 0
        {
            return Err(unsupported(format!(
                "inode {inode_number} has an invalid extent leaf"
            )));
        }
        let leaf_entries = usize::from(get_le16(&leaf, 2));
        let leaf_max = usize::from(get_le16(&leaf, 4));
        if leaf_entries > leaf_max || 12 + leaf_entries * 12 > tail {
            return Err(unsupported(format!(
                "inode {inode_number} extent leaf overflows"
            )));
        }
        validate_extent_entries(img, inode_number, &leaf[12..], leaf_entries)
    }
}

fn validate_extent_entries(
    img: &ParsedImage,
    inode_number: u32,
    entries: &[u8],
    count: usize,
) -> Result<(), Ext4Error> {
    let mut logical_end = 0u64;
    for index in 0..count {
        let entry = &entries[index * 12..][..12];
        let logical = u64::from(get_le32(entry, 0));
        let raw_len = get_le16(entry, 4);
        if raw_len == 0 || raw_len > 0x8000 || logical < logical_end {
            return Err(unsupported(format!(
                "inode {inode_number} has invalid extent ordering"
            )));
        }
        let block_count = if raw_len == 0x8000 {
            32768
        } else {
            u64::from(raw_len)
        };
        let physical = u64::from(get_le32(entry, 8)) | (u64::from(get_le16(entry, 6)) << 32);
        if physical
            .checked_add(block_count)
            .is_none_or(|end| end > img.num_blocks)
        {
            return Err(unsupported(format!(
                "inode {inode_number} extent is out of bounds"
            )));
        }
        logical_end = logical + block_count;
    }
    Ok(())
}

fn validate_external_xattrs(
    file: &mut File,
    img: &ParsedImage,
    block_number: u64,
    inode_number: u32,
) -> Result<(), Ext4Error> {
    if block_number >= img.num_blocks {
        return Err(unsupported(format!(
            "inode {inode_number} xattr block is out of bounds"
        )));
    }
    let block = read_block_at(file, block_number)?;
    if get_le32(&block, 0) != 0xEA02_0000 || get_le32(&block, 8) != 1 {
        return Err(unsupported(format!(
            "inode {inode_number} has a bad xattr header"
        )));
    }
    let mut checksum_input = block.clone();
    put_le32(&mut checksum_input, 16, 0);
    let mut checksum = crc32c::crc32c_raw(img.csum_seed, &block_number.to_le_bytes());
    checksum = crc32c::crc32c_raw(checksum, &checksum_input);
    if checksum != get_le32(&block, 16) {
        return Err(unsupported(format!(
            "inode {inode_number} xattr checksum mismatch"
        )));
    }
    validate_xattr_entries(&block[32..], 0, block.len(), inode_number)
}

fn validate_xattr_entries(
    entries: &[u8],
    base_offset: usize,
    end_offset: usize,
    inode_number: u32,
) -> Result<(), Ext4Error> {
    let mut cursor = 0usize;
    while cursor + 4 <= entries.len() && get_le32(entries, cursor) != 0 {
        if cursor + 16 > entries.len() {
            return Err(unsupported(format!(
                "inode {inode_number} has truncated xattrs"
            )));
        }
        let name_len = entries[cursor] as usize;
        let name_index = entries[cursor + 1];
        let value_offset = usize::from(get_le16(entries, cursor + 2));
        let value_size = get_le32(entries, cursor + 8) as usize;
        let entry_len = (16 + name_len + 3) & !3;
        if !matches!(name_index, 1 | 2 | 3 | 4 | 6)
            || cursor + entry_len > entries.len()
            || base_offset + value_offset + value_size > end_offset
        {
            return Err(unsupported(format!(
                "inode {inode_number} has malformed xattrs"
            )));
        }
        cursor += entry_len;
    }
    if cursor + 4 > entries.len() {
        return Err(unsupported(format!(
            "inode {inode_number} xattrs lack a terminator"
        )));
    }
    Ok(())
}

fn validate_backup_metadata(file: &mut File, img: &ParsedImage) -> Result<(), Ext4Error> {
    let geometry = img.geometry();
    for group in 1..img.num_groups {
        if !sparse_super_group(group) {
            continue;
        }
        let start = geometry.group_start_block(group) * EXT4_BLOCK_SIZE as u64;
        let backup = read_superblock_at(file, start, &format!("group {group} backup"))?;
        if get_le16(&backup, 0x5A) != group as u16 || backup[0..0x18] != img.sb[0..0x18] {
            return Err(unsupported(format!(
                "group {group} backup superblock differs"
            )));
        }
        let mut backup_gdt = vec![0u8; img.gdt.len()];
        file.seek(SeekFrom::Start(start + EXT4_BLOCK_SIZE as u64))?;
        file.read_exact(&mut backup_gdt)?;
        if backup_gdt != img.gdt {
            return Err(unsupported(format!("group {group} backup GDT differs")));
        }
    }
    Ok(())
}

fn read_block_at(file: &mut File, block: u64) -> Result<Vec<u8>, Ext4Error> {
    let mut buf = vec![0u8; EXT4_BLOCK_SIZE as usize];
    file.seek(SeekFrom::Start(block * EXT4_BLOCK_SIZE as u64))?;
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_block_at(file: &mut File, block: u64, data: &[u8]) -> Result<(), Ext4Error> {
    file.seek(SeekFrom::Start(block * EXT4_BLOCK_SIZE as u64))?;
    file.write_all(data)?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::format::JBD2_MAGIC;
    use super::super::formatter::{
        Ext4FormatOptions, format_ext4, format_ext4_for_test_with_reserved_gdt,
    };
    use super::super::jbd2::{JournalLocation, TestTransaction, write_test_log};
    use super::super::layout::{RESERVED_GDT_BLOCKS, count_used_bits, get_be32, put_be32};
    use super::*;
    use sha2::{Digest, Sha256};

    const MIB: u64 = 1024 * 1024;

    fn format_image(path: &Path, size_bytes: u64) {
        let opts = Ext4FormatOptions {
            size_bytes,
            journal_blocks: 4096,
        };
        format_ext4(path, &opts).unwrap();
    }

    fn parse(path: &Path) -> ParsedImage {
        let mut file = File::open(path).unwrap();
        parse_and_validate(&mut file).unwrap()
    }

    /// Re-open the image and check every invariant the resizer must preserve: superblock and
    /// descriptor checksums (via the parser), bitmap checksums, metadata/padding bits, per-group
    /// and total free-block accounting, and backup superblock + GDT copies.
    fn assert_image_invariants(path: &Path) {
        let mut file = File::open(path).unwrap();
        let img = parse_and_validate(&mut file).unwrap();
        let geo = img.geometry();

        let mut total_free = 0u64;
        for group in 0..img.num_groups {
            let desc =
                &img.gdt[group as usize * EXT4_DESC_SIZE as usize..][..EXT4_DESC_SIZE as usize];
            let block_bitmap =
                read_block_at(&mut file, geo.group_block_bitmap_block(group)).unwrap();
            let inode_bitmap =
                read_block_at(&mut file, geo.group_inode_bitmap_block(group)).unwrap();

            let bb_csum = get_le16(desc, 0x18) as u32 | ((get_le16(desc, 0x38) as u32) << 16);
            let ib_csum = get_le16(desc, 0x1A) as u32 | ((get_le16(desc, 0x3A) as u32) << 16);
            assert_eq!(
                bitmap_checksum(img.csum_seed, &block_bitmap, EXT4_BLOCK_SIZE as usize),
                bb_csum,
                "group {group} block bitmap checksum"
            );
            assert_eq!(
                bitmap_checksum(
                    img.csum_seed,
                    &inode_bitmap,
                    (EXT4_INODES_PER_GROUP / 8) as usize
                ),
                ib_csum,
                "group {group} inode bitmap checksum"
            );

            let blocks_in_group = geo.blocks_in_group(group);
            for bit in 0..geo.group_metadata_blocks(group) {
                assert_ne!(
                    block_bitmap[(bit / 8) as usize] & (1 << (bit % 8)),
                    0,
                    "group {group} metadata block {bit} not marked used"
                );
            }
            for bit in blocks_in_group..EXT4_BLOCKS_PER_GROUP {
                assert_ne!(
                    block_bitmap[(bit / 8) as usize] & (1 << (bit % 8)),
                    0,
                    "group {group} padding bit {bit} not set"
                );
            }

            let used = count_used_bits(&block_bitmap, blocks_in_group as usize);
            let free = get_le16(desc, 0x0C) as u32 | ((get_le16(desc, 0x2C) as u32) << 16);
            assert_eq!(
                free as usize,
                blocks_in_group as usize - used,
                "group {group} free block count"
            );
            total_free += free as u64;
        }
        assert_eq!(total_free, img.free_blocks, "superblock free block total");

        for group in 1..img.num_groups {
            if !sparse_super_group(group) {
                continue;
            }
            let start = geo.group_start_block(group) * EXT4_BLOCK_SIZE as u64;
            let mut backup_sb = vec![0u8; SB_SIZE];
            file.seek(SeekFrom::Start(start)).unwrap();
            file.read_exact(&mut backup_sb).unwrap();
            assert_eq!(get_le16(&backup_sb, 0x38), EXT4_SUPER_MAGIC);
            assert_eq!(get_le16(&backup_sb, 0x5A), group as u16);
            assert_eq!(
                superblock_checksum(&backup_sb),
                get_le32(&backup_sb, 0x3FC),
                "backup superblock checksum in group {group}"
            );
            assert_eq!(
                &backup_sb[0x00..0x18],
                &img.sb[0x00..0x18],
                "backup superblock counts in group {group}"
            );

            let mut backup_gdt = vec![0u8; img.gdt.len()];
            file.seek(SeekFrom::Start(
                (geo.group_start_block(group) + 1) * EXT4_BLOCK_SIZE as u64,
            ))
            .unwrap();
            file.read_exact(&mut backup_gdt).unwrap();
            assert_eq!(backup_gdt, img.gdt, "backup GDT in group {group}");
        }
    }

    /// Hash every block below `blocks` except block 0 and the superblock + GDT span at the start
    /// of each backup-super group — the only pre-existing regions a grow may rewrite.
    fn hash_stable_prefix(path: &Path, blocks: u64, gdt_span: u32) -> [u8; 32] {
        let mut file = File::open(path).unwrap();
        let img = parse_and_validate(&mut file).unwrap();
        let resize_inode_table_block = img.geometry().group_inode_table_block(0);
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; EXT4_BLOCK_SIZE as usize];
        for block in 0..blocks {
            let group = (block / EXT4_BLOCKS_PER_GROUP as u64) as u32;
            let offset_in_group = block % EXT4_BLOCKS_PER_GROUP as u64;
            let has_super = group == 0 || sparse_super_group(group);
            if has_super && offset_in_group < 1 + gdt_span as u64 {
                continue;
            }
            // A grow legitimately refreshes inode 7 and its double-indirect block so that the
            // reserved-GDT ownership graph includes newly created sparse-super backups.
            if block == resize_inode_table_block || block == img.resize_inode_block {
                continue;
            }
            file.seek(SeekFrom::Start(block * EXT4_BLOCK_SIZE as u64))
                .unwrap();
            file.read_exact(&mut buf).unwrap();
            hasher.update(&buf);
        }
        hasher.finalize().into()
    }

    fn journal_location(path: &Path) -> (JournalLocation, [u8; 16]) {
        let mut file = File::open(path).unwrap();
        let img = parse_and_validate(&mut file).unwrap();
        let location = jbd2::locate_journal(
            &mut file,
            img.geometry().group_inode_table_block(0),
            img.csum_seed,
        )
        .unwrap();
        let mut uuid = [0u8; 16];
        uuid.copy_from_slice(&img.sb[0x68..0x78]);
        (location, uuid)
    }

    /// Simulate the state every mounted-but-never-unmounted upper is left in: RECOVER set in the primary superblock (the kernel never sets it in backups).
    fn set_recover_flag(path: &Path) {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let mut sb = vec![0u8; SB_SIZE];
        file.seek(SeekFrom::Start(SB_OFFSET)).unwrap();
        file.read_exact(&mut sb).unwrap();
        let incompat = get_le32(&sb, 0x60) | EXT4_FEATURE_INCOMPAT_RECOVER;
        put_le32(&mut sb, 0x60, incompat);
        let checksum = superblock_checksum(&sb);
        put_le32(&mut sb, 0x3FC, checksum);
        file.seek(SeekFrom::Start(SB_OFFSET)).unwrap();
        file.write_all(&sb).unwrap();
    }

    fn write_dirty_journal(path: &Path, start_seq: u32, transactions: &[TestTransaction]) {
        let (location, uuid) = journal_location(path);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        write_test_log(&mut file, &location, &uuid, start_seq, transactions).unwrap();
        drop(file);
        set_recover_flag(path);
    }

    fn read_jbd2_superblock(path: &Path) -> Vec<u8> {
        let (location, _) = journal_location(path);
        let mut file = File::open(path).unwrap();
        let mut jsb = vec![0u8; 1024];
        file.seek(SeekFrom::Start(
            location.start_block * EXT4_BLOCK_SIZE as u64,
        ))
        .unwrap();
        file.read_exact(&mut jsb).unwrap();
        jsb
    }

    fn assert_recover_cleared_everywhere(path: &Path) {
        let mut file = File::open(path).unwrap();
        let img = parse_and_validate(&mut file).unwrap();
        assert_eq!(
            get_le32(&img.sb, 0x60) & EXT4_FEATURE_INCOMPAT_RECOVER,
            0,
            "primary superblock still has RECOVER"
        );
        let geo = img.geometry();
        for group in 1..img.num_groups {
            if !sparse_super_group(group) {
                continue;
            }
            let mut backup = vec![0u8; SB_SIZE];
            file.seek(SeekFrom::Start(
                geo.group_start_block(group) * EXT4_BLOCK_SIZE as u64,
            ))
            .unwrap();
            file.read_exact(&mut backup).unwrap();
            assert_eq!(
                get_le32(&backup, 0x60) & EXT4_FEATURE_INCOMPAT_RECOVER,
                0,
                "backup superblock in group {group} still has RECOVER"
            );
        }
    }

    fn hash_file(path: &Path) -> [u8; 32] {
        let mut file = File::open(path).unwrap();
        let mut hasher = Sha256::new();
        let mut buf = vec![0u8; 1 << 20];
        loop {
            let n = file.read(&mut buf).unwrap();
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
        }
        hasher.finalize().into()
    }

    fn pattern_block(byte: u8) -> Vec<u8> {
        vec![byte; EXT4_BLOCK_SIZE as usize]
    }

    #[test]
    fn test_freshly_formatted_image_passes_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fresh.ext4");
        format_image(&path, 256 * MIB);

        let img = parse(&path);
        assert_eq!(img.num_blocks, 65536);
        assert_eq!(img.num_groups, 2);
        assert_eq!(img.gdt_blocks, 1);
        assert_eq!(img.reserved_gdt_blocks, RESERVED_GDT_BLOCKS);
        assert_eq!(get_le32(&img.sb, EXT4_SB_ERROR_COUNT_OFFSET), 0);
        assert_eq!(
            get_le32(&img.sb, EXT4_SB_OVERHEAD_BLOCKS_OFFSET),
            (0..img.num_groups)
                .map(|group| img.geometry().group_metadata_blocks(group))
                .sum::<u32>()
        );
        assert_image_invariants(&path);
    }

    #[test]
    fn test_grow_doubles_aligned_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("grow.ext4");
        format_image(&path, 256 * MIB);

        let img = parse(&path);
        let span = img.gdt_blocks + img.reserved_gdt_blocks;
        let before = hash_stable_prefix(&path, img.num_blocks, span);

        let outcome = grow_image(&path, 512 * MIB).unwrap();
        assert_eq!(
            outcome,
            GrowOutcome {
                old_blocks: 65536,
                new_blocks: 131072,
                old_groups: 2,
                new_groups: 4,
            }
        );
        assert_eq!(std::fs::metadata(&path).unwrap().len(), 512 * MIB);

        // Group 3 is a sparse_super backup group, so the grow must have created its backup
        // superblock + GDT; assert_image_invariants verifies both.
        assert_image_invariants(&path);

        let after = hash_stable_prefix(&path, img.num_blocks, span);
        assert_eq!(before, after, "pre-existing data blocks were modified");
    }

    #[test]
    fn test_grow_crosses_sparse_super_backup_groups() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("backups.ext4");
        format_image(&path, 256 * MIB);

        let outcome = grow_image(&path, 1024 * MIB).unwrap();
        assert_eq!(outcome.new_groups, 8);

        let img = parse(&path);
        assert_eq!(img.num_groups, 8);
        assert_eq!(img.free_inodes, get_le32(&img.sb, 0x10));
        assert_image_invariants(&path);
    }

    #[test]
    fn test_grow_consumes_reserved_gdt_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("consume.ext4");
        format_image(&path, 256 * MIB);

        // 68 groups need two GDT blocks, so the second descriptor block comes out of the
        // reserved span while gdt_blocks + reserved stays 257.
        let outcome = grow_image(&path, 68 * 128 * MIB).unwrap();
        assert_eq!(outcome.new_groups, 68);

        let img = parse(&path);
        assert_eq!(img.gdt_blocks, 2);
        assert_eq!(img.reserved_gdt_blocks, RESERVED_GDT_BLOCKS - 1);
        assert_image_invariants(&path);
    }

    #[test]
    fn test_grow_rejects_corrupted_resize_inode_pointers() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt-resize-inode.ext4");
        format_image(&path, 256 * MIB);

        let img = parse(&path);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(
            img.resize_inode_block * u64::from(EXT4_BLOCK_SIZE) + u64::from(img.gdt_blocks) * 4,
        ))
        .unwrap();
        file.write_all(&0u32.to_le_bytes()).unwrap();
        drop(file);

        let result = grow_image(&path, 512 * MIB);
        match result {
            Err(Ext4Error::Unsupported(message)) => {
                assert!(
                    message.contains("double-indirect pointer"),
                    "message: {message}"
                )
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_grow_twice_reuses_headroom() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("twice.ext4");
        format_image(&path, 256 * MIB);

        grow_image(&path, 512 * MIB).unwrap();
        assert_image_invariants(&path);

        let outcome = grow_image(&path, 1024 * MIB).unwrap();
        assert_eq!(outcome.old_groups, 4);
        assert_eq!(outcome.new_groups, 8);
        assert_image_invariants(&path);
    }

    #[test]
    fn test_grow_extends_partial_final_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial-old.ext4");
        format_image(&path, 200 * MIB);

        let outcome = grow_image(&path, 256 * MIB).unwrap();
        assert_eq!(outcome.old_groups, 2);
        assert_eq!(outcome.new_groups, 2);
        assert_eq!(outcome.new_blocks - outcome.old_blocks, 56 * MIB / 4096);
        assert_image_invariants(&path);
    }

    #[test]
    fn test_grow_creates_partial_final_group() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("partial-new.ext4");
        format_image(&path, 256 * MIB);

        let outcome = grow_image(&path, 448 * MIB).unwrap();
        assert_eq!(outcome.new_groups, 4);
        assert_image_invariants(&path);
    }

    #[test]
    fn test_grow_rejects_shrink_and_noop() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("shrink.ext4");
        format_image(&path, 256 * MIB);

        let result = grow_image(&path, 128 * MIB);
        assert!(matches!(result, Err(Ext4Error::InvalidSize(_))));

        let result = grow_image(&path, 256 * MIB);
        assert!(matches!(result, Err(Ext4Error::InvalidSize(_))));
    }

    #[test]
    fn test_grow_rejects_unaligned_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("unaligned.ext4");
        format_image(&path, 256 * MIB);

        let result = grow_image(&path, 512 * MIB + 1);
        assert!(matches!(result, Err(Ext4Error::InvalidSize(_))));
    }

    #[test]
    fn test_grow_rejects_size_beyond_32_bit_block_addresses() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("huge.ext4");
        format_image(&path, 256 * MIB);

        let result = grow_image(&path, (MAX_BLOCKS + 1) * EXT4_BLOCK_SIZE as u64);
        assert!(matches!(result, Err(Ext4Error::TooLarge { .. })));
    }

    #[test]
    fn test_grow_over_capacity_reports_max_growable_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("pre-headroom.ext4");
        let opts = Ext4FormatOptions {
            size_bytes: 256 * MIB,
            journal_blocks: 4096,
        };
        format_ext4_for_test_with_reserved_gdt(&path, &opts, 0).unwrap();

        // One GDT block and no reserved headroom caps the image at 64 groups (8 GiB).
        let max_size_bytes = 64 * 128 * MIB;
        let result = grow_image(&path, 16 * 1024 * MIB);
        match result {
            Err(Ext4Error::ExceedsGdtCapacity {
                requested_bytes,
                max_size_bytes: reported_max,
            }) => {
                assert_eq!(requested_bytes, 16 * 1024 * MIB);
                assert_eq!(reported_max, max_size_bytes);
            }
            other => panic!("expected ExceedsGdtCapacity, got {other:?}"),
        }

        // Growing to exactly the capacity limit uses the remaining slack in the allocated
        // GDT block and succeeds.
        let outcome = grow_image(&path, max_size_bytes).unwrap();
        assert_eq!(outcome.new_groups, 64);
        assert_image_invariants(&path);
    }

    #[test]
    fn test_grow_rejects_corrupted_superblock() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("corrupt.ext4");
        format_image(&path, 256 * MIB);

        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        file.seek(SeekFrom::Start(SB_OFFSET + 0x20)).unwrap();
        file.write_all(&[0xFF]).unwrap();
        drop(file);

        let result = grow_image(&path, 512 * MIB);
        assert!(matches!(result, Err(Ext4Error::Unsupported(_))));
    }

    #[test]
    fn test_grow_rejects_foreign_feature_flags() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("foreign.ext4");
        format_image(&path, 256 * MIB);

        // Set an extra ro_compat flag and re-checksum so only the feature check can reject it.
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut sb = vec![0u8; SB_SIZE];
        file.seek(SeekFrom::Start(SB_OFFSET)).unwrap();
        file.read_exact(&mut sb).unwrap();
        let ro_compat = get_le32(&sb, 0x64);
        put_le32(&mut sb, 0x64, ro_compat | 0x8000);
        let checksum = superblock_checksum(&sb);
        put_le32(&mut sb, 0x3FC, checksum);
        file.seek(SeekFrom::Start(SB_OFFSET)).unwrap();
        file.write_all(&sb).unwrap();
        drop(file);

        let result = grow_image(&path, 512 * MIB);
        match result {
            Err(Ext4Error::Unsupported(message)) => {
                assert!(message.contains("feature flags"), "message: {message}")
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
    }

    #[test]
    fn test_grow_replays_pending_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("replay.ext4");
        format_image(&path, 256 * MIB);

        let (location, _) = journal_location(&path);
        let data_target = location.start_block + location.len_blocks as u64 + 16;
        let second_data_target = data_target + 1;
        let second_file_data = pattern_block(0xA5);
        let file_data = pattern_block(0x5A);
        write_dirty_journal(
            &path,
            2,
            &[TestTransaction {
                writes: vec![
                    (data_target, file_data.clone()),
                    (second_data_target, second_file_data.clone()),
                ],
                revokes: vec![],
                corrupt_commit: false,
            }],
        );

        let outcome = grow_image(&path, 512 * MIB).unwrap();
        assert_eq!(outcome.new_groups, 4);

        let mut file = File::open(&path).unwrap();
        assert_eq!(
            read_block_at(&mut file, data_target).unwrap(),
            file_data,
            "journaled data-block write was not replayed"
        );
        assert_eq!(
            read_block_at(&mut file, second_data_target).unwrap(),
            second_file_data,
            "second journaled data-block write was not replayed"
        );
        drop(file);

        assert_recover_cleared_everywhere(&path);
        let jsb = read_jbd2_superblock(&path);
        assert_eq!(get_be32(&jsb, 0x1C), 0, "journal s_start not reset");
        // Sequence 2 replayed, end-of-log at sequence 3, and the kernel-mirroring reset restarts one past that.
        assert_eq!(
            get_be32(&jsb, 0x18),
            4,
            "journal s_sequence not advanced past the replayed transaction"
        );
        assert_image_invariants(&path);
    }

    #[test]
    fn test_replay_restores_escaped_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("escape.ext4");
        format_image(&path, 256 * MIB);

        let (location, _) = journal_location(&path);
        let target = location.start_block + location.len_blocks as u64 + 16;
        let mut data = pattern_block(0x11);
        put_be32(&mut data, 0, JBD2_MAGIC);
        write_dirty_journal(
            &path,
            2,
            &[TestTransaction {
                writes: vec![(target, data.clone())],
                revokes: vec![],
                corrupt_commit: false,
            }],
        );

        grow_image(&path, 512 * MIB).unwrap();

        let mut file = File::open(&path).unwrap();
        let replayed = read_block_at(&mut file, target).unwrap();
        assert_eq!(
            get_be32(&replayed, 0),
            JBD2_MAGIC,
            "escape magic not restored"
        );
        assert_eq!(replayed, data);
    }

    #[test]
    fn test_replay_honors_revocations() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("revoke.ext4");
        format_image(&path, 256 * MIB);

        let (location, _) = journal_location(&path);
        let data_start = location.start_block + location.len_blocks as u64 + 16;
        let revoked_target = data_start;
        let kept_target = data_start + 1;
        let late_target = data_start + 2;
        // The revocation lives in a LATER transaction than the write it suppresses: replay of transaction 2 must skip revoked_target because transaction 3 revoked it.
        write_dirty_journal(
            &path,
            2,
            &[
                TestTransaction {
                    writes: vec![
                        (revoked_target, pattern_block(0xDE)),
                        (kept_target, pattern_block(0x22)),
                    ],
                    revokes: vec![],
                    corrupt_commit: false,
                },
                TestTransaction {
                    writes: vec![(late_target, pattern_block(0x33))],
                    revokes: vec![revoked_target],
                    corrupt_commit: false,
                },
            ],
        );

        grow_image(&path, 512 * MIB).unwrap();

        let mut file = File::open(&path).unwrap();
        assert_eq!(
            read_block_at(&mut file, revoked_target).unwrap(),
            vec![0u8; EXT4_BLOCK_SIZE as usize],
            "revoked block was replayed"
        );
        assert_eq!(
            read_block_at(&mut file, kept_target).unwrap(),
            pattern_block(0x22)
        );
        assert_eq!(
            read_block_at(&mut file, late_target).unwrap(),
            pattern_block(0x33)
        );
    }

    #[test]
    fn test_replay_stops_at_corrupt_commit() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("badcommit.ext4");
        format_image(&path, 256 * MIB);

        let (location, _) = journal_location(&path);
        let applied_target = location.start_block + location.len_blocks as u64 + 16;
        let dropped_target = applied_target + 1;
        write_dirty_journal(
            &path,
            2,
            &[
                TestTransaction {
                    writes: vec![(applied_target, pattern_block(0x44))],
                    revokes: vec![],
                    corrupt_commit: false,
                },
                TestTransaction {
                    writes: vec![(dropped_target, pattern_block(0x55))],
                    revokes: vec![],
                    corrupt_commit: true,
                },
            ],
        );

        grow_image(&path, 512 * MIB).unwrap();

        let mut file = File::open(&path).unwrap();
        assert_eq!(
            read_block_at(&mut file, applied_target).unwrap(),
            pattern_block(0x44),
            "committed transaction was not replayed"
        );
        assert_eq!(
            read_block_at(&mut file, dropped_target).unwrap(),
            vec![0u8; EXT4_BLOCK_SIZE as usize],
            "uncommitted transaction was replayed"
        );
        drop(file);

        // end-of-log at the corrupt commit: sequence 2 replayed, sequence 3 discarded, so the reset journal restarts at 4.
        let jsb = read_jbd2_superblock(&path);
        assert_eq!(get_be32(&jsb, 0x1C), 0);
        assert_eq!(get_be32(&jsb, 0x18), 4);
        assert_recover_cleared_everywhere(&path);
    }

    #[test]
    fn test_grow_clears_recover_flag_with_empty_journal() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("recover-clean.ext4");
        format_image(&path, 256 * MIB);
        set_recover_flag(&path);

        let outcome = grow_image(&path, 512 * MIB).unwrap();
        assert_eq!(outcome.new_groups, 4);

        assert_recover_cleared_everywhere(&path);
        // An empty log (s_start == 0) needs no recovery, so the journal superblock is left exactly as formatted.
        let jsb = read_jbd2_superblock(&path);
        assert_eq!(get_be32(&jsb, 0x1C), 0);
        assert_eq!(get_be32(&jsb, 0x18), 1);
        assert_image_invariants(&path);
    }

    #[test]
    fn test_replay_rejects_unknown_journal_features() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("badjournal.ext4");
        format_image(&path, 256 * MIB);

        // ASYNC_COMMIT (0x4) is a real jbd2 feature, but not one the formatter writes, so recovery must refuse it rather than misparse commit blocks.
        let (location, _) = journal_location(&path);
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mut jsb = vec![0u8; 1024];
        file.seek(SeekFrom::Start(
            location.start_block * EXT4_BLOCK_SIZE as u64,
        ))
        .unwrap();
        file.read_exact(&mut jsb).unwrap();
        let incompat = get_be32(&jsb, 0x28);
        put_be32(&mut jsb, 0x28, incompat | 0x04);
        jsb[0xFC..0x100].fill(0);
        let checksum = crc32c::crc32c_raw(0xFFFF_FFFF, &jsb);
        put_be32(&mut jsb, 0xFC, checksum);
        file.seek(SeekFrom::Start(
            location.start_block * EXT4_BLOCK_SIZE as u64,
        ))
        .unwrap();
        file.write_all(&jsb).unwrap();
        drop(file);
        set_recover_flag(&path);

        let before = hash_file(&path);
        let result = grow_image(&path, 512 * MIB);
        match result {
            Err(Ext4Error::Unsupported(message)) => {
                assert!(message.contains("journal feature"), "message: {message}")
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
        assert_eq!(
            hash_file(&path),
            before,
            "failed recovery modified the image"
        );
    }

    #[test]
    fn test_replay_rejects_target_beyond_filesystem() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oob.ext4");
        format_image(&path, 256 * MIB);

        // 256 MiB = 65536 blocks, so this target is past the end of the filesystem.
        write_dirty_journal(
            &path,
            2,
            &[TestTransaction {
                writes: vec![(70_000, pattern_block(0x66))],
                revokes: vec![],
                corrupt_commit: false,
            }],
        );

        let before = hash_file(&path);
        let result = grow_image(&path, 512 * MIB);
        match result {
            Err(Ext4Error::Unsupported(message)) => {
                assert!(
                    message.contains("beyond the filesystem"),
                    "message: {message}"
                )
            }
            other => panic!("expected Unsupported, got {other:?}"),
        }
        assert_eq!(
            hash_file(&path),
            before,
            "failed recovery modified the image"
        );
    }

    /// Full `e2fsck -fn` validation of a formatted and grown image. Gated behind `--ignored`
    /// because e2fsprogs is only guaranteed on Linux CI; skips cleanly when the binary is absent.
    #[test]
    #[ignore]
    fn test_e2fsck_validates_formatted_and_grown_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fsck.ext4");
        format_image(&path, 256 * MIB);

        let run_e2fsck = |label: &str| {
            let output = match std::process::Command::new("e2fsck")
                .arg("-fn")
                .arg(&path)
                .output()
            {
                Ok(output) => output,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    eprintln!("e2fsck not found; skipping");
                    return false;
                }
                Err(error) => panic!("failed to run e2fsck: {error}"),
            };
            assert!(
                output.status.success(),
                "e2fsck failed after {label}:\nstdout: {}\nstderr: {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            true
        };

        if !run_e2fsck("format") {
            return;
        }
        grow_image(&path, 512 * MIB).unwrap();
        run_e2fsck("grow to 512 MiB");
        grow_image(&path, 1024 * MIB).unwrap();
        run_e2fsck("grow to 1 GiB");
    }

    /// Cross a 64-group descriptor boundary so one reserved-GDT block becomes a live GDT block,
    /// then let the reference checker validate the rebuilt resize inode and all backup pointers.
    #[test]
    #[ignore]
    fn test_e2fsck_validates_consumed_reserved_gdt_block() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fsck-consumed-gdt.ext4");
        format_image(&path, 256 * MIB);

        grow_image(&path, 68 * 128 * MIB).unwrap();
        let output = match std::process::Command::new("e2fsck")
            .arg("-fn")
            .arg(&path)
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("e2fsck not found; skipping");
                return;
            }
            Err(error) => panic!("failed to run e2fsck: {error}"),
        };
        assert!(
            output.status.success(),
            "e2fsck failed after consuming reserved GDT headroom:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Same e2fsck gate for the recovery path: a dirty image (pending journal with escaped and revoked blocks) must replay, grow, and still be fully clean to `e2fsck -fn`.
    #[test]
    #[ignore]
    fn test_e2fsck_validates_replayed_and_grown_image() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fsck-replay.ext4");
        format_image(&path, 256 * MIB);

        let (location, _) = journal_location(&path);
        let data_start = location.start_block + location.len_blocks as u64 + 16;
        let mut escaped = pattern_block(0x11);
        put_be32(&mut escaped, 0, JBD2_MAGIC);
        write_dirty_journal(
            &path,
            2,
            &[
                TestTransaction {
                    writes: vec![(data_start + 2, pattern_block(0xA5)), (data_start, escaped)],
                    revokes: vec![],
                    corrupt_commit: false,
                },
                TestTransaction {
                    writes: vec![(data_start + 1, pattern_block(0x22))],
                    revokes: vec![data_start],
                    corrupt_commit: false,
                },
            ],
        );

        grow_image(&path, 512 * MIB).unwrap();

        let output = match std::process::Command::new("e2fsck")
            .arg("-fn")
            .arg(&path)
            .output()
        {
            Ok(output) => output,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                eprintln!("e2fsck not found; skipping");
                return;
            }
            Err(error) => panic!("failed to run e2fsck: {error}"),
        };
        assert!(
            output.status.success(),
            "e2fsck failed after replay + grow:\nstdout: {}\nstderr: {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
