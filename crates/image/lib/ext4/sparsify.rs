//! Offline sparsifier for ext4 upper images produced by this crate's formatter.
//!
//! Snapshotting a sandbox's upper layer copies every byte the guest ever wrote, including blocks
//! the guest has since deleted: ext4 marks those blocks free in its own block bitmap, but the raw
//! bytes stay physically allocated on the host file until something tells the host filesystem
//! otherwise. This module reads the guest's own free-block bitmap and deallocates (via
//! [`microsandbox_utils::extent::punch_hole`]) every host block the guest already considers free.
//!
//! Because those blocks are already logically free from ext4's point of view, no ext4 metadata —
//! bitmap, group descriptor, or superblock — is ever read for anything but locating free ranges,
//! and none is ever written back. This is a pure host-side deallocation, symmetric with
//! [`grow_image`](super::grow_image) but far simpler since it never changes the filesystem's
//! logical state.

use std::fs::OpenOptions;
use std::path::Path;

use microsandbox_utils::extent::punch_hole;

use super::format::EXT4_BLOCK_SIZE;
use super::formatter::Ext4Error;
use super::resizer::{parse_and_validate, read_block_at};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result of a sparsification pass.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SparsifyOutcome {
    /// Bytes deallocated on the host by this pass. Never reflects guest-visible content, only
    /// host storage no longer reserved for it.
    pub bytes_reclaimed: u64,

    /// True when the image needed journal recovery and sparsification was skipped rather than
    /// attempted. The caller decides whether that's worth surfacing; it's never an error.
    pub skipped_dirty: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Deallocate host storage for every block the guest ext4 filesystem at `path` already marks
/// free in its own block bitmaps.
///
/// This never mutates ext4 metadata: the bitmap already says these blocks are free, so there is
/// nothing to update on the filesystem side, only on the host's physical allocation of the file.
///
/// If the image needs journal recovery (the guest never cleanly unmounted), sparsification is skipped
/// rather than attempted — recovering a pending journal is out of scope here, and this is a pure
/// size optimization that must never risk the correctness of the image it runs on.
pub fn sparsify_image(path: &Path) -> Result<SparsifyOutcome, Ext4Error> {
    let mut file = OpenOptions::new().read(true).write(true).open(path)?;
    let img = parse_and_validate(&mut file)?;

    if img.needs_recovery {
        return Ok(SparsifyOutcome {
            skipped_dirty: true,
            ..Default::default()
        });
    }

    let geo = img.geometry();
    let mut bytes_reclaimed = 0u64;

    for group in 0..img.num_groups {
        let bitmap = read_block_at(&mut file, geo.group_block_bitmap_block(group))?;
        let blocks_in_group = geo.blocks_in_group(group);
        let group_start = geo.group_start_block(group);

        let mut bit = 0u32;
        while bit < blocks_in_group {
            if bit_is_set(&bitmap, bit) {
                bit += 1;
                continue;
            }

            let run_start = bit;
            while bit < blocks_in_group && !bit_is_set(&bitmap, bit) {
                bit += 1;
            }
            let run_len = u64::from(bit - run_start);
            let offset = (group_start + u64::from(run_start)) * u64::from(EXT4_BLOCK_SIZE);
            let len = run_len * u64::from(EXT4_BLOCK_SIZE);

            punch_hole(&file, offset, len)?;
            bytes_reclaimed += len;
        }
    }

    Ok(SparsifyOutcome {
        bytes_reclaimed,
        skipped_dirty: false,
    })
}

fn bit_is_set(bitmap: &[u8], bit: u32) -> bool {
    bitmap[(bit / 8) as usize] & (1 << (bit % 8)) != 0
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs::OpenOptions;

    use super::super::format::{EXT4_FEATURE_INCOMPAT_RECOVER, EXT4_SUPER_MAGIC};
    use super::super::formatter::{Ext4FormatOptions, format_ext4};
    use super::super::layout::{get_le16, get_le32, put_le32, superblock_checksum};
    use super::super::resizer::{
        parse_and_validate, read_block_at, validate_rootfs_image, write_block_at,
    };
    use super::*;

    const MIB: u64 = 1024 * 1024;

    fn format_image(path: &Path, size_bytes: u64) {
        let opts = Ext4FormatOptions {
            size_bytes,
            journal_blocks: 4096,
        };
        format_ext4(path, &opts).unwrap();
    }

    /// Write real, non-zero bytes into a block group-0 already marks free — reproducing "guest
    /// wrote a file, then deleted it" without needing an actual mount.
    fn write_garbage_into_a_free_block(path: &Path) -> u32 {
        let mut file = OpenOptions::new().read(true).write(true).open(path).unwrap();
        let img = parse_and_validate(&mut file).unwrap();
        let geo = img.geometry();
        let bitmap = read_block_at(&mut file, geo.group_block_bitmap_block(0)).unwrap();
        let blocks_in_group = geo.blocks_in_group(0);

        let free_bit = (0..blocks_in_group)
            .find(|&bit| !bit_is_set(&bitmap, bit))
            .expect("a freshly formatted image must have at least one free block");

        write_block_at(
            &mut file,
            geo.group_start_block(0) + u64::from(free_bit),
            &[0xCD; EXT4_BLOCK_SIZE as usize],
        )
        .unwrap();
        free_bit
    }

    #[test]
    fn sparsify_image_punches_holes_for_guest_free_blocks_without_touching_metadata() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upper.ext4");
        format_image(&path, 256 * MIB);
        let free_bit = write_garbage_into_a_free_block(&path);

        let outcome = sparsify_image(&path).unwrap();
        assert!(!outcome.skipped_dirty);
        assert!(outcome.bytes_reclaimed >= u64::from(EXT4_BLOCK_SIZE));

        // Bitmap must be byte-for-byte what it was: sparsification never writes ext4 metadata.
        let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let img = parse_and_validate(&mut file).unwrap();
        let geo = img.geometry();
        let bitmap = read_block_at(&mut file, geo.group_block_bitmap_block(0)).unwrap();
        assert!(
            !bit_is_set(&bitmap, free_bit),
            "sparsification must not mark the block used"
        );

        // Full invariant re-check: checksums, free counters, and inode structure all still hold.
        validate_rootfs_image(&path).unwrap();

        #[cfg(target_os = "linux")]
        {
            let apparent_len = std::fs::metadata(&path).unwrap().len();
            let allocated = microsandbox_utils::extent::allocated_file_bytes(&path).unwrap();
            assert!(
                allocated < apparent_len,
                "expected the sparsified image to have real holes: allocated={allocated} apparent={apparent_len}"
            );
        }
    }

    #[test]
    fn sparsify_image_skips_images_needing_journal_recovery() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("upper.ext4");
        format_image(&path, 256 * MIB);

        // Flip the superblock's RECOVER flag directly, as a hard guest stop would leave it.
        let mut file = OpenOptions::new().read(true).write(true).open(&path).unwrap();
        let mut sb = read_block_at_sb(&mut file);
        let incompat = get_le32(&sb, 0x60) | EXT4_FEATURE_INCOMPAT_RECOVER;
        put_le32(&mut sb, 0x60, incompat);
        let checksum = superblock_checksum(&sb);
        put_le32(&mut sb, 0x3FC, checksum);
        write_sb(&mut file, &sb);
        drop(file);

        let outcome = sparsify_image(&path).unwrap();
        assert!(outcome.skipped_dirty);
        assert_eq!(outcome.bytes_reclaimed, 0);
    }

    // Superblock is at a fixed byte offset, not block-aligned, so it's read/written directly
    // rather than through `read_block_at`/`write_block_at` (which operate on 4 KiB blocks).
    fn read_block_at_sb(file: &mut std::fs::File) -> Vec<u8> {
        use std::io::{Read, Seek, SeekFrom};
        let mut buf = vec![0u8; 1024];
        file.seek(SeekFrom::Start(1024)).unwrap();
        file.read_exact(&mut buf).unwrap();
        assert_eq!(get_le16(&buf, 0x38), EXT4_SUPER_MAGIC);
        buf
    }

    fn write_sb(file: &mut std::fs::File, sb: &[u8]) {
        use std::io::{Seek, SeekFrom, Write};
        file.seek(SeekFrom::Start(1024)).unwrap();
        file.write_all(sb).unwrap();
    }
}
