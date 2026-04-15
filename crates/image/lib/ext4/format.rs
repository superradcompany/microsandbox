#![allow(dead_code)]

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

// Superblock magic
pub const EXT4_SUPER_MAGIC: u16 = 0xEF53;

// Block geometry
pub const EXT4_BLOCK_SIZE: u32 = 4096;
pub const EXT4_LOG_BLOCK_SIZE: u32 = 2; // 2^(10+2) = 4096
pub const EXT4_BLOCKS_PER_GROUP: u32 = 32768;
pub const EXT4_INODES_PER_GROUP: u32 = 8192;
pub const EXT4_INODE_SIZE: u16 = 256;
pub const EXT4_FIRST_INO: u32 = 11;
pub const EXT4_JOURNAL_INO: u32 = 8;
pub const EXT4_ROOT_INO: u32 = 2;
pub const EXT4_DESC_SIZE: u16 = 64;
pub const EXT4_MIN_EXTRA_ISIZE: u16 = 32;

// Feature compat flags
pub const EXT4_FEATURE_COMPAT_HAS_JOURNAL: u32 = 0x04;
pub const EXT4_FEATURE_COMPAT_EXT_ATTR: u32 = 0x08;
pub const EXT4_FEATURE_COMPAT_DIR_INDEX: u32 = 0x20;

// Feature incompat flags
pub const EXT4_FEATURE_INCOMPAT_FILETYPE: u32 = 0x02;
pub const EXT4_FEATURE_INCOMPAT_EXTENTS: u32 = 0x40;
pub const EXT4_FEATURE_INCOMPAT_64BIT: u32 = 0x80;

// Feature ro-compat flags
pub const EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER: u32 = 0x01;
pub const EXT4_FEATURE_RO_COMPAT_LARGE_FILE: u32 = 0x02;
pub const EXT4_FEATURE_RO_COMPAT_HUGE_FILE: u32 = 0x08;
pub const EXT4_FEATURE_RO_COMPAT_DIR_NLINK: u32 = 0x20;
pub const EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE: u32 = 0x40;
pub const EXT4_FEATURE_RO_COMPAT_METADATA_CSUM: u32 = 0x400;

// Group descriptor flags
pub const EXT4_BG_INODE_ZEROED: u16 = 0x04;

// jbd2 constants (big-endian on disk)
pub const JBD2_MAGIC: u32 = 0xC03B3998;
pub const JBD2_SUPERBLOCK_V2: u32 = 4;

// S_IF mode bits
pub const S_IFREG: u16 = 0o100000;
pub const S_IFDIR: u16 = 0o040000;
pub const S_IFLNK: u16 = 0o120000;
pub const S_IFCHR: u16 = 0o020000;

// Inode flags
pub const EXT4_EXTENTS_FL: u32 = 0x00080000;

// Extent header magic
pub const EXT4_EH_MAGIC: u16 = 0xF30A;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// CRC32C with configurable initial seed.
///
/// Returns `true` if `group` should hold a backup superblock under the
/// `SPARSE_SUPER` feature. Group 0 always has the primary superblock;
/// group 1 always gets a backup; then powers of 3, 5, and 7.
pub fn sparse_super_group(group: u32) -> bool {
    if group <= 1 {
        return true;
    }
    for base in [3u32, 5, 7] {
        let mut p = base;
        while p < group {
            p *= base;
        }
        if p == group {
            return true;
        }
    }
    false
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sparse_super_groups() {
        // Group 0 and 1 are always sparse-super groups
        assert!(sparse_super_group(0));
        assert!(sparse_super_group(1));

        // Powers of 3: 3, 9, 27
        assert!(sparse_super_group(3));
        assert!(sparse_super_group(9));
        assert!(sparse_super_group(27));

        // Powers of 5: 5, 25
        assert!(sparse_super_group(5));
        assert!(sparse_super_group(25));

        // Powers of 7: 7, 49
        assert!(sparse_super_group(7));
        assert!(sparse_super_group(49));

        // Non-sparse-super groups
        assert!(!sparse_super_group(2));
        assert!(!sparse_super_group(4));
        assert!(!sparse_super_group(6));
        assert!(!sparse_super_group(8));
        assert!(!sparse_super_group(10));
        assert!(!sparse_super_group(11));
        assert!(!sparse_super_group(12));
    }

    #[test]
    fn test_crc32c_known_value() {
        use crate::crc32c::crc32c_raw;

        // CRC32C of empty data with ~0 seed should be ~0 (no bytes processed)
        let crc = crc32c_raw(0xFFFF_FFFF, &[]);
        assert_eq!(crc, 0xFFFF_FFFF);

        // Standard CRC32C of "123456789" is 0xE3069283
        let data = b"123456789";
        let crc = crc32c_raw(0xFFFF_FFFF, data) ^ 0xFFFF_FFFF;
        assert_eq!(crc, 0xE306_9283);
    }
}
