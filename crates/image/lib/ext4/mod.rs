mod format;
mod formatter;
mod jbd2;
mod layout;
mod resize_inode;
mod resizer;
mod rootfs;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use formatter::{Ext4Error, Ext4FormatOptions, format_ext4, format_ext4_with_tree};
pub use resizer::{GrowOutcome, SnapshotTrimOutcome, grow_image, trim_snapshot_image};
pub use rootfs::{
    EXT4_ROOTFS_MATERIALIZER_ABI, Ext4Artifact, Ext4RootfsOptions, materialize_ext4_rootfs,
};
