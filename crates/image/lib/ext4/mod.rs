mod format;

use std::io::{self, BufWriter, SeekFrom, Write};
use std::path::Path;

use crate::crc32c;
use crate::filetree::{DirectoryNode, FileTree, TreeNode};
use format::{
    EXT4_BG_INODE_ZEROED, EXT4_BLOCK_SIZE, EXT4_BLOCKS_PER_GROUP, EXT4_DESC_SIZE, EXT4_EH_MAGIC,
    EXT4_EXTENTS_FL, EXT4_FEATURE_COMPAT_DIR_INDEX, EXT4_FEATURE_COMPAT_EXT_ATTR,
    EXT4_FEATURE_COMPAT_HAS_JOURNAL, EXT4_FEATURE_INCOMPAT_64BIT, EXT4_FEATURE_INCOMPAT_EXTENTS,
    EXT4_FEATURE_INCOMPAT_FILETYPE, EXT4_FEATURE_RO_COMPAT_DIR_NLINK,
    EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE, EXT4_FEATURE_RO_COMPAT_HUGE_FILE,
    EXT4_FEATURE_RO_COMPAT_LARGE_FILE, EXT4_FEATURE_RO_COMPAT_METADATA_CSUM,
    EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER, EXT4_FIRST_INO, EXT4_INODE_SIZE, EXT4_INODES_PER_GROUP,
    EXT4_JOURNAL_INO, EXT4_LOG_BLOCK_SIZE, EXT4_MIN_EXTRA_ISIZE, EXT4_ROOT_INO, EXT4_SUPER_MAGIC,
    JBD2_MAGIC, JBD2_SUPERBLOCK_V2, S_IFCHR, S_IFDIR, S_IFLNK, S_IFREG,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default image size: 4 GiB.
const DEFAULT_SIZE_BYTES: u64 = 4 * 1024 * 1024 * 1024;

/// Default journal size in blocks (64 MiB at 4 KiB/block = 16384 blocks).
const DEFAULT_JOURNAL_BLOCKS: u32 = 16384;

/// Maximum number of block groups we format (keeps things simple).
const MAX_GROUPS: u32 = 32;

/// This minimal filesystem does not reserve space for online resize metadata.
const RESERVED_GDT_BLOCKS: u32 = 0;

/// ext4 directory entry file type: directory.
const EXT4_FT_DIR: u8 = 2;

/// ext4 directory entry file type: regular file.
#[allow(dead_code)]
const EXT4_FT_REG_FILE: u8 = 1;

/// ext4 directory entry file type: character device.
const EXT4_FT_CHRDEV: u8 = 3;

/// ext4 directory entry file type: symbolic link.
const EXT4_FT_SYMLINK: u8 = 7;

/// jbd2 superblocks are always 1024 bytes, even on 4 KiB block filesystems.
const JBD2_SUPERBLOCK_SIZE: usize = 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Options for creating an ext4 filesystem image.
pub struct Ext4FormatOptions {
    /// Total image size in bytes. Must be large enough to hold metadata and
    /// journal. Defaults to 4 GiB.
    pub size_bytes: u64,

    /// Number of 4 KiB blocks to allocate for the journal.
    /// Defaults to 16384 (64 MiB).
    pub journal_blocks: u32,
}

/// Errors that can occur during ext4 formatting.
#[derive(Debug)]
pub enum Ext4Error {
    /// An I/O error occurred while writing the image.
    Io(io::Error),

    /// The requested image size is too small to hold the minimum metadata and
    /// journal.
    TooSmall,

    /// The requested tree cannot be serialized by this minimal formatter.
    Layout(String),
}

/// Internal layout computed from `Ext4FormatOptions`.
struct Layout {
    num_blocks: u64,
    num_groups: u32,
    uuid: [u8; 16],
    gdt_blocks: u32,
    /// First block of the inode table in group 0.
    inode_table_block: u32,
    /// Number of blocks occupied by the inode table in group 0.
    inode_table_blocks: u32,
    /// First data block after inode table (root dir block).
    first_data_block: u32,
    /// First block of the journal region.
    journal_start_block: u32,
    /// Total journal blocks.
    journal_blocks: u32,
    /// CRC32C checksum seed derived from the UUID.
    csum_seed: u32,
    /// Feature compat flags.
    feature_compat: u32,
    /// Feature incompat flags.
    feature_incompat: u32,
    /// Feature ro-compat flags.
    feature_ro_compat: u32,
}

struct FsStats {
    group_free_blocks: Vec<u32>,
    group_free_inodes: Vec<u32>,
    group_used_dirs: Vec<u32>,
    total_free_blocks: u64,
    total_free_inodes: u64,
    total_used_blocks: u64,
}

enum NodeKind {
    Directory { children: u16, data: Vec<u8> },
    RegularFile { data: Vec<u8> },
    Symlink { target: Vec<u8>, inline: bool },
    CharDevice { major: u32, minor: u32 },
}

struct NodePlan {
    inode: u32,
    path: String,
    permissions: u16,
    uid: u16,
    gid: u16,
    kind: NodeKind,
    block_start: Option<u32>,
    block_count: u32,
}

struct DraftDirectory {
    children: u16,
    data: Vec<u8>,
}

struct DirEntrySpec {
    inode: u32,
    file_type: u8,
    name: Vec<u8>,
}

struct DataAllocator {
    regions: Vec<(u32, u32)>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Default for Ext4FormatOptions {
    fn default() -> Self {
        Self {
            size_bytes: DEFAULT_SIZE_BYTES,
            journal_blocks: DEFAULT_JOURNAL_BLOCKS,
        }
    }
}

impl std::fmt::Display for Ext4Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Ext4Error::Io(e) => write!(f, "ext4 I/O error: {e}"),
            Ext4Error::TooSmall => write!(f, "image size is too small for ext4 formatting"),
            Ext4Error::Layout(e) => write!(f, "ext4 layout error: {e}"),
        }
    }
}

impl std::error::Error for Ext4Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Ext4Error::Io(e) => Some(e),
            Ext4Error::TooSmall | Ext4Error::Layout(_) => None,
        }
    }
}

impl From<io::Error> for Ext4Error {
    fn from(e: io::Error) -> Self {
        Ext4Error::Io(e)
    }
}

impl Layout {
    #[cfg(test)]
    fn compute(opts: &Ext4FormatOptions) -> Result<Self, Ext4Error> {
        Self::compute_with_root_blocks(opts, 1)
    }

    fn compute_with_root_blocks(
        opts: &Ext4FormatOptions,
        root_dir_blocks: u32,
    ) -> Result<Self, Ext4Error> {
        let block_size = EXT4_BLOCK_SIZE as u64;
        let num_blocks = opts.size_bytes / block_size;
        let num_groups_raw = num_blocks.div_ceil(EXT4_BLOCKS_PER_GROUP as u64);
        let num_groups = num_groups_raw.min(MAX_GROUPS as u64) as u32;

        // We need at least: superblock(1) + GDT(1) + reserved_gdt(256) +
        // bitmaps(2) + inode_table + root_dir(1) + journal
        let inode_table_blocks =
            (EXT4_INODES_PER_GROUP as u64 * EXT4_INODE_SIZE as u64 / block_size) as u32;
        let gdt_blocks = (num_groups as u64 * EXT4_DESC_SIZE as u64).div_ceil(block_size) as u32;

        // Group 0 layout:
        //   block 0: superblock (bytes 0-4095, sb at offset 1024)
        //   next block(s): GDT
        //   next reserved blocks: reserved GDT
        //   next block: block bitmap
        //   next block: inode bitmap
        //   next N blocks: inode table
        //   next block: root dir data block
        //   next M blocks: journal

        let overhead_blocks = 1 + gdt_blocks + RESERVED_GDT_BLOCKS; // sb + gdt + reserved_gdt
        let block_bitmap_block = overhead_blocks;
        let inode_bitmap_block = block_bitmap_block + 1;
        let inode_table_block = inode_bitmap_block + 1;
        let first_data_block = inode_table_block + inode_table_blocks;
        let journal_start_block = first_data_block + root_dir_blocks;

        let min_blocks = journal_start_block as u64 + opts.journal_blocks as u64 + 1; // +1 slack
        if num_blocks < min_blocks {
            return Err(Ext4Error::TooSmall);
        }

        // Generate a random UUID
        let uuid = Self::generate_uuid();

        let csum_seed = crc32c::crc32c_raw(0xFFFF_FFFF, &uuid);

        let feature_compat = EXT4_FEATURE_COMPAT_HAS_JOURNAL
            | EXT4_FEATURE_COMPAT_EXT_ATTR
            | EXT4_FEATURE_COMPAT_DIR_INDEX;

        let feature_incompat = EXT4_FEATURE_INCOMPAT_FILETYPE
            | EXT4_FEATURE_INCOMPAT_EXTENTS
            | EXT4_FEATURE_INCOMPAT_64BIT;

        let feature_ro_compat = EXT4_FEATURE_RO_COMPAT_SPARSE_SUPER
            | EXT4_FEATURE_RO_COMPAT_LARGE_FILE
            | EXT4_FEATURE_RO_COMPAT_HUGE_FILE
            | EXT4_FEATURE_RO_COMPAT_DIR_NLINK
            | EXT4_FEATURE_RO_COMPAT_EXTRA_ISIZE
            | EXT4_FEATURE_RO_COMPAT_METADATA_CSUM;

        Ok(Layout {
            num_blocks,
            num_groups,
            uuid,
            gdt_blocks,
            inode_table_block,
            inode_table_blocks,
            first_data_block,
            journal_start_block,
            journal_blocks: opts.journal_blocks,
            csum_seed,
            feature_compat,
            feature_incompat,
            feature_ro_compat,
        })
    }

    fn generate_uuid() -> [u8; 16] {
        // Simple random UUID using /dev/urandom or fallback to timestamp-based
        let mut uuid = [0u8; 16];
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            let _ = f.read_exact(&mut uuid);
        } else {
            // Fallback: use system time as entropy source
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            let nanos = now.as_nanos();
            uuid[..8].copy_from_slice(&(nanos as u64).to_le_bytes());
            uuid[8..16].copy_from_slice(&((nanos >> 64) as u64).to_le_bytes());
        }
        // Set UUID version 4 and variant bits
        uuid[6] = (uuid[6] & 0x0F) | 0x40;
        uuid[7] = (uuid[7] & 0x3F) | 0x80;
        uuid
    }

    fn group_start_block(&self, group: u32) -> u32 {
        group * EXT4_BLOCKS_PER_GROUP
    }

    fn blocks_in_group(&self, group: u32) -> u32 {
        let group_start = self.group_start_block(group) as u64;
        std::cmp::min(
            EXT4_BLOCKS_PER_GROUP as u64,
            self.num_blocks.saturating_sub(group_start),
        ) as u32
    }

    fn group_has_backup_super(&self, group: u32) -> bool {
        group == 0 || sparse_super_group(group)
    }

    fn group_leading_overhead_blocks(&self, group: u32) -> u32 {
        if self.group_has_backup_super(group) {
            1 + self.gdt_blocks + RESERVED_GDT_BLOCKS
        } else {
            0
        }
    }

    fn group_block_bitmap_block(&self, group: u32) -> u32 {
        self.group_start_block(group) + self.group_leading_overhead_blocks(group)
    }

    fn group_inode_bitmap_block(&self, group: u32) -> u32 {
        self.group_block_bitmap_block(group) + 1
    }

    fn group_inode_table_block(&self, group: u32) -> u32 {
        self.group_inode_bitmap_block(group) + 1
    }

    fn group_data_start_block(&self, group: u32) -> u32 {
        let mut start = self.group_start_block(group) + self.group_metadata_blocks(group);
        if group == 0 {
            start = self.journal_start_block + self.journal_blocks;
        }
        start
    }

    fn group_metadata_blocks(&self, group: u32) -> u32 {
        self.group_leading_overhead_blocks(group) + 2 + self.inode_table_blocks
    }

    fn group_used_blocks(&self, group: u32) -> u32 {
        let mut used = self.group_metadata_blocks(group);
        if group == 0 {
            used += 1 + self.journal_blocks; // root dir + journal
        }
        used.min(self.blocks_in_group(group))
    }

    fn group_free_blocks(&self, group: u32) -> u32 {
        self.blocks_in_group(group)
            .saturating_sub(self.group_used_blocks(group))
    }

    fn group_free_inodes(&self, group: u32) -> u32 {
        if group == 0 {
            EXT4_INODES_PER_GROUP - (EXT4_FIRST_INO - 1)
        } else {
            EXT4_INODES_PER_GROUP
        }
    }

    #[cfg(test)]
    fn group_used_dirs(&self, group: u32) -> u32 {
        if group == 0 { 1 } else { 0 }
    }

    fn total_free_blocks(&self) -> u64 {
        (0..self.num_groups)
            .map(|group| self.group_free_blocks(group) as u64)
            .sum()
    }

    fn total_free_inodes(&self) -> u64 {
        (0..self.num_groups)
            .map(|group| self.group_free_inodes(group) as u64)
            .sum()
    }

    fn total_used_blocks(&self) -> u64 {
        (0..self.num_groups)
            .map(|group| self.group_used_blocks(group) as u64)
            .sum()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create and format a sparse ext4 filesystem image at `path`.
///
/// The image is suitable for use as an overlayfs upper layer. It is created as
/// a sparse file so the initial on-disk footprint is minimal despite the large
/// logical size.
pub fn format_ext4(path: &Path, options: &Ext4FormatOptions) -> Result<(), Ext4Error> {
    let tree = FileTree::new();
    format_ext4_with_tree(path, options, tree)
}

pub fn format_ext4_with_tree(
    path: &Path,
    options: &Ext4FormatOptions,
    tree: FileTree,
) -> Result<(), Ext4Error> {
    let mut next_inode = EXT4_FIRST_INO;
    let mut plans = Vec::new();
    let root_mode = tree.root.metadata.mode;
    let root_draft = draft_directory(
        "/",
        tree.root,
        EXT4_ROOT_INO,
        EXT4_ROOT_INO,
        &mut next_inode,
        &mut plans,
    )?;
    let root_dir_blocks = blocks_for_len(root_draft.data.len());
    let layout = Layout::compute_with_root_blocks(options, root_dir_blocks.max(1))?;
    let mut allocator = DataAllocator::new(&layout);

    for plan in &mut plans {
        allocate_node_data(&mut allocator, plan)?;
    }

    let mut all_plans = Vec::with_capacity(plans.len() + 1);
    all_plans.push(NodePlan {
        inode: EXT4_ROOT_INO,
        path: "/".to_string(),
        permissions: normalize_dir_permissions(root_mode),
        uid: 0,
        gid: 0,
        kind: NodeKind::Directory {
            children: root_draft.children,
            data: root_draft.data,
        },
        block_start: Some(layout.first_data_block),
        block_count: root_dir_blocks.max(1),
    });
    all_plans.extend(plans);
    all_plans.sort_by_key(|plan| plan.inode);

    let block_bitmaps = build_block_bitmaps_for_plan(&layout, &all_plans);
    let inode_bitmaps = build_inode_bitmaps_for_plan(&layout, &all_plans);
    let stats = compute_fs_stats(&layout, &block_bitmaps, &all_plans);

    let raw_file = std::fs::File::create(path)?;
    raw_file.set_len(options.size_bytes)?;
    let mut file = BufWriter::new(raw_file);

    write_bitmaps(&mut file, &layout, &block_bitmaps, &inode_bitmaps)?;
    write_tree_data(&mut file, &layout, &all_plans)?;
    write_inode_table_with_plan(&mut file, &layout, &all_plans)?;
    write_journal(&mut file, &layout)?;

    let sb_bytes = build_superblock_with_stats(&layout, &stats)?;
    write_superblock_at(&mut file, 0, &sb_bytes)?;

    let gdt_bytes = build_gdt_with_stats(&layout, &stats, &block_bitmaps, &inode_bitmaps)?;
    write_gdt_at(&mut file, 0, &gdt_bytes)?;

    for g in 1..layout.num_groups {
        if sparse_super_group(g) {
            let group_start_block = g as u64 * EXT4_BLOCKS_PER_GROUP as u64;
            write_superblock_at(&mut file, group_start_block, &sb_bytes)?;
            write_gdt_at(&mut file, group_start_block, &gdt_bytes)?;
        }
    }

    file.flush()?;
    // No sync_all() — the image is read from page cache by the VM on the
    // same host. Fsync would add 1-10ms for no benefit.

    Ok(())
}

fn draft_directory(
    path: &str,
    dir: DirectoryNode,
    inode: u32,
    parent_inode: u32,
    next_inode: &mut u32,
    plans: &mut Vec<NodePlan>,
) -> Result<DraftDirectory, Ext4Error> {
    if !dir.xattrs.is_empty() {
        return Err(Ext4Error::Layout(format!(
            "ext4 patch baking does not yet support xattrs on '{path}'"
        )));
    }

    let mut children = Vec::new();
    let mut child_dir_count = 0u16;

    for (name, node) in dir.entries {
        let name_bytes = name.as_os_str().as_encoded_bytes().to_vec();
        let child_path = child_path(path, &name_bytes);
        let child_inode = *next_inode;
        if child_inode >= EXT4_INODES_PER_GROUP {
            return Err(Ext4Error::Layout(
                "too many upper-layer inodes for group 0 inode table".to_string(),
            ));
        }
        *next_inode += 1;

        match node {
            TreeNode::Directory(child_dir) => {
                child_dir_count = child_dir_count.saturating_add(1);
                let dir_mode = child_dir.metadata.mode;
                let child_draft = draft_directory(
                    &child_path,
                    child_dir,
                    child_inode,
                    inode,
                    next_inode,
                    plans,
                )?;
                let block_count = blocks_for_len(child_draft.data.len());
                plans.push(NodePlan {
                    inode: child_inode,
                    path: child_path.clone(),
                    permissions: normalize_dir_permissions(dir_mode),
                    uid: 0,
                    gid: 0,
                    kind: NodeKind::Directory {
                        children: child_draft.children,
                        data: child_draft.data,
                    },
                    block_start: None,
                    block_count,
                });
                children.push(DirEntrySpec {
                    inode: child_inode,
                    file_type: EXT4_FT_DIR,
                    name: name_bytes,
                });
            }
            TreeNode::RegularFile(file) => {
                if !file.xattrs.is_empty() {
                    return Err(Ext4Error::Layout(format!(
                        "ext4 patch baking does not yet support xattrs on '{child_path}'"
                    )));
                }
                plans.push(NodePlan {
                    inode: child_inode,
                    path: child_path.clone(),
                    permissions: normalize_file_permissions(file.metadata.mode),
                    uid: 0,
                    gid: 0,
                    block_count: blocks_for_len(file.data.len()),
                    kind: NodeKind::RegularFile {
                        data: file.data.read_all().map_err(Ext4Error::Io)?,
                    },
                    block_start: None,
                });
                children.push(DirEntrySpec {
                    inode: child_inode,
                    file_type: EXT4_FT_REG_FILE,
                    name: name_bytes,
                });
            }
            TreeNode::Symlink(symlink) => {
                let target_len = symlink.target.len();
                let inline = target_len <= 59;
                let block_count = if inline {
                    0
                } else {
                    blocks_for_len(target_len)
                };
                plans.push(NodePlan {
                    inode: child_inode,
                    path: child_path.clone(),
                    permissions: 0o777,
                    uid: 0,
                    gid: 0,
                    kind: NodeKind::Symlink {
                        target: symlink.target,
                        inline,
                    },
                    block_start: None,
                    block_count,
                });
                children.push(DirEntrySpec {
                    inode: child_inode,
                    file_type: EXT4_FT_SYMLINK,
                    name: name_bytes,
                });
            }
            TreeNode::CharDevice(device) => {
                plans.push(NodePlan {
                    inode: child_inode,
                    path: child_path.clone(),
                    permissions: 0,
                    uid: 0,
                    gid: 0,
                    kind: NodeKind::CharDevice {
                        major: device.major,
                        minor: device.minor,
                    },
                    block_start: None,
                    block_count: 0,
                });
                children.push(DirEntrySpec {
                    inode: child_inode,
                    file_type: EXT4_FT_CHRDEV,
                    name: name_bytes,
                });
            }
            _ => {
                return Err(Ext4Error::Layout(format!(
                    "unsupported upper-layer node at '{child_path}'"
                )));
            }
        }
    }

    let data = build_directory_data(inode, parent_inode, &children, path)?;
    Ok(DraftDirectory {
        children: child_dir_count,
        data,
    })
}

fn child_path(parent: &str, name: &[u8]) -> String {
    let name = String::from_utf8_lossy(name);
    if parent == "/" {
        format!("/{name}")
    } else {
        format!("{parent}/{name}")
    }
}

fn normalize_file_permissions(mode: u16) -> u16 {
    let perms = mode & 0o7777;
    if perms == 0 { 0o644 } else { perms }
}

fn normalize_dir_permissions(mode: u16) -> u16 {
    let perms = mode & 0o7777;
    if perms == 0 { 0o755 } else { perms }
}

fn blocks_for_len(len: usize) -> u32 {
    if len == 0 {
        0
    } else {
        (len as u64).div_ceil(EXT4_BLOCK_SIZE as u64) as u32
    }
}

fn build_directory_data(
    dir_inode: u32,
    parent_inode: u32,
    children: &[DirEntrySpec],
    path: &str,
) -> Result<Vec<u8>, Ext4Error> {
    let mut entries = Vec::with_capacity(children.len() + 2);
    entries.push(DirEntrySpec {
        inode: dir_inode,
        file_type: EXT4_FT_DIR,
        name: b".".to_vec(),
    });
    entries.push(DirEntrySpec {
        inode: parent_inode,
        file_type: EXT4_FT_DIR,
        name: b"..".to_vec(),
    });
    entries.extend(children.iter().map(|entry| DirEntrySpec {
        inode: entry.inode,
        file_type: entry.file_type,
        name: entry.name.clone(),
    }));

    let mut blocks = Vec::new();
    let mut index = 0usize;
    while index < entries.len() {
        let mut block = vec![0u8; EXT4_BLOCK_SIZE as usize];
        let mut pos = 0usize;
        let data_limit = EXT4_BLOCK_SIZE as usize - 12;
        let block_start = index;

        while index < entries.len() {
            let min_len = dir_entry_len(entries[index].name.len());
            let needed = if pos == 0 { min_len } else { pos + min_len };
            if needed > data_limit {
                if pos == 0 {
                    return Err(Ext4Error::Layout(format!(
                        "directory entry too large for '{path}'"
                    )));
                }
                break;
            }
            pos += min_len;
            index += 1;
        }

        let mut write_pos = 0usize;
        for (entry_index, entry) in entries[block_start..index].iter().enumerate() {
            let is_last = entry_index + 1 == index - block_start;
            let rec_len = if is_last {
                (data_limit - write_pos) as u16
            } else {
                dir_entry_len(entry.name.len()) as u16
            };
            put_le32(&mut block, write_pos, entry.inode);
            put_le16(&mut block, write_pos + 4, rec_len);
            block[write_pos + 6] = entry.name.len() as u8;
            block[write_pos + 7] = entry.file_type;
            block[write_pos + 8..write_pos + 8 + entry.name.len()].copy_from_slice(&entry.name);
            write_pos += rec_len as usize;
        }

        let tail = data_limit;
        put_le32(&mut block, tail, 0);
        put_le16(&mut block, tail + 4, 12);
        block[tail + 6] = 0;
        block[tail + 7] = 0xDE;
        blocks.extend_from_slice(&block);
    }

    if blocks.is_empty() {
        let mut block = vec![0u8; EXT4_BLOCK_SIZE as usize];
        put_le32(&mut block, 0, dir_inode);
        put_le16(&mut block, 4, 12);
        block[6] = 1;
        block[7] = EXT4_FT_DIR;
        block[8] = b'.';
        put_le32(&mut block, 12, parent_inode);
        put_le16(&mut block, 16, (EXT4_BLOCK_SIZE - 24) as u16);
        block[18] = 2;
        block[19] = EXT4_FT_DIR;
        block[20] = b'.';
        block[21] = b'.';
        let tail = EXT4_BLOCK_SIZE as usize - 12;
        put_le32(&mut block, tail, 0);
        put_le16(&mut block, tail + 4, 12);
        block[tail + 7] = 0xDE;
        blocks = block;
    }

    Ok(blocks)
}

fn dir_entry_len(name_len: usize) -> usize {
    (8 + name_len + 3) & !3
}

fn allocate_node_data(allocator: &mut DataAllocator, plan: &mut NodePlan) -> Result<(), Ext4Error> {
    if plan.block_count == 0 {
        plan.block_start = None;
        return Ok(());
    }

    plan.block_start = allocator.allocate(plan.block_count, &plan.path)?;
    Ok(())
}

impl DataAllocator {
    fn new(layout: &Layout) -> Self {
        let mut regions = Vec::new();
        for group in 0..layout.num_groups {
            let group_start = layout.group_start_block(group);
            let group_end = group_start + layout.blocks_in_group(group);
            let start = layout.group_data_start_block(group);
            if start < group_end {
                regions.push((start, group_end - start));
            }
        }
        Self { regions }
    }

    fn allocate(&mut self, blocks: u32, path: &str) -> Result<Option<u32>, Ext4Error> {
        if blocks == 0 {
            return Ok(None);
        }

        for region in &mut self.regions {
            if region.1 >= blocks {
                let start = region.0;
                region.0 += blocks;
                region.1 -= blocks;
                return Ok(Some(start));
            }
        }

        Err(Ext4Error::Layout(format!(
            "not enough space in upper.ext4 for '{path}'"
        )))
    }
}

fn build_block_bitmaps_for_plan(layout: &Layout, plans: &[NodePlan]) -> Vec<Vec<u8>> {
    let mut used_extents = Vec::new();
    used_extents.push((
        layout.first_data_block,
        layout.journal_start_block - layout.first_data_block,
    ));
    used_extents.push((layout.journal_start_block, layout.journal_blocks));

    for plan in plans {
        if let Some(start) = plan.block_start
            && plan.block_count > 0
        {
            used_extents.push((start, plan.block_count));
        }
    }

    (0..layout.num_groups)
        .map(|group| {
            let mut bitmap = vec![0u8; EXT4_BLOCK_SIZE as usize];
            let group_start = layout.group_start_block(group);
            let group_end = group_start + layout.blocks_in_group(group);

            for bit in 0..layout.group_metadata_blocks(group) {
                bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
            }

            for (start, len) in &used_extents {
                let extent_start = *start;
                let extent_end = extent_start + *len;
                let overlap_start = extent_start.max(group_start);
                let overlap_end = extent_end.min(group_end);
                if overlap_start < overlap_end {
                    for block in overlap_start..overlap_end {
                        let bit = block - group_start;
                        bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
                    }
                }
            }

            let blocks_in_group = layout.blocks_in_group(group);
            for bit in blocks_in_group..EXT4_BLOCKS_PER_GROUP {
                bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
            }

            bitmap
        })
        .collect()
}

fn build_inode_bitmaps_for_plan(layout: &Layout, plans: &[NodePlan]) -> Vec<Vec<u8>> {
    let max_used_inode = plans
        .iter()
        .map(|plan| plan.inode)
        .max()
        .unwrap_or(EXT4_JOURNAL_INO)
        .max(EXT4_FIRST_INO - 1);

    (0..layout.num_groups)
        .map(|group| {
            let mut bitmap = vec![0u8; EXT4_BLOCK_SIZE as usize];
            if group == 0 {
                for bit in 0..max_used_inode {
                    bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
                }
            }
            for bit in EXT4_INODES_PER_GROUP..(EXT4_BLOCK_SIZE * 8) {
                bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
            }
            bitmap
        })
        .collect()
}

fn compute_fs_stats(layout: &Layout, block_bitmaps: &[Vec<u8>], plans: &[NodePlan]) -> FsStats {
    let max_used_inode = plans
        .iter()
        .map(|plan| plan.inode)
        .max()
        .unwrap_or(EXT4_JOURNAL_INO)
        .max(EXT4_FIRST_INO - 1);
    let dir_count = plans
        .iter()
        .filter(|plan| matches!(plan.kind, NodeKind::Directory { .. }))
        .count() as u32;

    let mut group_free_blocks = Vec::with_capacity(layout.num_groups as usize);
    let mut total_free_blocks = 0u64;
    let mut total_used_blocks = 0u64;
    for (group, bitmap) in block_bitmaps
        .iter()
        .enumerate()
        .take(layout.num_groups as usize)
    {
        let blocks_in_group = layout.blocks_in_group(group as u32) as usize;
        let used = count_used_bits(bitmap, blocks_in_group);
        let free = blocks_in_group.saturating_sub(used) as u32;
        group_free_blocks.push(free);
        total_free_blocks += free as u64;
        total_used_blocks += used as u64;
    }

    let mut group_free_inodes = vec![EXT4_INODES_PER_GROUP; layout.num_groups as usize];
    group_free_inodes[0] = EXT4_INODES_PER_GROUP - max_used_inode;
    let total_free_inodes = group_free_inodes.iter().map(|count| *count as u64).sum();

    let mut group_used_dirs = vec![0u32; layout.num_groups as usize];
    group_used_dirs[0] = dir_count;

    FsStats {
        group_free_blocks,
        group_free_inodes,
        group_used_dirs,
        total_free_blocks,
        total_free_inodes,
        total_used_blocks,
    }
}

fn count_used_bits(bitmap: &[u8], bits: usize) -> usize {
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

fn write_tree_data(
    file: &mut (impl std::io::Write + std::io::Seek),
    layout: &Layout,
    plans: &[NodePlan],
) -> Result<(), Ext4Error> {
    for plan in plans {
        match &plan.kind {
            NodeKind::Directory { data, .. } => {
                let start = plan.block_start.unwrap_or(layout.first_data_block);
                let mut bytes = data.clone();
                update_dir_block_checksums(layout.csum_seed, plan.inode, &mut bytes);
                write_extent_bytes(file, start, &bytes)?;
            }
            NodeKind::RegularFile { data } => {
                if let Some(start) = plan.block_start {
                    write_extent_bytes(file, start, data)?;
                }
            }
            NodeKind::Symlink { target, inline } => {
                if !inline && let Some(start) = plan.block_start {
                    write_extent_bytes(file, start, target)?;
                }
            }
            NodeKind::CharDevice { .. } => {}
        }
    }

    Ok(())
}

fn write_extent_bytes(
    file: &mut (impl std::io::Write + std::io::Seek),
    start_block: u32,
    data: &[u8],
) -> Result<(), Ext4Error> {
    let offset = start_block as u64 * EXT4_BLOCK_SIZE as u64;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(data)?;

    let pad = (EXT4_BLOCK_SIZE as usize - (data.len() % EXT4_BLOCK_SIZE as usize))
        % EXT4_BLOCK_SIZE as usize;
    if pad > 0 {
        static ZEROS: [u8; 4096] = [0u8; 4096];
        file.write_all(&ZEROS[..pad])?;
    }

    Ok(())
}

fn update_dir_block_checksums(csum_seed: u32, inode: u32, data: &mut [u8]) {
    for chunk in data.chunks_exact_mut(EXT4_BLOCK_SIZE as usize) {
        let tail = EXT4_BLOCK_SIZE as usize - 12;
        let checksum = dir_block_checksum(csum_seed, inode, 0, &chunk[..tail]);
        put_le32(chunk, tail + 8, checksum);
    }
}

fn write_inode_table_with_plan(
    file: &mut (impl std::io::Write + std::io::Seek),
    layout: &Layout,
    plans: &[NodePlan],
) -> Result<(), Ext4Error> {
    let table_offset = layout.inode_table_block as u64 * EXT4_BLOCK_SIZE as u64;

    let root_inode = build_inode_from_plan(layout, &plans[0])?;
    let root_offset = table_offset + (EXT4_ROOT_INO as u64 - 1) * EXT4_INODE_SIZE as u64;
    file.seek(SeekFrom::Start(root_offset))?;
    file.write_all(&root_inode)?;

    let journal_inode = build_journal_inode(layout);
    let journal_offset = table_offset + (EXT4_JOURNAL_INO as u64 - 1) * EXT4_INODE_SIZE as u64;
    file.seek(SeekFrom::Start(journal_offset))?;
    file.write_all(&journal_inode)?;

    for plan in plans.iter().filter(|plan| plan.inode >= EXT4_FIRST_INO) {
        let inode_bytes = build_inode_from_plan(layout, plan)?;
        let inode_offset = table_offset + (plan.inode as u64 - 1) * EXT4_INODE_SIZE as u64;
        file.seek(SeekFrom::Start(inode_offset))?;
        file.write_all(&inode_bytes)?;
    }

    Ok(())
}

fn build_inode_from_plan(layout: &Layout, plan: &NodePlan) -> Result<Vec<u8>, Ext4Error> {
    let mut inode = vec![0u8; EXT4_INODE_SIZE as usize];
    let (mode, size, links_count, extents) = match &plan.kind {
        NodeKind::Directory { children, data } => (
            S_IFDIR | normalize_dir_permissions(plan.permissions),
            data.len() as u64,
            2 + *children,
            true,
        ),
        NodeKind::RegularFile { data } => (
            S_IFREG | normalize_file_permissions(plan.permissions),
            data.len() as u64,
            1,
            true,
        ),
        NodeKind::Symlink { target, inline } => (S_IFLNK | 0o777, target.len() as u64, 1, !inline),
        NodeKind::CharDevice { .. } => (S_IFCHR | plan.permissions, 0, 1, false),
    };

    put_le16(&mut inode, 0x00, mode);
    put_le16(&mut inode, 0x02, plan.uid);
    put_le32(&mut inode, 0x04, size as u32);
    put_le16(&mut inode, 0x18, plan.gid);
    put_le16(&mut inode, 0x1A, links_count);
    put_le32(&mut inode, 0x1C, plan.block_count * (EXT4_BLOCK_SIZE / 512));
    if extents {
        put_le32(&mut inode, 0x20, EXT4_EXTENTS_FL);
    }

    match &plan.kind {
        NodeKind::Directory { .. } | NodeKind::RegularFile { .. } => {
            if let Some(start) = plan.block_start {
                write_extent_tree(&mut inode, 0x28, start, plan.block_count as u16);
            } else {
                write_empty_extent_tree(&mut inode, 0x28);
            }
        }
        NodeKind::Symlink { target, inline } => {
            if *inline {
                inode[0x28..0x28 + target.len()].copy_from_slice(target);
            } else if let Some(start) = plan.block_start {
                write_extent_tree(&mut inode, 0x28, start, plan.block_count as u16);
            }
        }
        NodeKind::CharDevice { major, minor } => {
            put_le32(&mut inode, 0x28, (*minor & 0xFF) | (major << 8));
        }
    }

    put_le32(&mut inode, 0x64, 0);
    put_le32(&mut inode, 0x6C, (size >> 32) as u32);
    put_le16(&mut inode, 0x80, EXT4_MIN_EXTRA_ISIZE);

    let csum = inode_checksum(layout.csum_seed, plan.inode, 0, &inode);
    put_le16(&mut inode, 0x7C, csum as u16);
    put_le16(&mut inode, 0x82, (csum >> 16) as u16);

    Ok(inode)
}

fn write_empty_extent_tree(buf: &mut [u8], offset: usize) {
    put_le16(buf, offset, EXT4_EH_MAGIC);
    put_le16(buf, offset + 2, 0);
    put_le16(buf, offset + 4, 4);
    put_le16(buf, offset + 6, 0);
    put_le32(buf, offset + 8, 0);
}

fn build_superblock_with_stats(layout: &Layout, stats: &FsStats) -> Result<Vec<u8>, Ext4Error> {
    let mut block = build_superblock(layout)?;
    let sb = &mut block[1024..2048];
    put_le32(sb, 0x0C, stats.total_free_blocks as u32);
    put_le32(sb, 0x10, stats.total_free_inodes as u32);
    put_le32(sb, 0x158, (stats.total_free_blocks >> 32) as u32);
    put_le32(sb, 0x194, stats.total_used_blocks as u32);
    put_le32(sb, 0x3FC, 0);
    let checksum = crc32c::crc32c_raw(0xFFFF_FFFF, &sb[..0x3FC]);
    put_le32(sb, 0x3FC, checksum);
    Ok(block)
}

fn build_gdt_with_stats(
    layout: &Layout,
    stats: &FsStats,
    block_bitmaps: &[Vec<u8>],
    inode_bitmaps: &[Vec<u8>],
) -> Result<Vec<u8>, Ext4Error> {
    let desc_size = EXT4_DESC_SIZE as usize;
    let mut gdt = vec![0u8; layout.num_groups as usize * desc_size];

    for g in 0..layout.num_groups {
        let off = g as usize * desc_size;
        let desc = &mut gdt[off..off + desc_size];
        let bb = layout.group_block_bitmap_block(g);
        let ib = layout.group_inode_bitmap_block(g);
        let it = layout.group_inode_table_block(g);
        let bb_csum = bitmap_checksum(
            layout.csum_seed,
            &block_bitmaps[g as usize],
            EXT4_BLOCK_SIZE as usize,
        );
        let ib_csum = bitmap_checksum(
            layout.csum_seed,
            &inode_bitmaps[g as usize],
            (EXT4_INODES_PER_GROUP / 8) as usize,
        );

        put_le32(desc, 0x00, bb);
        put_le32(desc, 0x04, ib);
        put_le32(desc, 0x08, it);
        put_le16(desc, 0x0C, stats.group_free_blocks[g as usize] as u16);
        put_le16(desc, 0x0E, stats.group_free_inodes[g as usize] as u16);
        put_le16(desc, 0x10, stats.group_used_dirs[g as usize] as u16);
        put_le16(desc, 0x12, EXT4_BG_INODE_ZEROED);
        put_le16(desc, 0x18, bb_csum as u16);
        put_le16(desc, 0x1A, ib_csum as u16);
        put_le16(desc, 0x1C, stats.group_free_inodes[g as usize] as u16);
        put_le16(desc, 0x38, (bb_csum >> 16) as u16);
        put_le16(desc, 0x3A, (ib_csum >> 16) as u16);
        put_le16(desc, 0x1E, 0);
        let checksum = gdt_checksum(layout.csum_seed, g, desc);
        put_le16(desc, 0x1E, checksum);
    }

    Ok(gdt)
}
#[cfg(test)]
fn build_block_bitmaps(layout: &Layout) -> Vec<Vec<u8>> {
    (0..layout.num_groups)
        .map(|group| build_block_bitmap(layout, group))
        .collect()
}

#[cfg(test)]
fn build_inode_bitmaps(layout: &Layout) -> Vec<Vec<u8>> {
    (0..layout.num_groups)
        .map(|group| build_inode_bitmap(layout, group))
        .collect()
}

#[cfg(test)]
fn build_block_bitmap(layout: &Layout, group: u32) -> Vec<u8> {
    let mut bitmap = vec![0u8; EXT4_BLOCK_SIZE as usize];

    // Metadata, the root directory block, and the journal are permanently
    // allocated within the filesystem image.
    let used = layout.group_used_blocks(group);
    for bit in 0..used {
        bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
    }

    // Bits beyond the final partial group are permanently unavailable.
    let blocks_in_group = layout.blocks_in_group(group);
    for bit in blocks_in_group..EXT4_BLOCKS_PER_GROUP {
        bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
    }

    bitmap
}

#[cfg(test)]
fn build_inode_bitmap(_layout: &Layout, group: u32) -> Vec<u8> {
    let mut bitmap = vec![0u8; EXT4_BLOCK_SIZE as usize];

    if group == 0 {
        // Inode numbering is 1-based; bit 0 corresponds to inode 1.
        for bit in 0..(EXT4_FIRST_INO - 1) {
            bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
        }
    }

    // The inode bitmap consumes only the first inodes-per-group bits; the
    // remaining padding bits in the block must stay permanently set.
    for bit in EXT4_INODES_PER_GROUP..(EXT4_BLOCK_SIZE * 8) {
        bitmap[(bit / 8) as usize] |= 1 << (bit % 8);
    }

    bitmap
}

fn write_bitmaps(
    file: &mut (impl std::io::Write + std::io::Seek),
    layout: &Layout,
    block_bitmaps: &[Vec<u8>],
    inode_bitmaps: &[Vec<u8>],
) -> Result<(), Ext4Error> {
    for group in 0..layout.num_groups as usize {
        let block_offset =
            layout.group_block_bitmap_block(group as u32) as u64 * EXT4_BLOCK_SIZE as u64;
        file.seek(SeekFrom::Start(block_offset))?;
        file.write_all(&block_bitmaps[group])?;

        let inode_offset =
            layout.group_inode_bitmap_block(group as u32) as u64 * EXT4_BLOCK_SIZE as u64;
        file.seek(SeekFrom::Start(inode_offset))?;
        file.write_all(&inode_bitmaps[group])?;
    }

    Ok(())
}

/// Build the 256-byte journal inode (inode 8).
fn build_journal_inode(layout: &Layout) -> Vec<u8> {
    let mut inode = vec![0u8; EXT4_INODE_SIZE as usize];

    let mode = S_IFREG | 0o600;
    let size = layout.journal_blocks as u64 * EXT4_BLOCK_SIZE as u64;

    // i_mode (offset 0, u16)
    put_le16(&mut inode, 0x00, mode);
    // i_size_lo (offset 4, u32)
    put_le32(&mut inode, 0x04, size as u32);
    // i_size_high (offset 108, u32)
    put_le32(&mut inode, 0x6C, (size >> 32) as u32);
    // i_links_count (offset 26, u16)
    put_le16(&mut inode, 0x1A, 1);
    // i_blocks_lo (offset 28, u32) -- in 512-byte sectors
    let sectors = (layout.journal_blocks as u64 * EXT4_BLOCK_SIZE as u64) / 512;
    put_le32(&mut inode, 0x1C, sectors as u32);
    // i_flags (offset 32, u32)
    put_le32(&mut inode, 0x20, EXT4_EXTENTS_FL);

    // i_block (offset 40, 60 bytes) -- extent tree pointing to journal blocks
    write_extent_tree(
        &mut inode,
        0x28,
        layout.journal_start_block,
        layout.journal_blocks as u16,
    );

    // i_generation (offset 100, u32)
    put_le32(&mut inode, 0x64, 0);

    // -- Extended inode fields --
    // i_extra_isize (offset 128, u16)
    put_le16(&mut inode, 0x80, EXT4_MIN_EXTRA_ISIZE);

    // Inode checksum
    let csum = inode_checksum(layout.csum_seed, EXT4_JOURNAL_INO, 0, &inode);
    // l_i_checksum_lo (offset 0x7C, u16)
    put_le16(&mut inode, 0x7C, csum as u16);
    // i_checksum_hi (offset 0x82, u16)
    put_le16(&mut inode, 0x82, (csum >> 16) as u16);

    inode
}

/// Write an extent tree header + one extent entry into `buf` at `offset`.
///
/// The extent tree header is 12 bytes, each extent entry is also 12 bytes.
fn write_extent_tree(buf: &mut [u8], offset: usize, start_block: u32, block_count: u16) {
    // Extent header (12 bytes)
    put_le16(buf, offset, EXT4_EH_MAGIC); // eh_magic
    put_le16(buf, offset + 2, 1); // eh_entries
    put_le16(buf, offset + 4, 4); // eh_max (for inode: (60-12)/12 = 4)
    put_le16(buf, offset + 6, 0); // eh_depth (leaf)
    put_le32(buf, offset + 8, 0); // eh_generation

    // Extent entry (12 bytes) at offset+12
    let ext_off = offset + 12;
    put_le32(buf, ext_off, 0); // ee_block (logical block 0)
    put_le16(buf, ext_off + 4, block_count); // ee_len
    put_le16(buf, ext_off + 6, 0); // ee_start_hi
    put_le32(buf, ext_off + 8, start_block); // ee_start_lo
}

/// Write the journal superblock at the first journal block.
fn write_journal(
    file: &mut (impl std::io::Write + std::io::Seek),
    layout: &Layout,
) -> Result<(), Ext4Error> {
    let mut jsb = vec![0u8; EXT4_BLOCK_SIZE as usize];

    // All jbd2 fields are BIG-ENDIAN.
    // Header (12 bytes)
    put_be32(&mut jsb, 0, JBD2_MAGIC); // h_magic
    put_be32(&mut jsb, 4, JBD2_SUPERBLOCK_V2); // h_blocktype
    put_be32(&mut jsb, 8, 0); // h_sequence (not used for sb)

    // Journal superblock fields
    put_be32(&mut jsb, 12, EXT4_BLOCK_SIZE); // s_blocksize
    put_be32(&mut jsb, 16, layout.journal_blocks); // s_maxlen
    put_be32(&mut jsb, 20, 1); // s_first (first log block)
    put_be32(&mut jsb, 24, 1); // s_sequence (next expected sequence)
    put_be32(&mut jsb, 28, 0); // s_start (0 = clean/no recovery needed)

    // s_errno (offset 32)
    put_be32(&mut jsb, 32, 0);
    // s_feature_compat (offset 36)
    put_be32(&mut jsb, 36, 0);
    // s_feature_incompat (offset 40) = CSUM_V3(0x10) | 64BIT(0x02) | REVOKE(0x01)
    put_be32(&mut jsb, 40, 0x13);
    // s_feature_ro_compat (offset 44)
    put_be32(&mut jsb, 44, 0);

    // s_uuid (offset 48, 16 bytes) -- same as filesystem UUID
    jsb[48..64].copy_from_slice(&layout.uuid);

    // s_nr_users (offset 64, u32)
    put_be32(&mut jsb, 64, 1);

    // s_dynsuper (offset 68, u32) -- block of dynamic superblock copy
    put_be32(&mut jsb, 68, 0);

    // s_max_transaction (offset 72), s_max_trans_data (offset 76)
    put_be32(&mut jsb, 72, 0);
    put_be32(&mut jsb, 76, 0);

    // s_checksum_type (offset 80, u8) = 4 (CRC32C)
    // Actually offset for checksum_type is at offset 80+... Let me use correct
    // offsets from the jbd2 spec:
    //   offset 80: padding (u8)
    //   offset 81-83: padding
    //   offset 84-87: s_padding2
    //   offset 88-91: s_num_fc_blks
    //   offset 92-95: s_head
    //   offset 96-255: s_padding[44]
    //   offset 256-271: s_users[16*48] (first 16 bytes = first user UUID)
    //
    // Correct jbd2 superblock layout (from kernel headers):
    //   0x00: h_magic (u32be)
    //   0x04: h_blocktype (u32be)
    //   0x08: h_sequence (u32be)
    //   0x0C: s_blocksize (u32be)
    //   0x10: s_maxlen (u32be)
    //   0x14: s_first (u32be)
    //   0x18: s_sequence (u32be)
    //   0x1C: s_start (u32be)
    //   0x20: s_errno (u32be)
    //   0x24: s_feature_compat (u32be)
    //   0x28: s_feature_incompat (u32be)
    //   0x2C: s_feature_ro_compat (u32be)
    //   0x30: s_uuid[16]
    //   0x40: s_nr_users (u32be)
    //   0x44: s_dynsuper (u32be)
    //   0x48: s_max_transaction (u32be)
    //   0x4C: s_max_trans_data (u32be)
    //   0x50: s_checksum_type (u8)
    //   0x51: s_padding2[3]
    //   0x54: s_padding[42] (u32be array = 168 bytes)
    //   0xFC: s_checksum (u32be)
    //   0x100: s_users[16*48]

    jsb[0x50] = 4; // s_checksum_type = CRC32C

    // s_checksum (offset 0xFC, u32be), computed over the 1024-byte on-disk
    // jbd2 superblock with the checksum field zeroed.
    let jsb_csum = crc32c::crc32c_raw(0xFFFF_FFFF, &jsb[..JBD2_SUPERBLOCK_SIZE]);
    put_be32(&mut jsb, 0xFC, jsb_csum);

    let offset = layout.journal_start_block as u64 * EXT4_BLOCK_SIZE as u64;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(&jsb)?;

    Ok(())
}

/// Build the 1024-byte ext4 superblock.
fn build_superblock(layout: &Layout) -> Result<Vec<u8>, Ext4Error> {
    // The superblock is 1024 bytes starting at byte 1024 within block 0.
    // We build a full 4096-byte block with the sb at offset 1024.
    let mut block = vec![0u8; EXT4_BLOCK_SIZE as usize];
    let sb = &mut block[1024..2048]; // 1024-byte superblock

    let total_blocks = layout.num_blocks;
    let total_inodes = layout.num_groups as u64 * EXT4_INODES_PER_GROUP as u64;

    let free_blocks = layout.total_free_blocks();
    let free_inodes = layout.total_free_inodes();

    // s_inodes_count (0x00, u32)
    put_le32(sb, 0x00, total_inodes as u32);
    // s_blocks_count_lo (0x04, u32)
    put_le32(sb, 0x04, total_blocks as u32);
    // s_r_blocks_count_lo (0x08, u32) -- reserved blocks for superuser
    put_le32(sb, 0x08, 0);
    // s_free_blocks_count_lo (0x0C, u32)
    put_le32(sb, 0x0C, free_blocks as u32);
    // s_free_inodes_count (0x10, u32)
    put_le32(sb, 0x10, free_inodes as u32);
    // s_first_data_block (0x14, u32) -- 0 for 4k blocks
    put_le32(sb, 0x14, 0);
    // s_log_block_size (0x18, u32)
    put_le32(sb, 0x18, EXT4_LOG_BLOCK_SIZE);
    // s_log_cluster_size (0x1C, u32)
    put_le32(sb, 0x1C, EXT4_LOG_BLOCK_SIZE);
    // s_blocks_per_group (0x20, u32)
    put_le32(sb, 0x20, EXT4_BLOCKS_PER_GROUP);
    // s_clusters_per_group (0x24, u32)
    put_le32(sb, 0x24, EXT4_BLOCKS_PER_GROUP);
    // s_inodes_per_group (0x28, u32)
    put_le32(sb, 0x28, EXT4_INODES_PER_GROUP);

    // s_mtime (0x2C, u32), s_wtime (0x30, u32)
    // Leave as 0.

    // s_mnt_count (0x34, u16)
    put_le16(sb, 0x34, 0);
    // s_max_mnt_count (0x36, u16) -- -1 = no limit
    put_le16(sb, 0x36, 0xFFFF);
    // s_magic (0x38, u16)
    put_le16(sb, 0x38, EXT4_SUPER_MAGIC);
    // s_state (0x3A, u16) -- 1 = clean
    put_le16(sb, 0x3A, 1);
    // s_errors (0x3C, u16) -- 1 = continue
    put_le16(sb, 0x3C, 1);
    // s_minor_rev_level (0x3E, u16)
    put_le16(sb, 0x3E, 0);

    // s_lastcheck (0x40, u32), s_checkinterval (0x44, u32)
    // Leave as 0.

    // s_creator_os (0x48, u32) -- 0 = Linux
    put_le32(sb, 0x48, 0);
    // s_rev_level (0x4C, u32) -- 1 = dynamic rev
    put_le32(sb, 0x4C, 1);

    // s_def_resuid (0x50, u16) -- 0
    put_le16(sb, 0x50, 0);
    // s_def_resgid (0x52, u16) -- 0
    put_le16(sb, 0x52, 0);

    // --- EXT4_DYNAMIC_REV specific ---
    // s_first_ino (0x54, u32)
    put_le32(sb, 0x54, EXT4_FIRST_INO);
    // s_inode_size (0x58, u16)
    put_le16(sb, 0x58, EXT4_INODE_SIZE);
    // s_block_group_nr (0x5A, u16) -- block group hosting this superblock
    put_le16(sb, 0x5A, 0);

    // s_feature_compat (0x5C, u32)
    put_le32(sb, 0x5C, layout.feature_compat);
    // s_feature_incompat (0x60, u32)
    put_le32(sb, 0x60, layout.feature_incompat);
    // s_feature_ro_compat (0x64, u32)
    put_le32(sb, 0x64, layout.feature_ro_compat);

    // s_uuid (0x68, 16 bytes)
    sb[0x68..0x78].copy_from_slice(&layout.uuid);

    // s_volume_name (0x78, 16 bytes) -- leave empty

    // s_last_mounted (0x88, 64 bytes) -- leave empty

    // s_algorithm_usage_bitmap (0xC8, u32) -- 0
    put_le32(sb, 0xC8, 0);

    // s_prealloc_blocks (0xCC, u8), s_prealloc_dir_blocks (0xCD, u8)
    sb[0xCC] = 0;
    sb[0xCD] = 0;

    // s_reserved_gdt_blocks (0xCE, u16)
    put_le16(sb, 0xCE, RESERVED_GDT_BLOCKS as u16);

    // s_journal_uuid (0xD0, 16 bytes) -- leave zeroed (internal journal)

    // s_journal_inum (0xE0, u32)
    put_le32(sb, 0xE0, EXT4_JOURNAL_INO);
    // s_journal_dev (0xE4, u32) -- 0 (internal)
    put_le32(sb, 0xE4, 0);
    // s_last_orphan (0xE8, u32)
    put_le32(sb, 0xE8, 0);

    // s_hash_seed (0xEC, 4*u32 = 16 bytes) -- random
    sb[0xEC..0xFC].copy_from_slice(&layout.uuid); // reuse uuid bytes as hash seed

    // s_def_hash_version (0xFC, u8) -- 1 = half MD4
    sb[0xFC] = 1;
    // s_jnl_backup_type (0xFD, u8) -- 1
    sb[0xFD] = 1;

    // s_desc_size (0xFE, u16)
    put_le16(sb, 0xFE, EXT4_DESC_SIZE);

    // s_default_mount_opts (0x100, u32) -- 0x000C (user_xattr, acl)
    put_le32(sb, 0x100, 0x000C);

    // s_first_meta_bg (0x104, u32)
    put_le32(sb, 0x104, 0);

    // s_mkfs_time (0x108, u32) -- leave 0

    // s_jnl_blocks (0x10C, 17*u32 = 68 bytes) -- journal inode i_block backup
    // Copy the extent tree from the journal inode.
    {
        let mut extent_buf = [0u8; 60];
        write_extent_tree(
            &mut extent_buf,
            0,
            layout.journal_start_block,
            layout.journal_blocks as u16,
        );
        // Copy 15 u32s (60 bytes) into s_jnl_blocks
        sb[0x10C..0x10C + 60].copy_from_slice(&extent_buf);
        // s_jnl_blocks[15] = i_size_lo
        let jsize = layout.journal_blocks as u64 * EXT4_BLOCK_SIZE as u64;
        put_le32(sb, 0x10C + 60, jsize as u32);
        // s_jnl_blocks[16] = i_size_hi
        put_le32(sb, 0x10C + 64, (jsize >> 32) as u32);
    }

    // --- 64-bit fields ---
    // s_blocks_count_hi (0x150, u32)
    put_le32(sb, 0x150, (total_blocks >> 32) as u32);
    // s_r_blocks_count_hi (0x154, u32)
    put_le32(sb, 0x154, 0);
    // s_free_blocks_count_hi (0x158, u32)
    put_le32(sb, 0x158, (free_blocks >> 32) as u32);

    // s_min_extra_isize (0x15C, u16)
    put_le16(sb, 0x15C, EXT4_MIN_EXTRA_ISIZE);
    // s_want_extra_isize (0x15E, u16)
    put_le16(sb, 0x15E, EXT4_MIN_EXTRA_ISIZE);

    // s_flags (0x160, u32)
    put_le32(sb, 0x160, 0);

    // s_log_groups_per_flex (0x174, u8) -- flex_bg disabled
    sb[0x174] = 0;

    // s_checksum_type (0x175, u8) -- 1 = CRC32C
    sb[0x175] = 1;

    // s_kbytes_written (0x178, u64) -- 0
    // s_snapshot_inum, etc. -- leave zeroed

    // s_overhead_clusters (0x194, u32)
    put_le32(sb, 0x194, layout.total_used_blocks() as u32);

    // s_checksum_seed (0x270, u32) -- crc32c::crc32c_raw(~0, uuid)
    // Only used if INCOMPAT_CSUM_SEED is set. For METADATA_CSUM without
    // CSUM_SEED, the kernel computes from the UUID. We don't set
    // INCOMPAT_CSUM_SEED so leave this zero.
    put_le32(sb, 0x270, 0);

    // s_encoding (0x27C, u16) -- 0 (no casefold)
    put_le16(sb, 0x27C, 0);

    // s_checksum (0x3FC, u32) -- CRC32C of sb bytes 0..0x3FC
    let sb_csum = crc32c::crc32c_raw(0xFFFF_FFFF, &sb[..0x3FC]);
    put_le32(sb, 0x3FC, sb_csum);

    Ok(block)
}

/// Build the group descriptor table (GDT). Returns a byte vector containing
/// all group descriptors (64 bytes each).
#[cfg(test)]
fn build_gdt(
    layout: &Layout,
    block_bitmaps: &[Vec<u8>],
    inode_bitmaps: &[Vec<u8>],
) -> Result<Vec<u8>, Ext4Error> {
    let desc_size = EXT4_DESC_SIZE as usize;
    let mut gdt = vec![0u8; layout.num_groups as usize * desc_size];

    for g in 0..layout.num_groups {
        let off = g as usize * desc_size;
        let desc = &mut gdt[off..off + desc_size];
        let bb = layout.group_block_bitmap_block(g);
        let ib = layout.group_inode_bitmap_block(g);
        let it = layout.group_inode_table_block(g);
        let bb_csum = bitmap_checksum(
            layout.csum_seed,
            &block_bitmaps[g as usize],
            EXT4_BLOCK_SIZE as usize,
        );
        let ib_csum = bitmap_checksum(
            layout.csum_seed,
            &inode_bitmaps[g as usize],
            (EXT4_INODES_PER_GROUP / 8) as usize,
        );

        put_le32(desc, 0x00, bb);
        put_le32(desc, 0x04, ib);
        put_le32(desc, 0x08, it);
        put_le16(desc, 0x0C, layout.group_free_blocks(g) as u16);
        put_le16(desc, 0x0E, layout.group_free_inodes(g) as u16);
        put_le16(desc, 0x10, layout.group_used_dirs(g) as u16);
        put_le16(desc, 0x12, EXT4_BG_INODE_ZEROED);
        put_le32(desc, 0x14, 0);
        put_le16(desc, 0x18, bb_csum as u16);
        put_le16(desc, 0x1A, ib_csum as u16);
        put_le16(desc, 0x1C, layout.group_free_inodes(g) as u16);
        put_le32(desc, 0x20, 0);
        put_le32(desc, 0x24, 0);
        put_le32(desc, 0x28, 0);
        put_le16(desc, 0x2C, 0);
        put_le16(desc, 0x2E, 0);
        put_le16(desc, 0x30, 0);
        put_le16(desc, 0x32, 0);
        put_le32(desc, 0x34, 0);
        put_le16(desc, 0x38, (bb_csum >> 16) as u16);
        put_le16(desc, 0x3A, (ib_csum >> 16) as u16);

        // GDT entry checksum (stored at bg_checksum, offset 0x1E)
        // crc32c(csum_seed, le32(group_num) || desc_bytes_with_checksum_zeroed) & 0xFFFF
        // Zero out the checksum field before computing.
        put_le16(desc, 0x1E, 0);
        let gdt_csum = gdt_checksum(layout.csum_seed, g, desc);
        put_le16(desc, 0x1E, gdt_csum);
    }

    Ok(gdt)
}

/// Write superblock at the given group's first block.
fn write_superblock_at(
    file: &mut (impl std::io::Write + std::io::Seek),
    group_start_block: u64,
    sb_block: &[u8],
) -> Result<(), Ext4Error> {
    // The superblock is always at byte offset 1024 within the first block of
    // the group. For group 0 the offset is 1024. For backup groups the sb is at
    // group_start_block * block_size + 0 (the whole block including the padding
    // before offset 1024).
    let offset = group_start_block * EXT4_BLOCK_SIZE as u64;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(sb_block)?;
    Ok(())
}

/// Write GDT at block (group_start_block + 1).
fn write_gdt_at(
    file: &mut (impl std::io::Write + std::io::Seek),
    group_start_block: u64,
    gdt: &[u8],
) -> Result<(), Ext4Error> {
    let offset = (group_start_block + 1) * EXT4_BLOCK_SIZE as u64;
    file.seek(SeekFrom::Start(offset))?;
    file.write_all(gdt)?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Checksums
//--------------------------------------------------------------------------------------------------

/// GDT entry checksum (16-bit).
fn gdt_checksum(csum_seed: u32, group: u32, desc: &[u8]) -> u16 {
    let mut crc = crc32c::crc32c_raw(csum_seed, &group.to_le_bytes());
    crc = crc32c::crc32c_raw(crc, desc);
    (crc & 0xFFFF) as u16
}

/// Inode checksum (32-bit, split across lo/hi in the inode).
fn inode_checksum(csum_seed: u32, inum: u32, generation: u32, inode_bytes: &[u8]) -> u32 {
    let mut crc = crc32c::crc32c_raw(csum_seed, &inum.to_le_bytes());
    crc = crc32c::crc32c_raw(crc, &generation.to_le_bytes());
    crc = crc32c::crc32c_raw(crc, &inode_bytes[..0x7C]);
    crc = crc32c::crc32c_raw(crc, &[0u8; 2]);
    crc = crc32c::crc32c_raw(crc, &inode_bytes[0x7E..0x82]);
    crc = crc32c::crc32c_raw(crc, &[0u8; 2]);
    crc = crc32c::crc32c_raw(crc, &inode_bytes[0x84..]);
    crc
}

/// Bitmap checksum (block bitmap or inode bitmap). The checksum is computed
/// over the raw bitmap data and stored in the corresponding GDT fields. This
/// helper just computes the raw CRC; the caller reads the bitmap from disk.
///
/// For now we compute it over an in-memory representation of the bitmap. The
/// `_block_addr` and `_bitmap_size` arguments are unused but kept for future
/// reference.
fn bitmap_checksum(csum_seed: u32, bitmap: &[u8], checksum_len: usize) -> u32 {
    crc32c::crc32c_raw(csum_seed, &bitmap[..checksum_len])
}

/// Directory block checksum.
fn dir_block_checksum(csum_seed: u32, inum: u32, generation: u32, data: &[u8]) -> u32 {
    let mut crc = crc32c::crc32c_raw(csum_seed, &inum.to_le_bytes());
    crc = crc32c::crc32c_raw(crc, &generation.to_le_bytes());
    crc = crc32c::crc32c_raw(crc, data);
    crc
}

//--------------------------------------------------------------------------------------------------
// Functions: Byte helpers
//--------------------------------------------------------------------------------------------------

fn put_le16(buf: &mut [u8], off: usize, val: u16) {
    buf[off..off + 2].copy_from_slice(&val.to_le_bytes());
}

fn put_le32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_le_bytes());
}

fn put_be32(buf: &mut [u8], off: usize, val: u32) {
    buf[off..off + 4].copy_from_slice(&val.to_be_bytes());
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use format::sparse_super_group;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_creates_file_of_correct_size() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.ext4");

        let size: u64 = 256 * 1024 * 1024; // 256 MiB
        let opts = Ext4FormatOptions {
            size_bytes: size,
            journal_blocks: 4096, // 16 MiB journal
        };

        format_ext4(&path, &opts).unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), size);
    }

    #[test]
    fn test_format_too_small() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("tiny.ext4");

        let opts = Ext4FormatOptions {
            size_bytes: 4096, // way too small
            journal_blocks: 16384,
        };

        let result = format_ext4(&path, &opts);
        assert!(matches!(result, Err(Ext4Error::TooSmall)));
    }

    #[test]
    fn test_format_default_options() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("default.ext4");

        let opts = Ext4FormatOptions::default();
        format_ext4(&path, &opts).unwrap();

        let meta = std::fs::metadata(&path).unwrap();
        assert_eq!(meta.len(), DEFAULT_SIZE_BYTES);
    }

    #[test]
    fn test_superblock_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("magic.ext4");

        let opts = Ext4FormatOptions {
            size_bytes: 256 * 1024 * 1024,
            journal_blocks: 4096,
        };
        format_ext4(&path, &opts).unwrap();

        // Read back and check magic number at offset 1024+0x38
        let data = std::fs::read(&path).unwrap();
        let magic = u16::from_le_bytes([data[1024 + 0x38], data[1024 + 0x39]]);
        assert_eq!(magic, EXT4_SUPER_MAGIC);
    }

    #[test]
    fn test_journal_magic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal.ext4");

        let opts = Ext4FormatOptions {
            size_bytes: 256 * 1024 * 1024,
            journal_blocks: 4096,
        };
        format_ext4(&path, &opts).unwrap();

        let layout = Layout::compute(&opts).unwrap();
        let data = std::fs::read(&path).unwrap();

        // Journal superblock is at journal_start_block * 4096
        let jsb_offset = layout.journal_start_block as usize * EXT4_BLOCK_SIZE as usize;
        let magic = u32::from_be_bytes([
            data[jsb_offset],
            data[jsb_offset + 1],
            data[jsb_offset + 2],
            data[jsb_offset + 3],
        ]);
        assert_eq!(magic, JBD2_MAGIC);
    }

    #[test]
    fn test_root_dir_inode_exists() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rootdir.ext4");

        let opts = Ext4FormatOptions {
            size_bytes: 256 * 1024 * 1024,
            journal_blocks: 4096,
        };
        format_ext4(&path, &opts).unwrap();

        let layout = Layout::compute(&opts).unwrap();
        let data = std::fs::read(&path).unwrap();

        // Root inode at inode_table_block * 4096 + (2-1)*256
        let inode_offset = layout.inode_table_block as usize * EXT4_BLOCK_SIZE as usize
            + 1 * EXT4_INODE_SIZE as usize;
        let mode = u16::from_le_bytes([data[inode_offset], data[inode_offset + 1]]);
        assert_eq!(mode, S_IFDIR | 0o755);
    }

    #[test]
    fn test_backup_group_bitmap_starts_after_backup_metadata() {
        let opts = Ext4FormatOptions {
            size_bytes: 256 * 1024 * 1024,
            journal_blocks: 4096,
        };
        let layout = Layout::compute(&opts).unwrap();
        let block_bitmaps = build_block_bitmaps(&layout);
        let inode_bitmaps = build_inode_bitmaps(&layout);
        let gdt = build_gdt(&layout, &block_bitmaps, &inode_bitmaps).unwrap();

        let desc = &gdt[EXT4_DESC_SIZE as usize..(2 * EXT4_DESC_SIZE as usize)];
        let block_bitmap = u32::from_le_bytes([desc[0], desc[1], desc[2], desc[3]]);
        let group_start = layout.group_start_block(1);

        assert_eq!(block_bitmap, layout.group_block_bitmap_block(1));
        assert!(block_bitmap > group_start + layout.gdt_blocks - 1);
    }

    #[test]
    fn test_inode_bitmap_padding_is_marked_used() {
        let layout = Layout::compute(&Ext4FormatOptions {
            size_bytes: 256 * 1024 * 1024,
            journal_blocks: 4096,
        })
        .unwrap();

        let bitmap = build_inode_bitmap(&layout, 0);
        for bit in EXT4_INODES_PER_GROUP..(EXT4_BLOCK_SIZE * 8) {
            assert_ne!(bitmap[(bit / 8) as usize] & (1 << (bit % 8)), 0);
        }
    }

    #[test]
    fn test_journal_superblock_checksum_matches_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("journal-csum.ext4");
        let opts = Ext4FormatOptions {
            size_bytes: 256 * 1024 * 1024,
            journal_blocks: 4096,
        };

        format_ext4(&path, &opts).unwrap();

        let layout = Layout::compute(&opts).unwrap();
        let data = std::fs::read(&path).unwrap();
        let offset = layout.journal_start_block as usize * EXT4_BLOCK_SIZE as usize;
        let mut jsb = data[offset..offset + JBD2_SUPERBLOCK_SIZE].to_vec();
        let stored = u32::from_be_bytes([jsb[0xFC], jsb[0xFD], jsb[0xFE], jsb[0xFF]]);

        jsb[0xFC..0x100].fill(0);
        let expected = crc32c::crc32c_raw(0xFFFF_FFFF, &jsb);

        assert_eq!(stored, expected);
    }

    #[test]
    fn test_root_dir_checksum_matches_contents() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("rootdir-csum.ext4");
        let opts = Ext4FormatOptions {
            size_bytes: 256 * 1024 * 1024,
            journal_blocks: 4096,
        };

        format_ext4(&path, &opts).unwrap();

        let layout = Layout::compute(&opts).unwrap();
        let data = std::fs::read(&path).unwrap();
        let sb = &data[1024..2048];
        let uuid = &sb[0x68..0x78];
        let csum_seed = crc32c::crc32c_raw(0xFFFF_FFFF, uuid);
        let block_offset = layout.first_data_block as usize * EXT4_BLOCK_SIZE as usize;
        let tail_offset = block_offset + EXT4_BLOCK_SIZE as usize - 12;
        let stored = u32::from_le_bytes([
            data[tail_offset + 8],
            data[tail_offset + 9],
            data[tail_offset + 10],
            data[tail_offset + 11],
        ]);
        let expected = dir_block_checksum(
            csum_seed,
            EXT4_ROOT_INO,
            0,
            &data[block_offset..tail_offset],
        );

        assert_eq!(stored, expected);
    }
}
