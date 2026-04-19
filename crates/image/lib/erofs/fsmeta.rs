//! EROFS fsmeta writer — metadata-only image for fsmerge.
//!
//! Produces an EROFS image where regular file inodes use chunk-based layout
//! (EROFS_INODE_CHUNK_BASED) referencing data in external layer blobs via
//! device table entries. Directories and symlinks use standard flat layout.

use std::collections::{BTreeMap, HashMap};
use std::ffi::OsString;
use std::io::{BufWriter, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use crate::crc32c;
use crate::filetree::{DirectoryNode, FileTree, InodeMetadata, TreeNode, Xattr};

use super::format::{
    self, EROFS_BLKSIZ, EROFS_BLKSIZ_BITS, EROFS_CHUNK_FORMAT_INDEXES, EROFS_CHUNK_INDEX_SIZE,
    EROFS_DEVICE_SLOT_SIZE, EROFS_DIRENT_SIZE, EROFS_FEATURE_COMPAT_SB_CHKSUM,
    EROFS_FEATURE_INCOMPAT_CHUNKED_FILE, EROFS_FEATURE_INCOMPAT_DEVICE_TABLE,
    EROFS_INODE_CHUNK_BASED, EROFS_INODE_EXTENDED_SIZE, EROFS_INODE_FLAT_INLINE,
    EROFS_INODE_FLAT_PLAIN, EROFS_ISLOT_SIZE, EROFS_NULL_ADDR, EROFS_SUPER_MAGIC,
    EROFS_SUPER_OFFSET, EROFS_SUPERBLOCK_SIZE, EROFS_XATTR_IBODY_HEADER_SIZE, dirent_file_type,
    erofs_xattr_align, mode_type_bits, new_encode_dev, xattr_prefix_index,
};
use super::writer::ErofsDataMap;
use super::writer::ErofsError;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

static ZEROS: [u8; 4096] = [0u8; 4096];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct FsmetaInodePlan {
    nid: u32,
    data_layout: u8,
    data_block_start: u32,
    data_block_count: u32,
    inline_tail_size: u32,
    xattr_ibody_size: u32,
    #[allow(dead_code)]
    total_inode_size: u32,
    #[allow(dead_code)]
    slots: u32,
    dir_data: Option<Vec<u8>>,
    parent_nid: u32,
    /// For chunk-based regular files: number of chunks.
    chunk_count: u32,
}

struct FsmetaLayoutState {
    plans: Vec<FsmetaInodePlan>,
    current_meta_offset: u64,
    /// Only used for directory data blocks (fsmeta has no file data blocks).
    current_data_block: u32,
    meta_blkaddr: u32,
    root_nid: u32,
    inode_count: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FsmetaLayoutState {
    fn new(meta_blkaddr: u32) -> Self {
        Self {
            plans: Vec::new(),
            current_meta_offset: meta_blkaddr as u64 * EROFS_BLKSIZ as u64,
            current_data_block: 0,
            meta_blkaddr,
            root_nid: 0,
            inode_count: 0,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Write an fsmeta EROFS image for fsmerge.
///
/// The output contains only metadata (superblock, device table, inodes with
/// chunk indexes). All file data is referenced by device ID and block address
/// into the layer blobs.
pub fn write_fsmeta(
    merged_tree: &FileTree,
    provenance: &HashMap<PathBuf, usize>,
    layer_maps: &[ErofsDataMap],
    output: &Path,
) -> Result<(), ErofsError> {
    // Iterative convergence: fsmeta_blocks depends on metadata size which depends
    // on mapped_blkaddr which depends on fsmeta_blocks. Start with an estimate.
    let num_devices = layer_maps.len();

    // Device table starts right after superblock block.
    // Superblock is in block 0 (1024 offset + 128 bytes). Device table follows.
    // We place device table immediately after the superblock at a 128-byte aligned
    // offset within the metadata area.
    //
    // Layout: [block 0: superblock] [device table] [metadata area] [dir data blocks]
    //
    // The device table lives at devt_slotoff * 128 from the start of the image.
    // We put it right after the superblock block in block 1 area.
    let devt_slotoff = (EROFS_SUPER_OFFSET as u32 + EROFS_SUPERBLOCK_SIZE) / EROFS_DEVICE_SLOT_SIZE;
    let devt_byte_offset = devt_slotoff as u64 * EROFS_DEVICE_SLOT_SIZE as u64;
    let devt_size = num_devices as u64 * EROFS_DEVICE_SLOT_SIZE as u64;
    let meta_start_byte = align_up(devt_byte_offset + devt_size, EROFS_BLKSIZ as u64);
    let meta_blkaddr = (meta_start_byte / EROFS_BLKSIZ as u64) as u32;

    // Estimate fsmeta_blocks (iterate to converge).
    let mut fsmeta_blocks: u32 = meta_blkaddr + 1; // initial guess

    for _iteration in 0..4 {
        let mut state = FsmetaLayoutState::new(meta_blkaddr);
        plan_fsmeta_directory(
            &merged_tree.root,
            0,
            &mut state,
            true,
            provenance,
            layer_maps,
            &PathBuf::new(),
        )?;
        state.root_nid = state.plans[0].nid;

        // Compute actual fsmeta_blocks: metadata + directory data blocks.
        let meta_end = align_up(state.current_meta_offset, EROFS_BLKSIZ as u64);
        let data_start_block = (meta_end / EROFS_BLKSIZ as u64) as u32;
        let computed_blocks = data_start_block + state.current_data_block;

        if computed_blocks == fsmeta_blocks {
            // Converged — write the image.
            return write_fsmeta_image(
                output,
                &state,
                merged_tree,
                provenance,
                layer_maps,
                fsmeta_blocks,
                num_devices,
                devt_slotoff,
                meta_blkaddr,
            );
        }
        fsmeta_blocks = computed_blocks;
    }

    // Final pass with the last estimate.
    let mut state = FsmetaLayoutState::new(meta_blkaddr);
    plan_fsmeta_directory(
        &merged_tree.root,
        0,
        &mut state,
        true,
        provenance,
        layer_maps,
        &PathBuf::new(),
    )?;
    state.root_nid = state.plans[0].nid;

    write_fsmeta_image(
        output,
        &state,
        merged_tree,
        provenance,
        layer_maps,
        fsmeta_blocks,
        num_devices,
        devt_slotoff,
        meta_blkaddr,
    )
}

#[allow(clippy::too_many_arguments)]
fn write_fsmeta_image(
    output: &Path,
    state: &FsmetaLayoutState,
    merged_tree: &FileTree,
    provenance: &HashMap<PathBuf, usize>,
    layer_maps: &[ErofsDataMap],
    fsmeta_blocks: u32,
    num_devices: usize,
    devt_slotoff: u32,
    _meta_blkaddr: u32,
) -> Result<(), ErofsError> {
    let mut file = BufWriter::new(std::fs::File::create(output)?);

    // Phase 1: Write device table.
    write_device_table(&mut file, layer_maps, fsmeta_blocks, devt_slotoff)?;

    // Phase 2: Write directory data blocks.
    let meta_end = align_up(state.current_meta_offset, EROFS_BLKSIZ as u64);
    let data_start_block = (meta_end / EROFS_BLKSIZ as u64) as u32;
    write_fsmeta_dir_data(
        &mut file,
        state,
        &merged_tree.root,
        data_start_block,
        &mut 0,
    )?;

    // Phase 3: Write metadata (inodes + chunk indexes).
    write_fsmeta_metadata(
        &mut file,
        state,
        merged_tree,
        provenance,
        layer_maps,
        data_start_block,
    )?;

    // Phase 4: Write superblock.
    write_fsmeta_superblock(
        &mut file,
        state,
        fsmeta_blocks,
        num_devices,
        devt_slotoff,
        layer_maps,
    )?;

    // Pad to block + sector alignment.
    file.flush()?;
    let current_len = file.seek(SeekFrom::End(0))?;
    let block_aligned = align_up(current_len, EROFS_BLKSIZ as u64);
    let target_len = align_up(block_aligned, 512);

    if target_len > current_len {
        file.seek(SeekFrom::Start(target_len - 1))?;
        file.write_all(&[0u8])?;
        file.flush()?;
    }

    Ok(())
}

fn write_device_table(
    file: &mut (impl Write + Seek),
    layer_maps: &[ErofsDataMap],
    fsmeta_blocks: u32,
    devt_slotoff: u32,
) -> Result<(), ErofsError> {
    let devt_offset = devt_slotoff as u64 * EROFS_DEVICE_SLOT_SIZE as u64;
    file.seek(SeekFrom::Start(devt_offset))?;

    let mut cumulative_blocks: u32 = fsmeta_blocks;
    for map in layer_maps {
        let mut slot = [0u8; EROFS_DEVICE_SLOT_SIZE as usize];
        // tag[64] — leave zeros
        // blocks: u32 at offset 0x40
        slot[0x40..0x44].copy_from_slice(&map.total_blocks.to_le_bytes());
        // mapped_blkaddr: u32 at offset 0x44
        slot[0x44..0x48].copy_from_slice(&cumulative_blocks.to_le_bytes());
        // reserved[56] — zeros
        file.write_all(&slot)?;
        cumulative_blocks += map.total_blocks;
    }

    Ok(())
}

/// Plan layout for a directory in the fsmeta tree.
fn plan_fsmeta_directory(
    dir: &DirectoryNode,
    parent_nid: u32,
    state: &mut FsmetaLayoutState,
    is_root: bool,
    provenance: &HashMap<PathBuf, usize>,
    layer_maps: &[ErofsDataMap],
    current_path: &Path,
) -> Result<u32, ErofsError> {
    let blksiz = EROFS_BLKSIZ as u64;

    let dir_plan_idx = state.plans.len();
    state.plans.push(FsmetaInodePlan {
        nid: 0,
        data_layout: 0,
        data_block_start: 0,
        data_block_count: 0,
        inline_tail_size: 0,
        xattr_ibody_size: 0,
        total_inode_size: 0,
        slots: 0,
        dir_data: None,
        parent_nid,
        chunk_count: 0,
    });
    state.inode_count += 1;

    let xattr_ibody_size = compute_xattr_ibody_size(&dir.xattrs)?;
    let dir_data_size = compute_dir_data_size(dir) as u64;
    let inode_fixed_size = EROFS_INODE_EXTENDED_SIZE + xattr_ibody_size;

    // Assign NID for this directory.
    let meta_base = state.meta_blkaddr as u64 * blksiz;
    let nid_offset = state.current_meta_offset - meta_base;
    let aligned_offset = nid_offset.div_ceil(EROFS_ISLOT_SIZE as u64) * EROFS_ISLOT_SIZE as u64;
    state.current_meta_offset = meta_base + aligned_offset;
    let nid = (aligned_offset / EROFS_ISLOT_SIZE as u64) as u32;

    // Directory data uses standard flat layout (same as per-layer writer).
    let d = decide_data_layout(
        dir_data_size,
        inode_fixed_size,
        state.current_meta_offset,
        &mut state.current_data_block,
    );

    let total_inode_size = inode_fixed_size + d.inline_tail_size;
    let slots = total_inode_size.div_ceil(EROFS_ISLOT_SIZE);
    state.current_meta_offset += (slots * EROFS_ISLOT_SIZE) as u64;

    state.plans[dir_plan_idx] = FsmetaInodePlan {
        nid,
        data_layout: d.layout,
        data_block_start: d.block_start,
        data_block_count: d.block_count,
        inline_tail_size: d.inline_tail_size,
        xattr_ibody_size,
        total_inode_size,
        slots,
        dir_data: None,
        parent_nid: if is_root { nid } else { parent_nid },
        chunk_count: 0,
    };

    let dir_nid = nid;

    // Plan children (depth-first).
    let mut child_nids: BTreeMap<OsString, u32> = BTreeMap::new();
    for (name, child) in &dir.entries {
        let child_path = current_path.join(name);
        let child_nid = match child {
            TreeNode::Directory(child_dir) => plan_fsmeta_directory(
                child_dir,
                dir_nid,
                state,
                false,
                provenance,
                layer_maps,
                &child_path,
            )?,
            TreeNode::RegularFile(_) => {
                plan_fsmeta_regular_file(child, state, provenance, layer_maps, &child_path)?
            }
            _ => plan_fsmeta_leaf_node(child, state)?,
        };
        child_nids.insert(name.clone(), child_nid);
    }

    // Serialize directory data with real NIDs.
    let dir_data = serialize_dir_blocks(
        dir,
        dir_nid,
        state.plans[dir_plan_idx].parent_nid,
        &child_nids,
    )?;
    state.plans[dir_plan_idx].dir_data = Some(dir_data);

    Ok(dir_nid)
}

/// Plan layout for a chunk-based regular file in fsmeta.
fn plan_fsmeta_regular_file(
    node: &TreeNode,
    state: &mut FsmetaLayoutState,
    provenance: &HashMap<PathBuf, usize>,
    layer_maps: &[ErofsDataMap],
    file_path: &Path,
) -> Result<u32, ErofsError> {
    let blksiz = EROFS_BLKSIZ as u64;

    let plan_idx = state.plans.len();
    state.plans.push(FsmetaInodePlan {
        nid: 0,
        data_layout: 0,
        data_block_start: 0,
        data_block_count: 0,
        inline_tail_size: 0,
        xattr_ibody_size: 0,
        total_inode_size: 0,
        slots: 0,
        dir_data: None,
        parent_nid: 0,
        chunk_count: 0,
    });
    state.inode_count += 1;

    let xattrs = node_xattrs(node);
    let xattr_ibody_size = compute_xattr_ibody_size(xattrs)?;

    // File size comes from the layer data map, not from the (stripped) tree
    // node — strip_file_data() zeroes all in-memory data before merge.
    let file_size = provenance
        .get(file_path)
        .and_then(|&layer_idx| layer_maps[layer_idx].file_blocks.get(file_path))
        .map(|&(_, size)| size)
        .unwrap_or(0);

    // Compute chunk count.
    let chunk_count = if file_size == 0 {
        0u32
    } else {
        file_size.div_ceil(blksiz) as u32
    };

    // Chunk index size: each chunk is 8 bytes.
    let chunk_index_size = chunk_count * EROFS_CHUNK_INDEX_SIZE;

    // Total inode = 64 (extended inode) + xattr ibody + chunk index (aligned to 32-byte slots).
    let inode_fixed_size = EROFS_INODE_EXTENDED_SIZE + xattr_ibody_size + chunk_index_size;

    // Assign NID.
    let meta_base = state.meta_blkaddr as u64 * blksiz;
    let nid_offset = state.current_meta_offset - meta_base;
    let aligned_offset = nid_offset.div_ceil(EROFS_ISLOT_SIZE as u64) * EROFS_ISLOT_SIZE as u64;
    state.current_meta_offset = meta_base + aligned_offset;
    let nid = (aligned_offset / EROFS_ISLOT_SIZE as u64) as u32;

    let slots = inode_fixed_size.div_ceil(EROFS_ISLOT_SIZE);
    state.current_meta_offset += (slots * EROFS_ISLOT_SIZE) as u64;

    state.plans[plan_idx] = FsmetaInodePlan {
        nid,
        data_layout: EROFS_INODE_CHUNK_BASED,
        data_block_start: EROFS_NULL_ADDR,
        data_block_count: 0,
        inline_tail_size: 0,
        xattr_ibody_size,
        total_inode_size: inode_fixed_size,
        slots,
        dir_data: None,
        parent_nid: 0,
        chunk_count,
    };

    Ok(nid)
}

/// Plan layout for a non-file, non-directory leaf node (symlink, device, fifo, socket).
fn plan_fsmeta_leaf_node(
    node: &TreeNode,
    state: &mut FsmetaLayoutState,
) -> Result<u32, ErofsError> {
    let blksiz = EROFS_BLKSIZ as u64;

    let plan_idx = state.plans.len();
    state.plans.push(FsmetaInodePlan {
        nid: 0,
        data_layout: 0,
        data_block_start: 0,
        data_block_count: 0,
        inline_tail_size: 0,
        xattr_ibody_size: 0,
        total_inode_size: 0,
        slots: 0,
        dir_data: None,
        parent_nid: 0,
        chunk_count: 0,
    });
    state.inode_count += 1;

    let xattrs = node_xattrs(node);
    let xattr_ibody_size = compute_xattr_ibody_size(xattrs)?;
    let data_size = node_data_size(node);
    let inode_fixed_size = EROFS_INODE_EXTENDED_SIZE + xattr_ibody_size;

    let meta_base = state.meta_blkaddr as u64 * blksiz;
    let nid_offset = state.current_meta_offset - meta_base;
    let aligned_offset = nid_offset.div_ceil(EROFS_ISLOT_SIZE as u64) * EROFS_ISLOT_SIZE as u64;
    state.current_meta_offset = meta_base + aligned_offset;
    let nid = (aligned_offset / EROFS_ISLOT_SIZE as u64) as u32;

    let d = decide_data_layout(
        data_size,
        inode_fixed_size,
        state.current_meta_offset,
        &mut state.current_data_block,
    );

    let total_inode_size = inode_fixed_size + d.inline_tail_size;
    let slots = total_inode_size.div_ceil(EROFS_ISLOT_SIZE);
    state.current_meta_offset += (slots * EROFS_ISLOT_SIZE) as u64;

    state.plans[plan_idx] = FsmetaInodePlan {
        nid,
        data_layout: d.layout,
        data_block_start: d.block_start,
        data_block_count: d.block_count,
        inline_tail_size: d.inline_tail_size,
        xattr_ibody_size,
        total_inode_size,
        slots,
        dir_data: None,
        parent_nid: 0,
        chunk_count: 0,
    };

    Ok(nid)
}

/// Write fsmeta data blocks for directories and non-inline symlinks.
fn write_fsmeta_dir_data(
    file: &mut (impl Write + Seek),
    state: &FsmetaLayoutState,
    dir: &DirectoryNode,
    data_start_block: u32,
    plan_idx: &mut usize,
) -> Result<(), ErofsError> {
    let blksiz = EROFS_BLKSIZ as u64;
    let plan = &state.plans[*plan_idx];
    *plan_idx += 1;

    if let Some(ref dir_data) = plan.dir_data
        && plan.data_block_count > 0
    {
        let abs_block = data_start_block + plan.data_block_start;
        let offset = abs_block as u64 * blksiz;
        file.seek(SeekFrom::Start(offset))?;

        let full_block_bytes = plan.data_block_count as usize * EROFS_BLKSIZ as usize;
        let data_to_write = &dir_data[..std::cmp::min(full_block_bytes, dir_data.len())];
        file.write_all(data_to_write)?;

        if data_to_write.len() < full_block_bytes {
            let pad = full_block_bytes - data_to_write.len();
            file.write_all(&ZEROS[..pad])?;
        }
    }

    for child in dir.entries.values() {
        match child {
            TreeNode::Directory(child_dir) => {
                write_fsmeta_dir_data(file, state, child_dir, data_start_block, plan_idx)?;
            }
            TreeNode::Symlink(s) => {
                let child_plan = &state.plans[*plan_idx];
                *plan_idx += 1;

                if child_plan.data_block_count > 0 {
                    let abs_block = data_start_block + child_plan.data_block_start;
                    let offset = abs_block as u64 * blksiz;
                    file.seek(SeekFrom::Start(offset))?;

                    let full_block_bytes =
                        child_plan.data_block_count as usize * EROFS_BLKSIZ as usize;
                    let data_to_write =
                        &s.target[..std::cmp::min(full_block_bytes, s.target.len())];
                    file.write_all(data_to_write)?;

                    if child_plan.data_layout == EROFS_INODE_FLAT_PLAIN
                        && data_to_write.len() < full_block_bytes
                    {
                        let pad = full_block_bytes - data_to_write.len();
                        file.write_all(&ZEROS[..pad])?;
                    }
                }
            }
            _ => {
                // All remaining leaf types have no fsmeta data blocks.
                *plan_idx += 1;
            }
        }
    }

    Ok(())
}

/// Write metadata for the fsmeta tree.
fn write_fsmeta_metadata(
    file: &mut (impl Write + Seek),
    state: &FsmetaLayoutState,
    merged_tree: &FileTree,
    provenance: &HashMap<PathBuf, usize>,
    layer_maps: &[ErofsDataMap],
    data_start_block: u32,
) -> Result<(), ErofsError> {
    write_fsmeta_inode(
        file,
        state,
        &TreeNode::Directory(clone_dir_shell(&merged_tree.root)),
        &merged_tree.root,
        provenance,
        layer_maps,
        data_start_block,
        &mut 0,
        &PathBuf::new(),
    )
}

#[allow(clippy::too_many_arguments)]
fn write_fsmeta_inode(
    file: &mut (impl Write + Seek),
    state: &FsmetaLayoutState,
    node: &TreeNode,
    real_dir: &DirectoryNode,
    provenance: &HashMap<PathBuf, usize>,
    layer_maps: &[ErofsDataMap],
    data_start_block: u32,
    plan_idx: &mut usize,
    current_path: &Path,
) -> Result<(), ErofsError> {
    let blksiz = EROFS_BLKSIZ as u64;
    let meta_base = state.meta_blkaddr as u64 * blksiz;
    let plan = &state.plans[*plan_idx];
    *plan_idx += 1;

    let inode_offset = meta_base + plan.nid as u64 * EROFS_ISLOT_SIZE as u64;
    file.seek(SeekFrom::Start(inode_offset))?;

    // Build 64-byte extended inode.
    let mut inode = [0u8; 64];

    let i_format: u16 = 1 | ((plan.data_layout as u16) << 1);
    inode[0..2].copy_from_slice(&i_format.to_le_bytes());

    let i_xattr_icount = compute_xattr_icount(plan.xattr_ibody_size);
    inode[2..4].copy_from_slice(&i_xattr_icount.to_le_bytes());

    let mode_bits = mode_type_bits(node);
    let meta = node_metadata(node);
    let i_mode = mode_bits | meta.mode;
    inode[4..6].copy_from_slice(&i_mode.to_le_bytes());

    // i_nb = 0
    inode[6..8].copy_from_slice(&0u16.to_le_bytes());

    // i_size — for regular files, the size comes from the layer data map
    // because strip_file_data() zeroes the in-memory data before merge.
    let i_size: u64 = match node {
        TreeNode::Directory(_) => {
            if let Some(ref dd) = plan.dir_data {
                dd.len() as u64
            } else {
                0
            }
        }
        TreeNode::RegularFile(_) => provenance
            .get(current_path)
            .and_then(|&layer_idx| layer_maps[layer_idx].file_blocks.get(current_path))
            .map(|&(_, size)| size)
            .unwrap_or(0),
        TreeNode::Symlink(s) => s.target.len() as u64,
        _ => 0,
    };
    inode[8..16].copy_from_slice(&i_size.to_le_bytes());

    // i_u: for chunk-based files this is chunk_info.format, for others it's startblk_lo/rdev.
    let i_u: u32 = match node {
        TreeNode::RegularFile(_) if plan.data_layout == EROFS_INODE_CHUNK_BASED => {
            // chunk_info.format: EROFS_CHUNK_FORMAT_INDEXES | log2(chunk_size / block_size)
            // chunk_size == block_size → additional_chunk_blkbits = 0
            EROFS_CHUNK_FORMAT_INDEXES as u32
        }
        TreeNode::CharDevice(d) | TreeNode::BlockDevice(d) => new_encode_dev(d.major, d.minor),
        TreeNode::Fifo(_) | TreeNode::Socket(_) => 0,
        _ => {
            if plan.data_block_start == EROFS_NULL_ADDR {
                EROFS_NULL_ADDR
            } else {
                data_start_block + plan.data_block_start
            }
        }
    };
    inode[16..20].copy_from_slice(&i_u.to_le_bytes());

    inode[20..24].copy_from_slice(&plan.nid.to_le_bytes());
    inode[24..28].copy_from_slice(&meta.uid.to_le_bytes());
    inode[28..32].copy_from_slice(&meta.gid.to_le_bytes());
    inode[32..40].copy_from_slice(&meta.mtime.to_le_bytes());
    inode[40..44].copy_from_slice(&meta.mtime_nsec.to_le_bytes());

    let nlink = node_nlink(node);
    inode[44..48].copy_from_slice(&nlink.to_le_bytes());

    file.write_all(&inode)?;

    // Write xattr ibody.
    let xattrs = node_xattrs(node);
    if plan.xattr_ibody_size > 0 {
        write_xattr_ibody(file, xattrs)?;
    }

    // For chunk-based regular files: write chunk index array.
    if plan.data_layout == EROFS_INODE_CHUNK_BASED
        && plan.chunk_count > 0
        && let TreeNode::RegularFile(_) = node
    {
        write_chunk_indexes(file, current_path, provenance, layer_maps, plan.chunk_count)?;
    }

    // For non-chunk inodes: write inline tail data.
    if plan.data_layout != EROFS_INODE_CHUNK_BASED && plan.inline_tail_size > 0 {
        match node {
            TreeNode::Directory(_) => {
                if let Some(ref dir_data) = plan.dir_data {
                    let full_block_bytes = plan.data_block_count as usize * EROFS_BLKSIZ as usize;
                    let tail = &dir_data[full_block_bytes..];
                    file.write_all(tail)?;
                }
            }
            TreeNode::Symlink(s) => {
                let full_block_bytes = plan.data_block_count as usize * EROFS_BLKSIZ as usize;
                let tail = &s.target[full_block_bytes..];
                file.write_all(tail)?;
            }
            _ => {}
        }
    }

    // Recurse into children for directories.
    if let TreeNode::Directory(_) = node {
        for (name, child) in &real_dir.entries {
            let child_path = current_path.join(name);
            match child {
                TreeNode::Directory(child_dir) => {
                    write_fsmeta_inode(
                        file,
                        state,
                        child,
                        child_dir,
                        provenance,
                        layer_maps,
                        data_start_block,
                        plan_idx,
                        &child_path,
                    )?;
                }
                _ => {
                    write_fsmeta_leaf(
                        file,
                        state,
                        child,
                        provenance,
                        layer_maps,
                        data_start_block,
                        plan_idx,
                        &child_path,
                    )?;
                }
            }
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_fsmeta_leaf(
    file: &mut (impl Write + Seek),
    state: &FsmetaLayoutState,
    node: &TreeNode,
    provenance: &HashMap<PathBuf, usize>,
    layer_maps: &[ErofsDataMap],
    data_start_block: u32,
    plan_idx: &mut usize,
    current_path: &Path,
) -> Result<(), ErofsError> {
    let blksiz = EROFS_BLKSIZ as u64;
    let meta_base = state.meta_blkaddr as u64 * blksiz;
    let plan = &state.plans[*plan_idx];
    *plan_idx += 1;

    let inode_offset = meta_base + plan.nid as u64 * EROFS_ISLOT_SIZE as u64;
    file.seek(SeekFrom::Start(inode_offset))?;

    let mut inode = [0u8; 64];

    let i_format: u16 = 1 | ((plan.data_layout as u16) << 1);
    inode[0..2].copy_from_slice(&i_format.to_le_bytes());

    let i_xattr_icount = compute_xattr_icount(plan.xattr_ibody_size);
    inode[2..4].copy_from_slice(&i_xattr_icount.to_le_bytes());

    let mode_bits = mode_type_bits(node);
    let meta = node_metadata(node);
    let i_mode = mode_bits | meta.mode;
    inode[4..6].copy_from_slice(&i_mode.to_le_bytes());

    inode[6..8].copy_from_slice(&0u16.to_le_bytes());

    // i_size — regular file sizes come from the layer data map; the tree
    // data was stripped before merge so f.data.len() is always zero here.
    let i_size: u64 = match node {
        TreeNode::RegularFile(_) => provenance
            .get(current_path)
            .and_then(|&layer_idx| layer_maps[layer_idx].file_blocks.get(current_path))
            .map(|&(_, size)| size)
            .unwrap_or(0),
        _ => node_data_size(node),
    };
    inode[8..16].copy_from_slice(&i_size.to_le_bytes());

    let i_u: u32 = match node {
        TreeNode::RegularFile(_) if plan.data_layout == EROFS_INODE_CHUNK_BASED => {
            EROFS_CHUNK_FORMAT_INDEXES as u32
        }
        TreeNode::CharDevice(d) | TreeNode::BlockDevice(d) => new_encode_dev(d.major, d.minor),
        TreeNode::Fifo(_) | TreeNode::Socket(_) => 0,
        _ => {
            if plan.data_block_start == EROFS_NULL_ADDR {
                EROFS_NULL_ADDR
            } else {
                data_start_block + plan.data_block_start
            }
        }
    };
    inode[16..20].copy_from_slice(&i_u.to_le_bytes());

    inode[20..24].copy_from_slice(&plan.nid.to_le_bytes());
    inode[24..28].copy_from_slice(&meta.uid.to_le_bytes());
    inode[28..32].copy_from_slice(&meta.gid.to_le_bytes());
    inode[32..40].copy_from_slice(&meta.mtime.to_le_bytes());
    inode[40..44].copy_from_slice(&meta.mtime_nsec.to_le_bytes());

    let nlink = node_nlink(node);
    inode[44..48].copy_from_slice(&nlink.to_le_bytes());

    file.write_all(&inode)?;

    let xattrs = node_xattrs(node);
    if plan.xattr_ibody_size > 0 {
        write_xattr_ibody(file, xattrs)?;
    }

    // For chunk-based regular files: write chunk index array.
    if plan.data_layout == EROFS_INODE_CHUNK_BASED && plan.chunk_count > 0 {
        write_chunk_indexes(file, current_path, provenance, layer_maps, plan.chunk_count)?;
    }

    // For non-chunk inodes with inline tail.
    if plan.data_layout != EROFS_INODE_CHUNK_BASED
        && plan.inline_tail_size > 0
        && let TreeNode::Symlink(s) = node
    {
        let full_block_bytes = plan.data_block_count as usize * EROFS_BLKSIZ as usize;
        let tail = &s.target[full_block_bytes..];
        file.write_all(tail)?;
    }

    Ok(())
}

/// Write chunk index entries for a regular file.
fn write_chunk_indexes(
    file: &mut (impl Write + Seek),
    file_path: &Path,
    provenance: &HashMap<PathBuf, usize>,
    layer_maps: &[ErofsDataMap],
    chunk_count: u32,
) -> Result<(), ErofsError> {
    let source_layer = provenance.get(file_path).copied();

    for chunk_idx in 0..chunk_count {
        let mut entry = [0u8; EROFS_CHUNK_INDEX_SIZE as usize];

        if let Some(layer_idx) = source_layer {
            let device_id = (layer_idx + 1) as u16; // 1-based
            if let Some(&(start_block, _size)) = layer_maps[layer_idx].file_blocks.get(file_path) {
                if start_block == EROFS_NULL_ADDR {
                    // Empty file in layer — should not happen with chunk_count > 0.
                    entry[2..4].copy_from_slice(&0u16.to_le_bytes()); // device_id = 0
                    entry[4..8].copy_from_slice(&EROFS_NULL_ADDR.to_le_bytes());
                } else {
                    // advise: u16 = 0
                    entry[2..4].copy_from_slice(&device_id.to_le_bytes());
                    let blkaddr = start_block + chunk_idx;
                    entry[4..8].copy_from_slice(&blkaddr.to_le_bytes());
                }
            } else {
                // File not found in layer data map — emit hole.
                entry[4..8].copy_from_slice(&EROFS_NULL_ADDR.to_le_bytes());
            }
        } else {
            // No provenance — emit hole.
            entry[4..8].copy_from_slice(&EROFS_NULL_ADDR.to_le_bytes());
        }

        file.write_all(&entry)?;
    }

    Ok(())
}

fn write_fsmeta_superblock(
    file: &mut (impl Write + Seek),
    state: &FsmetaLayoutState,
    fsmeta_blocks: u32,
    num_devices: usize,
    devt_slotoff: u32,
    layer_maps: &[ErofsDataMap],
) -> Result<(), ErofsError> {
    file.seek(SeekFrom::Start(0))?;
    file.write_all(&[0u8; EROFS_SUPER_OFFSET as usize])?;

    let mut sb = [0u8; EROFS_SUPERBLOCK_SIZE as usize];

    // magic
    sb[0x00..0x04].copy_from_slice(&EROFS_SUPER_MAGIC.to_le_bytes());

    // checksum (zeroed for now)
    sb[0x04..0x08].copy_from_slice(&0u32.to_le_bytes());

    // feature_compat (SB_CHKSUM)
    sb[0x08..0x0C].copy_from_slice(&EROFS_FEATURE_COMPAT_SB_CHKSUM.to_le_bytes());

    // blkszbits
    sb[0x0C] = EROFS_BLKSIZ_BITS;

    // sb_extslots = 0
    sb[0x0D] = 0;

    // rootnid_2b
    if state.root_nid > u16::MAX as u32 {
        return Err(ErofsError::NidOverflow);
    }
    sb[0x0E..0x10].copy_from_slice(&(state.root_nid as u16).to_le_bytes());

    // inos
    sb[0x10..0x18].copy_from_slice(&state.inode_count.to_le_bytes());

    // epoch = 0
    sb[0x18..0x20].copy_from_slice(&0u64.to_le_bytes());

    // fixed_nsec = 0
    sb[0x20..0x24].copy_from_slice(&0u32.to_le_bytes());

    // blocks_lo = fsmeta_blocks (metadata-only, no file data blocks)
    sb[0x24..0x28].copy_from_slice(&fsmeta_blocks.to_le_bytes());

    // meta_blkaddr
    sb[0x28..0x2C].copy_from_slice(&state.meta_blkaddr.to_le_bytes());

    // xattr_blkaddr = 0
    sb[0x2C..0x30].copy_from_slice(&0u32.to_le_bytes());

    // feature_incompat: CHUNKED_FILE | DEVICE_TABLE
    let feature_incompat =
        EROFS_FEATURE_INCOMPAT_CHUNKED_FILE | EROFS_FEATURE_INCOMPAT_DEVICE_TABLE;
    sb[0x50..0x54].copy_from_slice(&feature_incompat.to_le_bytes());

    // extra_devices: u16 at offset 0x56
    sb[0x56..0x58].copy_from_slice(&(num_devices as u16).to_le_bytes());

    // devt_slotoff: u16 at offset 0x58
    sb[0x58..0x5A].copy_from_slice(&(devt_slotoff as u16).to_le_bytes());

    // dirblkbits at offset 0x5A
    sb[0x5A] = 0;

    // Compute CRC32C over the full block 0 tail (bytes EROFS_SUPER_OFFSET..
    // EROFS_BLKSIZ) — the kernel reads the same region for verification.
    // This includes the superblock AND any device table entries that live
    // in block 0, so we must reconstruct the on-disk bytes here, not just
    // a zero-filled scratch buffer.
    let mut block = vec![0u8; EROFS_BLKSIZ as usize];
    block
        [EROFS_SUPER_OFFSET as usize..EROFS_SUPER_OFFSET as usize + EROFS_SUPERBLOCK_SIZE as usize]
        .copy_from_slice(&sb);

    let devt_byte_offset = devt_slotoff as usize * EROFS_DEVICE_SLOT_SIZE as usize;
    let mut cumulative_blocks: u32 = fsmeta_blocks;
    for (i, map) in layer_maps.iter().enumerate() {
        let slot_start = devt_byte_offset + i * EROFS_DEVICE_SLOT_SIZE as usize;
        if slot_start >= block.len() {
            break;
        }
        let slot_end = (slot_start + EROFS_DEVICE_SLOT_SIZE as usize).min(block.len());
        let mut slot = [0u8; EROFS_DEVICE_SLOT_SIZE as usize];
        slot[0x40..0x44].copy_from_slice(&map.total_blocks.to_le_bytes());
        slot[0x44..0x48].copy_from_slice(&cumulative_blocks.to_le_bytes());
        let copy_len = slot_end - slot_start;
        block[slot_start..slot_end].copy_from_slice(&slot[..copy_len]);
        cumulative_blocks = cumulative_blocks.wrapping_add(map.total_blocks);
    }

    let crc_data = &block[EROFS_SUPER_OFFSET as usize..EROFS_BLKSIZ as usize];
    let checksum = crc32c::crc32c_raw(0xFFFF_FFFF, crc_data);
    sb[0x04..0x08].copy_from_slice(&checksum.to_le_bytes());

    file.seek(SeekFrom::Start(EROFS_SUPER_OFFSET))?;
    file.write_all(&sb)?;

    // Do NOT pad the rest of block 0 with zeros — the device table lives
    // immediately after the superblock (starting at devt_slotoff * 128 = 1152)
    // and was already written by write_device_table(). Any bytes not covered
    // by the superblock, the device table, or metadata are already zero due
    // to the sparse file created by File::create.

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers (reuse from writer.rs patterns)
//--------------------------------------------------------------------------------------------------

fn align_up(value: u64, alignment: u64) -> u64 {
    value.div_ceil(alignment) * alignment
}

fn compute_xattr_ibody_size(xattrs: &[Xattr]) -> Result<u32, ErofsError> {
    if xattrs.is_empty() {
        return Ok(0);
    }
    let mut size = EROFS_XATTR_IBODY_HEADER_SIZE as usize;
    for xattr in xattrs {
        let (_, suffix) =
            xattr_prefix_index(&xattr.name).ok_or(ErofsError::UnsupportedXattrPrefix)?;
        let entry_size = 4 + suffix.len() + xattr.value.len();
        size += erofs_xattr_align(entry_size);
    }
    Ok(size as u32)
}

fn compute_xattr_icount(xattr_ibody_size: u32) -> u16 {
    if xattr_ibody_size == 0 {
        0
    } else {
        ((xattr_ibody_size - EROFS_XATTR_IBODY_HEADER_SIZE) / 4 + 1) as u16
    }
}

struct DataLayoutDecision {
    layout: u8,
    inline_tail_size: u32,
    block_count: u32,
    block_start: u32,
}

fn decide_data_layout(
    data_size: u64,
    inode_fixed_size: u32,
    meta_offset: u64,
    current_data_block: &mut u32,
) -> DataLayoutDecision {
    let blksiz = EROFS_BLKSIZ as u64;
    let tail_size = data_size % blksiz;
    let full_blocks = data_size / blksiz;

    if data_size == 0 {
        DataLayoutDecision {
            layout: EROFS_INODE_FLAT_PLAIN,
            inline_tail_size: 0,
            block_count: 0,
            block_start: EROFS_NULL_ADDR,
        }
    } else if tail_size == 0 {
        let start = *current_data_block;
        *current_data_block += full_blocks as u32;
        DataLayoutDecision {
            layout: EROFS_INODE_FLAT_PLAIN,
            inline_tail_size: 0,
            block_count: full_blocks as u32,
            block_start: start,
        }
    } else {
        let inode_pos_in_block = meta_offset % blksiz;
        let remaining_in_block = blksiz - inode_pos_in_block;
        let needed = inode_fixed_size as u64 + tail_size;

        if needed <= remaining_in_block {
            let start = if full_blocks > 0 {
                let s = *current_data_block;
                *current_data_block += full_blocks as u32;
                s
            } else {
                EROFS_NULL_ADDR
            };
            DataLayoutDecision {
                layout: EROFS_INODE_FLAT_INLINE,
                inline_tail_size: tail_size as u32,
                block_count: full_blocks as u32,
                block_start: start,
            }
        } else {
            let start = *current_data_block;
            *current_data_block += (full_blocks + 1) as u32;
            DataLayoutDecision {
                layout: EROFS_INODE_FLAT_PLAIN,
                inline_tail_size: 0,
                block_count: (full_blocks + 1) as u32,
                block_start: start,
            }
        }
    }
}

fn compute_dir_data_size(dir: &DirectoryNode) -> u32 {
    let entry_count = 2 + dir.entries.len();
    let mut names: Vec<&[u8]> = Vec::with_capacity(entry_count);
    names.push(b".");
    names.push(b"..");
    for name in dir.entries.keys() {
        names.push(name.as_bytes());
    }
    // EROFS requires dirents sorted by name in byte order.
    names.sort();

    let blksiz = EROFS_BLKSIZ as usize;
    let mut total_size = 0usize;
    let mut idx = 0;

    while idx < names.len() {
        let mut block_entries = 0;
        let mut name_area = 0usize;

        for name in &names[idx..] {
            let new_dirent_area = (block_entries + 1) * EROFS_DIRENT_SIZE as usize;
            let new_name_area = name_area + name.len();
            if new_dirent_area + new_name_area > blksiz {
                break;
            }
            name_area = new_name_area;
            block_entries += 1;
        }

        if block_entries == 0 {
            block_entries = 1;
            name_area = names[idx].len();
        }

        let dirent_area = block_entries * EROFS_DIRENT_SIZE as usize;
        let used = dirent_area + name_area;
        if idx + block_entries < names.len() {
            total_size += blksiz;
        } else {
            total_size += used;
        }
        idx += block_entries;
    }

    total_size as u32
}

fn serialize_dir_blocks(
    dir: &DirectoryNode,
    own_nid: u32,
    parent_nid: u32,
    child_nids: &BTreeMap<OsString, u32>,
) -> Result<Vec<u8>, ErofsError> {
    struct DirEntryInfo {
        name: Vec<u8>,
        nid: u64,
        file_type: u8,
    }

    let mut entries: Vec<DirEntryInfo> = Vec::new();
    entries.push(DirEntryInfo {
        name: b".".to_vec(),
        nid: own_nid as u64,
        file_type: format::EROFS_FT_DIR,
    });
    entries.push(DirEntryInfo {
        name: b"..".to_vec(),
        nid: parent_nid as u64,
        file_type: format::EROFS_FT_DIR,
    });

    for (name, child) in &dir.entries {
        let nid = *child_nids.get(name).expect("child NID not found") as u64;
        entries.push(DirEntryInfo {
            name: name.as_bytes().to_vec(),
            nid,
            file_type: dirent_file_type(child),
        });
    }

    // EROFS requires dirents sorted by name in byte order (memcmp).
    entries.sort_by(|a, b| a.name.cmp(&b.name));

    let blksiz = EROFS_BLKSIZ as usize;
    let mut result = Vec::new();
    let mut idx = 0;

    while idx < entries.len() {
        let mut block_entries = 0usize;
        let mut name_total = 0usize;

        for entry in &entries[idx..] {
            let new_dirent_area = (block_entries + 1) * EROFS_DIRENT_SIZE as usize;
            let new_name_total = name_total + entry.name.len();
            if new_dirent_area + new_name_total > blksiz {
                break;
            }
            name_total += entry.name.len();
            block_entries += 1;
        }

        if block_entries == 0 {
            block_entries = 1;
            name_total = entries[idx].name.len();
        }

        let dirent_area_size = block_entries * EROFS_DIRENT_SIZE as usize;
        let is_last_block = idx + block_entries >= entries.len();

        let mut block = vec![
            0u8;
            if is_last_block {
                dirent_area_size + name_total
            } else {
                blksiz
            }
        ];

        let mut name_offset = dirent_area_size;
        for i in 0..block_entries {
            let e = &entries[idx + i];
            let dirent_off = i * EROFS_DIRENT_SIZE as usize;

            block[dirent_off..dirent_off + 8].copy_from_slice(&e.nid.to_le_bytes());
            block[dirent_off + 8..dirent_off + 10]
                .copy_from_slice(&(name_offset as u16).to_le_bytes());
            block[dirent_off + 10] = e.file_type;
            block[dirent_off + 11] = 0;

            block[name_offset..name_offset + e.name.len()].copy_from_slice(&e.name);
            name_offset += e.name.len();
        }

        result.extend_from_slice(&block);
        idx += block_entries;
    }

    Ok(result)
}

fn node_data_size(node: &TreeNode) -> u64 {
    match node {
        TreeNode::RegularFile(f) => f.data.len() as u64,
        TreeNode::Symlink(s) => s.target.len() as u64,
        _ => 0,
    }
}

fn node_xattrs(node: &TreeNode) -> &[Xattr] {
    match node {
        TreeNode::RegularFile(f) => &f.xattrs,
        TreeNode::Directory(d) => &d.xattrs,
        _ => &[],
    }
}

fn node_metadata(node: &TreeNode) -> &InodeMetadata {
    match node {
        TreeNode::RegularFile(f) => &f.metadata,
        TreeNode::Directory(d) => &d.metadata,
        TreeNode::Symlink(s) => &s.metadata,
        TreeNode::CharDevice(d) => &d.metadata,
        TreeNode::BlockDevice(d) => &d.metadata,
        TreeNode::Fifo(m) => m,
        TreeNode::Socket(m) => m,
    }
}

fn node_nlink(node: &TreeNode) -> u32 {
    match node {
        TreeNode::RegularFile(f) => f.nlink,
        TreeNode::Directory(d) => {
            let child_dirs = d
                .entries
                .values()
                .filter(|c| matches!(c, TreeNode::Directory(_)))
                .count();
            2 + child_dirs as u32
        }
        _ => 1,
    }
}

fn write_xattr_ibody(file: &mut (impl Write + Seek), xattrs: &[Xattr]) -> Result<(), ErofsError> {
    let header = [0u8; EROFS_XATTR_IBODY_HEADER_SIZE as usize];
    file.write_all(&header)?;

    for xattr in xattrs {
        let (prefix_idx, suffix) =
            xattr_prefix_index(&xattr.name).ok_or(ErofsError::UnsupportedXattrPrefix)?;

        let mut entry = [0u8; 4];
        entry[0] = suffix.len() as u8;
        entry[1] = prefix_idx;
        entry[2..4].copy_from_slice(&(xattr.value.len() as u16).to_le_bytes());
        file.write_all(&entry)?;

        file.write_all(suffix)?;
        file.write_all(&xattr.value)?;

        let entry_size = 4 + suffix.len() + xattr.value.len();
        let aligned = erofs_xattr_align(entry_size);
        let pad = aligned - entry_size;
        if pad > 0 {
            file.write_all(&ZEROS[..pad])?;
        }
    }

    Ok(())
}

fn clone_dir_shell(dir: &DirectoryNode) -> DirectoryNode {
    DirectoryNode {
        metadata: InodeMetadata {
            uid: dir.metadata.uid,
            gid: dir.metadata.gid,
            mode: dir.metadata.mode,
            mtime: dir.metadata.mtime,
            mtime_nsec: dir.metadata.mtime_nsec,
        },
        xattrs: dir
            .xattrs
            .iter()
            .map(|x| Xattr {
                name: x.name.clone(),
                value: x.value.clone(),
            })
            .collect(),
        entries: BTreeMap::new(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{collections::HashMap, fs::File};

    use tempfile::tempdir;

    use crate::filetree::{FileTree, InodeMetadata, SymlinkNode, TreeNode};

    use super::{super::reader::ErofsReader, super::writer::ErofsDataMap, write_fsmeta};

    #[test]
    fn write_fsmeta_persists_plain_symlink_data_blocks() {
        let mut merged_tree = FileTree::new();
        let target = vec![b'a'; super::EROFS_BLKSIZ as usize];

        merged_tree
            .insert(
                b"link",
                TreeNode::Symlink(SymlinkNode {
                    metadata: InodeMetadata {
                        mode: 0o777,
                        ..Default::default()
                    },
                    target: target.clone(),
                }),
            )
            .expect("insert symlink");

        let output_dir = tempdir().expect("tempdir");
        let output = output_dir.path().join("fsmeta.erofs");
        let layer_maps = vec![ErofsDataMap {
            file_blocks: HashMap::new(),
            total_blocks: 1,
        }];

        write_fsmeta(&merged_tree, &HashMap::new(), &layer_maps, &output).expect("write fsmeta");

        let mut reader =
            ErofsReader::new(File::open(&output).expect("open fsmeta")).expect("create reader");
        assert_eq!(reader.read_link("/link").expect("read link"), target);
    }
}
