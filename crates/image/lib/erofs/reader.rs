//! Minimal EROFS reader for extracting file contents from our own images.
//!
//! Only supports the subset of EROFS that our writer produces:
//! - Extended inodes (64 bytes)
//! - Uncompressed data (FLAT_PLAIN or FLAT_INLINE)
//! - Sorted directory entries (binary search)
//! - No shared xattrs, no compression, no chunks

use std::os::unix::fs::FileExt;
use std::path::Path;
use std::{fs::File, io};

use super::format::{
    EROFS_BLKSIZ, EROFS_DIRENT_SIZE, EROFS_INODE_EXTENDED_SIZE, EROFS_INODE_FLAT_INLINE,
    EROFS_INODE_FLAT_PLAIN, EROFS_NULL_ADDR, EROFS_SUPER_OFFSET, EROFS_XATTR_IBODY_HEADER_SIZE,
    EROFS_XATTR_INDEX_SECURITY, EROFS_XATTR_INDEX_TRUSTED, EROFS_XATTR_INDEX_USER, S_IFBLK,
    S_IFCHR, S_IFDIR, S_IFIFO, S_IFLNK, S_IFMT, S_IFREG, S_IFSOCK, erofs_xattr_align,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A handle to an open EROFS image for reading.
pub struct ErofsReader {
    file: File,
    meta_blkaddr: u32,
    root_nid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErofsEntryKind {
    RegularFile,
    Directory,
    Symlink,
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErofsEntryInfo {
    pub kind: ErofsEntryKind,
    pub opaque: bool,
    pub whiteout: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ErofsReader {
    /// Open an EROFS image by parsing the superblock.
    pub fn new(file: File) -> io::Result<Self> {
        let mut sb = [0u8; 128];
        read_exact_at(&file, EROFS_SUPER_OFFSET, &mut sb)?;

        let magic = u32::from_le_bytes([sb[0], sb[1], sb[2], sb[3]]);
        if magic != 0xE0F5_E1E2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("bad EROFS magic: {magic:#x}"),
            ));
        }

        let root_nid = u16::from_le_bytes([sb[0x0E], sb[0x0F]]) as u32;
        let meta_blkaddr = u32::from_le_bytes([sb[0x28], sb[0x29], sb[0x2A], sb[0x2B]]);

        Ok(Self {
            file,
            meta_blkaddr,
            root_nid,
        })
    }

    /// Read a file by path from the EROFS image. Returns the file data.
    pub fn read_file(&mut self, path: &str) -> io::Result<Vec<u8>> {
        let target_inode = self.lookup_path(path)?;
        if (target_inode.mode & S_IFMT) != S_IFREG {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target is not a regular file",
            ));
        }
        self.read_inode_data(&target_inode)
    }

    /// Read a symlink target by path from the EROFS image.
    pub fn read_link(&mut self, path: &str) -> io::Result<Vec<u8>> {
        let target_inode = self.lookup_path(path)?;
        if (target_inode.mode & S_IFMT) != S_IFLNK {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "target is not a symlink",
            ));
        }
        self.read_inode_data(&target_inode)
    }

    pub fn entry_info(&mut self, path: &str) -> io::Result<ErofsEntryInfo> {
        let inode = self.lookup_path(path)?;
        let kind = inode_kind(&inode)?;
        let opaque = if kind == ErofsEntryKind::Directory {
            self.inode_is_opaque(&inode)?
        } else {
            false
        };
        let whiteout = kind == ErofsEntryKind::CharDevice && inode.rdev == 0;

        Ok(ErofsEntryInfo {
            kind,
            opaque,
            whiteout,
        })
    }

    fn inode_offset(&self, nid: u32) -> u64 {
        (self.meta_blkaddr as u64) * (EROFS_BLKSIZ as u64) + (nid as u64) * 32
    }

    fn read_inode(&mut self, nid: u32) -> io::Result<InodeInfo> {
        let offset = self.inode_offset(nid);

        let mut buf = [0u8; EROFS_INODE_EXTENDED_SIZE as usize];
        read_exact_at(&self.file, offset, &mut buf)?;

        let i_format = u16::from_le_bytes([buf[0], buf[1]]);
        let i_xattr_icount = u16::from_le_bytes([buf[2], buf[3]]);
        let mode = u16::from_le_bytes([buf[4], buf[5]]);
        let size = u64::from_le_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]);
        let i_u = u32::from_le_bytes([buf[16], buf[17], buf[18], buf[19]]);

        let data_layout = ((i_format >> 1) & 0x07) as u8;

        // Compute xattr ibody size to know where inline data starts.
        // Formula from EROFS spec: ibody = 12-byte header + (i_xattr_icount - 1) * 4 bytes.
        // The "- 1" accounts for the header occupying the first count unit.
        let xattr_ibody_size = if i_xattr_icount == 0 {
            0u32
        } else {
            12 + ((i_xattr_icount as u32) - 1) * 4
        };

        Ok(InodeInfo {
            nid,
            mode,
            size,
            data_layout,
            startblk_lo: i_u,
            rdev: i_u,
            xattr_ibody_size,
        })
    }

    fn lookup_path(&mut self, path: &str) -> io::Result<InodeInfo> {
        let components: Vec<&str> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|c| !c.is_empty())
            .collect();

        if components.is_empty() {
            if path == "/" {
                return self.read_inode(self.root_nid);
            }
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "empty path"));
        }

        let mut current_nid = self.root_nid;
        for (i, component) in components.iter().enumerate() {
            let inode = self.read_inode(current_nid)?;
            let mode_type = inode.mode & S_IFMT;

            if mode_type != S_IFDIR {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("not a directory at component '{component}'"),
                ));
            }

            let target_nid = self.lookup_in_dir(&inode, component)?;
            if i + 1 == components.len() {
                return self.read_inode(target_nid);
            }

            current_nid = target_nid;
        }

        Err(io::Error::new(io::ErrorKind::NotFound, "path not found"))
    }

    /// Look up a named entry in a directory inode's data.
    ///
    /// EROFS directory data is organized as self-contained blocks. Each block
    /// starts with a packed array of 12-byte dirent headers, followed by the
    /// concatenated name strings. The first dirent's `nameoff` field divided
    /// by 12 gives the number of dirents in that block (the kernel uses this
    /// same trick). Name lengths are derived from consecutive `nameoff`
    /// values; the last entry's name extends to the end of valid data.
    fn lookup_in_dir(&mut self, dir_inode: &InodeInfo, name: &str) -> io::Result<u32> {
        let dir_data = self.read_inode_data(dir_inode)?;
        let blksiz = EROFS_BLKSIZ as usize;
        let target = name.as_bytes();
        let block_count = dir_data.len().div_ceil(blksiz);
        let mut left = 0usize;
        let mut right = block_count;

        while left < right {
            let mid = (left + right) / 2;
            let block = dir_block(&dir_data, mid, blksiz);
            let dirent_count = dir_block_dirent_count(block)?;
            let first_name = dirent_name(block, 0, dirent_count)?;
            let last_name = dirent_name(block, dirent_count - 1, dirent_count)?;

            if target < first_name {
                right = mid;
                continue;
            }

            if target > last_name {
                left = mid + 1;
                continue;
            }

            return lookup_in_dir_block(block, dirent_count, target)?.ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("entry '{name}' not found in directory"),
                )
            });
        }

        Err(io::Error::new(
            io::ErrorKind::NotFound,
            format!("entry '{name}' not found in directory"),
        ))
    }

    fn read_inode_data(&mut self, inode: &InodeInfo) -> io::Result<Vec<u8>> {
        let size = inode.size as usize;
        if size == 0 {
            return Ok(Vec::new());
        }

        let blksiz = EROFS_BLKSIZ as usize;

        match inode.data_layout {
            EROFS_INODE_FLAT_PLAIN => {
                if inode.startblk_lo == EROFS_NULL_ADDR {
                    return Ok(Vec::new());
                }
                let data_offset = (inode.startblk_lo as u64) * (EROFS_BLKSIZ as u64);
                let mut data = vec![0u8; size];
                read_exact_at(&self.file, data_offset, &mut data)?;
                Ok(data)
            }
            EROFS_INODE_FLAT_INLINE => {
                let full_blocks = size / blksiz;
                let tail_size = size % blksiz;
                let mut data = Vec::with_capacity(size);

                // Read full blocks from data area.
                if full_blocks > 0 && inode.startblk_lo != EROFS_NULL_ADDR {
                    let data_offset = (inode.startblk_lo as u64) * (EROFS_BLKSIZ as u64);
                    let mut block_data = vec![0u8; full_blocks * blksiz];
                    read_exact_at(&self.file, data_offset, &mut block_data)?;
                    data.extend_from_slice(&block_data);
                }

                // Read inline tail from after inode metadata.
                if tail_size > 0 {
                    let inline_offset = self.inode_offset(inode.nid)
                        + EROFS_INODE_EXTENDED_SIZE as u64
                        + inode.xattr_ibody_size as u64;
                    let mut tail = vec![0u8; tail_size];
                    read_exact_at(&self.file, inline_offset, &mut tail)?;
                    data.extend_from_slice(&tail);
                }

                Ok(data)
            }
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("unsupported data layout: {}", inode.data_layout),
            )),
        }
    }

    fn inode_is_opaque(&mut self, inode: &InodeInfo) -> io::Result<bool> {
        for (name, value) in self.read_inode_xattrs(inode)? {
            if name == b"trusted.overlay.opaque" && value == b"y" {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn read_inode_xattrs(&mut self, inode: &InodeInfo) -> io::Result<Vec<(Vec<u8>, Vec<u8>)>> {
        if inode.xattr_ibody_size == 0 {
            return Ok(Vec::new());
        }

        let total = inode.xattr_ibody_size as usize;
        if total < EROFS_XATTR_IBODY_HEADER_SIZE as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "xattr ibody smaller than header",
            ));
        }

        let mut offset = self.inode_offset(inode.nid)
            + EROFS_INODE_EXTENDED_SIZE as u64
            + EROFS_XATTR_IBODY_HEADER_SIZE as u64;
        let mut remaining = total - EROFS_XATTR_IBODY_HEADER_SIZE as usize;
        let mut xattrs = Vec::new();

        while remaining > 0 {
            if remaining < 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "truncated xattr entry header",
                ));
            }

            let mut entry = [0u8; 4];
            read_exact_at(&self.file, offset, &mut entry)?;

            let name_len = entry[0] as usize;
            let name_index = entry[1];
            let value_len = u16::from_le_bytes([entry[2], entry[3]]) as usize;
            let entry_size = 4 + name_len + value_len;
            let aligned_size = erofs_xattr_align(entry_size);

            if aligned_size > remaining {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "xattr entry exceeds ibody size",
                ));
            }

            let mut suffix = vec![0u8; name_len];
            read_exact_at(&self.file, offset + 4, &mut suffix)?;
            let mut value = vec![0u8; value_len];
            read_exact_at(&self.file, offset + 4 + name_len as u64, &mut value)?;

            let name = match name_index {
                EROFS_XATTR_INDEX_USER => [b"user.".as_slice(), suffix.as_slice()].concat(),
                EROFS_XATTR_INDEX_TRUSTED => [b"trusted.".as_slice(), suffix.as_slice()].concat(),
                EROFS_XATTR_INDEX_SECURITY => [b"security.".as_slice(), suffix.as_slice()].concat(),
                other => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("unsupported xattr name index: {other}"),
                    ));
                }
            };

            xattrs.push((name, value));
            offset += aligned_size as u64;
            remaining -= aligned_size;
        }

        Ok(xattrs)
    }
}

//--------------------------------------------------------------------------------------------------
// Types: Internal
//--------------------------------------------------------------------------------------------------

struct InodeInfo {
    nid: u32,
    mode: u16,
    size: u64,
    data_layout: u8,
    startblk_lo: u32,
    rdev: u32,
    xattr_ibody_size: u32,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn read_exact_at(file: &File, offset: u64, mut buf: &mut [u8]) -> io::Result<()> {
    let mut current_offset = offset;
    while !buf.is_empty() {
        let read = file.read_at(buf, current_offset)?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "unexpected EOF",
            ));
        }
        current_offset += read as u64;
        buf = &mut buf[read..];
    }

    Ok(())
}

fn dir_block(dir_data: &[u8], block_idx: usize, blksiz: usize) -> &[u8] {
    let offset = block_idx * blksiz;
    let end = (offset + blksiz).min(dir_data.len());
    &dir_data[offset..end]
}

fn dir_block_dirent_count(block: &[u8]) -> io::Result<usize> {
    if block.len() < EROFS_DIRENT_SIZE as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "directory block smaller than one dirent",
        ));
    }

    let first_nameoff = u16::from_le_bytes([block[8], block[9]]) as usize;
    let dirent_size = EROFS_DIRENT_SIZE as usize;
    if first_nameoff < dirent_size
        || !first_nameoff.is_multiple_of(dirent_size)
        || first_nameoff > block.len()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid first dirent name offset",
        ));
    }

    Ok(first_nameoff / dirent_size)
}

fn dirent_name(block: &[u8], idx: usize, dirent_count: usize) -> io::Result<&[u8]> {
    let dirent_size = EROFS_DIRENT_SIZE as usize;
    let dirent_off = idx
        .checked_mul(dirent_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "dirent offset overflow"))?;

    if idx >= dirent_count || dirent_off + dirent_size > block.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dirent index out of bounds",
        ));
    }

    let nameoff = u16::from_le_bytes([block[dirent_off + 8], block[dirent_off + 9]]) as usize;
    let mut name_end = if idx + 1 < dirent_count {
        let next_off = dirent_off + dirent_size;
        u16::from_le_bytes([block[next_off + 8], block[next_off + 9]]) as usize
    } else {
        block.len()
    };

    if nameoff > name_end || name_end > block.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dirent name range out of bounds",
        ));
    }

    while name_end > nameoff && block[name_end - 1] == 0 {
        name_end -= 1;
    }

    Ok(&block[nameoff..name_end])
}

fn dirent_nid(block: &[u8], idx: usize) -> io::Result<u32> {
    let dirent_size = EROFS_DIRENT_SIZE as usize;
    let dirent_off = idx
        .checked_mul(dirent_size)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "dirent offset overflow"))?;
    if dirent_off + dirent_size > block.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dirent NID out of bounds",
        ));
    }

    let nid = u64::from_le_bytes([
        block[dirent_off],
        block[dirent_off + 1],
        block[dirent_off + 2],
        block[dirent_off + 3],
        block[dirent_off + 4],
        block[dirent_off + 5],
        block[dirent_off + 6],
        block[dirent_off + 7],
    ]);
    u32::try_from(nid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "dirent NID overflow"))
}

fn lookup_in_dir_block(
    block: &[u8],
    dirent_count: usize,
    target: &[u8],
) -> io::Result<Option<u32>> {
    let mut left = 0usize;
    let mut right = dirent_count;

    while left < right {
        let mid = (left + right) / 2;
        match target.cmp(dirent_name(block, mid, dirent_count)?) {
            std::cmp::Ordering::Less => right = mid,
            std::cmp::Ordering::Greater => left = mid + 1,
            std::cmp::Ordering::Equal => return dirent_nid(block, mid).map(Some),
        }
    }

    Ok(None)
}

fn inode_kind(inode: &InodeInfo) -> io::Result<ErofsEntryKind> {
    match inode.mode & S_IFMT {
        S_IFREG => Ok(ErofsEntryKind::RegularFile),
        S_IFDIR => Ok(ErofsEntryKind::Directory),
        S_IFLNK => Ok(ErofsEntryKind::Symlink),
        S_IFCHR => Ok(ErofsEntryKind::CharDevice),
        S_IFBLK => Ok(ErofsEntryKind::BlockDevice),
        S_IFIFO => Ok(ErofsEntryKind::Fifo),
        S_IFSOCK => Ok(ErofsEntryKind::Socket),
        other => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("unsupported inode mode type: {other:#o}"),
        )),
    }
}

/// Read a file from an EROFS image file on disk.
pub fn read_file_from_erofs(image_path: &Path, file_path: &str) -> io::Result<Vec<u8>> {
    let file = std::fs::File::open(image_path)?;
    let mut reader = ErofsReader::new(file)?;
    reader.read_file(file_path)
}

pub fn entry_info_from_erofs(image_path: &Path, file_path: &str) -> io::Result<ErofsEntryInfo> {
    let file = std::fs::File::open(image_path)?;
    let mut reader = ErofsReader::new(file)?;
    reader.entry_info(file_path)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{fs::File, io};

    use tempfile::tempdir;

    use super::ErofsReader;
    use crate::{
        erofs::write_erofs,
        filetree::{FileData, FileTree, InodeMetadata, RegularFileNode, TreeNode},
    };

    fn make_regular_file(data: &[u8]) -> TreeNode {
        TreeNode::RegularFile(RegularFileNode {
            metadata: InodeMetadata::default(),
            xattrs: Vec::new(),
            data: FileData::Memory(data.to_vec()),
            nlink: 1,
        })
    }

    #[test]
    fn lookup_path_resolves_large_multi_block_directory() {
        let mut tree = FileTree::new();
        for i in 0..5000 {
            let path = format!("dir/file-{i:04}.txt");
            tree.insert(path.as_bytes(), make_regular_file(b"x"))
                .expect("insert file");
        }

        let output_dir = tempdir().expect("tempdir");
        let output = output_dir.path().join("large-dir.erofs");
        write_erofs(&tree, &output).expect("write erofs");

        let file = File::open(&output).expect("open erofs");
        let mut reader = ErofsReader::new(file).expect("reader");

        assert_eq!(reader.read_file("/dir/file-0000.txt").expect("first"), b"x");
        assert_eq!(
            reader.read_file("/dir/file-2500.txt").expect("middle"),
            b"x"
        );
        assert_eq!(reader.read_file("/dir/file-4999.txt").expect("last"), b"x");

        let err = reader
            .entry_info("/dir/file-9999.txt")
            .expect_err("missing entry should fail");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }
}
