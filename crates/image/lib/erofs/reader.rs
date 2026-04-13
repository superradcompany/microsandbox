//! Minimal EROFS reader for extracting file contents from our own images.
//!
//! Only supports the subset of EROFS that our writer produces:
//! - Extended inodes (64 bytes)
//! - Uncompressed data (FLAT_PLAIN or FLAT_INLINE)
//! - Sorted directory entries (binary search)
//! - No shared xattrs, no compression, no chunks

use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

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
pub struct ErofsReader<R> {
    reader: R,
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

impl<R: Read + Seek> ErofsReader<R> {
    /// Open an EROFS image by parsing the superblock.
    pub fn new(mut reader: R) -> io::Result<Self> {
        reader.seek(SeekFrom::Start(EROFS_SUPER_OFFSET))?;
        let mut sb = [0u8; 128];
        reader.read_exact(&mut sb)?;

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
            reader,
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
        self.reader.seek(SeekFrom::Start(offset))?;

        let mut buf = [0u8; EROFS_INODE_EXTENDED_SIZE as usize];
        self.reader.read_exact(&mut buf)?;

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

        let mut offset = 0;
        while offset < dir_data.len() {
            let block_end = (offset + blksiz).min(dir_data.len());
            let block = &dir_data[offset..block_end];

            if block.len() < EROFS_DIRENT_SIZE as usize {
                break;
            }

            // dirent[0].nameoff / 12 = number of dirents in this block.
            let first_nameoff = u16::from_le_bytes([block[8], block[9]]) as usize;
            let dirent_count = first_nameoff / (EROFS_DIRENT_SIZE as usize);

            for i in 0..dirent_count {
                let de_off = i * (EROFS_DIRENT_SIZE as usize);
                if de_off + 12 > block.len() {
                    break;
                }

                let nid = u64::from_le_bytes([
                    block[de_off],
                    block[de_off + 1],
                    block[de_off + 2],
                    block[de_off + 3],
                    block[de_off + 4],
                    block[de_off + 5],
                    block[de_off + 6],
                    block[de_off + 7],
                ]);
                let nameoff = u16::from_le_bytes([block[de_off + 8], block[de_off + 9]]) as usize;

                // Name length: for intermediate entries, the next dirent's nameoff
                // marks where this name ends. For the last entry, scan to end of
                // valid data (names are NOT null-terminated in EROFS).
                let name_end = if i + 1 < dirent_count {
                    let next_off = (i + 1) * (EROFS_DIRENT_SIZE as usize);
                    u16::from_le_bytes([block[next_off + 8], block[next_off + 9]]) as usize
                } else {
                    let mut end = nameoff;
                    while end < block.len() && block[end] != 0 {
                        end += 1;
                    }
                    end
                };

                if nameoff <= block.len() && name_end <= block.len() {
                    let entry_name = &block[nameoff..name_end];
                    if entry_name == name.as_bytes() {
                        return Ok(nid as u32);
                    }
                }
            }

            offset += blksiz;
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
                self.reader.seek(SeekFrom::Start(data_offset))?;
                let mut data = vec![0u8; size];
                self.reader.read_exact(&mut data)?;
                Ok(data)
            }
            EROFS_INODE_FLAT_INLINE => {
                let full_blocks = size / blksiz;
                let tail_size = size % blksiz;
                let mut data = Vec::with_capacity(size);

                // Read full blocks from data area.
                if full_blocks > 0 && inode.startblk_lo != EROFS_NULL_ADDR {
                    let data_offset = (inode.startblk_lo as u64) * (EROFS_BLKSIZ as u64);
                    self.reader.seek(SeekFrom::Start(data_offset))?;
                    let mut block_data = vec![0u8; full_blocks * blksiz];
                    self.reader.read_exact(&mut block_data)?;
                    data.extend_from_slice(&block_data);
                }

                // Read inline tail from after inode metadata.
                if tail_size > 0 {
                    let inline_offset = self.inode_offset(inode.nid)
                        + EROFS_INODE_EXTENDED_SIZE as u64
                        + inode.xattr_ibody_size as u64;
                    self.reader.seek(SeekFrom::Start(inline_offset))?;
                    let mut tail = vec![0u8; tail_size];
                    self.reader.read_exact(&mut tail)?;
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

            self.reader.seek(SeekFrom::Start(offset))?;
            let mut entry = [0u8; 4];
            self.reader.read_exact(&mut entry)?;

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
            self.reader.read_exact(&mut suffix)?;
            let mut value = vec![0u8; value_len];
            self.reader.read_exact(&mut value)?;

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
    let mut reader = ErofsReader::new(io::BufReader::new(file))?;
    reader.read_file(file_path)
}

pub fn entry_info_from_erofs(image_path: &Path, file_path: &str) -> io::Result<ErofsEntryInfo> {
    let file = std::fs::File::open(image_path)?;
    let mut reader = ErofsReader::new(io::BufReader::new(file))?;
    reader.entry_info(file_path)
}
