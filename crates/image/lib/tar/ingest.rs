//! Tar stream ingestion into an in-memory `FileTree`.
//!
//! Reads an OCI layer tar stream (optionally compressed) and builds a `FileTree`
//! representing the layer's filesystem contents. Handles all OCI tar edge cases
//! including whiteouts, hardlinks, special files, and path validation.

use std::fmt;
use std::future::poll_fn;
use std::io::ErrorKind;
use std::pin::Pin;
use std::task::{Context, Poll};

use async_compression::tokio::bufread::{GzipDecoder, ZstdDecoder};
use sha2::{Digest as Sha2Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, BufReader, ReadBuf};

use crate::tree::{
    DataSpool, DeviceNode, DirectoryNode, FileData, FileTree, FileTreeError, InodeMetadata,
    RegularFileId, RegularFileNode, ResourceLimits, SPOOL_THRESHOLD, SymlinkNode, TreeNode, Xattr,
};

use super::pax::EmptyXattrFilter;
use super::records::{Member, Records};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Whiteout prefix used by OCI layers.
const WHITEOUT_PREFIX: &[u8] = b".wh.";

/// Opaque whiteout filename.
const OPAQUE_WHITEOUT: &[u8] = b".wh..wh..opq";

use crate::tree::{OPAQUE_XATTR_NAME, OPAQUE_XATTR_VALUE, WHITEOUT_MAJOR, WHITEOUT_MINOR};

/// Gzip magic bytes.
const GZIP_MAGIC: [u8; 2] = [0x1F, 0x8B];

/// Zstandard magic bytes.
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Entry cadence for cooperative scheduler yields during tar ingestion.
const INGEST_YIELD_EVERY_ENTRIES: u64 = 32;

/// Maximum file-body read size used while ingesting tar entries.
const ENTRY_READ_CHUNK_SIZE: usize = 64 * 1024;

/// Compressed input buffer size used before gzip/zstd decoders.
const COMPRESSED_INPUT_BUFFER_SIZE: usize = 256 * 1024;

/// Spool write batch size used after bounded decoder reads.
const SPOOL_WRITE_BUFFER_SIZE: usize = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Compression format for a layer blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Compression {
    /// Uncompressed tar.
    None,
    /// Gzip-compressed tar.
    Gzip,
    /// Zstandard-compressed tar.
    Zstd,
}

/// Errors that can occur during tar ingestion.
#[derive(Debug)]
pub enum IngestError {
    /// Underlying I/O error.
    Io(std::io::Error),
    /// Tar entry path contains `..` components.
    PathTraversal(String),
    /// Tar entry path exceeds the maximum allowed length.
    PathTooLong(String),
    /// Tar entry path exceeds the maximum allowed depth.
    PathTooDeep(String),
    /// A single file exceeds the maximum allowed size.
    FileTooLarge(String),
    /// The cumulative size of all extracted data exceeds the limit.
    TotalSizeExceeded,
    /// The number of tar entries exceeds the limit.
    EntryCountExceeded,
    /// A symlink target exceeds the maximum allowed length.
    SymlinkTargetTooLong(String),
    /// A hardlink references a target that does not exist in the tree.
    HardlinkTarget(String),
    /// A tar entry is invalid or unsupported.
    InvalidEntry(String),
    /// FileTree insertion error.
    Tree(FileTreeError),
}

/// Result of parsing a whiteout filename.
enum WhiteoutKind<'a> {
    /// Not a whiteout; the entry should be inserted normally.
    None,
    /// Opaque whiteout — the parent directory gets an xattr.
    Opaque,
    /// Regular whiteout — replace with a char device node at the given name.
    File(&'a [u8]),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Compression {
    /// Detect compression from an OCI media type string.
    pub fn from_media_type(media_type: &str) -> Self {
        if media_type.contains("gzip") {
            Compression::Gzip
        } else if media_type.contains("zstd") {
            Compression::Zstd
        } else {
            Compression::None
        }
    }

    /// Detect compression from magic bytes at the start of a stream.
    pub fn detect(magic: &[u8]) -> Self {
        if magic.len() >= 4 && magic[..4] == ZSTD_MAGIC {
            Compression::Zstd
        } else if magic.len() >= 2 && magic[..2] == GZIP_MAGIC {
            Compression::Gzip
        } else {
            Compression::None
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Display for IngestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IngestError::Io(e) => write!(f, "I/O error: {e}"),
            IngestError::PathTraversal(p) => write!(f, "path traversal in tar: \"{p}\""),
            IngestError::PathTooLong(p) => write!(f, "path too long: \"{p}\""),
            IngestError::PathTooDeep(p) => write!(f, "path too deep: \"{p}\""),
            IngestError::FileTooLarge(p) => write!(f, "file too large: \"{p}\""),
            IngestError::TotalSizeExceeded => write!(f, "total extracted size exceeded"),
            IngestError::EntryCountExceeded => write!(f, "entry count exceeded"),
            IngestError::SymlinkTargetTooLong(p) => {
                write!(f, "symlink target too long: \"{p}\"")
            }
            IngestError::HardlinkTarget(p) => {
                write!(f, "hardlink target not found: \"{p}\"")
            }
            IngestError::InvalidEntry(msg) => write!(f, "invalid tar entry: {msg}"),
            IngestError::Tree(e) => write!(f, "file tree error: {e}"),
        }
    }
}

impl std::error::Error for IngestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            IngestError::Io(e) => Some(e),
            IngestError::Tree(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for IngestError {
    fn from(e: std::io::Error) -> Self {
        IngestError::Io(e)
    }
}

impl From<FileTreeError> for IngestError {
    fn from(e: FileTreeError) -> Self {
        IngestError::Tree(e)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Ingest a decompressed tar stream into a `FileTree`.
///
/// If `spool` is provided, files larger than `SPOOL_THRESHOLD` are written
/// to the spool file instead of held in memory.
pub async fn ingest_tar<R: AsyncRead + Unpin>(
    reader: R,
    limits: &ResourceLimits,
    mut spool: Option<&mut DataSpool>,
) -> Result<FileTree, IngestError> {
    let mut archive = Records::new(EmptyXattrFilter::new(reader));
    let mut tree = FileTree::new();
    let mut entry_count: u64 = 0;
    let mut total_size: u64 = 0;
    let mut saw_hardlink = false;
    let mut spool_read_buf = Vec::new();
    let mut spool_write_buf = Vec::new();

    while let Some(entry) = archive.next().await? {
        entry_count += 1;
        if entry_count > limits.max_entry_count {
            return Err(IngestError::EntryCountExceeded);
        }

        let header = &entry.header;
        let raw_path = entry.path_bytes();
        let path = normalize_path(&raw_path, limits)?;

        // Skip empty paths (root directory entry `./` after stripping).
        let path = match path {
            Some(p) => p,
            None => continue,
        };

        let entry_type = header.entry_type();

        // Extract metadata from the header.
        let metadata = extract_metadata(&entry);

        match entry_type {
            tar::EntryType::Link => {
                // Hardlink — look up the target in the tree and clone its data.
                let link_target_bytes = entry.link_name_bytes().ok_or_else(|| {
                    IngestError::InvalidEntry("hardlink with no target".to_string())
                })?;
                let target_path = normalize_path(&link_target_bytes, limits)?;
                let target_path = match target_path {
                    Some(p) => p,
                    None => {
                        return Err(IngestError::HardlinkTarget(
                            String::from_utf8_lossy(&link_target_bytes).into_owned(),
                        ));
                    }
                };

                handle_hardlink(&mut tree, &path, &target_path)?;
                saw_hardlink = true;
            }
            tar::EntryType::Directory => {
                let node = TreeNode::Directory(DirectoryNode {
                    metadata,
                    xattrs: Vec::new(),
                    entries: std::collections::BTreeMap::new(),
                });
                tree.insert(&path, node)?;
            }
            tar::EntryType::Symlink => {
                let link_target = entry.link_name_bytes().ok_or_else(|| {
                    IngestError::InvalidEntry("symlink with no target".to_string())
                })?;

                if link_target.len() > limits.max_symlink_target {
                    return Err(IngestError::SymlinkTargetTooLong(
                        String::from_utf8_lossy(&path).into_owned(),
                    ));
                }

                // Check for whiteout handling before inserting.
                let file_name = path_filename(&path);
                match classify_whiteout(file_name) {
                    WhiteoutKind::Opaque => {
                        // Opaque whiteout: add xattr to the parent directory.
                        apply_opaque_xattr(&mut tree, &path)?;
                    }
                    WhiteoutKind::File(real_name) => {
                        // Regular whiteout: insert a char device node.
                        let whiteout_path = replace_filename(&path, real_name);
                        let node = TreeNode::CharDevice(DeviceNode {
                            metadata,
                            major: WHITEOUT_MAJOR,
                            minor: WHITEOUT_MINOR,
                        });
                        tree.insert(&whiteout_path, node)?;
                    }
                    WhiteoutKind::None => {
                        let node = TreeNode::Symlink(SymlinkNode {
                            metadata,
                            target: link_target.into_owned(),
                        });
                        tree.insert(&path, node)?;
                    }
                }
            }
            tar::EntryType::Regular | tar::EntryType::Continuous => {
                // Read file data.
                let size = entry.size;
                if size > limits.max_file_size {
                    return Err(IngestError::FileTooLarge(
                        String::from_utf8_lossy(&path).into_owned(),
                    ));
                }
                total_size = total_size.saturating_add(size);
                if total_size > limits.max_total_size {
                    return Err(IngestError::TotalSizeExceeded);
                }

                // Check for whiteouts before reading the file body — whiteout
                // markers don't carry data, so reading would be wasted I/O.
                let file_name = path_filename(&path);
                match classify_whiteout(file_name) {
                    WhiteoutKind::Opaque => {
                        apply_opaque_xattr(&mut tree, &path)?;
                    }
                    WhiteoutKind::File(real_name) => {
                        let whiteout_path = replace_filename(&path, real_name);
                        let node = TreeNode::CharDevice(DeviceNode {
                            metadata,
                            major: WHITEOUT_MAJOR,
                            minor: WHITEOUT_MINOR,
                        });
                        tree.insert(&whiteout_path, node)?;
                    }
                    WhiteoutKind::None => {
                        let file_data = if size >= SPOOL_THRESHOLD
                            && let Some(spool) = spool.as_mut()
                        {
                            stream_entry_to_spool(
                                archive.body(),
                                size,
                                spool,
                                &mut spool_read_buf,
                                &mut spool_write_buf,
                            )
                            .await?
                        } else {
                            FileData::Memory(read_entry_to_memory(archive.body(), size).await?)
                        };

                        let node = TreeNode::RegularFile(RegularFileNode {
                            id: RegularFileId::new(),
                            metadata,
                            xattrs: Vec::new(),
                            data: file_data,
                            nlink: 1,
                        });
                        tree.insert(&path, node)?;
                    }
                }
            }
            tar::EntryType::Char => {
                let major = header.device_major().map_err(IngestError::Io)?.unwrap_or(0);
                let minor = header.device_minor().map_err(IngestError::Io)?.unwrap_or(0);
                let node = TreeNode::CharDevice(DeviceNode {
                    metadata,
                    major,
                    minor,
                });
                tree.insert(&path, node)?;
            }
            tar::EntryType::Block => {
                let major = header.device_major().map_err(IngestError::Io)?.unwrap_or(0);
                let minor = header.device_minor().map_err(IngestError::Io)?.unwrap_or(0);
                let node = TreeNode::BlockDevice(DeviceNode {
                    metadata,
                    major,
                    minor,
                });
                tree.insert(&path, node)?;
            }
            tar::EntryType::Fifo => {
                let node = TreeNode::Fifo(metadata);
                tree.insert(&path, node)?;
            }
            // Socket type is not a standard tar entry type but we handle it if encountered.
            kind if kind.as_byte() == 0o140 => {
                // Unix socket (type '`' = 0o140 = 96).
                let node = TreeNode::Socket(metadata);
                tree.insert(&path, node)?;
            }
            _ => {
                // Ignore unsupported member types, including GNU sparse files.
                // The record reader validates their framing and drains their bodies.
            }
        }

        if entry_count.is_multiple_of(INGEST_YIELD_EVERY_ENTRIES) {
            tokio::task::yield_now().await;
        }
    }

    if saw_hardlink {
        tree.refresh_regular_nlinks();
    }

    Ok(tree)
}

/// Ingest a compressed tar stream, automatically decompressing based on the
/// specified compression format.
/// Result of tar ingestion including the decompressed content hash.
pub struct IngestResult {
    /// The in-memory file tree built from the tar stream.
    pub tree: FileTree,
    /// SHA-256 hex digest of the decompressed tar stream (the OCI diff_id).
    pub uncompressed_digest: String,
}

pub async fn ingest_compressed_tar<R: AsyncRead + Unpin>(
    reader: R,
    compression: Compression,
    limits: &ResourceLimits,
    spool_path: Option<&std::path::Path>,
) -> Result<IngestResult, IngestError> {
    let mut spool = spool_path
        .map(DataSpool::new)
        .transpose()
        .map_err(IngestError::Io)?;

    match compression {
        Compression::None => {
            let mut hashing = HashingReader::new(reader);
            let tree = ingest_tar(&mut hashing, limits, spool.as_mut()).await?;
            drain_reader(&mut hashing).await?;
            Ok(IngestResult {
                tree,
                uncompressed_digest: hashing.hex_digest(),
            })
        }
        Compression::Gzip => {
            let decoder = GzipDecoder::new(BufReader::with_capacity(
                COMPRESSED_INPUT_BUFFER_SIZE,
                reader,
            ));
            let mut hashing = HashingReader::new(decoder);
            let tree = ingest_tar(&mut hashing, limits, spool.as_mut()).await?;
            // Drain any remaining bytes (tar EOF padding) to include
            // them in the hash — diff_id covers the full decompressed stream.
            drain_reader(&mut hashing).await?;
            Ok(IngestResult {
                tree,
                uncompressed_digest: hashing.hex_digest(),
            })
        }
        Compression::Zstd => {
            let decoder = ZstdDecoder::new(BufReader::with_capacity(
                COMPRESSED_INPUT_BUFFER_SIZE,
                reader,
            ));
            let mut hashing = HashingReader::new(decoder);
            let tree = ingest_tar(&mut hashing, limits, spool.as_mut()).await?;
            drain_reader(&mut hashing).await?;
            Ok(IngestResult {
                tree,
                uncompressed_digest: hashing.hex_digest(),
            })
        }
    }
}

/// Read all remaining bytes from a reader to ensure the full stream is
/// consumed (and hashed, if wrapped in `HashingReader`). The tar parser
/// may stop before the EOF padding; the diff_id covers the full stream.
async fn drain_reader<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(), IngestError> {
    let mut buf = vec![0u8; ENTRY_READ_CHUNK_SIZE];
    loop {
        let n = reader.read(&mut buf).await.map_err(IngestError::Io)?;
        if n == 0 {
            break;
        }
    }
    Ok(())
}

/// AsyncRead wrapper that computes SHA-256 of all data flowing through it.
struct HashingReader<R> {
    inner: R,
    hasher: Sha256,
}

impl<R> HashingReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            hasher: Sha256::new(),
        }
    }

    fn hex_digest(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for HashingReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &result {
            let new_bytes = &buf.filled()[before..];
            if !new_bytes.is_empty() {
                self.hasher.update(new_bytes);
            }
        }
        result
    }
}

/// Normalize a raw tar path: strip leading `./` and `/`, reject `..`
/// components, and enforce length/depth limits.
///
/// Returns `Ok(None)` for empty paths (for example the root `./` or `/` entry
/// after stripping).
fn normalize_path(raw: &[u8], limits: &ResourceLimits) -> Result<Option<Vec<u8>>, IngestError> {
    let path = strip_dot_slash(raw);
    let path = strip_leading_slashes(path);

    // Strip trailing slashes.
    let path = strip_trailing_slashes(path);

    // Empty after stripping means this is the root entry.
    if path.is_empty() {
        return Ok(None);
    }

    // Reject `..` components.
    let mut depth: usize = 0;
    for component in path.split(|&b| b == b'/') {
        if component.is_empty() {
            continue;
        }
        if component == b".." {
            return Err(IngestError::PathTraversal(
                String::from_utf8_lossy(path).into_owned(),
            ));
        }
        depth += 1;
    }

    // Enforce path length limit.
    if path.len() > limits.max_path_length {
        return Err(IngestError::PathTooLong(
            String::from_utf8_lossy(path).into_owned(),
        ));
    }

    // Enforce path depth limit.
    if depth > limits.max_path_depth {
        return Err(IngestError::PathTooDeep(
            String::from_utf8_lossy(path).into_owned(),
        ));
    }

    Ok(Some(path.to_vec()))
}

/// Strip leading `./` prefix from a path.
fn strip_dot_slash(path: &[u8]) -> &[u8] {
    if path.starts_with(b"./") {
        &path[2..]
    } else if path == b"." {
        b""
    } else {
        path
    }
}

/// Strip trailing slashes from a path.
fn strip_trailing_slashes(path: &[u8]) -> &[u8] {
    let mut end = path.len();
    while end > 0 && path[end - 1] == b'/' {
        end -= 1;
    }
    &path[..end]
}

/// Strip all leading slashes from a path.
fn strip_leading_slashes(path: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < path.len() && path[start] == b'/' {
        start += 1;
    }
    &path[start..]
}

/// Extract metadata from a tar header.
fn extract_metadata(entry: &Member) -> InodeMetadata {
    let header = &entry.header;
    let uid = entry.uid.unwrap_or_else(|| header.uid().unwrap_or(0)) as u32;
    let gid = entry.gid.unwrap_or_else(|| header.gid().unwrap_or(0)) as u32;
    let mode = (header.mode().unwrap_or(0o644) & 0o7777) as u16;
    let mtime = header.mtime().unwrap_or(0);

    InodeMetadata {
        uid,
        gid,
        mode,
        mtime,
        mtime_nsec: 0,
    }
}

/// Get the filename component of a path (bytes after the last `/`).
fn path_filename(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(pos) => &path[pos + 1..],
        None => path,
    }
}

/// Get the parent portion of a path (bytes before the last `/`).
/// Returns an empty slice if there is no parent.
fn path_parent(path: &[u8]) -> &[u8] {
    match path.iter().rposition(|&b| b == b'/') {
        Some(pos) => &path[..pos],
        None => b"",
    }
}

/// Replace the filename component of a path with a new name.
fn replace_filename(path: &[u8], new_name: &[u8]) -> Vec<u8> {
    let parent = path_parent(path);
    if parent.is_empty() {
        new_name.to_vec()
    } else {
        let mut result = parent.to_vec();
        result.push(b'/');
        result.extend_from_slice(new_name);
        result
    }
}

/// Classify a filename as an OCI whiteout type.
///
/// OCI tar layers use two whiteout conventions:
/// - `.wh.<name>` — marks `<name>` as deleted in this layer
/// - `.wh..wh..opq` — marks the parent directory as opaque (hides all
///   entries from lower layers)
///
/// During ingestion these are converted to overlayfs-native representations:
/// `.wh.<name>` becomes a char device (0,0) inode, and `.wh..wh..opq`
/// becomes a `trusted.overlay.opaque=y` xattr on the parent directory.
fn classify_whiteout(filename: &[u8]) -> WhiteoutKind<'_> {
    if filename == OPAQUE_WHITEOUT {
        WhiteoutKind::Opaque
    } else if filename.starts_with(WHITEOUT_PREFIX) {
        let real_name = &filename[WHITEOUT_PREFIX.len()..];
        if real_name.is_empty() {
            WhiteoutKind::None
        } else {
            WhiteoutKind::File(real_name)
        }
    } else {
        WhiteoutKind::None
    }
}

/// Apply the opaque xattr to the parent directory of the given path.
fn apply_opaque_xattr(tree: &mut FileTree, path: &[u8]) -> Result<(), IngestError> {
    let parent = path_parent(path);

    // The parent is either the root (empty path) or a named directory.
    let dir = if parent.is_empty() {
        &mut tree.root
    } else {
        // Ensure the parent directory exists by inserting it if needed.
        match tree.get_mut(parent) {
            Some(TreeNode::Directory(dir)) => dir,
            _ => {
                // Create the parent directory, then retrieve it.
                let node = TreeNode::Directory(DirectoryNode::new(InodeMetadata::default()));
                tree.insert(parent, node)?;
                match tree.get_mut(parent) {
                    Some(TreeNode::Directory(dir)) => dir,
                    _ => {
                        return Err(IngestError::InvalidEntry(
                            "failed to create parent for opaque whiteout".to_string(),
                        ));
                    }
                }
            }
        }
    };

    // Add the opaque xattr if not already present.
    let already_has = dir
        .xattrs
        .iter()
        .any(|x| x.name == OPAQUE_XATTR_NAME && x.value == OPAQUE_XATTR_VALUE);

    if !already_has {
        dir.xattrs.push(Xattr {
            name: OPAQUE_XATTR_NAME.to_vec(),
            value: OPAQUE_XATTR_VALUE.to_vec(),
        });
    }

    Ok(())
}

/// Handle a hardlink entry by cloning the target's data to the new path.
fn handle_hardlink(
    tree: &mut FileTree,
    link_path: &[u8],
    target_path: &[u8],
) -> Result<(), IngestError> {
    let node = match tree.get_mut(target_path) {
        Some(TreeNode::RegularFile(f)) => {
            let new_nlink = f.nlink + 1;
            f.nlink = new_nlink;
            TreeNode::RegularFile(RegularFileNode {
                id: f.id,
                metadata: f.metadata.clone(),
                xattrs: f.xattrs.clone(),
                data: f.data.clone_ref(),
                nlink: new_nlink,
            })
        }
        Some(_) => {
            return Err(IngestError::HardlinkTarget(format!(
                "hardlink target is not a regular file: \"{}\"",
                String::from_utf8_lossy(target_path)
            )));
        }
        None => {
            return Err(IngestError::HardlinkTarget(
                String::from_utf8_lossy(target_path).into_owned(),
            ));
        }
    };

    tree.insert(link_path, node)?;

    Ok(())
}

async fn read_entry_to_memory<R: AsyncRead + Unpin>(
    entry: &mut R,
    size: u64,
) -> Result<Vec<u8>, IngestError> {
    let size = usize::try_from(size)
        .map_err(|_| IngestError::InvalidEntry("file too large to fit in memory".to_string()))?;
    let mut data = Vec::with_capacity(size);
    let mut remaining = size;

    while remaining > 0 {
        let start = data.len();
        let to_read = remaining.min(ENTRY_READ_CHUNK_SIZE);
        let read = {
            let mut read_buf = ReadBuf::uninit(&mut data.spare_capacity_mut()[..to_read]);
            poll_fn(|cx| Pin::new(&mut *entry).poll_read(cx, &mut read_buf))
                .await
                .map_err(IngestError::Io)?;
            read_buf.filled().len()
        };

        if read == 0 {
            return Err(IngestError::Io(std::io::Error::new(
                ErrorKind::UnexpectedEof,
                "failed to fill whole buffer",
            )));
        }

        // SAFETY: `poll_read` reported `read` initialized bytes in the spare
        // capacity window above, and the window begins at the previous length.
        unsafe {
            data.set_len(start + read);
        }
        remaining -= read;
    }

    Ok(data)
}

async fn stream_entry_to_spool<R: AsyncRead + Unpin>(
    entry: &mut R,
    size: u64,
    spool: &mut DataSpool,
    read_buf: &mut Vec<u8>,
    write_buf: &mut Vec<u8>,
) -> Result<FileData, IngestError> {
    let offset = spool.current_offset();
    let mut remaining = size;

    if read_buf.len() != ENTRY_READ_CHUNK_SIZE {
        read_buf.resize(ENTRY_READ_CHUNK_SIZE, 0);
    }
    if write_buf.capacity() < SPOOL_WRITE_BUFFER_SIZE {
        write_buf.reserve(SPOOL_WRITE_BUFFER_SIZE - write_buf.capacity());
    }
    write_buf.clear();

    while remaining > 0 {
        let to_read = remaining.min(read_buf.len() as u64) as usize;
        entry
            .read_exact(&mut read_buf[..to_read])
            .await
            .map_err(IngestError::Io)?;

        if write_buf.len() + to_read > SPOOL_WRITE_BUFFER_SIZE && !write_buf.is_empty() {
            spool.write_chunk(write_buf).map_err(IngestError::Io)?;
            write_buf.clear();
        }

        write_buf.extend_from_slice(&read_buf[..to_read]);
        remaining -= to_read as u64;
    }

    if !write_buf.is_empty() {
        spool.write_chunk(write_buf).map_err(IngestError::Io)?;
        write_buf.clear();
    }

    Ok(spool.data_ref(offset, size))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ---- Path normalization tests ----

    #[test]
    fn normalize_strips_dot_slash_prefix() {
        let limits = ResourceLimits::default();
        let result = normalize_path(b"./foo/bar.txt", &limits).unwrap();
        assert_eq!(result, Some(b"foo/bar.txt".to_vec()));
    }

    #[test]
    fn normalize_strips_bare_dot() {
        let limits = ResourceLimits::default();
        let result = normalize_path(b".", &limits).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn normalize_strips_dot_slash_only() {
        let limits = ResourceLimits::default();
        let result = normalize_path(b"./", &limits).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn normalize_strips_absolute_path_prefix() {
        let limits = ResourceLimits::default();
        let result = normalize_path(b"/etc/passwd", &limits).unwrap();
        assert_eq!(result, Some(b"etc/passwd".to_vec()));
    }

    #[test]
    fn normalize_skips_bare_root_path() {
        let limits = ResourceLimits::default();
        let result = normalize_path(b"/", &limits).unwrap();
        assert_eq!(result, None);
    }

    #[test]
    fn normalize_rejects_dotdot() {
        let limits = ResourceLimits::default();
        let result = normalize_path(b"foo/../etc/passwd", &limits);
        assert!(matches!(result, Err(IngestError::PathTraversal(_))));
    }

    #[test]
    fn normalize_rejects_leading_dotdot() {
        let limits = ResourceLimits::default();
        let result = normalize_path(b"../etc/passwd", &limits);
        assert!(matches!(result, Err(IngestError::PathTraversal(_))));
    }

    #[test]
    fn normalize_allows_dotdot_in_filename() {
        // A file literally named "..foo" is fine, only bare ".." is rejected.
        let limits = ResourceLimits::default();
        let result = normalize_path(b"dir/..foo", &limits).unwrap();
        assert_eq!(result, Some(b"dir/..foo".to_vec()));
    }

    #[test]
    fn normalize_enforces_path_length() {
        let limits = ResourceLimits {
            max_path_length: 10,
            ..ResourceLimits::default()
        };
        let result = normalize_path(b"a/very/long/path/here", &limits);
        assert!(matches!(result, Err(IngestError::PathTooLong(_))));
    }

    #[test]
    fn normalize_enforces_path_depth() {
        let limits = ResourceLimits {
            max_path_depth: 2,
            ..ResourceLimits::default()
        };
        let result = normalize_path(b"a/b/c", &limits);
        assert!(matches!(result, Err(IngestError::PathTooDeep(_))));
    }

    #[test]
    fn normalize_strips_trailing_slash() {
        let limits = ResourceLimits::default();
        let result = normalize_path(b"./foo/bar/", &limits).unwrap();
        assert_eq!(result, Some(b"foo/bar".to_vec()));
    }

    // ---- Compression detection tests ----

    #[test]
    fn detect_gzip_magic() {
        assert_eq!(
            Compression::detect(&[0x1F, 0x8B, 0x08, 0x00]),
            Compression::Gzip
        );
    }

    #[test]
    fn detect_zstd_magic() {
        assert_eq!(
            Compression::detect(&[0x28, 0xB5, 0x2F, 0xFD, 0x00]),
            Compression::Zstd
        );
    }

    #[test]
    fn detect_none_for_unknown() {
        assert_eq!(
            Compression::detect(&[0x00, 0x00, 0x00, 0x00]),
            Compression::None
        );
    }

    #[test]
    fn detect_none_for_short_input() {
        assert_eq!(Compression::detect(&[0x1F]), Compression::None);
    }

    #[test]
    fn detect_zstd_takes_priority_over_partial_gzip() {
        // Zstd magic is checked first (4 bytes), then gzip (2 bytes).
        assert_eq!(
            Compression::detect(&[0x28, 0xB5, 0x2F, 0xFD]),
            Compression::Zstd
        );
    }

    #[test]
    fn from_media_type_gzip() {
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.v1.tar+gzip"),
            Compression::Gzip
        );
    }

    #[test]
    fn from_media_type_zstd() {
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.v1.tar+zstd"),
            Compression::Zstd
        );
    }

    #[test]
    fn from_media_type_plain() {
        assert_eq!(
            Compression::from_media_type("application/vnd.oci.image.layer.v1.tar"),
            Compression::None
        );
    }

    // ---- Whiteout classification tests ----

    #[test]
    fn classify_whiteout_opaque() {
        assert!(matches!(
            classify_whiteout(b".wh..wh..opq"),
            WhiteoutKind::Opaque
        ));
    }

    #[test]
    fn classify_whiteout_regular() {
        match classify_whiteout(b".wh.myfile") {
            WhiteoutKind::File(name) => assert_eq!(name, b"myfile"),
            _ => panic!("expected WhiteoutKind::File"),
        }
    }

    #[test]
    fn classify_whiteout_empty_name() {
        // `.wh.` alone with nothing after should not be treated as a whiteout file.
        assert!(matches!(classify_whiteout(b".wh."), WhiteoutKind::None));
    }

    #[test]
    fn classify_whiteout_normal_file() {
        assert!(matches!(
            classify_whiteout(b"regular_file.txt"),
            WhiteoutKind::None
        ));
    }

    // ---- Helper function tests ----

    #[test]
    fn path_filename_with_parent() {
        assert_eq!(path_filename(b"a/b/c.txt"), b"c.txt");
    }

    #[test]
    fn path_filename_no_parent() {
        assert_eq!(path_filename(b"file.txt"), b"file.txt");
    }

    #[test]
    fn path_parent_with_components() {
        assert_eq!(path_parent(b"a/b/c.txt"), b"a/b");
    }

    #[test]
    fn path_parent_single_component() {
        assert_eq!(path_parent(b"file.txt"), b"");
    }

    #[test]
    fn replace_filename_with_parent() {
        assert_eq!(
            replace_filename(b"dir/.wh.myfile", b"myfile"),
            b"dir/myfile"
        );
    }

    #[test]
    fn replace_filename_no_parent() {
        assert_eq!(replace_filename(b".wh.myfile", b"myfile"), b"myfile");
    }

    // ---- Integration tests using the sync `tar` crate to build test archives ----

    // Use the synchronous builder only to construct test fixtures.
    use ::tar as sync_tar;
    use async_compression::tokio::write::GzipEncoder;
    use tempfile::tempdir;
    use tokio::io::AsyncWriteExt;

    fn physical_record(
        archive: &mut Vec<u8>,
        kind: u8,
        name: &[u8],
        declared_size: u64,
        body: &[u8],
    ) {
        let mut header = sync_tar::Header::new_ustar();
        header.as_ustar_mut().unwrap().name[..name.len()].copy_from_slice(name);
        header.set_entry_type(sync_tar::EntryType::new(kind));
        header.set_size(declared_size);
        header.set_mode(0o644);
        header.set_cksum();
        archive.extend_from_slice(header.as_bytes());
        archive.extend_from_slice(body);
        archive.resize(archive.len().next_multiple_of(512), 0);
    }

    fn pax_records(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut records = Vec::new();
        for (key, value) in fields {
            let base = key.len() + value.len() + 3;
            let mut len = base + 1;
            while len != base + len.to_string().len() {
                len = base + len.to_string().len();
            }
            records.extend_from_slice(format!("{len} ").as_bytes());
            records.extend_from_slice(key);
            records.push(b'=');
            records.extend_from_slice(value);
            records.push(b'\n');
        }
        records
    }

    #[tokio::test]
    async fn ingest_pax_overrides_names_ids_and_body_framing() {
        use tokio::io::AsyncWriteExt;

        let mut archive = Vec::new();
        let pax = pax_records(&[
            (b"path", b"discarded"),
            (b"path", b"dir/\xff"),
            (b"size", b"513"),
            (b"uid", b"1234"),
            (b"gid", b"2345"),
        ]);
        physical_record(&mut archive, b'x', b"PaxHeader", pax.len() as u64, &pax);
        let body = vec![b'q'; 513];
        physical_record(&mut archive, b'0', b"placeholder", 0, &body);
        let pax = pax_records(&[(b"linkpath", b"discarded"), (b"linkpath", b"dir/\xff")]);
        physical_record(&mut archive, b'x', b"PaxHeader", pax.len() as u64, &pax);
        physical_record(&mut archive, b'1', b"hardlink", 0, b"");
        let (mut sender, reader) = tokio::io::duplex(7);
        let send = async move { sender.write_all(&archive).await.unwrap() };
        let limits = ResourceLimits::default();
        let ((), tree) = tokio::join!(send, ingest_tar(reader, &limits, None));
        let tree = tree.unwrap();
        let Some(TreeNode::RegularFile(file)) = tree.get(b"dir/\xff") else {
            panic!("expected effective PAX path");
        };
        let Some(TreeNode::RegularFile(link)) = tree.get(b"hardlink") else {
            panic!("expected hardlink via effective PAX linkpath");
        };
        assert_eq!(file.data, FileData::Memory(body));
        assert_eq!((file.metadata.uid, file.metadata.gid), (1234, 2345));
        assert_eq!((file.id, file.nlink), (link.id, 2));
        assert!(tree.get(b"placeholder").is_none());
    }

    #[tokio::test]
    async fn ingest_gnu_names_stop_at_first_nul_without_consuming_pax_size() {
        let mut archive = Vec::new();
        let pax = pax_records(&[(b"size", b"513")]);
        physical_record(&mut archive, b'x', b"PaxHeader", pax.len() as u64, &pax);
        let name = b"gnu-name\0ignored";
        physical_record(&mut archive, b'L', b"LongName", name.len() as u64, name);
        let body = vec![b'q'; 513];
        physical_record(&mut archive, b'0', b"placeholder", 0, &body);
        let target = b"gnu-name\0ignored";
        physical_record(&mut archive, b'K', b"LongLink", target.len() as u64, target);
        physical_record(&mut archive, b'2', b"symlink", 0, b"");
        let tree = ingest_tar(archive.as_slice(), &ResourceLimits::default(), None)
            .await
            .unwrap();
        assert!(
            matches!(tree.get(b"gnu-name"), Some(TreeNode::RegularFile(file)) if file.data == FileData::Memory(body))
        );
        assert!(
            matches!(tree.get(b"symlink"), Some(TreeNode::Symlink(link)) if link.target == b"gnu-name")
        );
    }

    #[tokio::test]
    async fn ingest_rejects_invalid_or_ambiguous_local_extensions() {
        let path = pax_records(&[(b"path", b"equal")]);
        let link = pax_records(&[(b"linkpath", b"equal")]);
        for records in [
            vec![(b'x', b"12 path=x\n".as_slice())],
            vec![(b'x', path.as_slice()), (b'x', path.as_slice())],
            vec![(b'L', b"equal\0"), (b'L', b"equal\0")],
            vec![(b'x', path.as_slice()), (b'L', b"equal\0")],
            vec![(b'L', b"equal\0"), (b'x', path.as_slice())],
            vec![(b'x', link.as_slice()), (b'K', b"equal\0")],
            vec![(b'K', b"equal\0"), (b'x', link.as_slice())],
        ] {
            let mut archive = Vec::new();
            for (kind, payload) in records {
                physical_record(
                    &mut archive,
                    kind,
                    b"Extension",
                    payload.len() as u64,
                    payload,
                );
            }
            physical_record(&mut archive, b'0', b"file", 0, b"");
            assert!(matches!(
                ingest_tar(archive.as_slice(), &ResourceLimits::default(), None).await,
                Err(IngestError::Io(_))
            ));
        }
        let mut archive = Vec::new();
        physical_record(&mut archive, b'x', b"PaxHeader", path.len() as u64, &path);
        assert!(matches!(
            ingest_tar(archive.as_slice(), &ResourceLimits::default(), None).await,
            Err(IngestError::Io(_))
        ));
    }

    #[tokio::test]
    async fn ingest_preserves_solaris_local_and_ignored_global_pax_framing() {
        let mut archive = Vec::new();
        let pax = pax_records(&[(b"size", b"9999"), (b"path", b"ignored-name")]);
        physical_record(&mut archive, b'x', b"PaxHeader", pax.len() as u64, &pax);
        // Global metadata is neither parsed nor inherited.
        physical_record(&mut archive, b'g', b"Global", 7, b"ignored");
        let pax = pax_records(&[(b"path", b"solaris"), (b"uid", b"42")]);
        physical_record(&mut archive, b'X', b"Solaris", pax.len() as u64, &pax);
        physical_record(&mut archive, b'0', b"placeholder", 2, b"ok");

        let tree = ingest_tar(archive.as_slice(), &ResourceLimits::default(), None)
            .await
            .unwrap();
        assert_eq!(tree.node_count(), 1);
        assert!(
            matches!(tree.get(b"solaris"), Some(TreeNode::RegularFile(file))
            if file.data == FileData::Memory(b"ok".to_vec()) && file.metadata.uid == 42)
        );
    }

    #[tokio::test]
    async fn ingest_validates_and_skips_gnu_sparse_without_expanding_holes() {
        let mut header = sync_tar::Header::new_gnu();
        header.set_path("sparse").unwrap();
        header.set_entry_type(sync_tar::EntryType::GNUSparse);
        header.set_size(3);
        let hole = 1_u64 << 38; // forces base-256 GNU sparse numbers
        let gnu = header.as_gnu_mut().unwrap();
        gnu.set_real_size(hole + 3);
        gnu.set_is_extended(true);
        header.set_cksum();
        let mut extension = sync_tar::GnuExtSparseHeader::new();
        let first = &mut extension.sparse_mut()[0];
        first.set_offset(hole);
        first.set_length(3);

        let mut archive = header.as_bytes().to_vec();
        archive.extend_from_slice(extension.as_bytes());
        archive.extend_from_slice(b"abc");
        archive.resize(archive.len().next_multiple_of(512), 0);
        physical_record(&mut archive, b'0', b"after", 2, b"ok");
        let tree = ingest_tar(archive.as_slice(), &ResourceLimits::default(), None)
            .await
            .unwrap();
        assert!(tree.get(b"sparse").is_none());
        assert!(
            matches!(tree.get(b"after"), Some(TreeNode::RegularFile(file))
            if file.data == FileData::Memory(b"ok".to_vec()))
        );

        // A half-empty descriptor must not be silently ignored.
        let incomplete = &mut extension.sparse_mut()[1];
        incomplete.set_length(0);
        archive[512..1024].copy_from_slice(extension.as_bytes());
        assert!(matches!(
            ingest_tar(archive.as_slice(), &ResourceLimits::default(), None).await,
            Err(IngestError::Io(_))
        ));
    }

    #[tokio::test]
    async fn ingest_rejects_incomplete_records_and_ambiguous_ustar() {
        let mut archive = Vec::new();
        physical_record(&mut archive, b'0', b"file", 3, b"abc");
        for end in [511, 514, 1023] {
            assert!(matches!(
                ingest_tar(&archive[..end], &ResourceLimits::default(), None).await,
                Err(IngestError::Io(_))
            ));
        }

        let mut header = sync_tar::Header::new_ustar();
        header.set_path("file").unwrap();
        header.set_size(0);
        header.as_ustar_mut().unwrap().version = [0; 2];
        header.set_cksum();
        assert!(matches!(
            ingest_tar(
                header.as_bytes().as_slice(),
                &ResourceLimits::default(),
                None
            )
            .await,
            Err(IngestError::Io(_))
        ));

        let mut archive = Vec::new();
        physical_record(&mut archive, b'0', b"file", u64::MAX, b"");
        assert!(matches!(
            ingest_tar(archive.as_slice(), &ResourceLimits::default(), None).await,
            Err(IngestError::Io(_))
        ));
    }

    fn build_tar(build: impl FnOnce(&mut sync_tar::Builder<Vec<u8>>)) -> Vec<u8> {
        let mut builder = sync_tar::Builder::new(Vec::new());
        build(&mut builder);
        builder.into_inner().unwrap()
    }

    async fn gzip(data: &[u8]) -> Vec<u8> {
        let mut encoder = GzipEncoder::new(Vec::new());
        encoder.write_all(data).await.unwrap();
        encoder.shutdown().await.unwrap();
        encoder.into_inner()
    }

    #[tokio::test]
    async fn ingest_regular_file() {
        let data = build_tar(|b| {
            let content = b"hello world";
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("foo.txt").unwrap();
            header.set_size(content.len() as u64);
            header.set_entry_type(sync_tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_uid(1000);
            header.set_gid(1000);
            header.set_mtime(1234567890);
            header.set_cksum();
            b.append(&header, &content[..]).unwrap();
        });

        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, None)
            .await
            .unwrap();

        match tree.get(b"foo.txt").unwrap() {
            TreeNode::RegularFile(f) => {
                assert_eq!(f.data, FileData::Memory(b"hello world".to_vec()));
                assert_eq!(f.metadata.uid, 1000);
                assert_eq!(f.metadata.gid, 1000);
                assert_eq!(f.metadata.mode, 0o644);
                assert_eq!(f.metadata.mtime, 1234567890);
                assert_eq!(f.nlink, 1);
            }
            _ => panic!("expected regular file"),
        }
    }

    #[tokio::test]
    async fn ingest_gzip_large_file_without_spool() {
        let content = (0..SPOOL_THRESHOLD as usize * 8 + 13)
            .map(|i| (i % 251) as u8)
            .collect::<Vec<_>>();
        let tar_data = build_tar(|b| {
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("large.bin").unwrap();
            header.set_size(content.len() as u64);
            header.set_entry_type(sync_tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            b.append(&header, content.as_slice()).unwrap();
        });
        let data = gzip(&tar_data).await;

        let limits = ResourceLimits::default();
        let result =
            ingest_compressed_tar(std::io::Cursor::new(data), Compression::Gzip, &limits, None)
                .await
                .unwrap();

        match result.tree.get(b"large.bin").unwrap() {
            TreeNode::RegularFile(f) => {
                assert_eq!(f.data, FileData::Memory(content));
            }
            _ => panic!("expected regular file"),
        }
    }

    #[tokio::test]
    async fn ingest_large_file_spools_to_disk() {
        let content = vec![b'x'; SPOOL_THRESHOLD as usize + 1];
        let data = build_tar(|b| {
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("large.bin").unwrap();
            header.set_size(content.len() as u64);
            header.set_entry_type(sync_tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            b.append(&header, content.as_slice()).unwrap();
        });

        let tempdir = tempdir().unwrap();
        let spool_path = tempdir.path().join("layer.spool");
        let mut spool = DataSpool::new(&spool_path).unwrap();
        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, Some(&mut spool))
            .await
            .unwrap();

        match tree.get(b"large.bin").unwrap() {
            TreeNode::RegularFile(f) => {
                assert!(matches!(f.data, FileData::Spool { .. }));
                assert_eq!(f.data.read_all().unwrap(), content);
            }
            _ => panic!("expected regular file"),
        }
    }

    #[tokio::test]
    async fn ingest_multiple_large_files_spools_to_distinct_ranges() {
        let first = vec![b'a'; SPOOL_THRESHOLD as usize + 17];
        let second = vec![b'b'; SPOOL_THRESHOLD as usize * 2 + 31];
        let data = build_tar(|b| {
            for (path, content) in [
                ("first.bin", first.as_slice()),
                ("second.bin", second.as_slice()),
            ] {
                let mut header = sync_tar::Header::new_gnu();
                header.set_path(path).unwrap();
                header.set_size(content.len() as u64);
                header.set_entry_type(sync_tar::EntryType::Regular);
                header.set_mode(0o644);
                header.set_cksum();
                b.append(&header, content).unwrap();
            }
        });

        let tempdir = tempdir().unwrap();
        let spool_path = tempdir.path().join("layer.spool");
        let mut spool = DataSpool::new(&spool_path).unwrap();
        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, Some(&mut spool))
            .await
            .unwrap();

        for (path, content) in [
            (b"first.bin".as_slice(), first),
            (b"second.bin".as_slice(), second),
        ] {
            match tree.get(path).unwrap() {
                TreeNode::RegularFile(f) => {
                    assert!(matches!(f.data, FileData::Spool { .. }));
                    assert_eq!(f.data.read_all().unwrap(), content);
                }
                _ => panic!("expected regular file"),
            }
        }
    }

    #[tokio::test]
    async fn ingest_directory() {
        let data = build_tar(|b| {
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("mydir/").unwrap();
            header.set_size(0);
            header.set_entry_type(sync_tar::EntryType::Directory);
            header.set_mode(0o755);
            header.set_cksum();
            b.append(&header, &[] as &[u8]).unwrap();
        });

        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, None)
            .await
            .unwrap();

        match tree.get(b"mydir").unwrap() {
            TreeNode::Directory(d) => {
                assert_eq!(d.metadata.mode, 0o755);
            }
            _ => panic!("expected directory"),
        }
    }

    #[tokio::test]
    async fn ingest_symlink() {
        let data = build_tar(|b| {
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("link").unwrap();
            header.set_size(0);
            header.set_entry_type(sync_tar::EntryType::Symlink);
            header.set_link_name("/usr/bin/target").unwrap();
            header.set_mode(0o777);
            header.set_cksum();
            b.append(&header, &[] as &[u8]).unwrap();
        });

        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, None)
            .await
            .unwrap();

        match tree.get(b"link").unwrap() {
            TreeNode::Symlink(s) => {
                assert_eq!(s.target, b"/usr/bin/target");
            }
            _ => panic!("expected symlink"),
        }
    }

    #[tokio::test]
    async fn ingest_hardlink() {
        let data = build_tar(|b| {
            // First: the original file.
            let content = b"shared data";
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("original.txt").unwrap();
            header.set_size(content.len() as u64);
            header.set_entry_type(sync_tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            b.append(&header, &content[..]).unwrap();

            // Second: a hardlink to the original.
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("hardlink.txt").unwrap();
            header.set_size(0);
            header.set_entry_type(sync_tar::EntryType::Link);
            header.set_link_name("original.txt").unwrap();
            header.set_cksum();
            b.append(&header, &[] as &[u8]).unwrap();
        });

        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, None)
            .await
            .unwrap();

        // Both should exist with the same data, inode identity, and nlink=2.
        let original = match tree.get(b"original.txt").unwrap() {
            TreeNode::RegularFile(f) => f,
            _ => panic!("expected regular file"),
        };
        let hardlink = match tree.get(b"hardlink.txt").unwrap() {
            TreeNode::RegularFile(f) => f,
            _ => panic!("expected regular file"),
        };

        assert_eq!(original.data, FileData::Memory(b"shared data".to_vec()));
        assert_eq!(hardlink.data, FileData::Memory(b"shared data".to_vec()));
        assert_eq!(original.id, hardlink.id);
        assert_eq!(original.nlink, 2);
        assert_eq!(hardlink.nlink, 2);
        assert_eq!(tree.total_data_size(), b"shared data".len() as u64);
    }

    #[tokio::test]
    async fn ingest_hardlink_chain_refreshes_link_counts() {
        let data = build_tar(|b| {
            let content = b"shared data";
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("original.txt").unwrap();
            header.set_size(content.len() as u64);
            header.set_entry_type(sync_tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            b.append(&header, &content[..]).unwrap();

            for (link_name, target_name) in [
                ("hardlink-a.txt", "original.txt"),
                ("hardlink-b.txt", "hardlink-a.txt"),
            ] {
                let mut header = sync_tar::Header::new_gnu();
                header.set_path(link_name).unwrap();
                header.set_size(0);
                header.set_entry_type(sync_tar::EntryType::Link);
                header.set_link_name(target_name).unwrap();
                header.set_cksum();
                b.append(&header, &[] as &[u8]).unwrap();
            }
        });

        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, None)
            .await
            .unwrap();

        let ids = ["original.txt", "hardlink-a.txt", "hardlink-b.txt"].map(|path| {
            match tree.get(path.as_bytes()).unwrap() {
                TreeNode::RegularFile(f) => {
                    assert_eq!(f.nlink, 3);
                    f.id
                }
                _ => panic!("expected regular file"),
            }
        });

        assert_eq!(ids[0], ids[1]);
        assert_eq!(ids[0], ids[2]);
        assert_eq!(tree.total_data_size(), b"shared data".len() as u64);
    }

    #[tokio::test]
    async fn ingest_hardlink_missing_target() {
        let data = build_tar(|b| {
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("bad_link.txt").unwrap();
            header.set_size(0);
            header.set_entry_type(sync_tar::EntryType::Link);
            header.set_link_name("nonexistent.txt").unwrap();
            header.set_cksum();
            b.append(&header, &[] as &[u8]).unwrap();
        });

        let limits = ResourceLimits::default();
        let result = ingest_tar(std::io::Cursor::new(data), &limits, None).await;
        assert!(matches!(result, Err(IngestError::HardlinkTarget(_))));
    }

    #[tokio::test]
    async fn ingest_whiteout_file() {
        let data = build_tar(|b| {
            // A whiteout marker for "deleted_file".
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("dir/.wh.deleted_file").unwrap();
            header.set_size(0);
            header.set_entry_type(sync_tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            b.append(&header, &[] as &[u8]).unwrap();
        });

        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, None)
            .await
            .unwrap();

        // Should be inserted as a char device at "dir/deleted_file".
        match tree.get(b"dir/deleted_file").unwrap() {
            TreeNode::CharDevice(dev) => {
                assert_eq!(dev.major, 0);
                assert_eq!(dev.minor, 0);
            }
            _ => panic!("expected char device (whiteout)"),
        }

        // The .wh. file itself should not exist.
        assert!(tree.get(b"dir/.wh.deleted_file").is_none());
    }

    #[tokio::test]
    async fn ingest_opaque_whiteout() {
        let data = build_tar(|b| {
            // Create the parent directory first.
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("mydir/").unwrap();
            header.set_size(0);
            header.set_entry_type(sync_tar::EntryType::Directory);
            header.set_mode(0o755);
            header.set_cksum();
            b.append(&header, &[] as &[u8]).unwrap();

            // Opaque whiteout.
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("mydir/.wh..wh..opq").unwrap();
            header.set_size(0);
            header.set_entry_type(sync_tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            b.append(&header, &[] as &[u8]).unwrap();
        });

        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, None)
            .await
            .unwrap();

        // The parent directory should have the opaque xattr.
        match tree.get(b"mydir").unwrap() {
            TreeNode::Directory(d) => {
                assert!(
                    d.xattrs
                        .iter()
                        .any(|x| x.name == OPAQUE_XATTR_NAME && x.value == OPAQUE_XATTR_VALUE)
                );
            }
            _ => panic!("expected directory"),
        }
    }

    #[tokio::test]
    async fn ingest_accepts_absolute_path_in_tar() {
        let data = build_tar(|b| {
            let mut header = sync_tar::Header::new_gnu();
            header.set_size(0);
            header.set_entry_type(sync_tar::EntryType::Regular);
            header.set_mode(0o644);
            // Write path bytes directly into the GNU header name field
            // to bypass the tar crate's absolute-path rejection.
            let path_bytes = b"/etc/passwd";
            let gnu = header.as_gnu_mut().unwrap();
            gnu.name[..path_bytes.len()].copy_from_slice(path_bytes);
            gnu.name[path_bytes.len()] = 0;
            header.set_cksum();
            b.append(&header, &[] as &[u8]).unwrap();
        });

        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, None)
            .await
            .unwrap();
        assert!(matches!(
            tree.get(b"etc/passwd"),
            Some(TreeNode::RegularFile(_))
        ));
    }

    #[tokio::test]
    async fn ingest_accepts_absolute_hardlink_target() {
        let data = build_tar(|b| {
            let content = b"shared data";
            let mut header = sync_tar::Header::new_gnu();
            header.set_size(content.len() as u64);
            header.set_entry_type(sync_tar::EntryType::Regular);
            header.set_mode(0o644);
            let path_bytes = b"/nix/store/original.txt";
            let gnu = header.as_gnu_mut().unwrap();
            gnu.name[..path_bytes.len()].copy_from_slice(path_bytes);
            gnu.name[path_bytes.len()] = 0;
            header.set_cksum();
            b.append(&header, &content[..]).unwrap();

            let mut header = sync_tar::Header::new_gnu();
            header.set_size(0);
            header.set_entry_type(sync_tar::EntryType::Link);
            let path_bytes = b"/nix/store/link.txt";
            let link_bytes = b"/nix/store/original.txt";
            let gnu = header.as_gnu_mut().unwrap();
            gnu.name[..path_bytes.len()].copy_from_slice(path_bytes);
            gnu.name[path_bytes.len()] = 0;
            gnu.linkname[..link_bytes.len()].copy_from_slice(link_bytes);
            gnu.linkname[link_bytes.len()] = 0;
            header.set_cksum();
            b.append(&header, &[] as &[u8]).unwrap();
        });

        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, None)
            .await
            .unwrap();

        match tree.get(b"nix/store/link.txt").unwrap() {
            TreeNode::RegularFile(f) => {
                assert_eq!(f.data, FileData::Memory(b"shared data".to_vec()));
                assert_eq!(f.nlink, 2);
            }
            _ => panic!("expected regular file"),
        }
    }

    #[tokio::test]
    async fn ingest_entry_count_exceeded() {
        let data = build_tar(|b| {
            for i in 0..5 {
                let mut header = sync_tar::Header::new_gnu();
                header.set_path(format!("file{i}.txt")).unwrap();
                header.set_size(0);
                header.set_entry_type(sync_tar::EntryType::Regular);
                header.set_mode(0o644);
                header.set_cksum();
                b.append(&header, &[] as &[u8]).unwrap();
            }
        });

        let limits = ResourceLimits {
            max_entry_count: 3,
            ..ResourceLimits::default()
        };
        let result = ingest_tar(std::io::Cursor::new(data), &limits, None).await;
        assert!(matches!(result, Err(IngestError::EntryCountExceeded)));
    }

    #[tokio::test]
    async fn ingest_file_too_large() {
        let data = build_tar(|b| {
            let content = vec![0u8; 1024];
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("big.bin").unwrap();
            header.set_size(content.len() as u64);
            header.set_entry_type(sync_tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            b.append(&header, &content[..]).unwrap();
        });

        let limits = ResourceLimits {
            max_file_size: 512,
            ..ResourceLimits::default()
        };
        let result = ingest_tar(std::io::Cursor::new(data), &limits, None).await;
        assert!(matches!(result, Err(IngestError::FileTooLarge(_))));
    }

    #[tokio::test]
    async fn ingest_dot_slash_prefix_stripped() {
        let data = build_tar(|b| {
            let content = b"data";
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("./foo/bar.txt").unwrap();
            header.set_size(content.len() as u64);
            header.set_entry_type(sync_tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            b.append(&header, &content[..]).unwrap();
        });

        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, None)
            .await
            .unwrap();

        // Should be accessible without the ./ prefix.
        assert!(tree.get(b"foo/bar.txt").is_some());
    }

    #[tokio::test]
    async fn ingest_root_entry_skipped() {
        let data = build_tar(|b| {
            // Root directory entry `./`
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("./").unwrap();
            header.set_size(0);
            header.set_entry_type(sync_tar::EntryType::Directory);
            header.set_mode(0o755);
            header.set_cksum();
            b.append(&header, &[] as &[u8]).unwrap();

            // A regular file.
            let content = b"data";
            let mut header = sync_tar::Header::new_gnu();
            header.set_path("./file.txt").unwrap();
            header.set_size(content.len() as u64);
            header.set_entry_type(sync_tar::EntryType::Regular);
            header.set_mode(0o644);
            header.set_cksum();
            b.append(&header, &content[..]).unwrap();
        });

        let limits = ResourceLimits::default();
        let tree = ingest_tar(std::io::Cursor::new(data), &limits, None)
            .await
            .unwrap();

        // The root entry should not appear as a named node.
        // Only the file should exist.
        assert_eq!(tree.node_count(), 1);
        assert!(tree.get(b"file.txt").is_some());
    }
}
