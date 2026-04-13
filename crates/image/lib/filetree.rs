use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::ffi::OsStrExt;
use std::sync::Arc;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEFAULT_MAX_TOTAL_SIZE: u64 = 10 * 1024 * 1024 * 1024; // 10 GiB
const DEFAULT_MAX_FILE_SIZE: u64 = 5 * 1024 * 1024 * 1024; // 5 GiB
const DEFAULT_MAX_ENTRY_COUNT: u64 = 1_000_000;
const DEFAULT_MAX_PATH_LENGTH: usize = 4096;
const DEFAULT_MAX_PATH_DEPTH: usize = 128;
const DEFAULT_MAX_SYMLINK_TARGET: usize = 4096;

const DEFAULT_DIR_MODE: u16 = 0o755;

/// Overlayfs whiteout: char device with major=0, minor=0 signals deletion.
pub(crate) const WHITEOUT_MAJOR: u32 = 0;
pub(crate) const WHITEOUT_MINOR: u32 = 0;

/// Overlayfs opaque directory xattr: hides all lower-layer entries.
pub(crate) const OPAQUE_XATTR_NAME: &[u8] = b"trusted.overlay.opaque";
pub(crate) const OPAQUE_XATTR_VALUE: &[u8] = b"y";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// File content storage — either in-memory for small files or spooled to
/// disk for large files to keep memory usage bounded.
pub enum FileData {
    /// Small file content held in memory.
    Memory(Vec<u8>),
    /// Large file content written to a shared spool file on disk.
    /// Multiple `FileData::Spool` entries can reference different regions
    /// of the same underlying spool file via `Arc`.
    Spool {
        spool: Arc<std::sync::Mutex<std::fs::File>>,
        offset: u64,
        len: u64,
    },
}

/// Threshold below which file data is kept in memory (64 KiB).
/// Files at or above this size are spooled to disk during tar ingestion.
pub const SPOOL_THRESHOLD: u64 = u64::MAX; // TODO: restore to 64 * 1024 after debugging

/// A writable spool file for large file data during tar ingestion.
pub struct DataSpool {
    file: std::fs::File,
    shared: Arc<std::sync::Mutex<std::fs::File>>,
    offset: u64,
}

pub struct ResourceLimits {
    pub max_total_size: u64,
    pub max_file_size: u64,
    pub max_entry_count: u64,
    pub max_path_length: usize,
    pub max_path_depth: usize,
    pub max_symlink_target: usize,
}

pub struct InodeMetadata {
    pub uid: u32,
    pub gid: u32,
    pub mode: u16,
    pub mtime: u64,
    pub mtime_nsec: u32,
}

pub struct Xattr {
    pub name: Vec<u8>,
    pub value: Vec<u8>,
}

pub enum TreeNode {
    RegularFile(RegularFileNode),
    Directory(DirectoryNode),
    Symlink(SymlinkNode),
    CharDevice(DeviceNode),
    BlockDevice(DeviceNode),
    Fifo(InodeMetadata),
    Socket(InodeMetadata),
}

pub struct RegularFileNode {
    pub metadata: InodeMetadata,
    pub xattrs: Vec<Xattr>,
    pub data: FileData,
    pub nlink: u32,
}

pub struct DirectoryNode {
    pub metadata: InodeMetadata,
    pub xattrs: Vec<Xattr>,
    pub entries: BTreeMap<OsString, TreeNode>,
}

pub struct SymlinkNode {
    pub metadata: InodeMetadata,
    pub target: Vec<u8>,
}

pub struct DeviceNode {
    pub metadata: InodeMetadata,
    pub major: u32,
    pub minor: u32,
}

pub struct FileTree {
    pub root: DirectoryNode,
}

#[derive(Debug)]
pub enum FileTreeError {
    PathEmpty,
    PathTraversal(String),
    NotADirectory(String),
    EntryExists(String),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl FileData {
    /// Total byte length of the file content.
    pub fn len(&self) -> usize {
        match self {
            FileData::Memory(v) => v.len(),
            FileData::Spool { len, .. } => *len as usize,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Read the entire content into memory. For `Memory` variant this
    /// clones; for `Spool` this reads from disk.
    pub fn read_all(&self) -> std::io::Result<Vec<u8>> {
        match self {
            FileData::Memory(v) => Ok(v.clone()),
            FileData::Spool { spool, offset, len } => {
                let mut buf = vec![0u8; *len as usize];
                let mut file = spool
                    .lock()
                    .map_err(|_| std::io::Error::other("spool lock poisoned"))?;
                file.seek(SeekFrom::Start(*offset))?;
                file.read_exact(&mut buf)?;
                Ok(buf)
            }
        }
    }

    /// Borrow the in-memory bytes directly (only for `Memory` variant).
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            FileData::Memory(v) => Some(v),
            FileData::Spool { .. } => None,
        }
    }

    /// Write content to an output writer, reading from spool if needed.
    /// Avoids loading the entire file into memory for large spooled files.
    pub fn write_to(&self, out: &mut impl std::io::Write) -> std::io::Result<()> {
        self.write_range(0, self.len(), out)
    }

    /// Write a byte range of the content to an output writer.
    pub fn write_range(
        &self,
        start: usize,
        len: usize,
        out: &mut impl std::io::Write,
    ) -> std::io::Result<()> {
        match self {
            FileData::Memory(v) => out.write_all(&v[start..start + len]),
            FileData::Spool { spool, offset, .. } => {
                let mut file = spool
                    .lock()
                    .map_err(|_| std::io::Error::other("spool lock poisoned"))?;
                file.seek(SeekFrom::Start(*offset + start as u64))?;
                let mut remaining = len;
                let mut buf = [0u8; 65536];
                while remaining > 0 {
                    let to_read = remaining.min(buf.len());
                    file.read_exact(&mut buf[..to_read])?;
                    out.write_all(&buf[..to_read])?;
                    remaining -= to_read;
                }
                Ok(())
            }
        }
    }
}

impl DataSpool {
    /// Create a new spool file at the given path.
    pub fn new(path: &std::path::Path) -> std::io::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .truncate(true)
            .read(true)
            .write(true)
            .open(path)?;
        let shared = Arc::new(std::sync::Mutex::new(file.try_clone()?));
        Ok(Self {
            file,
            shared,
            offset: 0,
        })
    }

    /// Write data to the spool and return a `FileData::Spool` reference.
    pub fn write_data(&mut self, data: &[u8]) -> std::io::Result<FileData> {
        use std::io::Write;
        let offset = self.offset;
        self.file.write_all(data)?;
        self.offset += data.len() as u64;
        Ok(FileData::Spool {
            spool: Arc::clone(&self.shared),
            offset,
            len: data.len() as u64,
        })
    }

    /// Clone a spool reference for a hardlinked file.
    pub fn clone_ref(data: &FileData) -> FileData {
        match data {
            FileData::Memory(v) => FileData::Memory(v.clone()),
            FileData::Spool { spool, offset, len } => FileData::Spool {
                spool: Arc::clone(spool),
                offset: *offset,
                len: *len,
            },
        }
    }
}

impl DirectoryNode {
    pub fn new(metadata: InodeMetadata) -> Self {
        Self {
            metadata,
            xattrs: Vec::new(),
            entries: BTreeMap::new(),
        }
    }

    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }
}

impl Default for FileTree {
    fn default() -> Self {
        Self::new()
    }
}

impl FileTree {
    pub fn new() -> Self {
        Self {
            root: DirectoryNode::new(InodeMetadata::default()),
        }
    }

    pub fn insert(&mut self, path: &[u8], node: TreeNode) -> Result<(), FileTreeError> {
        use std::collections::btree_map::Entry;

        let components = split_path(path)?;
        if components.is_empty() {
            return Err(FileTreeError::PathEmpty);
        }

        let (parent_components, file_name) = components.split_at(components.len() - 1);

        // Traverse to the parent directory, creating missing intermediates.
        // Uses the BTreeMap entry API to do a single lookup per component
        // instead of contains_key + insert + get_mut (3 lookups).
        let mut current = &mut self.root;
        for component in parent_components {
            let key = OsStr::from_bytes(component).to_os_string();
            current = match current.entries.entry(key) {
                Entry::Vacant(e) => {
                    let dir = TreeNode::Directory(DirectoryNode::new(InodeMetadata::default()));
                    match e.insert(dir) {
                        TreeNode::Directory(d) => d,
                        _ => unreachable!(),
                    }
                }
                Entry::Occupied(e) => match e.into_mut() {
                    TreeNode::Directory(d) => d,
                    _ => {
                        let path_str = String::from_utf8_lossy(component).into_owned();
                        return Err(FileTreeError::NotADirectory(path_str));
                    }
                },
            };
        }

        // Insert the final node. Directory-over-directory merges metadata
        // but keeps existing entries. Non-directory replaces non-directory.
        let key = OsStr::from_bytes(file_name[0]).to_os_string();
        match current.entries.entry(key) {
            Entry::Vacant(e) => {
                e.insert(node);
            }
            Entry::Occupied(mut e) => match (e.get(), &node) {
                (TreeNode::Directory(_), TreeNode::Directory(_)) => {
                    if let TreeNode::Directory(existing) = e.get_mut()
                        && let TreeNode::Directory(new_dir) = node
                    {
                        existing.metadata = new_dir.metadata;
                        existing.xattrs = new_dir.xattrs;
                    }
                }
                (TreeNode::Directory(_), _) => {
                    let path_str = String::from_utf8_lossy(file_name[0]).into_owned();
                    return Err(FileTreeError::EntryExists(path_str));
                }
                _ => {
                    e.insert(node);
                }
            },
        }

        Ok(())
    }

    pub fn get(&self, path: &[u8]) -> Option<&TreeNode> {
        let components = split_path(path).ok()?;
        if components.is_empty() {
            return None;
        }

        let (parent_components, file_name) = components.split_at(components.len() - 1);

        let mut current = &self.root;
        for component in parent_components {
            let key = OsStr::from_bytes(component);
            match current.entries.get(key) {
                Some(TreeNode::Directory(dir)) => {
                    current = dir;
                }
                _ => return None,
            }
        }

        current.entries.get(OsStr::from_bytes(file_name[0]))
    }

    pub fn get_mut(&mut self, path: &[u8]) -> Option<&mut TreeNode> {
        let components = split_path(path).ok()?;
        if components.is_empty() {
            return None;
        }

        let (parent_components, file_name) = components.split_at(components.len() - 1);

        let mut current = &mut self.root;
        for component in parent_components {
            let key = OsStr::from_bytes(component);
            match current.entries.get_mut(key) {
                Some(TreeNode::Directory(dir)) => {
                    current = dir;
                }
                _ => return None,
            }
        }

        current.entries.get_mut(OsStr::from_bytes(file_name[0]))
    }

    pub fn remove(&mut self, path: &[u8]) -> Option<TreeNode> {
        let components = split_path(path).ok()?;
        if components.is_empty() {
            return None;
        }

        let (parent_components, file_name) = components.split_at(components.len() - 1);

        let mut current = &mut self.root;
        for component in parent_components {
            let key = OsStr::from_bytes(component);
            match current.entries.get_mut(key) {
                Some(TreeNode::Directory(dir)) => {
                    current = dir;
                }
                _ => return None,
            }
        }

        current.entries.remove(OsStr::from_bytes(file_name[0]))
    }

    pub fn node_count(&self) -> u64 {
        count_nodes_in_dir(&self.root)
    }

    pub fn total_data_size(&self) -> u64 {
        data_size_in_dir(&self.root)
    }

    pub fn merge_layer(&mut self, layer: FileTree) {
        merge_directory(&mut self.root, layer.root);
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_total_size: DEFAULT_MAX_TOTAL_SIZE,
            max_file_size: DEFAULT_MAX_FILE_SIZE,
            max_entry_count: DEFAULT_MAX_ENTRY_COUNT,
            max_path_length: DEFAULT_MAX_PATH_LENGTH,
            max_path_depth: DEFAULT_MAX_PATH_DEPTH,
            max_symlink_target: DEFAULT_MAX_SYMLINK_TARGET,
        }
    }
}

impl Default for InodeMetadata {
    fn default() -> Self {
        Self {
            uid: 0,
            gid: 0,
            mode: DEFAULT_DIR_MODE,
            mtime: 0,
            mtime_nsec: 0,
        }
    }
}

impl fmt::Display for FileTreeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            FileTreeError::PathEmpty => write!(f, "path is empty"),
            FileTreeError::PathTraversal(p) => {
                write!(f, "path traversal attempt: \"..\" in path \"{p}\"")
            }
            FileTreeError::NotADirectory(p) => {
                write!(f, "not a directory: \"{p}\"")
            }
            FileTreeError::EntryExists(p) => {
                write!(f, "entry already exists: \"{p}\"")
            }
        }
    }
}

impl std::error::Error for FileTreeError {}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn split_path(path: &[u8]) -> Result<Vec<&[u8]>, FileTreeError> {
    let components: Vec<&[u8]> = path
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .collect();

    if components.is_empty() {
        return Err(FileTreeError::PathEmpty);
    }

    for component in &components {
        if *component == b".." {
            let path_str = String::from_utf8_lossy(path).into_owned();
            return Err(FileTreeError::PathTraversal(path_str));
        }
    }

    Ok(components)
}

fn count_nodes_in_dir(dir: &DirectoryNode) -> u64 {
    let mut count = 0u64;
    for node in dir.entries.values() {
        count += 1;
        if let TreeNode::Directory(child_dir) = node {
            count += count_nodes_in_dir(child_dir);
        }
    }
    count
}

fn data_size_in_dir(dir: &DirectoryNode) -> u64 {
    let mut size = 0u64;
    for node in dir.entries.values() {
        match node {
            TreeNode::RegularFile(file) => {
                size += file.data.len() as u64;
            }
            TreeNode::Directory(child_dir) => {
                size += data_size_in_dir(child_dir);
            }
            _ => {}
        }
    }
    size
}

fn is_whiteout_device(node: &TreeNode) -> bool {
    matches!(node, TreeNode::CharDevice(dev) if dev.major == WHITEOUT_MAJOR && dev.minor == WHITEOUT_MINOR)
}

fn has_opaque_xattr(dir: &DirectoryNode) -> bool {
    dir.xattrs
        .iter()
        .any(|x| x.name == OPAQUE_XATTR_NAME && x.value == OPAQUE_XATTR_VALUE)
}

fn merge_directory(base: &mut DirectoryNode, layer: DirectoryNode) {
    for (name, layer_node) in layer.entries {
        if is_whiteout_device(&layer_node) {
            base.entries.remove(&name);
            continue;
        }

        match layer_node {
            TreeNode::Directory(layer_dir) => {
                let opaque = has_opaque_xattr(&layer_dir);

                match base.entries.get_mut(&name) {
                    Some(TreeNode::Directory(base_dir)) => {
                        if opaque {
                            base_dir.entries.clear();
                        }
                        base_dir.metadata = layer_dir.metadata;
                        base_dir.xattrs = layer_dir.xattrs;
                        merge_directory(
                            base_dir,
                            DirectoryNode {
                                metadata: InodeMetadata::default(),
                                xattrs: Vec::new(),
                                entries: layer_dir.entries,
                            },
                        );
                    }
                    _ => {
                        base.entries.insert(name, TreeNode::Directory(layer_dir));
                    }
                }
            }
            other => {
                base.entries.insert(name, other);
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn make_regular_file(data: &[u8]) -> TreeNode {
        TreeNode::RegularFile(RegularFileNode {
            metadata: InodeMetadata::default(),
            xattrs: Vec::new(),
            data: data.to_vec(),
            nlink: 1,
        })
    }

    fn make_directory() -> TreeNode {
        TreeNode::Directory(DirectoryNode::new(InodeMetadata::default()))
    }

    fn make_whiteout() -> TreeNode {
        TreeNode::CharDevice(DeviceNode {
            metadata: InodeMetadata::default(),
            major: 0,
            minor: 0,
        })
    }

    fn make_opaque_directory() -> DirectoryNode {
        DirectoryNode {
            metadata: InodeMetadata::default(),
            xattrs: vec![Xattr {
                name: OPAQUE_XATTR_NAME.to_vec(),
                value: OPAQUE_XATTR_VALUE.to_vec(),
            }],
            entries: BTreeMap::new(),
        }
    }

    #[test]
    fn insert_and_get_file() {
        let mut tree = FileTree::new();
        tree.insert(b"hello.txt", make_regular_file(b"hello world"))
            .unwrap();

        let node = tree.get(b"hello.txt").unwrap();
        match node {
            TreeNode::RegularFile(f) => assert_eq!(f.data, b"hello world"),
            _ => panic!("expected regular file"),
        }
    }

    #[test]
    fn insert_with_missing_parents_creates_them() {
        let mut tree = FileTree::new();
        tree.insert(b"a/b/c/file.txt", make_regular_file(b"deep"))
            .unwrap();

        // Intermediate directories should exist.
        let node = tree.get(b"a").unwrap();
        assert!(matches!(node, TreeNode::Directory(_)));

        let node = tree.get(b"a/b").unwrap();
        assert!(matches!(node, TreeNode::Directory(_)));

        let node = tree.get(b"a/b/c").unwrap();
        assert!(matches!(node, TreeNode::Directory(_)));

        let node = tree.get(b"a/b/c/file.txt").unwrap();
        assert!(matches!(node, TreeNode::RegularFile(_)));
    }

    #[test]
    fn reject_dotdot_in_path() {
        let mut tree = FileTree::new();
        let result = tree.insert(b"a/../etc/passwd", make_regular_file(b"bad"));
        assert!(matches!(result, Err(FileTreeError::PathTraversal(_))));
    }

    #[test]
    fn merge_layer_replaces_file() {
        let mut base = FileTree::new();
        base.insert(b"config.txt", make_regular_file(b"old"))
            .unwrap();

        let mut layer = FileTree::new();
        layer
            .insert(b"config.txt", make_regular_file(b"new"))
            .unwrap();

        base.merge_layer(layer);

        match base.get(b"config.txt").unwrap() {
            TreeNode::RegularFile(f) => assert_eq!(f.data, b"new"),
            _ => panic!("expected regular file"),
        }
    }

    #[test]
    fn merge_layer_whiteout_removes_file() {
        let mut base = FileTree::new();
        base.insert(b"dir/secret.txt", make_regular_file(b"sensitive"))
            .unwrap();

        let mut layer = FileTree::new();
        layer.insert(b"dir", make_directory()).unwrap();
        layer.insert(b"dir/secret.txt", make_whiteout()).unwrap();

        base.merge_layer(layer);

        assert!(base.get(b"dir/secret.txt").is_none());
        // The parent directory should still exist.
        assert!(base.get(b"dir").is_some());
    }

    #[test]
    fn merge_layer_opaque_dir_clears_existing_entries() {
        let mut base = FileTree::new();
        base.insert(b"dir/a.txt", make_regular_file(b"a")).unwrap();
        base.insert(b"dir/b.txt", make_regular_file(b"b")).unwrap();

        let mut layer = FileTree::new();
        let mut opaque_dir = make_opaque_directory();
        opaque_dir
            .entries
            .insert(OsString::from("c.txt"), make_regular_file(b"c"));
        layer
            .root
            .entries
            .insert(OsString::from("dir"), TreeNode::Directory(opaque_dir));

        base.merge_layer(layer);

        // Old entries should be gone.
        assert!(base.get(b"dir/a.txt").is_none());
        assert!(base.get(b"dir/b.txt").is_none());
        // New entry should be present.
        match base.get(b"dir/c.txt").unwrap() {
            TreeNode::RegularFile(f) => assert_eq!(f.data, b"c"),
            _ => panic!("expected regular file"),
        }
    }

    #[test]
    fn node_count_and_data_size() {
        let mut tree = FileTree::new();
        tree.insert(b"a/file1.txt", make_regular_file(b"hello"))
            .unwrap();
        tree.insert(b"a/file2.txt", make_regular_file(b"world!"))
            .unwrap();
        tree.insert(b"b/nested/file3.txt", make_regular_file(b"!"))
            .unwrap();

        // a, a/file1.txt, a/file2.txt, b, b/nested, b/nested/file3.txt = 6
        assert_eq!(tree.node_count(), 6);
        // 5 + 6 + 1 = 12
        assert_eq!(tree.total_data_size(), 12);
    }

    #[test]
    fn remove_node() {
        let mut tree = FileTree::new();
        tree.insert(b"a/b.txt", make_regular_file(b"data")).unwrap();
        assert!(tree.get(b"a/b.txt").is_some());

        let removed = tree.remove(b"a/b.txt");
        assert!(removed.is_some());
        assert!(tree.get(b"a/b.txt").is_none());
    }

    #[test]
    fn empty_path_is_rejected() {
        let mut tree = FileTree::new();
        let result = tree.insert(b"", make_regular_file(b"data"));
        assert!(matches!(result, Err(FileTreeError::PathEmpty)));
    }

    #[test]
    fn not_a_directory_error() {
        let mut tree = FileTree::new();
        tree.insert(b"a", make_regular_file(b"file")).unwrap();

        let result = tree.insert(b"a/b", make_regular_file(b"nested"));
        assert!(matches!(result, Err(FileTreeError::NotADirectory(_))));
    }

    #[test]
    fn resource_limits_default() {
        let limits = ResourceLimits::default();
        assert_eq!(limits.max_total_size, 10 * 1024 * 1024 * 1024);
        assert_eq!(limits.max_file_size, 5 * 1024 * 1024 * 1024);
        assert_eq!(limits.max_entry_count, 1_000_000);
        assert_eq!(limits.max_path_length, 4096);
        assert_eq!(limits.max_path_depth, 128);
        assert_eq!(limits.max_symlink_target, 4096);
    }
}
