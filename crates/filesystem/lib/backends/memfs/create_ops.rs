//! Creation operations: create, mkdir, mknod, symlink, link.

use std::{
    collections::BTreeMap,
    ffi::CStr,
    io,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

use super::{
    MemFs, inode,
    types::{FileHandle, InodeContent, InodeMeta, MemNode, ROOT_INODE},
};
use crate::{
    Context, Entry, Extensions, OpenOptions,
    backends::shared::{init_binary, name_validation, platform},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Create a regular file and open it atomically.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_create(
    fs: &MemFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    mode: u32,
    _kill_priv: bool,
    flags: u32,
    umask: u32,
    _extensions: Extensions,
) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
    name_validation::validate_memfs_name(name)?;

    if parent == ROOT_INODE && init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eexist());
    }

    let parent_node = inode::get_node(fs, parent)?;
    let ino = inode::alloc_inode(fs)?;
    let now = inode::current_time();
    let effective_mode = platform::MODE_REG | (mode & !umask & 0o7777);

    let node = Arc::new(MemNode {
        inode: ino,
        kind: platform::MODE_REG,
        lookup_refs: AtomicU64::new(1),
        meta: RwLock::new(InodeMeta {
            uid: ctx.uid,
            gid: ctx.gid,
            mode: effective_mode,
            rdev: 0,
            nlink: 1,
            size: 0,
            atime: now,
            mtime: now,
            ctime: now,
        }),
        content: InodeContent::RegularFile {
            data: RwLock::new(Vec::new()),
        },
        xattrs: RwLock::new(BTreeMap::new()),
    });

    // Insert into parent's children.
    let name_bytes = name.to_bytes().to_vec();
    match &parent_node.content {
        InodeContent::Directory { children, .. } => {
            let mut ch = children.write().unwrap();
            if ch.contains_key(&name_bytes) {
                // Undo inode allocation.
                fs.inode_count.fetch_sub(1, Ordering::Relaxed);
                return Err(platform::eexist());
            }
            ch.insert(name_bytes, ino);
        }
        _ => {
            fs.inode_count.fetch_sub(1, Ordering::Relaxed);
            return Err(platform::enotdir());
        }
    }

    // Update parent timestamps.
    {
        let mut meta = parent_node.meta.write().unwrap();
        meta.mtime = now;
        meta.ctime = now;
    }

    // Register node.
    fs.nodes.write().unwrap().insert(ino, node.clone());

    // Create file handle.
    let handle = fs.next_handle.fetch_add(1, Ordering::Relaxed);
    let handle_flags = super::normalize_handle_flags(fs.writeback.load(Ordering::Relaxed), flags);
    let fh = Arc::new(FileHandle {
        node: Arc::clone(&node),
        flags: handle_flags,
    });
    fs.file_handles.write().unwrap().insert(handle, fh);

    let entry = inode::build_entry(fs, &node);
    Ok((entry, Some(handle), fs.cache_open_options()))
}

/// Create a directory.
pub(crate) fn do_mkdir(
    fs: &MemFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    mode: u32,
    umask: u32,
    _extensions: Extensions,
) -> io::Result<Entry> {
    name_validation::validate_memfs_name(name)?;

    if parent == ROOT_INODE && init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eexist());
    }

    let parent_node = inode::get_node(fs, parent)?;
    let ino = inode::alloc_inode(fs)?;
    let now = inode::current_time();
    let effective_mode = platform::MODE_DIR | (mode & !umask & 0o7777);

    let node = Arc::new(MemNode {
        inode: ino,
        kind: platform::MODE_DIR,
        lookup_refs: AtomicU64::new(1),
        meta: RwLock::new(InodeMeta {
            uid: ctx.uid,
            gid: ctx.gid,
            mode: effective_mode,
            rdev: 0,
            nlink: 2, // . and parent's link
            size: 4096,
            atime: now,
            mtime: now,
            ctime: now,
        }),
        content: InodeContent::Directory {
            children: RwLock::new(BTreeMap::new()),
            parent: AtomicU64::new(parent),
        },
        xattrs: RwLock::new(BTreeMap::new()),
    });

    // Insert into parent's children.
    let name_bytes = name.to_bytes().to_vec();
    match &parent_node.content {
        InodeContent::Directory { children, .. } => {
            let mut ch = children.write().unwrap();
            if ch.contains_key(&name_bytes) {
                fs.inode_count.fetch_sub(1, Ordering::Relaxed);
                return Err(platform::eexist());
            }
            ch.insert(name_bytes, ino);
        }
        _ => {
            fs.inode_count.fetch_sub(1, Ordering::Relaxed);
            return Err(platform::enotdir());
        }
    }

    // Update parent: increment nlink (subdirectory adds a "..") and timestamps.
    {
        let mut meta = parent_node.meta.write().unwrap();
        meta.nlink += 1;
        meta.mtime = now;
        meta.ctime = now;
    }

    // Register node.
    fs.nodes.write().unwrap().insert(ino, node.clone());

    let entry = inode::build_entry(fs, &node);
    Ok(entry)
}

/// Create a file node (regular file, special file, etc).
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_mknod(
    fs: &MemFs,
    ctx: Context,
    parent: u64,
    name: &CStr,
    mode: u32,
    rdev: u32,
    umask: u32,
    _extensions: Extensions,
) -> io::Result<Entry> {
    name_validation::validate_memfs_name(name)?;

    if parent == ROOT_INODE && init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eexist());
    }

    let parent_node = inode::get_node(fs, parent)?;
    let ino = inode::alloc_inode(fs)?;
    let now = inode::current_time();

    let file_type = mode & platform::MODE_TYPE_MASK;
    let effective_mode = file_type | (mode & !umask & 0o7777);

    let (kind, content) = match file_type {
        m if m == platform::MODE_REG => (
            platform::MODE_REG,
            InodeContent::RegularFile {
                data: RwLock::new(Vec::new()),
            },
        ),
        m if m == platform::MODE_BLK
            || m == platform::MODE_CHR
            || m == platform::MODE_FIFO
            || m == platform::MODE_SOCK =>
        {
            (file_type, InodeContent::Special)
        }
        _ => {
            fs.inode_count.fetch_sub(1, Ordering::Relaxed);
            return Err(platform::einval());
        }
    };

    let node = Arc::new(MemNode {
        inode: ino,
        kind,
        lookup_refs: AtomicU64::new(1),
        meta: RwLock::new(InodeMeta {
            uid: ctx.uid,
            gid: ctx.gid,
            mode: effective_mode,
            rdev,
            nlink: 1,
            size: 0,
            atime: now,
            mtime: now,
            ctime: now,
        }),
        content,
        xattrs: RwLock::new(BTreeMap::new()),
    });

    // Insert into parent's children.
    let name_bytes = name.to_bytes().to_vec();
    match &parent_node.content {
        InodeContent::Directory { children, .. } => {
            let mut ch = children.write().unwrap();
            if ch.contains_key(&name_bytes) {
                fs.inode_count.fetch_sub(1, Ordering::Relaxed);
                return Err(platform::eexist());
            }
            ch.insert(name_bytes, ino);
        }
        _ => {
            fs.inode_count.fetch_sub(1, Ordering::Relaxed);
            return Err(platform::enotdir());
        }
    }

    // Update parent timestamps.
    {
        let mut meta = parent_node.meta.write().unwrap();
        meta.mtime = now;
        meta.ctime = now;
    }

    fs.nodes.write().unwrap().insert(ino, node.clone());

    let entry = inode::build_entry(fs, &node);
    Ok(entry)
}

/// Create a symbolic link.
pub(crate) fn do_symlink(
    fs: &MemFs,
    ctx: Context,
    linkname: &CStr,
    parent: u64,
    name: &CStr,
    _extensions: Extensions,
) -> io::Result<Entry> {
    name_validation::validate_memfs_name(name)?;

    if parent == ROOT_INODE && init_binary::is_init_name(name.to_bytes()) {
        return Err(platform::eexist());
    }

    let parent_node = inode::get_node(fs, parent)?;
    let ino = inode::alloc_inode(fs)?;
    let now = inode::current_time();
    let target = linkname.to_bytes().to_vec();

    let node = Arc::new(MemNode {
        inode: ino,
        kind: platform::MODE_LNK,
        lookup_refs: AtomicU64::new(1),
        meta: RwLock::new(InodeMeta {
            uid: ctx.uid,
            gid: ctx.gid,
            mode: platform::MODE_LNK | 0o777,
            rdev: 0,
            nlink: 1,
            size: target.len() as u64,
            atime: now,
            mtime: now,
            ctime: now,
        }),
        content: InodeContent::Symlink { target },
        xattrs: RwLock::new(BTreeMap::new()),
    });

    // Insert into parent's children.
    let name_bytes = name.to_bytes().to_vec();
    match &parent_node.content {
        InodeContent::Directory { children, .. } => {
            let mut ch = children.write().unwrap();
            if ch.contains_key(&name_bytes) {
                fs.inode_count.fetch_sub(1, Ordering::Relaxed);
                return Err(platform::eexist());
            }
            ch.insert(name_bytes, ino);
        }
        _ => {
            fs.inode_count.fetch_sub(1, Ordering::Relaxed);
            return Err(platform::enotdir());
        }
    }

    // Update parent timestamps.
    {
        let mut meta = parent_node.meta.write().unwrap();
        meta.mtime = now;
        meta.ctime = now;
    }

    fs.nodes.write().unwrap().insert(ino, node.clone());

    let entry = inode::build_entry(fs, &node);
    Ok(entry)
}

/// Create a hard link.
pub(crate) fn do_link(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    newparent: u64,
    newname: &CStr,
) -> io::Result<Entry> {
    name_validation::validate_memfs_name(newname)?;

    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    let node = inode::get_node(fs, ino)?;

    // Cannot hardlink directories.
    if node.kind == platform::MODE_DIR {
        return Err(platform::eperm());
    }

    let parent_node = inode::get_node(fs, newparent)?;
    let name_bytes = newname.to_bytes().to_vec();
    let now = inode::current_time();

    // Insert into parent's children.
    match &parent_node.content {
        InodeContent::Directory { children, .. } => {
            let mut ch = children.write().unwrap();
            if ch.contains_key(&name_bytes) {
                return Err(platform::eexist());
            }
            ch.insert(name_bytes, ino);
        }
        _ => return Err(platform::enotdir()),
    }

    // Increment nlink and lookup_refs.
    {
        let mut meta = node.meta.write().unwrap();
        meta.nlink += 1;
        meta.ctime = now;
    }
    inode::inc_lookup(&node);

    // Update parent timestamps.
    {
        let mut meta = parent_node.meta.write().unwrap();
        meta.mtime = now;
        meta.ctime = now;
    }

    let entry = inode::build_entry(fs, &node);
    Ok(entry)
}
