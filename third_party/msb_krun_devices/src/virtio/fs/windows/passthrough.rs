use std::collections::btree_map;
use std::collections::BTreeMap;
use std::convert::TryInto;
use std::ffi::{CStr, OsStr};
use std::fs::{File, FileType, OpenOptions as StdOpenOptions};
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicI32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use crossbeam_channel::{unbounded, Sender};
use windows_sys::Win32::Foundation::{
    ERROR_ACCESS_DENIED, ERROR_ALREADY_EXISTS, ERROR_DIR_NOT_EMPTY, ERROR_FILE_EXISTS,
    ERROR_FILE_NOT_FOUND, ERROR_INVALID_NAME, ERROR_PATH_NOT_FOUND, ERROR_PRIVILEGE_NOT_HELD,
    ERROR_SHARING_VIOLATION,
};
use windows_sys::Win32::Storage::FileSystem::{
    CreateSymbolicLinkW, GetDiskFreeSpaceExW, FILE_ATTRIBUTE_READONLY,
    SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE, SYMBOLIC_LINK_FLAG_DIRECTORY,
};

use crate::windows::memory_mapping::{
    discard_file_range, is_unsupported_discard_error, WindowsFileMappingAccess,
    WindowsFileMappingView,
};

use super::super::bindings;
use super::super::filesystem::{
    Context, DirEntry, Entry, ExportTable, Extensions, FileSystem, FsOptions, GetxattrReply,
    ListxattrReply, OpenOptions, SetattrValid, ZeroCopyReader, ZeroCopyWriter,
};
use super::super::fuse;
use utils::worker_message::WorkerMessage;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const INIT_CSTR: &[u8] = b"init.krun\0";
const INIT_BINARY: &[u8] = include_bytes!("../../../../init");

const DT_UNKNOWN: u32 = 0;
const DT_DIR: u32 = 4;
const DT_REG: u32 = 8;
const DT_LNK: u32 = 10;

const LINUX_EIO: i32 = 5;
const LINUX_EBADF: i32 = 9;
const LINUX_EACCES: i32 = 13;
const LINUX_EBUSY: i32 = 16;
const LINUX_EEXIST: i32 = 17;
const LINUX_ENOENT: i32 = 2;
const LINUX_ENOTDIR: i32 = 20;
const LINUX_EISDIR: i32 = 21;
const LINUX_EINVAL: i32 = 22;
const LINUX_ENOTEMPTY: i32 = 39;
const LINUX_ELOOP: i32 = 40;
const LINUX_EOPNOTSUPP: i32 = 95;

const LINUX_O_ACCMODE: i32 = 0o3;
const LINUX_O_WRONLY: i32 = 0o1;
const LINUX_O_RDWR: i32 = 0o2;

const FALLOC_FL_KEEP_SIZE: u32 = 0x01;
const FALLOC_FL_PUNCH_HOLE: u32 = 0x02;

const S_IFMT: u32 = 0o170000;
const S_IFREG: u32 = 0o100000;
const S_IFDIR: u32 = 0o040000;
const S_IFLNK: u32 = 0o120000;

const WINDOWS_TICKS_PER_SECOND: u64 = 10_000_000;
const WINDOWS_TO_UNIX_EPOCH_SECONDS: u64 = 11_644_473_600;
const STATFS_FRAGMENT_SIZE: u64 = 4096;
const STATFS_NAME_MAX: u64 = 255;

type Inode = u64;
type Handle = u64;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct Config {
    pub root_dir: String,
    pub allow_root_dir_delete: bool,
    pub export_fsid: u64,
    pub export_table: Option<ExportTable>,
}

pub struct PassthroughFs {
    inodes: RwLock<InodeTable>,
    next_inode: AtomicU64,
    init_inode: u64,
    handles: RwLock<BTreeMap<Handle, Arc<HandleData>>>,
    next_handle: AtomicU64,
    init_handle: u64,
    map_windows: Mutex<BTreeMap<u64, WindowsFileMappingView>>,
    root: PathBuf,
    _cfg: Config,
}

#[derive(Default)]
struct InodeTable {
    by_inode: BTreeMap<Inode, Arc<InodeData>>,
    by_path: BTreeMap<PathBuf, Arc<InodeData>>,
}

struct InodeData {
    inode: Inode,
    path: PathBuf,
    refcount: AtomicU64,
}

struct HandleData {
    inode: Inode,
    flags: u32,
    kind: HandleKind,
    dirstream: Mutex<DirStream>,
}

enum HandleKind {
    File(RwLock<File>),
    Directory(PathBuf),
}

struct CachedDirEntry {
    ino: bindings::ino64_t,
    offset: u64,
    type_: u32,
    name: Box<[u8]>,
}

#[derive(Default)]
struct DirStream {
    entries: Vec<CachedDirEntry>,
    ready: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub fn new(cfg: Config) -> io::Result<Self> {
        let root = std::fs::canonicalize(&cfg.root_dir).map_err(host_error)?;
        let metadata = std::fs::symlink_metadata(&root).map_err(host_error)?;
        if !metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        Ok(Self {
            inodes: RwLock::new(InodeTable::default()),
            next_inode: AtomicU64::new(fuse::ROOT_ID + 2),
            init_inode: fuse::ROOT_ID + 1,
            handles: RwLock::new(BTreeMap::new()),
            next_handle: AtomicU64::new(1),
            init_handle: 0,
            map_windows: Mutex::new(BTreeMap::new()),
            root,
            _cfg: cfg,
        })
    }

    fn do_lookup(&self, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let child = self.child_path(parent, name)?;
        let metadata = std::fs::symlink_metadata(&child).map_err(host_error)?;
        let inode_data = self.intern_path(child, 1);
        let attr = stat_from_metadata(&metadata, inode_data.inode);

        Ok(Entry {
            inode: inode_data.inode,
            generation: 0,
            attr,
            attr_flags: 0,
            attr_timeout: self.cfg_attr_timeout(),
            entry_timeout: self.cfg_entry_timeout(),
        })
    }

    fn child_path(&self, parent: Inode, name: &CStr) -> io::Result<PathBuf> {
        let name = cstr_to_component(name)?;
        let parent = self.inode(parent)?.path.clone();
        Ok(parent.join(name))
    }

    fn inode(&self, inode: Inode) -> io::Result<Arc<InodeData>> {
        self.inodes
            .read()
            .unwrap()
            .by_inode
            .get(&inode)
            .cloned()
            .ok_or_else(|| linux_error(LINUX_EBADF))
    }

    fn intern_path(&self, path: PathBuf, lookup_count: u64) -> Arc<InodeData> {
        let mut table = self.inodes.write().unwrap();
        if let Some(data) = table.by_path.get(&path) {
            if lookup_count != 0 {
                data.refcount.fetch_add(lookup_count, Ordering::Acquire);
            }
            return data.clone();
        }

        let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
        let data = Arc::new(InodeData {
            inode,
            path: path.clone(),
            refcount: AtomicU64::new(lookup_count),
        });
        table.by_inode.insert(inode, data.clone());
        table.by_path.insert(path, data.clone());
        data
    }

    fn insert_root(&self) -> io::Result<bindings::stat64> {
        let metadata = std::fs::symlink_metadata(&self.root).map_err(host_error)?;
        let data = Arc::new(InodeData {
            inode: fuse::ROOT_ID,
            path: self.root.clone(),
            refcount: AtomicU64::new(2),
        });

        let mut table = self.inodes.write().unwrap();
        table.by_inode.clear();
        table.by_path.clear();
        table.by_inode.insert(fuse::ROOT_ID, data.clone());
        table.by_path.insert(self.root.clone(), data);

        Ok(stat_from_metadata(&metadata, fuse::ROOT_ID))
    }

    fn do_open(&self, inode: Inode, flags: u32) -> io::Result<(Option<Handle>, OpenOptions)> {
        let data = self.inode(inode)?;
        let options = open_options_from_flags(flags, false)?;
        reject_symlink(&data.path)?;

        let metadata = std::fs::symlink_metadata(&data.path).map_err(host_error)?;
        if metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_EISDIR));
        }

        let file = options.open(&data.path).map_err(host_error)?;
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode,
            flags,
            kind: HandleKind::File(RwLock::new(file)),
            dirstream: Mutex::new(DirStream::default()),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));
        Ok((Some(handle), OpenOptions::empty()))
    }

    fn do_opendir(&self, inode: Inode, flags: u32) -> io::Result<(Option<Handle>, OpenOptions)> {
        validate_directory_open(flags)?;

        let data = self.inode(inode)?;
        let metadata = std::fs::symlink_metadata(&data.path).map_err(host_error)?;
        if !metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode,
            flags,
            kind: HandleKind::Directory(data.path.clone()),
            dirstream: Mutex::new(DirStream::default()),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));
        Ok((Some(handle), OpenOptions::empty()))
    }

    fn do_release(&self, inode: Inode, handle: Handle) -> io::Result<()> {
        let mut handles = self.handles.write().unwrap();
        if let btree_map::Entry::Occupied(entry) = handles.entry(handle) {
            if entry.get().inode == inode {
                entry.remove();
                return Ok(());
            }
        }

        Err(linux_error(LINUX_EBADF))
    }

    fn handle(&self, inode: Inode, handle: Handle) -> io::Result<Arc<HandleData>> {
        self.handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.inode == inode)
            .cloned()
            .ok_or_else(|| linux_error(LINUX_EBADF))
    }

    fn forget_path(&self, path: &Path) {
        let mut inodes = self.inodes.write().unwrap();
        if let Some(data) = inodes.by_path.remove(path) {
            inodes.by_inode.remove(&data.inode);
        }
    }

    fn entry_for_path(&self, path: PathBuf, lookup_count: u64) -> io::Result<Entry> {
        let metadata = std::fs::symlink_metadata(&path).map_err(host_error)?;
        let inode_data = self.intern_path(path, lookup_count);
        let attr = stat_from_metadata(&metadata, inode_data.inode);

        Ok(Entry {
            inode: inode_data.inode,
            generation: 0,
            attr,
            attr_flags: 0,
            attr_timeout: self.cfg_attr_timeout(),
            entry_timeout: self.cfg_entry_timeout(),
        })
    }

    fn do_create(
        &self,
        parent: Inode,
        name: &CStr,
        flags: u32,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        let path = self.child_path(parent, name)?;
        let parent = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let metadata = std::fs::symlink_metadata(parent).map_err(host_error)?;
        if !metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let options = open_options_from_flags(flags, true)?;
        let file = options.open(&path).map_err(host_error)?;
        let entry = self.entry_for_path(path, 1)?;
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let data = HandleData {
            inode: entry.inode,
            flags,
            kind: HandleKind::File(RwLock::new(file)),
            dirstream: Mutex::new(DirStream::default()),
        };

        self.handles.write().unwrap().insert(handle, Arc::new(data));
        Ok((entry, Some(handle), OpenOptions::empty()))
    }

    fn do_mkdir(&self, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let path = self.child_path(parent, name)?;
        std::fs::create_dir(&path).map_err(host_error)?;
        self.entry_for_path(path, 1)
    }

    fn do_unlink(&self, parent: Inode, name: &CStr) -> io::Result<()> {
        let path = self.child_path(parent, name)?;
        std::fs::remove_file(&path).map_err(host_error)?;
        self.forget_path(&path);
        Ok(())
    }

    fn do_rmdir(&self, parent: Inode, name: &CStr) -> io::Result<()> {
        let path = self.child_path(parent, name)?;
        std::fs::remove_dir(&path).map_err(host_error)?;
        self.forget_path(&path);
        Ok(())
    }

    fn do_rename(
        &self,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        if flags & bindings::LINUX_RENAME_EXCHANGE as u32 != 0
            || flags & bindings::LINUX_RENAME_WHITEOUT as u32 != 0
        {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }

        let old_path = self.child_path(olddir, oldname)?;
        let new_path = self.child_path(newdir, newname)?;
        if flags & bindings::LINUX_RENAME_NOREPLACE as u32 != 0 && new_path.exists() {
            return Err(linux_error(LINUX_EEXIST));
        }

        std::fs::rename(&old_path, &new_path).map_err(host_error)?;
        self.rename_inode_path(&old_path, &new_path);
        Ok(())
    }

    fn rename_inode_path(&self, old_path: &Path, new_path: &Path) {
        let mut inodes = self.inodes.write().unwrap();
        let Some(old_data) = inodes.by_path.remove(old_path) else {
            if let Some(replaced) = inodes.by_path.remove(new_path) {
                inodes.by_inode.remove(&replaced.inode);
            }
            return;
        };

        if let Some(replaced) = inodes.by_path.remove(new_path) {
            inodes.by_inode.remove(&replaced.inode);
        }

        // Windows does not give this backend a cheap fd-like identity for every path. Preserve the
        // guest-visible source inode across rename by moving its path entry, which matches the
        // important POSIX behavior for atomic temp-file replacement patterns such as heartbeat files.
        let data = Arc::new(InodeData {
            inode: old_data.inode,
            path: new_path.to_path_buf(),
            refcount: AtomicU64::new(old_data.refcount.load(Ordering::Acquire)),
        });
        inodes.by_inode.insert(data.inode, data.clone());
        inodes.by_path.insert(new_path.to_path_buf(), data);
    }

    fn do_symlink(&self, linkname: &CStr, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let path = self.child_path(parent, name)?;
        let parent_path = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let metadata = std::fs::symlink_metadata(parent_path).map_err(host_error)?;
        if !metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let target = cstr_to_symlink_target(linkname)?;
        create_windows_symlink(&path, &target, symlink_target_is_directory(&path, &target))?;
        self.entry_for_path(path, 1)
    }

    fn do_readlink(&self, inode: Inode) -> io::Result<Vec<u8>> {
        let data = self.inode(inode)?;
        let metadata = std::fs::symlink_metadata(&data.path).map_err(host_error)?;
        if !metadata.file_type().is_symlink() {
            return Err(linux_error(LINUX_EINVAL));
        }

        let target = std::fs::read_link(&data.path).map_err(host_error)?;
        Ok(path_to_guest_bytes(&target))
    }

    fn do_readdir<F>(
        &self,
        inode: Inode,
        handle: Handle,
        size: u32,
        mut offset: u64,
        mut add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        if size == 0 {
            return Ok(());
        }

        let handle_data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.inode == inode)
            .cloned()
            .ok_or_else(|| linux_error(LINUX_EBADF))?;

        let dir = match &handle_data.kind {
            HandleKind::Directory(path) => path.clone(),
            HandleKind::File(_) => return Err(linux_error(LINUX_ENOTDIR)),
        };

        let mut dirstream = handle_data.dirstream.lock().unwrap();
        if !dirstream.ready {
            self.fill_dir_stream(&dir, &mut dirstream)?;
        }

        while let Some(entry) = dirstream.get_entry(offset) {
            offset += 1;
            if add_entry(entry)? == 0 {
                break;
            }
        }

        Ok(())
    }

    fn fill_dir_stream(&self, dir: &Path, dirstream: &mut DirStream) -> io::Result<()> {
        for entry in std::fs::read_dir(dir).map_err(host_error)? {
            let entry = entry.map_err(host_error)?;
            let file_type = entry.file_type().map_err(host_error)?;
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.is_empty() || name == "." || name == ".." {
                continue;
            }

            let inode = self.intern_path(entry.path(), 0).inode;
            dirstream.entries.push(CachedDirEntry {
                ino: inode,
                offset: dirstream.entries.len() as u64 + 1,
                type_: dirent_type(file_type),
                name: name.into_bytes().into_boxed_slice(),
            });
        }

        dirstream.ready = true;
        Ok(())
    }

    fn do_getattr(&self, inode: Inode) -> io::Result<(bindings::stat64, Duration)> {
        if inode == self.init_inode {
            return Ok((init_stat(self.init_inode), self.cfg_attr_timeout()));
        }

        let data = self.inode(inode)?;
        let metadata = std::fs::symlink_metadata(&data.path).map_err(host_error)?;
        Ok((
            stat_from_metadata(&metadata, inode),
            self.cfg_attr_timeout(),
        ))
    }

    fn cfg_entry_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    fn cfg_attr_timeout(&self) -> Duration {
        Duration::from_secs(5)
    }

    #[allow(clippy::too_many_arguments)]
    fn do_setupmapping(
        &self,
        inode: Inode,
        handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        let sender = map_sender
            .as_ref()
            .ok_or_else(|| linux_error(bindings::LINUX_ENOSYS))?;
        let guest_addr = checked_mapping_guest_addr(moffset, len, guest_shm_base, shm_size)?;
        let len: usize = len.try_into().map_err(|_| linux_error(LINUX_EINVAL))?;
        let access = mapping_access(flags);

        debug!(
            "setupmapping: ino {inode:?} handle={handle} foffset={foffset:x} moffset={moffset:x} len={len} flags={flags:x}"
        );
        if self.map_windows.lock().unwrap().contains_key(&guest_addr) {
            return Err(linux_error(LINUX_EBUSY));
        }

        let view = if inode == self.init_inode {
            init_mapping_view(foffset, len, access)?
        } else {
            let data = self.inode(inode)?;
            reject_symlink(&data.path)?;
            let metadata = std::fs::symlink_metadata(&data.path).map_err(host_error)?;
            if metadata.file_type().is_dir() {
                return Err(linux_error(LINUX_EISDIR));
            }

            mapping_view_for_path(&data.path, foffset, len, access)?
        };

        let host_addr = view.host_addr();
        debug!("setupmapping: ino {inode:?} guest_addr={guest_addr:x} len={len}");
        request_mapping(
            sender,
            host_addr,
            guest_addr,
            len as u64,
            access == WindowsFileMappingAccess::ReadWrite,
        )?;

        self.map_windows.lock().unwrap().insert(guest_addr, view);
        Ok(())
    }

    fn do_removemapping(
        &self,
        requests: Vec<fuse::RemovemappingOne>,
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        let sender = map_sender
            .as_ref()
            .ok_or_else(|| linux_error(bindings::LINUX_ENOSYS))?;

        for req in requests {
            let guest_addr =
                checked_mapping_guest_addr(req.moffset, req.len, guest_shm_base, shm_size)?;
            debug!("removemapping: guest_addr={guest_addr:x} len={}", req.len);

            let view = self
                .map_windows
                .lock()
                .unwrap()
                .remove(&guest_addr)
                .ok_or_else(|| linux_error(LINUX_EINVAL))?;
            request_unmapping(sender, guest_addr, req.len)?;
            drop(view);
        }

        Ok(())
    }

    fn do_fallocate(
        &self,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        let handle_data = self.handle(inode, handle)?;
        let file = match &handle_data.kind {
            HandleKind::File(file) => file.write().unwrap(),
            HandleKind::Directory(_) => return Err(linux_error(LINUX_EISDIR)),
        };

        match mode {
            0 => {
                let len = offset
                    .checked_add(length)
                    .ok_or_else(|| linux_error(LINUX_EINVAL))?;
                if file.metadata().map_err(host_error)?.len() < len {
                    file.set_len(len).map_err(host_error)?;
                }
                Ok(())
            }
            mode if mode == (FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE) => {
                discard_file_range(&file, offset, length).map_err(|error| {
                    if is_unsupported_discard_error(&error) {
                        linux_error(LINUX_EOPNOTSUPP)
                    } else {
                        host_error(error)
                    }
                })
            }
            _ => Err(linux_error(LINUX_EOPNOTSUPP)),
        }
    }
}

impl DirStream {
    fn get_entry(&self, offset: u64) -> Option<DirEntry<'_>> {
        self.entries.get(offset as usize).map(|entry| DirEntry {
            ino: entry.ino,
            offset: entry.offset,
            type_: entry.type_,
            name: &entry.name,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl FileSystem for PassthroughFs {
    type Inode = Inode;
    type Handle = Handle;

    fn init(&self, capable: FsOptions) -> io::Result<FsOptions> {
        self.insert_root()?;

        let mut opts = FsOptions::empty();
        if capable.contains(FsOptions::HAS_IOCTL_DIR) {
            opts |= FsOptions::HAS_IOCTL_DIR;
        }

        Ok(opts)
    }

    fn destroy(&self) {
        self.map_windows.lock().unwrap().clear();
        self.handles.write().unwrap().clear();
        self.inodes.write().unwrap().by_inode.clear();
        self.inodes.write().unwrap().by_path.clear();
    }

    fn statfs(&self, _ctx: Context, inode: Inode) -> io::Result<bindings::statvfs64> {
        if inode != self.init_inode {
            let _ = self.inode(inode)?;
        }

        statfs_for_path(&self.root)
    }

    fn lookup(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<Entry> {
        let init_name = unsafe { CStr::from_bytes_with_nul_unchecked(INIT_CSTR) };
        if parent == fuse::ROOT_ID && name == init_name {
            return Ok(Entry {
                inode: self.init_inode,
                generation: 0,
                attr: init_stat(self.init_inode),
                attr_flags: 0,
                attr_timeout: self.cfg_attr_timeout(),
                entry_timeout: self.cfg_entry_timeout(),
            });
        }

        self.do_lookup(parent, name)
    }

    fn forget(&self, _ctx: Context, inode: Inode, count: u64) {
        if inode == self.init_inode {
            return;
        }

        forget_one(&mut self.inodes.write().unwrap(), inode, count);
    }

    fn batch_forget(&self, _ctx: Context, requests: Vec<(Inode, u64)>) {
        let mut inodes = self.inodes.write().unwrap();
        for (inode, count) in requests {
            if inode != self.init_inode {
                forget_one(&mut inodes, inode, count);
            }
        }
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: Inode,
        _handle: Option<Handle>,
    ) -> io::Result<(bindings::stat64, Duration)> {
        self.do_getattr(inode)
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: Inode,
        attr: bindings::stat64,
        handle: Option<Handle>,
        valid: SetattrValid,
    ) -> io::Result<(bindings::stat64, Duration)> {
        if inode == self.init_inode {
            return Err(linux_error(LINUX_EACCES));
        }
        validate_setattr(valid)?;

        let data = self.inode(inode)?;
        reject_symlink(&data.path)?;

        if valid.contains(SetattrValid::SIZE) {
            let size: u64 = attr
                .st_size
                .try_into()
                .map_err(|_| linux_error(LINUX_EINVAL))?;
            if let Some(handle) = handle {
                let handle_data = self.handle(inode, handle)?;
                match &handle_data.kind {
                    HandleKind::File(file) => {
                        file.write().unwrap().set_len(size).map_err(host_error)?
                    }
                    HandleKind::Directory(_) => return Err(linux_error(LINUX_EISDIR)),
                }
            } else {
                StdOpenOptions::new()
                    .write(true)
                    .open(&data.path)
                    .map_err(host_error)?
                    .set_len(size)
                    .map_err(host_error)?;
            }
        }

        if valid.contains(SetattrValid::MODE) {
            let mut permissions = std::fs::metadata(&data.path)
                .map_err(host_error)?
                .permissions();
            permissions.set_readonly(attr.st_mode & 0o222 == 0);
            std::fs::set_permissions(&data.path, permissions).map_err(host_error)?;
        }

        self.do_getattr(inode)
    }

    fn readlink(&self, _ctx: Context, inode: Inode) -> io::Result<Vec<u8>> {
        self.do_readlink(inode)
    }

    fn symlink(
        &self,
        _ctx: Context,
        linkname: &CStr,
        parent: Inode,
        name: &CStr,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        self.do_symlink(linkname, parent, name)
    }

    fn mknod(
        &self,
        _ctx: Context,
        inode: Inode,
        name: &CStr,
        mode: u32,
        _rdev: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        if mode & S_IFMT != S_IFREG {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }

        let path = self.child_path(inode, name)?;
        StdOpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .map_err(host_error)?;
        self.entry_for_path(path, 1)
    }

    fn mkdir(
        &self,
        _ctx: Context,
        parent: Inode,
        name: &CStr,
        _mode: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        self.do_mkdir(parent, name)
    }

    fn unlink(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_unlink(parent, name)
    }

    fn rmdir(&self, _ctx: Context, parent: Inode, name: &CStr) -> io::Result<()> {
        self.do_rmdir(parent, name)
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: Inode,
        oldname: &CStr,
        newdir: Inode,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        self.do_rename(olddir, oldname, newdir, newname, flags)
    }

    fn open(
        &self,
        _ctx: Context,
        inode: Inode,
        _kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        if inode == self.init_inode {
            return Ok((Some(self.init_handle), OpenOptions::empty()));
        }

        self.do_open(inode, flags)
    }

    fn create(
        &self,
        _ctx: Context,
        parent: Inode,
        name: &CStr,
        _mode: u32,
        _kill_priv: bool,
        flags: u32,
        _umask: u32,
        _extensions: Extensions,
    ) -> io::Result<(Entry, Option<Handle>, OpenOptions)> {
        self.do_create(parent, name, flags)
    }

    fn read<W: io::Write + ZeroCopyWriter>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut w: W,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        if inode == self.init_inode {
            let off: usize = offset.try_into().map_err(|_| linux_error(LINUX_EINVAL))?;
            if off >= INIT_BINARY.len() {
                return Ok(0);
            }

            let len = (size as usize).min(INIT_BINARY.len() - off);
            return w.write(&INIT_BINARY[off..off + len]);
        }

        let handle_data = self
            .handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.inode == inode)
            .cloned()
            .ok_or_else(|| linux_error(LINUX_EBADF))?;

        let file = match &handle_data.kind {
            HandleKind::File(file) => file.read().unwrap(),
            HandleKind::Directory(_) => return Err(linux_error(LINUX_EISDIR)),
        };

        // Zero-copy reads can surface Win32 file errors; normalize them before the server writes
        // the raw value into the Linux FUSE reply header.
        w.write_from(&file, size as usize, offset)
            .map_err(host_error)
    }

    fn write<R: io::Read + ZeroCopyReader>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mut r: R,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        _kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        if inode == self.init_inode {
            return Err(linux_error(LINUX_EACCES));
        }

        let handle_data = self.handle(inode, handle)?;
        let file = match &handle_data.kind {
            HandleKind::File(file) => file.write().unwrap(),
            HandleKind::Directory(_) => return Err(linux_error(LINUX_EISDIR)),
        };

        let offset = if handle_data.flags & bindings::LINUX_O_APPEND as u32 != 0 {
            file.metadata().map_err(host_error)?.len()
        } else {
            offset
        };
        r.read_to(&file, size as usize, offset).map_err(host_error)
    }

    fn flush(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        _lock_owner: u64,
    ) -> io::Result<()> {
        if inode == self.init_inode && handle == self.init_handle {
            return Ok(());
        }

        let handle_data = self.handle(inode, handle)?;
        match &handle_data.kind {
            HandleKind::File(file) => file.read().unwrap().sync_data().map_err(host_error),
            HandleKind::Directory(_) => Ok(()),
        }
    }

    fn fsync(&self, _ctx: Context, inode: Inode, datasync: bool, handle: Handle) -> io::Result<()> {
        let handle_data = self.handle(inode, handle)?;
        match &handle_data.kind {
            HandleKind::File(file) if datasync => {
                file.read().unwrap().sync_data().map_err(host_error)
            }
            HandleKind::File(file) => file.read().unwrap().sync_all().map_err(host_error),
            HandleKind::Directory(_) => Ok(()),
        }
    }

    fn fallocate(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        mode: u32,
        offset: u64,
        length: u64,
    ) -> io::Result<()> {
        self.do_fallocate(inode, handle, mode, offset, length)
    }

    fn setupmapping(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        self.do_setupmapping(
            inode,
            handle,
            foffset,
            len,
            flags,
            moffset,
            guest_shm_base,
            shm_size,
            map_sender,
        )
    }

    fn removemapping(
        &self,
        _ctx: Context,
        requests: Vec<fuse::RemovemappingOne>,
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        self.do_removemapping(requests, guest_shm_base, shm_size, map_sender)
    }

    #[allow(clippy::too_many_arguments)]
    fn ioctl(
        &self,
        _ctx: Context,
        _inode: Inode,
        _handle: Handle,
        _flags: u32,
        cmd: u32,
        arg: u64,
        _in_size: u32,
        _out_size: u32,
        exit_code: &Arc<AtomicI32>,
    ) -> io::Result<Vec<u8>> {
        // These request values are part of the Linux guest /init.krun contract, so keep them
        // literal on Windows instead of deriving them from the host platform.
        const VIRTIO_IOC_EXIT_CODE_REQ: u32 = 0x7602;
        const VIRTIO_IOC_REMOVE_ROOT_DIR_REQ: u32 = 0x7603;

        match cmd {
            VIRTIO_IOC_EXIT_CODE_REQ => {
                exit_code.store(arg as i32, Ordering::SeqCst);
                Ok(Vec::new())
            }
            VIRTIO_IOC_REMOVE_ROOT_DIR_REQ if self._cfg.allow_root_dir_delete => {
                std::fs::remove_dir_all(&self.root).map_err(host_error)?;
                Ok(Vec::new())
            }
            _ => Err(linux_error(LINUX_EOPNOTSUPP)),
        }
    }

    fn release(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        if inode == self.init_inode && handle == self.init_handle {
            return Ok(());
        }

        self.do_release(inode, handle)
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: Inode,
        flags: u32,
    ) -> io::Result<(Option<Handle>, OpenOptions)> {
        self.do_opendir(inode, flags)
    }

    fn readdir<F>(
        &self,
        _ctx: Context,
        inode: Inode,
        handle: Handle,
        size: u32,
        offset: u64,
        add_entry: F,
    ) -> io::Result<()>
    where
        F: FnMut(DirEntry) -> io::Result<usize>,
    {
        self.do_readdir(inode, handle, size, offset, add_entry)
    }

    fn releasedir(
        &self,
        _ctx: Context,
        inode: Inode,
        _flags: u32,
        handle: Handle,
    ) -> io::Result<()> {
        self.do_release(inode, handle)
    }

    fn setxattr(
        &self,
        _ctx: Context,
        _inode: Inode,
        _name: &CStr,
        _value: &[u8],
        _flags: u32,
    ) -> io::Result<()> {
        Err(linux_error(LINUX_EOPNOTSUPP))
    }

    fn getxattr(
        &self,
        _ctx: Context,
        _inode: Inode,
        _name: &CStr,
        _size: u32,
    ) -> io::Result<GetxattrReply> {
        Err(linux_error(LINUX_EOPNOTSUPP))
    }

    fn listxattr(&self, _ctx: Context, _inode: Inode, _size: u32) -> io::Result<ListxattrReply> {
        Err(linux_error(LINUX_EOPNOTSUPP))
    }

    fn removexattr(&self, _ctx: Context, _inode: Inode, _name: &CStr) -> io::Result<()> {
        Err(linux_error(LINUX_EOPNOTSUPP))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn forget_one(inodes: &mut InodeTable, inode: Inode, count: u64) {
    let Some(data) = inodes.by_inode.get(&inode) else {
        return;
    };

    let refcount = data.refcount.load(Ordering::Relaxed);
    let new_count = refcount.saturating_sub(count);
    data.refcount.store(new_count, Ordering::Release);
    if new_count == 0 && inode != fuse::ROOT_ID {
        let path = data.path.clone();
        inodes.by_inode.remove(&inode);
        inodes.by_path.remove(&path);
    }
}

fn open_options_from_flags(flags: u32, create: bool) -> io::Result<StdOpenOptions> {
    let flags = flags as i32;
    if flags & bindings::LINUX_O_DIRECT != 0 {
        return Err(linux_error(LINUX_EOPNOTSUPP));
    }
    if !create && flags & (bindings::LINUX_O_CREAT | bindings::LINUX_O_EXCL) != 0 {
        return Err(linux_error(LINUX_EINVAL));
    }
    if flags & bindings::LINUX_O_DIRECTORY != 0 {
        return Err(linux_error(LINUX_EISDIR));
    }

    let accmode = flags & LINUX_O_ACCMODE;
    let mut options = StdOpenOptions::new();
    match accmode {
        0 => {
            options.read(true);
        }
        LINUX_O_WRONLY => {
            options.write(true);
        }
        LINUX_O_RDWR => {
            options.read(true).write(true);
        }
        _ => return Err(linux_error(LINUX_EINVAL)),
    };

    if flags & bindings::LINUX_O_APPEND != 0 {
        options.append(true);
    }
    if flags & bindings::LINUX_O_TRUNC != 0 {
        if accmode == 0 {
            return Err(linux_error(LINUX_EACCES));
        }
        options.truncate(true);
    }

    if create {
        if flags & bindings::LINUX_O_EXCL != 0 {
            options.create_new(true);
        } else {
            options.create(true);
        }
        if accmode == 0 {
            options.write(true);
        }
    }

    Ok(options)
}

fn validate_directory_open(flags: u32) -> io::Result<()> {
    let flags = flags as i32;
    if flags & bindings::LINUX_O_DIRECT != 0 {
        return Err(linux_error(LINUX_EOPNOTSUPP));
    }

    let accmode = flags & LINUX_O_ACCMODE;
    if accmode == LINUX_O_WRONLY || accmode == LINUX_O_RDWR {
        return Err(linux_error(LINUX_EACCES));
    }

    Ok(())
}

fn validate_setattr(valid: SetattrValid) -> io::Result<()> {
    let supported = SetattrValid::SIZE | SetattrValid::MODE | SetattrValid::KILL_SUIDGID;
    let unsupported = SetattrValid::from_bits_truncate(valid.bits() & !supported.bits());
    if unsupported.is_empty() {
        Ok(())
    } else {
        Err(linux_error(LINUX_EOPNOTSUPP))
    }
}

fn checked_mapping_guest_addr(
    moffset: u64,
    len: u64,
    guest_shm_base: u64,
    shm_size: u64,
) -> io::Result<u64> {
    let end = moffset
        .checked_add(len)
        .ok_or_else(|| linux_error(LINUX_EINVAL))?;
    if end > shm_size {
        return Err(linux_error(LINUX_EINVAL));
    }

    guest_shm_base
        .checked_add(moffset)
        .ok_or_else(|| linux_error(LINUX_EINVAL))
}

fn mapping_access(flags: u64) -> WindowsFileMappingAccess {
    if flags & fuse::SetupmappingFlags::WRITE.bits() != 0 {
        WindowsFileMappingAccess::ReadWrite
    } else {
        WindowsFileMappingAccess::ReadOnly
    }
}

fn mapping_view_for_path(
    path: &Path,
    foffset: u64,
    len: usize,
    access: WindowsFileMappingAccess,
) -> io::Result<WindowsFileMappingView> {
    let mut options = StdOpenOptions::new();
    options.read(true);
    if access == WindowsFileMappingAccess::ReadWrite {
        options.write(true);
    }
    let file = options.open(path).map_err(host_error)?;

    let end = foffset
        .checked_add(len as u64)
        .ok_or_else(|| linux_error(LINUX_EINVAL))?;
    if access == WindowsFileMappingAccess::ReadOnly
        && end > file.metadata().map_err(host_error)?.len()
    {
        return read_only_oversized_mapping_view(&file, foffset, len);
    }

    WindowsFileMappingView::map_file(&file, foffset, len, access).map_err(host_error)
}

fn read_only_oversized_mapping_view(
    file: &File,
    foffset: u64,
    len: usize,
) -> io::Result<WindowsFileMappingView> {
    let mut view = WindowsFileMappingView::map_anonymous(len, WindowsFileMappingAccess::ReadWrite)
        .map_err(host_error)?;
    let file_len = file.metadata().map_err(host_error)?.len();
    if foffset < file_len {
        let to_copy: usize = len.min((file_len - foffset).try_into().unwrap_or(usize::MAX));
        let mut bytes = vec![0u8; to_copy];
        let read = file.seek_read(&mut bytes, foffset).map_err(host_error)?;
        view.copy_from_slice(&bytes[..read]).map_err(host_error)?;
    }

    Ok(view)
}

fn init_mapping_view(
    foffset: u64,
    len: usize,
    access: WindowsFileMappingAccess,
) -> io::Result<WindowsFileMappingView> {
    let mut view = WindowsFileMappingView::map_anonymous(len, access).map_err(host_error)?;
    let foffset: usize = foffset.try_into().map_err(|_| linux_error(LINUX_EINVAL))?;
    if foffset < INIT_BINARY.len() {
        let to_copy = len.min(INIT_BINARY.len() - foffset);
        view.copy_from_slice(&INIT_BINARY[foffset..foffset + to_copy])
            .map_err(host_error)?;
    }

    Ok(view)
}

fn request_mapping(
    sender: &Sender<WorkerMessage>,
    host_addr: u64,
    guest_addr: u64,
    len: u64,
    writable: bool,
) -> io::Result<()> {
    let (reply_sender, reply_receiver) = unbounded();
    sender
        .send(WorkerMessage::DaxAddMapping(
            reply_sender,
            host_addr,
            guest_addr,
            len,
            writable,
        ))
        .map_err(|_| linux_error(LINUX_EIO))?;
    if reply_receiver.recv().map_err(|_| linux_error(LINUX_EIO))? {
        Ok(())
    } else {
        Err(linux_error(LINUX_EINVAL))
    }
}

fn request_unmapping(sender: &Sender<WorkerMessage>, guest_addr: u64, len: u64) -> io::Result<()> {
    let (reply_sender, reply_receiver) = unbounded();
    sender
        .send(WorkerMessage::GpuRemoveMapping(
            reply_sender,
            guest_addr,
            len,
        ))
        .map_err(|_| linux_error(LINUX_EIO))?;
    if reply_receiver.recv().map_err(|_| linux_error(LINUX_EIO))? {
        Ok(())
    } else {
        Err(linux_error(LINUX_EINVAL))
    }
}

fn statfs_for_path(path: &Path) -> io::Result<bindings::statvfs64> {
    let path = path_to_wide(path);
    let mut available = 0u64;
    let mut total = 0u64;
    let mut free = 0u64;

    // SAFETY: The path pointer references a nul-terminated UTF-16 buffer and the out-pointers are
    // valid for the duration of the call.
    let ok = unsafe {
        GetDiskFreeSpaceExW(
            path.as_ptr(),
            &mut available as *mut u64,
            &mut total as *mut u64,
            &mut free as *mut u64,
        )
    };
    if ok == 0 {
        return Err(host_error(io::Error::last_os_error()));
    }

    Ok(bindings::statvfs64 {
        f_blocks: total / STATFS_FRAGMENT_SIZE,
        f_bfree: free / STATFS_FRAGMENT_SIZE,
        f_bavail: available / STATFS_FRAGMENT_SIZE,
        f_files: 0,
        f_ffree: 0,
        f_bsize: STATFS_FRAGMENT_SIZE,
        f_namemax: STATFS_NAME_MAX,
        f_frsize: STATFS_FRAGMENT_SIZE,
    })
}

fn reject_symlink(path: &Path) -> io::Result<()> {
    let metadata = std::fs::symlink_metadata(path).map_err(host_error)?;
    if metadata.file_type().is_symlink() {
        return Err(linux_error(LINUX_ELOOP));
    }

    Ok(())
}

fn create_windows_symlink(link: &Path, target: &Path, directory: bool) -> io::Result<()> {
    let link = path_to_wide(link);
    let target = path_to_wide(target);
    let mut flags = SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE;
    if directory {
        flags |= SYMBOLIC_LINK_FLAG_DIRECTORY;
    }

    // SAFETY: Both pointers reference nul-terminated UTF-16 buffers that live for the call.
    let created = unsafe { CreateSymbolicLinkW(link.as_ptr(), target.as_ptr(), flags) };
    if created {
        Ok(())
    } else {
        Err(host_error(io::Error::last_os_error()))
    }
}

fn symlink_target_is_directory(link: &Path, target: &Path) -> bool {
    let resolved = if target.is_absolute() {
        target.to_path_buf()
    } else {
        link.parent().unwrap_or_else(|| Path::new("")).join(target)
    };

    std::fs::metadata(resolved)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
}

fn cstr_to_symlink_target(target: &CStr) -> io::Result<PathBuf> {
    let target = target.to_str().map_err(|_| linux_error(LINUX_EINVAL))?;
    if target.is_empty() {
        return Err(linux_error(LINUX_EINVAL));
    }

    Ok(PathBuf::from(target))
}

fn path_to_wide(path: &Path) -> Vec<u16> {
    path.as_os_str()
        .encode_wide()
        .chain(std::iter::once(0))
        .collect()
}

fn path_to_guest_bytes(path: &Path) -> Vec<u8> {
    os_str_to_guest_bytes(path.as_os_str())
}

fn os_str_to_guest_bytes(path: &OsStr) -> Vec<u8> {
    path.to_string_lossy().into_owned().into_bytes()
}

fn cstr_to_component(name: &CStr) -> io::Result<&str> {
    let component = name.to_str().map_err(|_| linux_error(LINUX_EINVAL))?;
    if component.is_empty()
        || component == "."
        || component == ".."
        || component.contains('\\')
        || component.contains('/')
    {
        return Err(linux_error(LINUX_EINVAL));
    }

    Ok(component)
}

fn stat_from_metadata(metadata: &std::fs::Metadata, inode: Inode) -> bindings::stat64 {
    let size = metadata.file_size() as i64;
    let (atime, atime_nsec) = filetime_to_unix(metadata.last_access_time());
    let (mtime, mtime_nsec) = filetime_to_unix(metadata.last_write_time());
    let (ctime, ctime_nsec) = filetime_to_unix(metadata.creation_time());

    bindings::stat64 {
        st_ino: inode,
        st_size: size,
        st_blocks: blocks_for_size(metadata.file_size()),
        st_atime: atime,
        st_mtime: mtime,
        st_ctime: ctime,
        st_atime_nsec: atime_nsec,
        st_mtime_nsec: mtime_nsec,
        st_ctime_nsec: ctime_nsec,
        st_mode: mode_from_metadata(metadata),
        st_nlink: 1,
        st_uid: 0,
        st_gid: 0,
        st_rdev: 0,
        st_blksize: 4096,
    }
}

fn init_stat(inode: Inode) -> bindings::stat64 {
    bindings::stat64 {
        st_ino: inode,
        st_size: INIT_BINARY.len() as i64,
        st_blocks: blocks_for_size(INIT_BINARY.len() as u64),
        st_mode: S_IFREG | 0o755,
        st_nlink: 1,
        st_blksize: 4096,
        ..Default::default()
    }
}

fn mode_from_metadata(metadata: &std::fs::Metadata) -> u32 {
    let file_type = metadata.file_type();
    let type_bits = if file_type.is_dir() {
        S_IFDIR
    } else if file_type.is_symlink() {
        S_IFLNK
    } else if file_type.is_file() {
        S_IFREG
    } else {
        0
    };

    let readonly = metadata.file_attributes() & FILE_ATTRIBUTE_READONLY != 0;
    let perms = if readonly { 0o555 } else { 0o777 };
    (type_bits & S_IFMT) | perms
}

fn dirent_type(file_type: FileType) -> u32 {
    if file_type.is_dir() {
        DT_DIR
    } else if file_type.is_symlink() {
        DT_LNK
    } else if file_type.is_file() {
        DT_REG
    } else {
        DT_UNKNOWN
    }
}

fn blocks_for_size(size: u64) -> i64 {
    size.div_ceil(512).try_into().unwrap_or(i64::MAX)
}

fn filetime_to_unix(filetime: u64) -> (i64, i64) {
    let seconds = filetime / WINDOWS_TICKS_PER_SECOND;
    if seconds < WINDOWS_TO_UNIX_EPOCH_SECONDS {
        return (0, 0);
    }

    let unix_seconds = seconds - WINDOWS_TO_UNIX_EPOCH_SECONDS;
    let nanos = (filetime % WINDOWS_TICKS_PER_SECOND) * 100;
    (
        unix_seconds.try_into().unwrap_or(i64::MAX),
        nanos.try_into().unwrap_or(i64::MAX),
    )
}

fn host_error(error: io::Error) -> io::Error {
    let errno = match error.raw_os_error() {
        Some(code)
            if code == ERROR_FILE_NOT_FOUND as i32 || code == ERROR_PATH_NOT_FOUND as i32 =>
        {
            LINUX_ENOENT
        }
        Some(code) if code == ERROR_ACCESS_DENIED as i32 => LINUX_EACCES,
        Some(code) if code == ERROR_PRIVILEGE_NOT_HELD as i32 => LINUX_EACCES,
        Some(code) if code == ERROR_ALREADY_EXISTS as i32 || code == ERROR_FILE_EXISTS as i32 => {
            LINUX_EEXIST
        }
        Some(code) if code == ERROR_DIR_NOT_EMPTY as i32 => LINUX_ENOTEMPTY,
        Some(code) if code == ERROR_SHARING_VIOLATION as i32 => LINUX_EBUSY,
        Some(code) if code == ERROR_INVALID_NAME as i32 => LINUX_EINVAL,
        _ => match error.kind() {
            io::ErrorKind::NotFound => LINUX_ENOENT,
            io::ErrorKind::PermissionDenied => LINUX_EACCES,
            io::ErrorKind::AlreadyExists => LINUX_EEXIST,
            io::ErrorKind::InvalidInput => LINUX_EINVAL,
            _ => LINUX_EIO,
        },
    };

    linux_error(errno)
}

fn linux_error(errno: i32) -> io::Error {
    io::Error::from_raw_os_error(errno)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::windows::fs::FileExt;
    use std::sync::Arc;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    struct TempDir {
        path: PathBuf,
    }

    struct CaptureWriter {
        bytes: Vec<u8>,
    }

    struct FailingZeroCopyWriter;

    struct SourceReader {
        bytes: Vec<u8>,
        pos: usize,
    }

    impl TempDir {
        fn new() -> Self {
            let mut path = std::env::temp_dir();
            let unique = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            path.push(format!("msb-krun-fs-test-{}-{unique}", std::process::id()));
            fs::create_dir(&path).unwrap();
            Self { path }
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.path);
        }
    }

    impl Write for CaptureWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.bytes.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ZeroCopyWriter for CaptureWriter {
        fn write_from(&mut self, file: &File, count: usize, offset: u64) -> io::Result<usize> {
            let mut file = file.try_clone()?;
            file.seek(SeekFrom::Start(offset))?;
            let mut take = file.take(count as u64);
            take.read_to_end(&mut self.bytes)
        }
    }

    impl Write for FailingZeroCopyWriter {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            Ok(buf.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl ZeroCopyWriter for FailingZeroCopyWriter {
        fn write_from(&mut self, _file: &File, _count: usize, _offset: u64) -> io::Result<usize> {
            // Model a Windows file failure returned by the server's zero-copy adapter.
            Err(io::Error::from_raw_os_error(ERROR_ACCESS_DENIED as i32))
        }
    }

    impl Read for SourceReader {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let len = buf.len().min(self.bytes.len().saturating_sub(self.pos));
            buf[..len].copy_from_slice(&self.bytes[self.pos..self.pos + len]);
            self.pos += len;
            Ok(len)
        }
    }

    impl ZeroCopyReader for SourceReader {
        fn read_to(&mut self, file: &File, count: usize, offset: u64) -> io::Result<usize> {
            let len = count.min(self.bytes.len().saturating_sub(self.pos));
            if len == 0 {
                return Ok(0);
            }

            let written = file.seek_write(&self.bytes[self.pos..self.pos + len], offset)?;
            self.pos += written;
            Ok(written)
        }
    }

    fn context() -> Context {
        Context {
            uid: 0,
            gid: 0,
            pid: 0,
        }
    }

    fn expect_linux_error<T>(result: io::Result<T>, errno: i32) {
        match result {
            Ok(_) => panic!("expected linux errno {errno}"),
            Err(error) => assert_eq!(error.raw_os_error(), Some(errno)),
        }
    }

    #[test]
    fn init_requests_directory_ioctls_when_available() {
        let temp = TempDir::new();
        let fs = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();

        let options = fs.init(FsOptions::HAS_IOCTL_DIR).unwrap();

        assert!(options.contains(FsOptions::HAS_IOCTL_DIR));
    }

    #[test]
    fn lookup_open_read_and_release_file() {
        let temp = TempDir::new();
        fs::write(temp.path.join("hello.txt"), b"hello from windows fs").unwrap();

        let fs = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let name = CStr::from_bytes_with_nul(b"hello.txt\0").unwrap();
        let entry = fs.lookup(context(), fuse::ROOT_ID, name).unwrap();
        assert_eq!(entry.attr.st_size, 21);
        assert_eq!(entry.attr.st_mode & S_IFMT, S_IFREG);

        let (handle, _) = fs.open(context(), entry.inode, false, 0).unwrap();
        let handle = handle.unwrap();
        let mut writer = CaptureWriter { bytes: Vec::new() };
        let read = fs
            .read(context(), entry.inode, handle, &mut writer, 5, 6, None, 0)
            .unwrap();

        assert_eq!(read, 5);
        assert_eq!(writer.bytes, b"from ");
        fs.release(context(), entry.inode, 0, handle, false, false, None)
            .unwrap();
    }

    #[test]
    fn read_translates_zero_copy_win32_errors() {
        let temp = TempDir::new();
        fs::write(temp.path.join("denied.txt"), b"content").unwrap();

        let fs = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let name = CStr::from_bytes_with_nul(b"denied.txt\0").unwrap();
        let entry = fs.lookup(context(), fuse::ROOT_ID, name).unwrap();
        let (handle, _) = fs.open(context(), entry.inode, false, 0).unwrap();
        let handle = handle.unwrap();

        expect_linux_error(
            fs.read(
                context(),
                entry.inode,
                handle,
                FailingZeroCopyWriter,
                7,
                0,
                None,
                0,
            ),
            LINUX_EACCES,
        );
        fs.release(context(), entry.inode, 0, handle, false, false, None)
            .unwrap();
    }

    #[test]
    fn readdir_lists_children() {
        let temp = TempDir::new();
        fs::write(temp.path.join("alpha.txt"), b"alpha").unwrap();
        fs::create_dir(temp.path.join("nested")).unwrap();

        let fs = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let (handle, _) = fs.opendir(context(), fuse::ROOT_ID, 0).unwrap();
        let handle = handle.unwrap();
        let mut names = Vec::new();
        fs.readdir(context(), fuse::ROOT_ID, handle, 4096, 0, |entry| {
            names.push(String::from_utf8(entry.name.to_vec()).unwrap());
            Ok(1)
        })
        .unwrap();

        names.sort();
        assert_eq!(names, vec!["alpha.txt", "nested"]);
        fs.releasedir(context(), fuse::ROOT_ID, 0, handle).unwrap();
    }

    #[test]
    fn opendir_accepts_guest_directory_flags() {
        let temp = TempDir::new();
        let fs = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();

        let flags = (bindings::LINUX_O_DIRECTORY
            | bindings::LINUX_O_CLOEXEC
            | bindings::LINUX_O_LARGEFILE) as u32;
        #[cfg(target_arch = "aarch64")]
        assert_eq!(flags, 0xa4000);

        let (handle, _) = fs.opendir(context(), fuse::ROOT_ID, flags).unwrap();
        fs.releasedir(context(), fuse::ROOT_ID, 0, handle.unwrap())
            .unwrap();
    }

    #[test]
    fn create_write_fsync_and_truncate_file() {
        let temp = TempDir::new();
        let passthrough = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();

        let name = CStr::from_bytes_with_nul(b"created.txt\0").unwrap();
        let flags = (bindings::LINUX_O_CREAT | bindings::LINUX_O_TRUNC | LINUX_O_RDWR) as u32;
        let (entry, handle, _) = passthrough
            .create(
                context(),
                fuse::ROOT_ID,
                name,
                S_IFREG | 0o644,
                false,
                flags,
                0,
                Extensions::default(),
            )
            .unwrap();
        let handle = handle.unwrap();

        let payload = b"hello writable virtiofs";
        let mut reader = SourceReader {
            bytes: payload.to_vec(),
            pos: 0,
        };
        let written = passthrough
            .write(
                context(),
                entry.inode,
                handle,
                &mut reader,
                payload.len() as u32,
                0,
                None,
                false,
                false,
                flags,
            )
            .unwrap();

        assert_eq!(written, payload.len());
        passthrough
            .fsync(context(), entry.inode, false, handle)
            .unwrap();
        assert_eq!(fs::read(temp.path.join("created.txt")).unwrap(), payload);

        let mut attr = bindings::stat64 {
            st_size: 5,
            ..Default::default()
        };
        passthrough
            .setattr(
                context(),
                entry.inode,
                attr,
                Some(handle),
                SetattrValid::SIZE,
            )
            .unwrap();
        assert_eq!(fs::read(temp.path.join("created.txt")).unwrap(), b"hello");

        attr.st_mode = S_IFREG | 0o444;
        passthrough
            .setattr(
                context(),
                entry.inode,
                attr,
                Some(handle),
                SetattrValid::MODE,
            )
            .unwrap();
        assert!(fs::metadata(temp.path.join("created.txt"))
            .unwrap()
            .permissions()
            .readonly());

        passthrough
            .setattr(
                context(),
                entry.inode,
                attr,
                Some(handle),
                SetattrValid::KILL_SUIDGID,
            )
            .unwrap();
        expect_linux_error(
            passthrough.setattr(
                context(),
                entry.inode,
                attr,
                Some(handle),
                SetattrValid::UID | SetattrValid::GID,
            ),
            LINUX_EOPNOTSUPP,
        );
        expect_linux_error(
            passthrough.setattr(
                context(),
                entry.inode,
                attr,
                Some(handle),
                SetattrValid::ATIME | SetattrValid::MTIME,
            ),
            LINUX_EOPNOTSUPP,
        );

        passthrough
            .release(context(), entry.inode, 0, handle, false, false, None)
            .unwrap();
    }

    #[test]
    fn mkdir_rename_unlink_and_rmdir() {
        let temp = TempDir::new();
        let passthrough = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();

        let dir_name = CStr::from_bytes_with_nul(b"nested\0").unwrap();
        let dir = passthrough
            .mkdir(
                context(),
                fuse::ROOT_ID,
                dir_name,
                S_IFDIR | 0o755,
                0,
                Extensions::default(),
            )
            .unwrap();
        assert!(temp.path.join("nested").is_dir());

        let file_name = CStr::from_bytes_with_nul(b"file.txt\0").unwrap();
        let flags = (bindings::LINUX_O_CREAT | LINUX_O_RDWR) as u32;
        let (entry, handle, _) = passthrough
            .create(
                context(),
                dir.inode,
                file_name,
                S_IFREG | 0o644,
                false,
                flags,
                0,
                Extensions::default(),
            )
            .unwrap();
        let handle = handle.unwrap();
        passthrough
            .release(context(), entry.inode, 0, handle, false, false, None)
            .unwrap();

        let renamed = CStr::from_bytes_with_nul(b"renamed.txt\0").unwrap();
        passthrough
            .rename(context(), dir.inode, file_name, fuse::ROOT_ID, renamed, 0)
            .unwrap();
        assert!(!temp.path.join("nested").join("file.txt").exists());
        assert!(temp.path.join("renamed.txt").is_file());

        passthrough
            .unlink(context(), fuse::ROOT_ID, renamed)
            .unwrap();
        assert!(!temp.path.join("renamed.txt").exists());

        passthrough
            .rmdir(context(), fuse::ROOT_ID, dir_name)
            .unwrap();
        assert!(!temp.path.join("nested").exists());
    }

    #[test]
    fn rename_replace_moves_source_inode_to_target_path() {
        let temp = TempDir::new();
        fs::write(temp.path.join("heartbeat.json"), b"old").unwrap();
        fs::write(temp.path.join("heartbeat.tmp"), b"new").unwrap();

        let passthrough = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();

        let target_name = CStr::from_bytes_with_nul(b"heartbeat.json\0").unwrap();
        let temp_name = CStr::from_bytes_with_nul(b"heartbeat.tmp\0").unwrap();
        let source = passthrough
            .lookup(context(), fuse::ROOT_ID, temp_name)
            .unwrap();

        passthrough
            .rename(
                context(),
                fuse::ROOT_ID,
                temp_name,
                fuse::ROOT_ID,
                target_name,
                0,
            )
            .unwrap();

        let (attr, _) = passthrough.getattr(context(), source.inode, None).unwrap();
        assert_eq!(attr.st_size, 3);

        let (handle, _) = passthrough.open(context(), source.inode, false, 0).unwrap();
        let handle = handle.unwrap();
        let mut writer = CaptureWriter { bytes: Vec::new() };
        passthrough
            .read(context(), source.inode, handle, &mut writer, 3, 0, None, 0)
            .unwrap();
        assert_eq!(writer.bytes, b"new");
        passthrough
            .release(context(), source.inode, 0, handle, false, false, None)
            .unwrap();
    }

    #[test]
    fn sparse_high_offset_write_reads_zero_holes() {
        let temp = TempDir::new();
        let passthrough = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();

        let name = CStr::from_bytes_with_nul(b"sparse.bin\0").unwrap();
        let flags = (bindings::LINUX_O_CREAT | LINUX_O_RDWR) as u32;
        let (entry, handle, _) = passthrough
            .create(
                context(),
                fuse::ROOT_ID,
                name,
                S_IFREG | 0o644,
                false,
                flags,
                0,
                Extensions::default(),
            )
            .unwrap();
        let handle = handle.unwrap();

        let head = b"HEAD";
        let tail = b"TAIL";
        let tail_offset = 16 * 1024 * 1024 + 123;

        let mut head_reader = SourceReader {
            bytes: head.to_vec(),
            pos: 0,
        };
        assert_eq!(
            passthrough
                .write(
                    context(),
                    entry.inode,
                    handle,
                    &mut head_reader,
                    head.len() as u32,
                    0,
                    None,
                    false,
                    false,
                    flags,
                )
                .unwrap(),
            head.len()
        );

        let mut tail_reader = SourceReader {
            bytes: tail.to_vec(),
            pos: 0,
        };
        assert_eq!(
            passthrough
                .write(
                    context(),
                    entry.inode,
                    handle,
                    &mut tail_reader,
                    tail.len() as u32,
                    tail_offset,
                    None,
                    false,
                    false,
                    flags,
                )
                .unwrap(),
            tail.len()
        );
        passthrough
            .fsync(context(), entry.inode, false, handle)
            .unwrap();

        let (attr, _) = passthrough
            .getattr(context(), entry.inode, Some(handle))
            .unwrap();
        assert_eq!(attr.st_size, tail_offset as i64 + tail.len() as i64);

        let mut head_writer = CaptureWriter { bytes: Vec::new() };
        assert_eq!(
            passthrough
                .read(
                    context(),
                    entry.inode,
                    handle,
                    &mut head_writer,
                    head.len() as u32,
                    0,
                    None,
                    flags,
                )
                .unwrap(),
            head.len()
        );
        assert_eq!(head_writer.bytes, head);

        let mut hole_writer = CaptureWriter { bytes: Vec::new() };
        assert_eq!(
            passthrough
                .read(
                    context(),
                    entry.inode,
                    handle,
                    &mut hole_writer,
                    32,
                    1024 * 1024,
                    None,
                    flags,
                )
                .unwrap(),
            32
        );
        assert_eq!(hole_writer.bytes, vec![0; 32]);

        let mut tail_writer = CaptureWriter { bytes: Vec::new() };
        assert_eq!(
            passthrough
                .read(
                    context(),
                    entry.inode,
                    handle,
                    &mut tail_writer,
                    (8 + tail.len()) as u32,
                    tail_offset - 8,
                    None,
                    flags,
                )
                .unwrap(),
            8 + tail.len()
        );
        assert_eq!(tail_writer.bytes[..8], [0; 8]);
        assert_eq!(&tail_writer.bytes[8..], tail);

        passthrough
            .release(context(), entry.inode, 0, handle, false, false, None)
            .unwrap();
    }

    #[test]
    fn fallocate_extends_and_punches_holes_when_supported() {
        let temp = TempDir::new();
        let passthrough = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();

        let name = CStr::from_bytes_with_nul(b"fallocate.bin\0").unwrap();
        let flags = (bindings::LINUX_O_CREAT | LINUX_O_RDWR) as u32;
        let (entry, handle, _) = passthrough
            .create(
                context(),
                fuse::ROOT_ID,
                name,
                S_IFREG | 0o644,
                false,
                flags,
                0,
                Extensions::default(),
            )
            .unwrap();
        let handle = handle.unwrap();

        passthrough
            .fallocate(context(), entry.inode, handle, 0, 0, 4096)
            .unwrap();
        let (attr, _) = passthrough
            .getattr(context(), entry.inode, Some(handle))
            .unwrap();
        assert_eq!(attr.st_size, 4096);

        let payload = vec![0xa5; 4096];
        let mut reader = SourceReader {
            bytes: payload,
            pos: 0,
        };
        assert_eq!(
            passthrough
                .write(
                    context(),
                    entry.inode,
                    handle,
                    &mut reader,
                    4096,
                    0,
                    None,
                    false,
                    false,
                    flags,
                )
                .unwrap(),
            4096
        );

        expect_linux_error(
            passthrough.fallocate(context(), entry.inode, handle, 0x08, 0, 4096),
            LINUX_EOPNOTSUPP,
        );

        match passthrough.fallocate(
            context(),
            entry.inode,
            handle,
            FALLOC_FL_KEEP_SIZE | FALLOC_FL_PUNCH_HOLE,
            1024,
            512,
        ) {
            Ok(()) => {}
            Err(error) if error.raw_os_error() == Some(LINUX_EOPNOTSUPP) => {
                eprintln!("skipping hole-punch assertion because this filesystem does not support sparse zero-data controls");
                passthrough
                    .release(context(), entry.inode, 0, handle, false, false, None)
                    .unwrap();
                return;
            }
            Err(error) => panic!("hole punch failed: {error:?}"),
        }

        let (attr, _) = passthrough
            .getattr(context(), entry.inode, Some(handle))
            .unwrap();
        assert_eq!(attr.st_size, 4096);

        let mut writer = CaptureWriter { bytes: Vec::new() };
        assert_eq!(
            passthrough
                .read(
                    context(),
                    entry.inode,
                    handle,
                    &mut writer,
                    544,
                    1008,
                    None,
                    flags,
                )
                .unwrap(),
            544
        );
        assert_eq!(writer.bytes[..16], [0xa5; 16]);
        assert_eq!(writer.bytes[16..528], [0; 512]);
        assert_eq!(writer.bytes[528..], [0xa5; 16]);

        passthrough
            .release(context(), entry.inode, 0, handle, false, false, None)
            .unwrap();
    }

    #[test]
    fn concurrent_non_overlapping_writes_are_stable() {
        let temp = TempDir::new();
        let passthrough = Arc::new(
            PassthroughFs::new(Config {
                root_dir: temp.path.to_string_lossy().into_owned(),
                ..Default::default()
            })
            .unwrap(),
        );
        passthrough.init(FsOptions::empty()).unwrap();

        let name = CStr::from_bytes_with_nul(b"concurrent.bin\0").unwrap();
        let flags = (bindings::LINUX_O_CREAT | LINUX_O_RDWR) as u32;
        let (entry, handle, _) = passthrough
            .create(
                context(),
                fuse::ROOT_ID,
                name,
                S_IFREG | 0o644,
                false,
                flags,
                0,
                Extensions::default(),
            )
            .unwrap();
        passthrough
            .release(
                context(),
                entry.inode,
                0,
                handle.unwrap(),
                false,
                false,
                None,
            )
            .unwrap();

        let mut workers = Vec::new();
        for index in 0..8 {
            let passthrough = passthrough.clone();
            workers.push(std::thread::spawn(move || {
                let offset = index as u64 * 1024 * 1024 + 4093;
                let payload = vec![b'A' + index as u8; 8192];
                let (handle, _) = passthrough
                    .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
                    .unwrap();
                let handle = handle.unwrap();
                let mut reader = SourceReader {
                    bytes: payload.clone(),
                    pos: 0,
                };

                assert_eq!(
                    passthrough
                        .write(
                            context(),
                            entry.inode,
                            handle,
                            &mut reader,
                            payload.len() as u32,
                            offset,
                            None,
                            false,
                            false,
                            LINUX_O_RDWR as u32,
                        )
                        .unwrap(),
                    payload.len()
                );
                passthrough
                    .fsync(context(), entry.inode, true, handle)
                    .unwrap();
                passthrough
                    .release(context(), entry.inode, 0, handle, false, false, None)
                    .unwrap();

                (offset, payload)
            }));
        }

        let mut expected = Vec::new();
        for worker in workers {
            expected.push(worker.join().unwrap());
        }

        let (handle, _) = passthrough
            .open(context(), entry.inode, false, LINUX_O_RDWR as u32)
            .unwrap();
        let handle = handle.unwrap();
        for (offset, payload) in expected {
            let mut writer = CaptureWriter { bytes: Vec::new() };
            assert_eq!(
                passthrough
                    .read(
                        context(),
                        entry.inode,
                        handle,
                        &mut writer,
                        payload.len() as u32,
                        offset,
                        None,
                        LINUX_O_RDWR as u32,
                    )
                    .unwrap(),
                payload.len()
            );
            assert_eq!(writer.bytes, payload);
        }
        passthrough
            .release(context(), entry.inode, 0, handle, false, false, None)
            .unwrap();
    }

    #[test]
    fn symlink_and_readlink_round_trip() {
        let temp = TempDir::new();
        fs::write(temp.path.join("target.txt"), b"target").unwrap();

        let passthrough = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();

        let target = CStr::from_bytes_with_nul(b"target.txt\0").unwrap();
        let link = CStr::from_bytes_with_nul(b"link.txt\0").unwrap();
        let entry = match passthrough.symlink(
            context(),
            target,
            fuse::ROOT_ID,
            link,
            Extensions::default(),
        ) {
            Ok(entry) => entry,
            Err(error) if error.raw_os_error() == Some(LINUX_EACCES) => {
                eprintln!("skipping symlink test because this machine denies symlink creation");
                return;
            }
            Err(error) => panic!("symlink failed: {error:?}"),
        };

        assert_eq!(entry.attr.st_mode & S_IFMT, S_IFLNK);
        assert!(fs::symlink_metadata(temp.path.join("link.txt"))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(
            passthrough.readlink(context(), entry.inode).unwrap(),
            b"target.txt"
        );
        expect_linux_error(
            passthrough.open(context(), entry.inode, false, 0),
            LINUX_ELOOP,
        );
    }

    #[test]
    fn symlink_target_directory_detection_uses_link_parent() {
        let temp = TempDir::new();
        fs::create_dir(temp.path.join("dir-target")).unwrap();
        fs::write(temp.path.join("file-target"), b"target").unwrap();

        let link = temp.path.join("link");
        assert!(symlink_target_is_directory(&link, Path::new("dir-target")));
        assert!(!symlink_target_is_directory(
            &link,
            Path::new("file-target")
        ));
        assert!(!symlink_target_is_directory(
            &link,
            Path::new("missing-target")
        ));
    }

    #[test]
    fn xattrs_return_not_supported() {
        let temp = TempDir::new();
        fs::write(temp.path.join("hello.txt"), b"hello").unwrap();

        let passthrough = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();

        let file = CStr::from_bytes_with_nul(b"hello.txt\0").unwrap();
        let entry = passthrough.lookup(context(), fuse::ROOT_ID, file).unwrap();
        let name = CStr::from_bytes_with_nul(b"user.test\0").unwrap();

        expect_linux_error(passthrough.readlink(context(), entry.inode), LINUX_EINVAL);
        expect_linux_error(
            passthrough.setxattr(context(), entry.inode, name, b"value", 0),
            LINUX_EOPNOTSUPP,
        );
        expect_linux_error(
            passthrough.getxattr(context(), entry.inode, name, 0),
            LINUX_EOPNOTSUPP,
        );
        expect_linux_error(
            passthrough.listxattr(context(), entry.inode, 0),
            LINUX_EOPNOTSUPP,
        );
        expect_linux_error(
            passthrough.removexattr(context(), entry.inode, name),
            LINUX_EOPNOTSUPP,
        );
    }

    #[test]
    fn statfs_reports_host_capacity() {
        let temp = TempDir::new();
        let passthrough = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();

        let stat = passthrough.statfs(context(), fuse::ROOT_ID).unwrap();

        assert!(stat.f_blocks > 0);
        assert!(stat.f_bfree <= stat.f_blocks);
        assert_eq!(stat.f_bsize, STATFS_FRAGMENT_SIZE);
        assert_eq!(stat.f_frsize, STATFS_FRAGMENT_SIZE);
        assert_eq!(stat.f_namemax, STATFS_NAME_MAX);
    }

    #[test]
    fn ioctl_records_init_exit_code() {
        let temp = TempDir::new();
        let passthrough = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();

        let exit_code = Arc::new(AtomicI32::new(i32::MAX));
        passthrough
            .ioctl(
                context(),
                passthrough.init_inode,
                passthrough.init_handle,
                0,
                0x7602,
                42,
                0,
                0,
                &exit_code,
            )
            .unwrap();

        assert_eq!(exit_code.load(Ordering::SeqCst), 42);
    }

    #[test]
    fn ioctl_removes_root_only_when_configured() {
        let temp = TempDir::new();
        fs::write(temp.path.join("owned.txt"), b"owned").unwrap();
        let passthrough = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            allow_root_dir_delete: true,
            ..Default::default()
        })
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();

        let exit_code = Arc::new(AtomicI32::new(i32::MAX));
        passthrough
            .ioctl(context(), fuse::ROOT_ID, 0, 0, 0x7603, 0, 0, 0, &exit_code)
            .unwrap();

        assert!(!temp.path.exists());
    }

    #[test]
    fn setupmapping_and_removemapping_manage_file_view() {
        let temp = TempDir::new();
        fs::write(temp.path.join("dax.txt"), b"windows-dax").unwrap();

        let passthrough = PassthroughFs::new(Config {
            root_dir: temp.path.to_string_lossy().into_owned(),
            ..Default::default()
        })
        .unwrap();
        passthrough.init(FsOptions::empty()).unwrap();

        let name = CStr::from_bytes_with_nul(b"dax.txt\0").unwrap();
        let entry = passthrough.lookup(context(), fuse::ROOT_ID, name).unwrap();
        let (handle, _) = passthrough.open(context(), entry.inode, false, 0).unwrap();
        let handle = handle.unwrap();
        let (sender, receiver) = unbounded();
        let map_sender = Some(sender);
        let worker = std::thread::spawn(move || {
            match receiver.recv().unwrap() {
                WorkerMessage::DaxAddMapping(reply, host_addr, guest_addr, len, writable) => {
                    assert_ne!(host_addr, 0);
                    assert_eq!(guest_addr, 0x3000);
                    assert_eq!(len, 11);
                    assert!(!writable);
                    reply.send(true).unwrap();
                }
                _ => panic!("unexpected worker message"),
            }
            match receiver.recv().unwrap() {
                WorkerMessage::GpuRemoveMapping(reply, guest_addr, len) => {
                    assert_eq!(guest_addr, 0x3000);
                    assert_eq!(len, 11);
                    reply.send(true).unwrap();
                }
                _ => panic!("unexpected worker message"),
            }
        });

        passthrough
            .setupmapping(
                context(),
                entry.inode,
                handle,
                0,
                11,
                fuse::SetupmappingFlags::READ.bits(),
                0x2000,
                0x1000,
                0x8000,
                &map_sender,
            )
            .unwrap();
        passthrough
            .removemapping(
                context(),
                vec![fuse::RemovemappingOne {
                    moffset: 0x2000,
                    len: 11,
                }],
                0x1000,
                0x8000,
                &map_sender,
            )
            .unwrap();

        worker.join().unwrap();
        passthrough
            .release(context(), entry.inode, 0, handle, false, false, None)
            .unwrap();
    }
}
