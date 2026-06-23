//! Inode, handle, and lookup helpers for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
pub(super) struct InodeTable {
    pub(super) by_inode: BTreeMap<u64, Arc<InodeData>>,
    pub(super) by_path: BTreeMap<PathBuf, Arc<InodeData>>,
}

pub(super) struct InodeData {
    pub(super) inode: u64,
    pub(super) path: PathBuf,
    pub(super) virtual_meta: RwLock<VirtualMetadata>,
}

#[derive(Clone, Debug, Default)]
pub(super) struct VirtualMetadata {
    pub(super) uid: u32,
    pub(super) gid: u32,
    pub(super) mode: Option<u32>,
    pub(super) rdev: u64,
}

pub(super) struct HandleData {
    pub(super) inode: u64,
    pub(super) flags: u32,
    pub(super) file: Mutex<File>,
}

pub(super) struct DirHandle {
    pub(super) inode: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn insert_root(&self) -> io::Result<Entry> {
        let metadata = self.safe_metadata(&self.root)?;
        let data = Arc::new(InodeData {
            inode: ROOT_INODE,
            path: self.root.clone(),
            virtual_meta: RwLock::new(VirtualMetadata::default()),
        });

        let mut inodes = self.inodes.write().unwrap();
        inodes.by_inode.clear();
        inodes.by_path.clear();
        inodes.by_inode.insert(ROOT_INODE, data.clone());
        inodes.by_path.insert(self.root.clone(), data.clone());

        self.entry_from_metadata(&metadata, data.as_ref())
    }

    pub(super) fn inode(&self, inode: u64) -> io::Result<Arc<InodeData>> {
        self.inodes
            .read()
            .unwrap()
            .by_inode
            .get(&inode)
            .cloned()
            .ok_or_else(|| linux_error(LINUX_EBADF))
    }

    pub(super) fn intern_path(&self, path: PathBuf) -> Arc<InodeData> {
        let mut inodes = self.inodes.write().unwrap();
        if let Some(data) = inodes.by_path.get(&path) {
            return data.clone();
        }

        let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
        let data = Arc::new(InodeData {
            inode,
            path: path.clone(),
            virtual_meta: RwLock::new(VirtualMetadata::default()),
        });
        inodes.by_inode.insert(inode, data.clone());
        inodes.by_path.insert(path, data.clone());
        data
    }

    pub(super) fn child_path(&self, parent: u64, name: &CStr) -> io::Result<PathBuf> {
        let name = validate_component(name)?;
        let parent = self.inode(parent)?;
        Ok(parent.path.join(name))
    }

    pub(super) fn entry_for_path(&self, path: PathBuf) -> io::Result<Entry> {
        let metadata = self.safe_metadata(&path)?;
        let data = self.intern_path(path.clone());
        self.entry_from_metadata(&metadata, data.as_ref())
    }

    pub(super) fn do_lookup(&self, parent: u64, name: &CStr) -> io::Result<Entry> {
        if self.cfg.inject_init && parent == ROOT_INODE && name.to_bytes() == INIT_NAME {
            return Ok(init_entry(self.cfg.entry_timeout, self.cfg.attr_timeout));
        }

        let path = self.child_path(parent, name)?;
        self.entry_for_path(path)
    }

    pub(super) fn handle(&self, inode: u64, handle: u64) -> io::Result<Arc<HandleData>> {
        if self.cfg.inject_init && inode == INIT_INODE && handle == INIT_HANDLE {
            return Err(linux_error(LINUX_EBADF));
        }

        self.handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.inode == inode)
            .cloned()
            .ok_or_else(|| linux_error(LINUX_EBADF))
    }
}
