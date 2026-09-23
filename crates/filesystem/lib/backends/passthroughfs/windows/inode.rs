//! Inode, handle, and lookup helpers for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
pub(super) struct InodeTable {
    pub(super) by_inode: BTreeMap<u64, Arc<InodeData>>,
    pub(super) by_path: BTreeMap<PathBuf, Arc<InodeData>>,
    pub(super) by_identity: BTreeMap<(u32, u64), Arc<InodeData>>,
}

pub(super) struct InodeData {
    pub(super) inode: u64,
    pub(super) path: RwLock<PathBuf>,
    pub(super) identity: Option<(u32, u64)>,
    pub(super) virtual_meta: RwLock<VirtualMetadata>,
    /// Owned-only pin after the tracked namespace link disappears.
    pub(super) retained: Mutex<Option<File>>,
    /// A pinned ADS preserves shared guest metadata even after namespace unlink.
    pub(super) retained_stat: Mutex<Option<File>>,
    /// Guest lookup references, used for owned detached-object reclamation.
    pub(super) lookups: AtomicU64,
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
    pub(super) flags: u32,
    pub(super) snapshot: Mutex<Option<Vec<DirSnapshotEntry>>>,
}

#[derive(Clone)]
pub(super) struct DirSnapshotEntry {
    pub(super) inode: u64,
    pub(super) name: Vec<u8>,
    pub(super) offset: u64,
    pub(super) file_type: u32,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl InodeData {
    pub(super) fn path(&self) -> PathBuf {
        self.path.read().unwrap().clone()
    }
}

impl PassthroughFs {
    pub(super) fn owned_identity(&self, path: &Path) -> io::Result<Option<(u32, u64)>> {
        if self.cfg.owned_checkpoint.is_none() {
            return Ok(None);
        }
        let file = StdOpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(path)
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        mobility::file_identity(&file).map(Some)
    }

    pub(super) fn record_owned_entry(&self, entry: Entry) -> Entry {
        self.record_owned_lookup(entry.inode);
        entry
    }

    pub(super) fn record_owned_lookup(&self, inode: u64) {
        if self.cfg.owned_checkpoint.is_some()
            && let Ok(data) = self.inode(inode)
        {
            let _ = data
                .lookups
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |count| {
                    Some(count.saturating_add(1))
                });
        }
    }

    pub(super) fn forget_owned(&self, inode: u64, count: u64) {
        if self.cfg.owned_checkpoint.is_none() {
            return;
        }
        if let Ok(data) = self.inode(inode) {
            let _ = data
                .lookups
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                    Some(current.saturating_sub(count))
                });
        }
        self.reap_owned_inode(inode);
    }

    pub(super) fn reap_owned_inode(&self, inode: u64) {
        if self.cfg.owned_checkpoint.is_none() || inode <= INIT_INODE {
            return;
        }
        // Directory enumeration holds its snapshot lock while interning names. Do not
        // acquire that lock under the inode-table write lock in the opposite order.
        if self.dir_handles.read().unwrap().values().any(|handle| {
            handle
                .snapshot
                .lock()
                .unwrap()
                .as_ref()
                .is_some_and(|entries| entries.iter().any(|entry| entry.inode == inode))
        }) {
            return;
        }
        let mut inodes = self.inodes.write().unwrap();
        let Some(data) = inodes.by_inode.get(&inode) else {
            return;
        };
        if data.retained.lock().unwrap().is_none()
            || data.lookups.load(Ordering::Acquire) != 0
            || self
                .handles
                .read()
                .unwrap()
                .values()
                .any(|handle| handle.inode == inode)
        {
            return;
        }
        // No guest inode, open file, or cached directory entry can reference this pin now.
        let identity = data.identity;
        inodes.by_inode.remove(&inode);
        if let Some(identity) = identity {
            inodes.by_identity.remove(&identity);
        }
    }

    pub(super) fn insert_root(&self) -> io::Result<Entry> {
        let metadata = self.safe_metadata(&self.root)?;
        let data = Arc::new(InodeData {
            inode: ROOT_INODE,
            path: RwLock::new(self.root.clone()),
            identity: self.owned_identity(&self.root)?,
            virtual_meta: RwLock::new(VirtualMetadata::default()),
            retained: Mutex::new(None),
            retained_stat: Mutex::new(None),
            lookups: AtomicU64::new(0),
        });

        let mut inodes = self.inodes.write().unwrap();
        inodes.by_inode.clear();
        inodes.by_path.clear();
        inodes.by_identity.clear();
        inodes.by_inode.insert(ROOT_INODE, data.clone());
        inodes.by_path.insert(self.root.clone(), data.clone());
        if let Some(identity) = data.identity {
            inodes.by_identity.insert(identity, data.clone());
        }

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

    pub(super) fn intern_path(&self, path: PathBuf) -> io::Result<Arc<InodeData>> {
        let identity = self.owned_identity(&path)?;
        let mut inodes = self.inodes.write().unwrap();
        if let Some(data) = inodes.by_path.get(&path) {
            return Ok(data.clone());
        }
        if let Some(identity) = identity
            && let Some(data) = inodes.by_identity.get(&identity).cloned()
        {
            // FUSE aliases must share one logical inode, not just equal st_ino values:
            // otherwise the guest can cache conflicting file contents and attributes.
            inodes.by_path.insert(path.clone(), data.clone());
            if data.retained.lock().unwrap().is_some() {
                *data.path.write().unwrap() = path;
                *data.retained.lock().unwrap() = None;
                *data.retained_stat.lock().unwrap() = None;
            }
            return Ok(data);
        }

        let inode = self.next_inode.fetch_add(1, Ordering::Relaxed);
        let data = Arc::new(InodeData {
            inode,
            path: RwLock::new(path.clone()),
            identity,
            virtual_meta: RwLock::new(VirtualMetadata::default()),
            retained: Mutex::new(None),
            retained_stat: Mutex::new(None),
            lookups: AtomicU64::new(0),
        });
        inodes.by_inode.insert(inode, data.clone());
        inodes.by_path.insert(path, data.clone());
        if let Some(identity) = identity {
            inodes.by_identity.insert(identity, data.clone());
        }
        Ok(data)
    }

    pub(super) fn child_path(&self, parent: u64, name: &CStr) -> io::Result<PathBuf> {
        let name = validate_component(name)?;
        let parent = self.inode(parent)?;
        Ok(parent.path().join(name))
    }

    pub(super) fn entry_for_path(&self, path: PathBuf) -> io::Result<Entry> {
        let metadata = self.safe_metadata(&path)?;
        let data = self.intern_path(path.clone())?;
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
