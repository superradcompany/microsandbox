//! Inode, handle, and lookup helpers for the Windows passthrough backend.

use std::collections::BTreeSet;
use std::ffi::CString;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::ptr::null;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_ID_DESCRIPTOR, FILE_ID_DESCRIPTOR_0, FILE_NAME_NORMALIZED, FILE_READ_ATTRIBUTES,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdType, GetFinalPathNameByHandleW,
    OpenFileById, VOLUME_NAME_DOS,
};

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
    pub(super) fn path_identity(&self, path: &Path) -> io::Result<Option<(u32, u64)>> {
        let file = StdOpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
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
            // Renamed `try_update` in Rust 1.99; keep older toolchains building.
            #[allow(deprecated)]
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
            // Renamed `try_update` in Rust 1.99; keep older toolchains building.
            #[allow(deprecated)]
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
            identity: self.path_identity(&self.root)?,
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
        let identity = self.path_identity(&path)?;
        let mut inodes = self.inodes.write().unwrap();
        if let Some(data) = inodes.by_path.get(&path).cloned() {
            // A cached alias (hard link) can outlive the canonical name.
            if identity.is_some() && data.identity == identity {
                let displaced =
                    Self::follow_host_rename(&mut inodes, &data, &path, |p| self.path_identity(p));
                self.finish_displaced(&mut inodes, displaced);
            }
            return Ok(data);
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
            } else {
                let displaced =
                    Self::follow_host_rename(&mut inodes, &data, &path, |p| self.path_identity(p));
                self.finish_displaced(&mut inodes, displaced);
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

    /// Renamed or moved on the host (same file identity, new name): if the
    /// canonical path no longer resolves to this object, re-point it to
    /// `path` (a live name of the same object) and drop the stale alias.
    /// Otherwise every operation through the inode (stat, open, and the
    /// readdir of its directory) fails until the sandbox restarts. A live
    /// hard link keeps its canonical path.
    /// Returns the inodes whose cached names the moved descendants took.
    fn follow_host_rename(
        inodes: &mut InodeTable,
        data: &Arc<InodeData>,
        path: &Path,
        identity_of: impl Fn(&Path) -> io::Result<Option<(u32, u64)>>,
    ) -> Vec<Arc<InodeData>> {
        if data.retained.lock().unwrap().is_some() {
            return Vec::new();
        }
        let canonical = data.path();
        if canonical == path || identity_of(&canonical).ok().flatten() == data.identity {
            return Vec::new();
        }
        if inodes
            .by_path
            .get(&canonical)
            .is_some_and(|alias| Arc::ptr_eq(alias, data))
        {
            inodes.by_path.remove(&canonical);
        }
        *data.path.write().unwrap() = path.to_path_buf();
        Self::follow_host_rename_descendants(inodes, data, &canonical, path, &identity_of)
    }

    /// Names a moved descendant took from stale cached entries. An inode that
    /// held one follows its file to the name the file has now, found by its
    /// file id, taking its cached descendants along as a host rename does, so
    /// reads, writes, listings and metadata through it, by handle or by path,
    /// reach its own file or directory and not the one that took its old
    /// name. A stale entry the followed name or a descendant takes over is
    /// finished the same way. An inode whose file is gone, or has no name the
    /// guest can reach, lost its name as in an unlink.
    fn finish_displaced(&self, inodes: &mut InodeTable, displaced: Vec<Arc<InodeData>>) {
        if displaced.is_empty() {
            return;
        }
        // Opened once for the whole batch: this runs under the table lock.
        let root = self.open_root_by_name();
        let mut pending = displaced;
        let mut seen = BTreeSet::new();
        while let Some(data) = pending.pop() {
            // Displaced only through another name, or already followed in
            // this batch: it still holds a live name of its own.
            let canonical = data.path();
            if data.identity.is_some()
                && inodes
                    .by_path
                    .get(&canonical)
                    .is_some_and(|alias| Arc::ptr_eq(alias, &data))
                && self.path_identity(&canonical).ok().flatten() == data.identity
            {
                continue;
            }
            // A host racing these moves could hand an inode back; finish it
            // instead of following it again.
            let name = match &root {
                Ok(root) if seen.insert(data.inode) => self.current_name(&data, root),
                Ok(_) => Ok(None),
                Err(error) => Err(io::Error::new(error.kind(), error.to_string())),
            };
            let path = match name {
                Ok(Some(path)) => path,
                Ok(None) => {
                    self.finish_removed_alias(inodes, &data);
                    continue;
                }
                Err(error) => {
                    tracing::debug!(
                        ?error,
                        inode = data.inode,
                        "cannot find the host name of a displaced inode"
                    );
                    self.finish_removed_alias(inodes, &data);
                    continue;
                }
            };

            let old = data.path();
            *data.path.write().unwrap() = path.clone();
            if inodes
                .by_path
                .get(&old)
                .is_some_and(|alias| Arc::ptr_eq(alias, &data))
            {
                inodes.by_path.remove(&old);
            }
            if let Some(stale) = inodes.by_path.insert(path.clone(), data.clone())
                && !Arc::ptr_eq(&stale, &data)
            {
                pending.push(stale);
            }
            // Only a directory with cached descendants has any to take along;
            // the walk over every tracked inode is skipped otherwise.
            let has_descendants = inodes
                .by_path
                .range(old.clone()..)
                .find(|(key, _)| **key != old)
                .is_some_and(|(key, _)| key.starts_with(&old));
            if has_descendants {
                pending.extend(Self::follow_host_rename_descendants(
                    inodes,
                    &data,
                    &old,
                    &path,
                    &|p: &Path| self.path_identity(p),
                ));
            }
        }
    }

    /// The mount root opened for asking a file's name by its file id, with
    /// the root's own final path to take the file's path relative to.
    fn open_root_by_name(&self) -> io::Result<(File, PathBuf)> {
        let root = StdOpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(&self.root)
            .map_err(host_error)?;
        let root_path = final_path(&root)?;
        Ok((root, root_path))
    }

    /// The path under the mount root that names the file or directory of
    /// `data` now. `None` when it is on another volume or its name is not one
    /// the guest can reach.
    fn current_name(
        &self,
        data: &InodeData,
        (root, root_path): &(File, PathBuf),
    ) -> io::Result<Option<PathBuf>> {
        let Some(identity) = data.identity else {
            return Ok(None);
        };
        let file = open_by_file_index(root, identity.1)?;
        if mobility::file_identity(&file)? != identity {
            return Ok(None);
        }

        let host = final_path(&file)?;
        let Ok(relative) = host.strip_prefix(root_path) else {
            return Ok(None);
        };
        let mut path = self.root.clone();
        for component in relative.components() {
            let Component::Normal(name) = component else {
                return Ok(None);
            };
            let Some(name) = name.to_str().and_then(|name| CString::new(name).ok()) else {
                return Ok(None);
            };
            let Ok(name) = validate_component(&name) else {
                return Ok(None);
            };
            path.push(name);
        }

        // The name is checked by path as a lookup checks it, with no reparse
        // point on the way, and read again: the host may have moved the file
        // once more since its name was asked.
        if path == self.root
            || self.safe_metadata(&path).is_err()
            || self.path_identity(&path)? != Some(identity)
        {
            return Ok(None);
        }
        Ok(Some(path))
    }

    /// A directory renamed on the host takes its cached descendants along:
    /// each alias and canonical path under `old` is rewritten under `new`, as
    /// `rename_inode_path` does for guest-side renames, but only when the host
    /// confirms the same object now lives at the rewritten path. Entries that
    /// fail the check stay put: they belong to whatever now occupies `old`
    /// (cached through the stale directory inode before this repair), or the
    /// object is gone. The repaired directory and its new alias are skipped.
    /// Identity checks run only for entries under `old`, on this rare path.
    fn follow_host_rename_descendants(
        inodes: &mut InodeTable,
        repaired: &Arc<InodeData>,
        old: &Path,
        new: &Path,
        identity_of: &impl Fn(&Path) -> io::Result<Option<(u32, u64)>>,
    ) -> Vec<Arc<InodeData>> {
        let rewritten = |p: &Path| -> Option<PathBuf> {
            if p == old {
                return None;
            }
            p.strip_prefix(old).ok().map(|rest| new.join(rest))
        };
        // Without a file identity there is nothing to check: follow the move.
        let live_at = |data: &InodeData, target: &Path| match data.identity {
            Some(id) => identity_of(target).ok().flatten() == Some(id),
            None => true,
        };
        let moved = inodes
            .by_path
            .range(old.to_path_buf()..)
            .take_while(|(p, _)| p.starts_with(old))
            .filter(|(_, d)| !Arc::ptr_eq(d, repaired))
            .filter_map(|(p, d)| {
                let target = rewritten(p)?;
                live_at(d, &target).then(|| (p.clone(), target, d.clone()))
            })
            .collect::<Vec<_>>();
        // All sources out before any insert: on an upward move a target can be
        // another source's key (`p/c/c/f` -> `p/c/f`). A target held by a
        // non-source entry is stale, since the host now has this object there: it
        // is returned, to be finished as an unlink.
        for (source, _, _) in &moved {
            inodes.by_path.remove(source);
        }
        let mut displaced = Vec::new();
        for (_, target, data) in moved {
            if let Some(stale) = inodes.by_path.insert(target, data.clone())
                && !Arc::ptr_eq(&stale, &data)
            {
                displaced.push(stale);
            }
        }
        for data in inodes.by_inode.values() {
            if Arc::ptr_eq(data, repaired) {
                continue;
            }
            if let Some(target) = rewritten(&data.path())
                && live_at(data, &target)
            {
                *data.path.write().unwrap() = target;
            }
        }
        displaced
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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open, for reading attributes, the file or directory with the file index
/// `index` on the volume `volume` is on.
fn open_by_file_index(volume: &File, index: u64) -> io::Result<File> {
    let descriptor = FILE_ID_DESCRIPTOR {
        dwSize: size_of::<FILE_ID_DESCRIPTOR>() as u32,
        Type: FileIdType,
        Anonymous: FILE_ID_DESCRIPTOR_0 {
            FileId: index as i64,
        },
    };

    // SAFETY: the volume handle is open for the duration of the call, the
    // descriptor is initialized and outlives it, and no security attributes
    // are passed.
    let handle = unsafe {
        OpenFileById(
            volume.as_raw_handle() as HANDLE,
            &descriptor,
            FILE_READ_ATTRIBUTES,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            null(),
            FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT,
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(host_error(io::Error::last_os_error()));
    }

    // SAFETY: OpenFileById returned a new handle, owned from here by the File.
    Ok(unsafe { File::from_raw_handle(handle) })
}

/// The normalized host path of an open file, in the `\\?\` form
/// `std::fs::canonicalize` returns (`\\?\C:\...` or `\\?\UNC\...`).
fn final_path(file: &File) -> io::Result<PathBuf> {
    let mut buffer = vec![0u16; 512];
    loop {
        // SAFETY: the handle is open for the duration of the call, and the
        // buffer is writable for the length passed, counted in UTF-16 units.
        let len = unsafe {
            GetFinalPathNameByHandleW(
                file.as_raw_handle() as HANDLE,
                buffer.as_mut_ptr(),
                buffer.len() as u32,
                FILE_NAME_NORMALIZED | VOLUME_NAME_DOS,
            )
        } as usize;
        if len == 0 {
            return Err(io::Error::last_os_error());
        }
        if len < buffer.len() {
            buffer.truncate(len);
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        // Too small: `len` is the size needed, terminating null included.
        buffer.resize(len.max(buffer.len() + 1), 0);
    }
}
