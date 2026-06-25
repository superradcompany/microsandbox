//! DynFileSystem callback table for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl DynFileSystem for PassthroughFs {
    fn init(&self, _capable: FsOptions) -> io::Result<FsOptions> {
        self.insert_root()?;
        Ok(FsOptions::empty())
    }

    fn destroy(&self) {
        self.handles.write().unwrap().clear();
        self.dir_handles.write().unwrap().clear();
        self.inodes.write().unwrap().by_inode.clear();
        self.inodes.write().unwrap().by_path.clear();
    }

    fn lookup(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<Entry> {
        self.do_lookup(parent, name)
    }

    fn getattr(
        &self,
        _ctx: Context,
        inode: u64,
        _handle: Option<u64>,
    ) -> io::Result<(stat64, Duration)> {
        self.do_getattr(inode)
    }

    fn setattr(
        &self,
        _ctx: Context,
        inode: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        self.do_setattr(inode, attr, handle, valid)
    }

    fn readlink(&self, _ctx: Context, inode: u64) -> io::Result<Vec<u8>> {
        self.do_readlink(inode)
    }

    fn symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        self.do_symlink(ctx, linkname, parent, name)
    }

    #[allow(clippy::too_many_arguments)]
    fn mknod(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        self.do_mknod(ctx, parent, name, mode, rdev, umask)
    }

    fn mkdir(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        umask: u32,
        _extensions: Extensions,
    ) -> io::Result<Entry> {
        self.require_writable()?;
        let path = self.child_path(parent, name)?;
        let parent_path = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        std::fs::create_dir(&path).map_err(host_error)?;
        let entry = self.entry_for_path(path)?;
        let data = self.inode(entry.inode)?;
        if let Err(error) = self.set_virtual_metadata(
            data.as_ref(),
            ctx.uid,
            ctx.gid,
            S_IFDIR | (mode & !umask & 0o7777),
            0,
        ) {
            let _ = std::fs::remove_dir(&data.path);
            self.remove_inode_path(&data.path);
            return Err(error);
        }
        self.entry_for_path(data.path.clone())
    }

    fn unlink(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.require_writable()?;
        let path = self.child_path(parent, name)?;
        let metadata = self.safe_metadata(&path)?;
        if metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_EISDIR));
        }

        std::fs::remove_file(&path).map_err(host_error)?;
        if let Some(store) = &self.stat_store {
            store.remove(&path)?;
        }
        self.remove_inode_path(&path);
        Ok(())
    }

    fn rmdir(&self, _ctx: Context, parent: u64, name: &CStr) -> io::Result<()> {
        self.require_writable()?;
        let path = self.child_path(parent, name)?;
        let metadata = self.safe_metadata(&path)?;
        if !metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        std::fs::remove_dir(&path).map_err(host_error)?;
        if let Some(store) = &self.stat_store {
            store.remove(&path)?;
        }
        self.remove_inode_path(&path);
        Ok(())
    }

    fn rename(
        &self,
        _ctx: Context,
        olddir: u64,
        oldname: &CStr,
        newdir: u64,
        newname: &CStr,
        flags: u32,
    ) -> io::Result<()> {
        self.require_writable()?;
        if flags & (RENAME_EXCHANGE | RENAME_WHITEOUT) != 0 {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }

        let old_path = self.child_path(olddir, oldname)?;
        self.safe_metadata(&old_path)?;
        let new_path = self.child_path(newdir, newname)?;
        let new_parent = new_path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(new_parent)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }
        if flags & RENAME_NOREPLACE != 0 && new_path.exists() {
            return Err(linux_error(LINUX_EEXIST));
        }
        if new_path.exists() {
            self.safe_metadata(&new_path)?;
        }

        std::fs::rename(&old_path, &new_path).map_err(host_error)?;
        if let Some(store) = &self.stat_store {
            store.rename(&old_path, &new_path)?;
        }
        self.rename_inode_path(&old_path, &new_path);
        Ok(())
    }

    fn link(&self, _ctx: Context, inode: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        self.do_link(inode, newparent, newname)
    }

    fn open(
        &self,
        _ctx: Context,
        inode: u64,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        self.do_open(inode, kill_priv, flags)
    }

    fn create(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        _kill_priv: bool,
        flags: u32,
        umask: u32,
        _extensions: Extensions,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        self.do_create(ctx, parent, name, mode, flags, umask)
    }

    fn read(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        w: &mut dyn ZeroCopyWriter,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _flags: u32,
    ) -> io::Result<usize> {
        if self.cfg.inject_init && inode == INIT_INODE && handle == INIT_HANDLE {
            let init_file = self
                .init_file
                .as_ref()
                .ok_or_else(|| linux_error(LINUX_EBADF))?
                .lock()
                .unwrap();
            return w.write_from(&init_file, size as usize, offset);
        }

        let handle = self.handle(inode, handle)?;
        if !open_flags_readable(handle.flags) {
            return Err(linux_error(LINUX_EBADF));
        }
        let file = handle.file.lock().unwrap();
        w.write_from(&file, size as usize, offset)
            .map_err(host_error)
    }

    fn write(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        r: &mut dyn ZeroCopyReader,
        size: u32,
        offset: u64,
        _lock_owner: Option<u64>,
        _delayed_write: bool,
        kill_priv: bool,
        _flags: u32,
    ) -> io::Result<usize> {
        self.require_writable()?;
        let handle = self.handle(inode, handle)?;
        if !open_flags_writable(handle.flags) {
            return Err(linux_error(LINUX_EBADF));
        }

        let data = self.inode(inode)?;
        let old_len = self.safe_metadata(&data.path)?.len();
        let file = handle.file.lock().unwrap();
        let offset = if handle.flags & LINUX_O_APPEND as u32 != 0 {
            file.metadata().map_err(host_error)?.len()
        } else {
            offset
        };
        self.quota_charge_growth(old_len, offset.saturating_add(size as u64))?;
        let written = r
            .read_to(&file, size as usize, offset)
            .map_err(host_error)?;
        if kill_priv {
            self.clear_priv_bits(data.as_ref())?;
        }
        Ok(written)
    }

    fn flush(&self, _ctx: Context, inode: u64, handle: u64, _lock_owner: u64) -> io::Result<()> {
        if self.cfg.inject_init && inode == INIT_INODE && handle == INIT_HANDLE {
            return Ok(());
        }

        let handle = self.handle(inode, handle)?;
        handle.file.lock().unwrap().sync_data().map_err(host_error)
    }

    fn fsync(&self, _ctx: Context, inode: u64, datasync: bool, handle: u64) -> io::Result<()> {
        if self.cfg.inject_init && inode == INIT_INODE && handle == INIT_HANDLE {
            return Ok(());
        }

        let handle = self.handle(inode, handle)?;
        let file = handle.file.lock().unwrap();
        if datasync {
            file.sync_data().map_err(host_error)
        } else {
            file.sync_all().map_err(host_error)
        }
    }

    fn release(
        &self,
        _ctx: Context,
        inode: u64,
        _flags: u32,
        handle: u64,
        _flush: bool,
        _flock_release: bool,
        _lock_owner: Option<u64>,
    ) -> io::Result<()> {
        if self.cfg.inject_init && inode == INIT_INODE && handle == INIT_HANDLE {
            return Ok(());
        }

        let mut handles = self.handles.write().unwrap();
        match handles.remove(&handle) {
            Some(data) if data.inode == inode => Ok(()),
            Some(data) => {
                handles.insert(handle, data);
                Err(linux_error(LINUX_EBADF))
            }
            None => Err(linux_error(LINUX_EBADF)),
        }
    }

    fn statfs(&self, _ctx: Context, _inode: u64) -> io::Result<statvfs64> {
        if let Some(quota) = &self.quota {
            return Ok(super::super::quota::quota_statvfs(
                quota.baseline(),
                quota.limit(),
                quota.used(),
            ));
        }

        Ok(statvfs64 {
            f_bsize: 4096,
            f_frsize: 4096,
            f_blocks: 1,
            f_bfree: 0,
            f_bavail: 0,
            f_files: self.inodes.read().unwrap().by_inode.len() as u64,
            f_ffree: 0,
            f_namemax: 255,
            ..Default::default()
        })
    }

    fn setxattr(
        &self,
        _ctx: Context,
        _inode: u64,
        _name: &CStr,
        _value: &[u8],
        _flags: u32,
    ) -> io::Result<()> {
        Err(linux_error(LINUX_EOPNOTSUPP))
    }

    fn getxattr(
        &self,
        _ctx: Context,
        _inode: u64,
        _name: &CStr,
        _size: u32,
    ) -> io::Result<GetxattrReply> {
        Err(linux_error(LINUX_ENODATA))
    }

    fn listxattr(&self, _ctx: Context, _inode: u64, size: u32) -> io::Result<ListxattrReply> {
        if size == 0 {
            Ok(ListxattrReply::Count(0))
        } else {
            Ok(ListxattrReply::Names(Vec::new()))
        }
    }

    fn removexattr(&self, _ctx: Context, _inode: u64, _name: &CStr) -> io::Result<()> {
        Err(linux_error(LINUX_ENODATA))
    }

    fn opendir(
        &self,
        _ctx: Context,
        inode: u64,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if flags & LINUX_O_DIRECT as u32 != 0 {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }
        if self.cfg.inject_init && inode == INIT_INODE {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let data = self.inode(inode)?;
        let metadata = self.safe_metadata(&data.path)?;
        if !metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.dir_handles
            .write()
            .unwrap()
            .insert(handle, Arc::new(DirHandle { inode }));
        Ok((Some(handle), OpenOptions::empty()))
    }

    fn readdir(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
    ) -> io::Result<Vec<DirEntry<'static>>> {
        let dir_handle = self
            .dir_handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.inode == inode)
            .cloned()
            .ok_or_else(|| linux_error(LINUX_EBADF))?;
        let _ = dir_handle;

        Ok(self
            .dir_entries(inode)?
            .into_iter()
            .map(|(dir_entry, _)| dir_entry)
            .skip(offset as usize)
            .collect())
    }

    fn readdirplus(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
    ) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        let dir_handle = self
            .dir_handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.inode == inode)
            .cloned()
            .ok_or_else(|| linux_error(LINUX_EBADF))?;
        let _ = dir_handle;

        Ok(self
            .dir_entries(inode)?
            .into_iter()
            .skip(offset as usize)
            .collect())
    }

    fn fsyncdir(&self, _ctx: Context, inode: u64, _datasync: bool, handle: u64) -> io::Result<()> {
        self.dir_handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.inode == inode)
            .map(|_| ())
            .ok_or_else(|| linux_error(LINUX_EBADF))
    }

    fn releasedir(&self, _ctx: Context, inode: u64, _flags: u32, handle: u64) -> io::Result<()> {
        let mut handles = self.dir_handles.write().unwrap();
        match handles.remove(&handle) {
            Some(data) if data.inode == inode => Ok(()),
            Some(data) => {
                handles.insert(handle, data);
                Err(linux_error(LINUX_EBADF))
            }
            None => Err(linux_error(LINUX_EBADF)),
        }
    }

    fn access(&self, _ctx: Context, inode: u64, mask: u32) -> io::Result<()> {
        if self.cfg.readonly && mask & LINUX_ACCESS_W_OK != 0 {
            return Err(linux_error(LINUX_EACCES));
        }
        if self.cfg.inject_init && inode == INIT_INODE {
            return Ok(());
        }

        let data = self.inode(inode)?;
        let metadata = self.safe_metadata(&data.path)?;
        let st = self.stat_from_metadata(&metadata, data.as_ref())?;
        check_access(_ctx, &st, mask)
    }
}
