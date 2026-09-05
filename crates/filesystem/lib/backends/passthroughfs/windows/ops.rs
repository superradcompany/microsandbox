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
        // Validate the name before the deny check so a non-UTF-8 (invalid)
        // name fails with EINVAL rather than EACCES, matching lookup.
        let path = self.child_path(parent, name)?;
        if self.deny_matches_name(parent, name, true) {
            return Err(linux_error(LINUX_EACCES));
        }
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
        // Validate the name before the deny check so a non-UTF-8 (invalid)
        // name fails with EINVAL rather than EACCES, matching lookup.
        let path = self.child_path(parent, name)?;
        if self.deny_matches_name(parent, name, false) {
            return Err(linux_error(LINUX_EACCES));
        }
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
        // Validate the name before the deny check so a non-UTF-8 (invalid)
        // name fails with EINVAL rather than EACCES, matching lookup.
        let path = self.child_path(parent, name)?;
        if self.deny_matches_name(parent, name, true) {
            return Err(linux_error(LINUX_EACCES));
        }
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

        // Validate both names before the deny check so a non-UTF-8 (invalid)
        // name fails with EINVAL rather than EACCES, matching lookup.
        let old_path = self.child_path(olddir, oldname)?;
        let new_path = self.child_path(newdir, newname)?;

        // The source type can change between the deny checks and the move when
        // an external writer (host process, or a second mount on the same host
        // directory) bypasses the single-threaded virtio-fs worker that
        // serializes guest requests. A directory swapped in for a file would
        // otherwise land at a dir-only-denied destination. Narrow this by
        // capturing the source file's identity, re-verifying the source path
        // still refers to it immediately before the move, and retrying the
        // whole check+move on a mismatch.
        const MAX_RETRIES: u32 = 3;
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            if attempts > MAX_RETRIES {
                return Err(linux_error(LINUX_EBUSY));
            }

            // A rename replaces the destination with the source's type, so the
            // destination's effective type is the source's; use it for both deny
            // checks so a dir-only pattern like `node_modules/` rejects renaming
            // a directory to that name while still allowing a same-named file.
            let source_meta = self.safe_metadata(&old_path)?;
            let source_is_dir = if self.deny.has_dir_only_patterns() {
                source_meta.file_type().is_dir()
            } else {
                false
            };

            if self.deny_matches_name(olddir, oldname, source_is_dir)
                || self.deny_matches_name(newdir, newname, source_is_dir)
            {
                return Err(linux_error(LINUX_EACCES));
            }

            // A rename whose destination already exists as a *directory* denied
            // by a dir-only pattern would otherwise surface a raw EISDIR/ENOTDIR
            // and leak the hidden entry's existence and type. Reject it explicitly.
            if self.deny.has_dir_only_patterns() {
                let dest_is_dir = self
                    .safe_metadata(&new_path)
                    .map(|m| m.file_type().is_dir())
                    .unwrap_or(false);
                if dest_is_dir && self.deny_matches_name(newdir, newname, true) {
                    return Err(linux_error(LINUX_EACCES));
                }
            }

            // The source path must still refer to the same file before moving it.
            // Only retry on a definitive identity mismatch. A dir-only pattern
            // distinguishes files from directories, so a file named `node_modules`
            // is legitimately renamable while a directory is denied. The stale-type
            // risk is therefore only real when a directory could land at a
            // dir-only-denied *destination* after a file was decided; the
            // source-side collision is already enforced by the deny check above (a
            // denied directory is rejected outright). Refuse just that destination
            // case, and only when the source was decided to be a file (the decision
            // a swap could invalidate). `is_dir` only affects matching under
            // dir-only patterns, so gate on that too and skip the redundant pass
            // otherwise.
            // When the filesystem reports no file identity (FAT32/exFAT, some
            // network volumes) the source's type at move time cannot be verified.
            // On such filesystems this guard makes a rename fail closed (EBUSY)
            // only when the destination collides with a dir-only pattern and the
            // source was decided to be a file, because that is the one case a swap
            // could turn into a directory landing at a denied name. Ordinary
            // renames between non-denied paths, and renames of a same-named file
            // away from a dir-only pattern, are unaffected: FAT/exFAT keeps nearly
            // full rename support except for the narrow destination-collision case.
            // The window between this re-check and the path-based rename below is
            // irreducible: nothing pins the source through the move, so a fast
            // enough external writer can still swap a directory past this final
            // check. That residual risk is accepted, matching the Linux and macOS
            // backends, where no rename-conditional-on-inode operation exists and
            // the same window cannot be closed at all (upstream virtiofsd accepts
            // the same race).
            let after_identity = file_identity(&self.safe_metadata(&old_path)?);
            let dir_denied = !source_is_dir
                && self.deny.has_dir_only_patterns()
                && self.deny_matches_name(newdir, newname, true);
            match (file_identity(&source_meta), after_identity) {
                (Some(before), Some(after)) if before != after => continue,
                (None, _) | (_, None) if dir_denied => {
                    return Err(linux_error(LINUX_EBUSY));
                }
                _ => {}
            }

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
            break;
        }

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
        // A read-only handle has no buffered writes to persist. On Windows, flush
        // maps to FlushFileBuffers, which requires the handle to hold GENERIC_WRITE
        // and returns ERROR_ACCESS_DENIED on a read-only handle. That surfaces as a
        // spurious EACCES on the guest close() of any read. Skip flush for read-only
        // handles: there is nothing to sync.
        if !open_flags_write(handle.flags) {
            return Ok(());
        }
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

    fn readdir_for_each(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
        add_entry: &mut AddDirEntry<'_>,
    ) -> io::Result<()> {
        let dir_handle = self
            .dir_handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.inode == inode)
            .cloned()
            .ok_or_else(|| linux_error(LINUX_EBADF))?;
        let _ = dir_handle;

        self.dir_entries_for_each(inode, offset, &mut |dir_entry, _entry| add_entry(dir_entry))
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

    fn readdirplus_for_each(
        &self,
        _ctx: Context,
        inode: u64,
        handle: u64,
        _size: u32,
        offset: u64,
        add_entry: &mut AddDirEntryPlus<'_>,
    ) -> io::Result<()> {
        let dir_handle = self
            .dir_handles
            .read()
            .unwrap()
            .get(&handle)
            .filter(|data| data.inode == inode)
            .cloned()
            .ok_or_else(|| linux_error(LINUX_EBADF))?;
        let _ = dir_handle;

        self.dir_entries_for_each(inode, offset, add_entry)
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
