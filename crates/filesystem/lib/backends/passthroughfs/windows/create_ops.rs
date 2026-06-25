//! Creation and link operations for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn do_create(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        flags: u32,
        umask: u32,
    ) -> io::Result<(Entry, Option<u64>, OpenOptions)> {
        self.require_writable()?;
        let path = self.child_path(parent, name)?;
        let parent_path = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        self.quota_ensure_baseline();

        let options = open_options_from_flags(flags, true)?;
        let file = options.open(&path).map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        let metadata = self.safe_metadata(&path)?;
        let data = self.intern_path(path.clone());
        if let Err(error) = self.set_virtual_metadata(
            data.as_ref(),
            ctx.uid,
            ctx.gid,
            (mode_from_metadata(&metadata) & S_IFMT) | (mode & !umask & 0o7777),
            0,
        ) {
            let _ = std::fs::remove_file(&path);
            self.remove_inode_path(&path);
            return Err(error);
        }

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles.write().unwrap().insert(
            handle,
            Arc::new(HandleData {
                inode: data.inode,
                flags,
                file: Mutex::new(file),
            }),
        );

        Ok((
            self.entry_from_metadata(&metadata, data.as_ref())?,
            Some(handle),
            OpenOptions::empty(),
        ))
    }

    pub(super) fn do_mknod(
        &self,
        ctx: Context,
        parent: u64,
        name: &CStr,
        mode: u32,
        rdev: u32,
        umask: u32,
    ) -> io::Result<Entry> {
        self.require_writable()?;
        let path = self.child_path(parent, name)?;
        let parent_path = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let file_type = mode & S_IFMT;
        if !self.cfg.stat_virtualization_enabled() && file_type != 0 && file_type != S_IFREG {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }

        let file = StdOpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;

        let metadata = self.safe_metadata(&path)?;
        let data = self.intern_path(path);
        let virtual_type = if file_type == 0 { S_IFREG } else { file_type };
        let virtual_mode = virtual_type | (mode & !umask & 0o7777);
        if let Err(error) =
            self.set_virtual_metadata(data.as_ref(), ctx.uid, ctx.gid, virtual_mode, rdev)
        {
            let _ = std::fs::remove_file(&data.path);
            self.remove_inode_path(&data.path);
            return Err(error);
        }

        self.entry_from_metadata(&metadata, data.as_ref())
    }

    pub(super) fn do_symlink(
        &self,
        ctx: Context,
        linkname: &CStr,
        parent: u64,
        name: &CStr,
    ) -> io::Result<Entry> {
        self.require_writable()?;
        if !self.cfg.stat_virtualization_enabled() {
            return Err(linux_error(LINUX_EOPNOTSUPP));
        }

        let path = self.child_path(parent, name)?;
        let parent_path = path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        self.quota_ensure_baseline();

        let mut file = StdOpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&path)
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        if let Err(error) = self.quota_charge_file_to(&file, linkname.to_bytes().len() as u64) {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }
        if let Err(error) = file.write_all(linkname.to_bytes()).map_err(host_error) {
            let _ = std::fs::remove_file(&path);
            return Err(error);
        }

        let metadata = self.safe_metadata(&path)?;
        let data = self.intern_path(path);
        if let Err(error) =
            self.set_virtual_metadata(data.as_ref(), ctx.uid, ctx.gid, S_IFLNK | 0o777, 0)
        {
            let _ = std::fs::remove_file(&data.path);
            self.remove_inode_path(&data.path);
            return Err(error);
        }

        self.entry_from_metadata(&metadata, data.as_ref())
    }

    pub(super) fn do_readlink(&self, inode: u64) -> io::Result<Vec<u8>> {
        if self.cfg.inject_init && inode == INIT_INODE {
            return Err(linux_error(LINUX_EINVAL));
        }

        let data = self.inode(inode)?;
        let metadata = self.safe_metadata(&data.path)?;
        let current = self.current_override(&metadata, data.as_ref())?;
        if current.mode & S_IFMT != S_IFLNK {
            return Err(linux_error(LINUX_EINVAL));
        }

        let mut file = StdOpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&data.path)
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        let mut target = Vec::new();
        file.read_to_end(&mut target).map_err(host_error)?;
        Ok(target)
    }

    pub(super) fn do_link(&self, inode: u64, newparent: u64, newname: &CStr) -> io::Result<Entry> {
        self.require_writable()?;
        if self.cfg.inject_init && inode == INIT_INODE {
            return Err(linux_error(LINUX_EACCES));
        }

        let source = self.inode(inode)?;
        self.safe_metadata(&source.path)?;
        let new_path = self.child_path(newparent, newname)?;
        let parent_path = new_path.parent().ok_or_else(|| linux_error(LINUX_EINVAL))?;
        let parent_metadata = self.safe_metadata(parent_path)?;
        if !parent_metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        std::fs::hard_link(&source.path, &new_path).map_err(host_error)?;
        let metadata = self.safe_metadata(&new_path)?;
        let data = self.intern_path(new_path);
        let current = self.current_override(&metadata, source.as_ref())?;
        if let Err(error) = self.set_virtual_metadata(
            data.as_ref(),
            current.uid,
            current.gid,
            current.mode,
            current.rdev,
        ) {
            let _ = std::fs::remove_file(&data.path);
            self.remove_inode_path(&data.path);
            return Err(error);
        }

        self.entry_from_metadata(&metadata, data.as_ref())
    }
}
