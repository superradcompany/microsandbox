//! Directory enumeration helpers for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn dir_entries(&self, inode: u64) -> io::Result<Vec<(DirEntry<'static>, Entry)>> {
        let data = self.inode(inode)?;
        let metadata = self.safe_metadata(&data.path)?;
        if !metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_ENOTDIR));
        }

        let mut entries = Vec::new();
        entries.push((
            DirEntry {
                ino: inode,
                offset: 1,
                type_: DT_DIR,
                name: b".",
            },
            self.entry_from_metadata(&metadata, data.as_ref())?,
        ));
        entries.push((
            DirEntry {
                ino: ROOT_INODE,
                offset: 2,
                type_: DT_DIR,
                name: b"..",
            },
            self.parent_entry(data.as_ref())?,
        ));

        if self.cfg.inject_init && inode == ROOT_INODE {
            entries.push((
                DirEntry {
                    ino: INIT_INODE,
                    offset: entries.len() as u64 + 1,
                    type_: DT_REG,
                    name: INIT_NAME,
                },
                init_entry(self.cfg.entry_timeout, self.cfg.attr_timeout),
            ));
        }

        for entry in std::fs::read_dir(&data.path).map_err(host_error)? {
            let entry = entry.map_err(host_error)?;
            let name = entry.file_name();
            let name = name.to_str().ok_or_else(|| linux_error(LINUX_EINVAL))?;
            if is_reserved_name(name) {
                continue;
            }
            let name_buffer = format!("{name}\0");
            let name = CStr::from_bytes_with_nul(name_buffer.as_bytes())
                .map_err(|_| linux_error(LINUX_EINVAL))?;
            validate_component(name)?;

            let path = entry.path();
            let metadata = self.safe_metadata(&path)?;
            let child = self.intern_path(path);
            let full_entry = self.entry_from_metadata(&metadata, child.as_ref())?;
            let dir_entry = DirEntry {
                ino: child.inode,
                offset: entries.len() as u64 + 1,
                type_: dirent_type_from_mode(full_entry.attr.st_mode),
                name: leak_name(name.to_bytes()),
            };
            entries.push((dir_entry, full_entry));
        }

        Ok(entries)
    }

    pub(super) fn parent_entry(&self, data: &InodeData) -> io::Result<Entry> {
        let parent_path = data.path.parent().unwrap_or(&self.root);
        let parent_path = if data.inode == ROOT_INODE || !parent_path.starts_with(&self.root) {
            self.root.clone()
        } else {
            parent_path.to_path_buf()
        };
        self.entry_for_path(parent_path)
    }
}
