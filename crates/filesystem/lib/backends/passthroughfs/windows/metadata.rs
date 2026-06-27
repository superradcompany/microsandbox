//! Attribute operations for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn safe_metadata(&self, path: &Path) -> io::Result<std::fs::Metadata> {
        ensure_lexically_under_root(&self.root, path)?;
        safe_metadata_under_root(&self.root, path)
    }

    pub(super) fn stat_from_metadata(
        &self,
        metadata: &std::fs::Metadata,
        data: &InodeData,
    ) -> io::Result<stat64> {
        if !self.cfg.stat_virtualization_enabled() {
            return Ok(host_stat_from_metadata(metadata, data.inode));
        }

        if let Some(store) = &self.stat_store {
            let mut st = host_stat_from_metadata(metadata, data.inode);
            if let Some(override_stat) = store.read(&data.path)? {
                apply_override_stat(&mut st, override_stat);
            }
            return Ok(st);
        }

        Ok(stat_from_metadata(metadata, data))
    }

    pub(super) fn entry_from_metadata(
        &self,
        metadata: &std::fs::Metadata,
        data: &InodeData,
    ) -> io::Result<Entry> {
        Ok(Entry {
            inode: data.inode,
            generation: 0,
            attr: self.stat_from_metadata(metadata, data)?,
            attr_flags: 0,
            attr_timeout: self.cfg.attr_timeout,
            entry_timeout: self.cfg.entry_timeout,
        })
    }

    pub(super) fn current_override(
        &self,
        metadata: &std::fs::Metadata,
        data: &InodeData,
    ) -> io::Result<OverrideStat> {
        if let Some(store) = &self.stat_store
            && let Some(override_stat) = store.read(&data.path)?
        {
            return Ok(override_stat);
        }

        if self.stat_store.is_some() {
            return Ok(OverrideStat::new(0, 0, mode_from_metadata(metadata), 0));
        }

        let virtual_meta = data.virtual_meta.read().unwrap();
        Ok(OverrideStat {
            version: OVERRIDE_VERSION,
            _pad: [0; 3],
            uid: virtual_meta.uid,
            gid: virtual_meta.gid,
            mode: virtual_meta
                .mode
                .unwrap_or_else(|| mode_from_metadata(metadata)),
            rdev: virtual_meta.rdev.try_into().unwrap_or(u32::MAX),
        })
    }

    pub(super) fn set_virtual_metadata(
        &self,
        data: &InodeData,
        uid: u32,
        gid: u32,
        mode: u32,
        rdev: u32,
    ) -> io::Result<()> {
        if self.cfg.stat_virtualization_enabled() {
            let mut meta = data.virtual_meta.write().unwrap();
            meta.uid = uid;
            meta.gid = gid;
            meta.mode = Some(mode);
            meta.rdev = u64::from(rdev);
        }

        if let Some(store) = &self.stat_store {
            store.write(&data.path, uid, gid, mode, rdev)?;
        }

        if (self.cfg.mirror_host_permissions() || !self.cfg.stat_virtualization_enabled())
            && mirror_eligible_type(mode & S_IFMT)
        {
            apply_host_permissions(&data.path, mode)?;
        }

        Ok(())
    }

    pub(super) fn clear_priv_bits(&self, data: &InodeData) -> io::Result<()> {
        let metadata = self.safe_metadata(&data.path)?;
        let current = self.current_override(&metadata, data)?;
        let mode = current.mode & !(S_ISUID | S_ISGID);
        if mode != current.mode {
            self.set_virtual_metadata(data, current.uid, current.gid, mode, current.rdev)?;
        }
        Ok(())
    }

    pub(super) fn do_getattr(&self, inode: u64) -> io::Result<(stat64, Duration)> {
        if self.cfg.inject_init && inode == INIT_INODE {
            return Ok((init_stat(), self.cfg.attr_timeout));
        }

        let data = self.inode(inode)?;
        let metadata = self.safe_metadata(&data.path)?;
        Ok((
            self.stat_from_metadata(&metadata, data.as_ref())?,
            self.cfg.attr_timeout,
        ))
    }

    pub(super) fn do_setattr(
        &self,
        inode: u64,
        attr: stat64,
        handle: Option<u64>,
        valid: SetattrValid,
    ) -> io::Result<(stat64, Duration)> {
        if self.cfg.inject_init && inode == INIT_INODE {
            return Err(linux_error(LINUX_EACCES));
        }
        if valid.intersects(
            SetattrValid::SIZE
                | SetattrValid::MODE
                | SetattrValid::UID
                | SetattrValid::GID
                | SetattrValid::ATIME
                | SetattrValid::MTIME
                | SetattrValid::ATIME_NOW
                | SetattrValid::MTIME_NOW
                | SetattrValid::CTIME,
        ) {
            self.require_writable()?;
        }

        let data = self.inode(inode)?;
        let metadata = self.safe_metadata(&data.path)?;
        if metadata.file_type().is_dir() && valid.contains(SetattrValid::SIZE) {
            return Err(linux_error(LINUX_EISDIR));
        }

        if valid.contains(SetattrValid::SIZE) {
            self.quota_ensure_baseline();
            let size: u64 = attr
                .st_size
                .try_into()
                .map_err(|_| linux_error(LINUX_EINVAL))?;
            if let Some(handle) = handle {
                let handle = self.handle(inode, handle)?;
                let file = handle.file.lock().unwrap();
                self.quota_charge_growth(metadata.len(), size)?;
                file.set_len(size).map_err(host_error)?;
            } else {
                let file = StdOpenOptions::new()
                    .write(true)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                    .open(&data.path)
                    .map_err(host_error)?;
                reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
                self.quota_charge_growth(metadata.len(), size)?;
                file.set_len(size).map_err(host_error)?;
            }
        }

        let kill_priv = valid.intersects(SetattrValid::UID | SetattrValid::GID)
            || (valid.contains(SetattrValid::SIZE) && valid.contains(SetattrValid::KILL_SUIDGID));
        if valid.intersects(SetattrValid::MODE | SetattrValid::UID | SetattrValid::GID) {
            if !self.cfg.stat_virtualization_enabled()
                && valid.intersects(SetattrValid::UID | SetattrValid::GID)
            {
                return Err(linux_error(LINUX_EPERM));
            }

            let current = self.current_override(&metadata, data.as_ref())?;
            let uid = if valid.contains(SetattrValid::UID) {
                attr.st_uid
            } else {
                current.uid
            };
            let gid = if valid.contains(SetattrValid::GID) {
                attr.st_gid
            } else {
                current.gid
            };
            let mode = if valid.contains(SetattrValid::MODE) {
                (current.mode & S_IFMT) | (attr.st_mode & !S_IFMT)
            } else {
                current.mode
            };
            let mode = if kill_priv {
                mode & !(S_ISUID | S_ISGID)
            } else {
                mode
            };
            self.set_virtual_metadata(data.as_ref(), uid, gid, mode, current.rdev)?;
        } else if kill_priv {
            self.clear_priv_bits(data.as_ref())?;
        }

        if valid.intersects(
            SetattrValid::ATIME
                | SetattrValid::MTIME
                | SetattrValid::ATIME_NOW
                | SetattrValid::MTIME_NOW,
        ) {
            let times = build_file_times(attr, valid)?;
            if let Some(handle) = handle {
                let handle = self.handle(inode, handle)?;
                handle
                    .file
                    .lock()
                    .unwrap()
                    .set_times(times)
                    .map_err(host_error)?;
            } else {
                let file = StdOpenOptions::new()
                    .write(true)
                    .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
                    .open(&data.path)
                    .map_err(host_error)?;
                reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
                file.set_times(times).map_err(host_error)?;
            }
        }

        self.do_getattr(inode)
    }
}
