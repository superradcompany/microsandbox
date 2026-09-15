//! Removal and rename operations for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct PreparedOwnedUnlink {
    data: Arc<InodeData>,
    file: File,
    stat: OverrideStat,
    stat_file: Option<File>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn prepare_owned_unlink(
        &self,
        path: &Path,
    ) -> io::Result<Option<PreparedOwnedUnlink>> {
        if self.cfg.owned_checkpoint.is_none() {
            return Ok(None);
        }
        let data = self.inodes.read().unwrap().by_path.get(path).cloned();
        let Some(data) = data else {
            return Ok(None);
        };
        let metadata = self.safe_metadata(path)?;
        if !metadata.is_file() {
            return Ok(None);
        }
        let current = self.current_override(&metadata, &data)?;
        let file = StdOpenOptions::new()
            .read(true)
            .write(!metadata.permissions().readonly())
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        let stat_file = self.pin_owned_stat(path, current)?;
        Ok(Some(PreparedOwnedUnlink {
            data,
            file,
            stat: current,
            stat_file,
        }))
    }

    pub(super) fn retain_owned_unlink(&self, prepared: Option<PreparedOwnedUnlink>) {
        if let Some(PreparedOwnedUnlink {
            data,
            file,
            stat,
            stat_file,
        }) = prepared
        {
            *data.virtual_meta.write().unwrap() = inode::VirtualMetadata {
                uid: stat.uid,
                gid: stat.gid,
                mode: Some(stat.mode),
                rdev: u64::from(stat.rdev),
            };
            *data.retained.lock().unwrap() = Some(file);
            *data.retained_stat.lock().unwrap() = stat_file;
        }
    }

    pub(super) fn remove_inode_path(&self, path: &Path) {
        let mut inodes = self.inodes.write().unwrap();
        if let Some(data) = inodes.by_path.remove(path) {
            self.finish_removed_alias(&mut inodes, &data);
            drop(inodes);
            self.reap_owned_inode(data.inode);
        }
    }

    fn finish_removed_alias(&self, inodes: &mut InodeTable, data: &Arc<InodeData>) {
        if self.cfg.owned_checkpoint.is_some()
            && let Some(path) = inodes
                .by_path
                .iter()
                .find_map(|(path, alias)| (alias.inode == data.inode).then(|| path.clone()))
        {
            *data.path.write().unwrap() = path;
            *data.retained.lock().unwrap() = None;
            *data.retained_stat.lock().unwrap() = None;
        } else if data.retained.lock().unwrap().is_none() {
            inodes.by_inode.remove(&data.inode);
            if let Some(identity) = data.identity {
                inodes.by_identity.remove(&identity);
            }
        }
    }

    pub(super) fn rename_inode_path(&self, old_path: &Path, new_path: &Path) {
        if old_path == new_path {
            return;
        }
        let mut inodes = self.inodes.write().unwrap();
        let replaced = inodes.by_path.remove(new_path);
        let moved = inodes
            .by_path
            .iter()
            .filter(|(path, _)| {
                path.as_path() == old_path
                    || (self.cfg.owned_checkpoint.is_some() && path.starts_with(old_path))
            })
            .map(|(path, data)| (path.clone(), data.clone()))
            .collect::<Vec<_>>();
        for (path, data) in moved {
            inodes.by_path.remove(&path);
            // Owned state records current child paths, including cached descendants of
            // a renamed directory. An unrelated destination inode keeps its retained pin.
            let path = new_path.join(path.strip_prefix(old_path).expect("selected descendant"));
            let canonical = data.path();
            if canonical.starts_with(old_path) {
                *data.path.write().unwrap() = new_path.join(
                    canonical
                        .strip_prefix(old_path)
                        .expect("selected descendant"),
                );
            }
            inodes.by_path.insert(path, data);
        }
        if let Some(replaced) = &replaced {
            self.finish_removed_alias(&mut inodes, replaced);
        }
        drop(inodes);
        if let Some(replaced) = replaced {
            self.reap_owned_inode(replaced.inode);
        }
    }
}
