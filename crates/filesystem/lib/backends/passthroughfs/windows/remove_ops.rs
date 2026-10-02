//! Removal and rename operations for the Windows passthrough backend.

use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::{
    ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_READ_ATTRIBUTES,
    FILE_RENAME_INFO, FileDispositionInfoEx, FileRenameInfoEx, SetFileInformationByHandle,
};

use super::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const FILE_RENAME_REPLACE_IF_EXISTS: u32 = 0x1;
const FILE_RENAME_POSIX_SEMANTICS: u32 = 0x2;

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
    /// Remove the name now while keeping open handles and DAX views valid.
    /// DeleteFile can report success but defer namespace removal until the last
    /// mapped-file handle closes, which violates the guest's unlink semantics.
    pub(super) fn unlink_file(&self, path: &Path) -> io::Result<()> {
        let file = StdOpenOptions::new()
            .access_mode(DELETE | FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(host_error)?;

        let retained = self.prepare_owned_unlink(path)?;
        let state = self.dax_files.get(&file)?;
        self.with_file_mappings_suspended(&state, || {
            let info = FILE_DISPOSITION_INFO_EX {
                Flags: FILE_DISPOSITION_FLAG_DELETE
                    | FILE_DISPOSITION_FLAG_POSIX_SEMANTICS
                    | FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
            };

            // SAFETY: file owns the live handle and info has the documented layout.
            let deleted = unsafe {
                SetFileInformationByHandle(
                    file.as_raw_handle(),
                    FileDispositionInfoEx,
                    (&info as *const FILE_DISPOSITION_INFO_EX).cast(),
                    std::mem::size_of_val(&info) as u32,
                )
            };

            let error = (deleted == 0).then(io::Error::last_os_error);
            drop(file); // POSIX deletion removes the link when this handle closes.

            if let Some(error) = error {
                // Preserve the existing fallback on filesystems without POSIX
                // deletion only when no DAX backing pins the deleted object.
                if !state.has_mappings()
                    && error.raw_os_error().is_some_and(|code| {
                        [
                            ERROR_INVALID_FUNCTION,
                            ERROR_NOT_SUPPORTED,
                            ERROR_INVALID_PARAMETER,
                        ]
                        .contains(&(code as u32))
                    })
                {
                    std::fs::remove_file(path).map_err(host_error)?;
                } else {
                    return Err(host_error(error));
                }
            }

            // Commit namespace bookkeeping before remapping: a remap error
            // cannot undo a successful host deletion.
            self.retain_owned_unlink(retained);
            self.remove_inode_path(path);
            if let Some(store) = &self.stat_store {
                store.remove(path)?;
            }
            Ok(())
        })
    }

    /// Replacing a mapped destination must preserve its old file for DAX readers.
    pub(super) fn rename_file(&self, old_path: &Path, new_path: &Path) -> io::Result<()> {
        let retained = if old_path != new_path && new_path.exists() {
            self.prepare_owned_unlink(new_path)?
        } else {
            None
        };
        let finish = || {
            self.retain_owned_unlink(retained);
            self.rename_inode_path(old_path, new_path);
            if let Some(store) = &self.stat_store {
                store.rename(old_path, new_path)?;
            }
            Ok(())
        };
        if old_path == new_path || !new_path.exists() {
            std::fs::rename(old_path, new_path).map_err(host_error)?;
            return finish();
        }
        let destination = StdOpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(new_path)
            .map_err(host_error)?;
        let state = self.dax_files.get(&destination)?;
        self.with_file_mappings_suspended(&state, || {
            drop(destination);
            if state.has_mappings() {
                Self::rename_file_posix(old_path, new_path)?;
            } else {
                std::fs::rename(old_path, new_path).map_err(host_error)?;
            }
            finish()
        })
    }

    fn rename_file_posix(old_path: &Path, new_path: &Path) -> io::Result<()> {
        let file = StdOpenOptions::new()
            .access_mode(DELETE)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_BACKUP_SEMANTICS)
            .open(old_path)
            .map_err(host_error)?;
        let name: Vec<u16> = new_path.as_os_str().encode_wide().collect();
        let name_bytes =
            u32::try_from(name.len().saturating_mul(2)).map_err(|_| linux_error(LINUX_EINVAL))?;
        let size = std::mem::offset_of!(FILE_RENAME_INFO, FileName) + name_bytes as usize + 2;
        let size = u32::try_from(size).map_err(|_| linux_error(LINUX_EINVAL))?;

        // Pointer-sized words provide the alignment of FILE_RENAME_INFO. The
        // trailing UTF-16 name is variable-sized and the last word stays zero.
        let mut buffer = vec![0usize; (size as usize).div_ceil(std::mem::size_of::<usize>())];
        let info = buffer.as_mut_ptr().cast::<FILE_RENAME_INFO>();

        // SAFETY: buffer is aligned and large enough for the header and name,
        // and file owns the handle until the synchronous call returns.
        let renamed = unsafe {
            (*info).Anonymous.Flags = FILE_RENAME_REPLACE_IF_EXISTS | FILE_RENAME_POSIX_SEMANTICS;
            (*info).RootDirectory = std::ptr::null_mut();
            (*info).FileNameLength = name_bytes;
            let destination = info
                .cast::<u8>()
                .add(std::mem::offset_of!(FILE_RENAME_INFO, FileName))
                .cast::<u16>();
            std::ptr::copy_nonoverlapping(name.as_ptr(), destination, name.len());
            SetFileInformationByHandle(file.as_raw_handle(), FileRenameInfoEx, info.cast(), size)
        };
        if renamed == 0 {
            return Err(host_error(io::Error::last_os_error()));
        }

        Ok(())
    }

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
        if let Some(path) = inodes
            .by_path
            .iter()
            .find_map(|(path, alias)| (alias.inode == data.inode).then(|| path.clone()))
        {
            *data.path.write().unwrap() = path;
            *data.retained.lock().unwrap() = None;
            *data.retained_stat.lock().unwrap() = None;
        } else if data.retained.lock().unwrap().is_none() {
            inodes.by_inode.remove(&data.inode);
            if let Some(identity) = data.identity
                && inodes
                    .by_identity
                    .get(&identity)
                    .is_some_and(|entry| entry.inode == data.inode)
            {
                if let Some(alias) = inodes
                    .by_path
                    .values()
                    .find(|alias| alias.identity == Some(identity))
                    .cloned()
                {
                    inodes.by_identity.insert(identity, alias);
                } else {
                    inodes.by_identity.remove(&identity);
                }
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
            let path = if path == old_path {
                new_path.to_path_buf()
            } else {
                new_path.join(path.strip_prefix(old_path).expect("selected descendant"))
            };
            let canonical = data.path();
            if canonical == old_path {
                *data.path.write().unwrap() = new_path.to_path_buf();
            } else if canonical.starts_with(old_path) {
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
