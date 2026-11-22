//! Removal and rename operations for the Windows passthrough backend.

#[cfg(test)]
use std::cell::RefCell;
use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Foundation::{
    ERROR_INVALID_FUNCTION, ERROR_INVALID_PARAMETER, ERROR_NOT_SUPPORTED,
};
use windows_sys::Win32::Storage::FileSystem::{
    DELETE, FILE_DISPOSITION_FLAG_DELETE, FILE_DISPOSITION_FLAG_IGNORE_READONLY_ATTRIBUTE,
    FILE_DISPOSITION_FLAG_POSIX_SEMANTICS, FILE_DISPOSITION_INFO_EX, FILE_READ_ATTRIBUTES,
    FILE_RENAME_INFO, FILE_WRITE_ATTRIBUTES, FileDispositionInfoEx, FileRenameInfoEx,
    SetFileInformationByHandle,
};

use super::*;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const FILE_RENAME_REPLACE_IF_EXISTS: u32 = 0x1;
const FILE_RENAME_POSIX_SEMANTICS: u32 = 0x2;

#[cfg(test)]
thread_local! {
    /// Runs on the unlinking thread after the host deletion and before the
    /// inode table follows it, so a test can act inside that window.
    pub(super) static AFTER_HOST_UNLINK: RefCell<Option<Box<dyn FnOnce()>>> =
        const { RefCell::new(None) };
}

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

            after_host_unlink();
            // Commit namespace bookkeeping before remapping: a remap error
            // cannot undo a successful host deletion.
            self.finish_unlink_path(path, retained);
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
            self.rename_inode_path(old_path, new_path, retained);
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

    /// Pin a file about to lose its name. Owned mounts pin every tracked file;
    /// other mounts pin only files the guest still has open, so that fstat,
    /// read and write keep working on the old object as POSIX requires.
    pub(super) fn prepare_owned_unlink(
        &self,
        path: &Path,
    ) -> io::Result<Option<PreparedOwnedUnlink>> {
        let data = self.inodes.read().unwrap().by_path.get(path).cloned();
        let Some(data) = data else {
            return Ok(None);
        };
        if self.cfg.owned_checkpoint.is_none() {
            if !self.has_open_handle(data.inode) {
                return Ok(None);
            }
            // The pin is best effort here: if any step fails, the unlink goes
            // ahead without it, and finish_removed_alias falls back to
            // retain_open_file, which pins a clone of the guest's own handle.
            return Ok(self.pin_open_file(path, data));
        }
        let metadata = self.safe_metadata(path)?;
        if !metadata.is_file() {
            return Ok(None);
        }
        // Read the guest metadata now: an ADS override moves with whichever
        // file holds the name, so after a rename-over it is the new file's.
        let current = self.current_override(&metadata, &data)?;
        let file = StdOpenOptions::new()
            .read(true)
            .write(!metadata.permissions().readonly())
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .map_err(host_error)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        if !Self::holds_own_object(&data, &file) {
            return Ok(None);
        }
        let stat_file = self.pin_owned_stat(path, current)?;
        Ok(Some(PreparedOwnedUnlink {
            data,
            file,
            stat: current,
            stat_file,
        }))
    }

    /// Pin a file the guest has open on a mount without an owned checkpoint.
    /// Attribute access is enough for fstat; write access keeps a guest
    /// chmod/utimes on the open file working. Without write access there is
    /// no pin here, and the fallback pins a clone of the guest's own handle.
    fn pin_open_file(&self, path: &Path, data: Arc<InodeData>) -> Option<PreparedOwnedUnlink> {
        let metadata = self.safe_metadata(path).ok()?;
        if !metadata.is_file() {
            return None;
        }
        // Read the guest metadata now: an ADS override moves with whichever
        // file holds the name, so after a rename-over it is the new file's.
        let current = self.current_override(&metadata, &data).ok()?;
        let file = StdOpenOptions::new()
            .access_mode(FILE_READ_ATTRIBUTES | FILE_WRITE_ATTRIBUTES)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(path)
            .ok()?;
        reject_reparse_metadata(&file.metadata().ok()?).ok()?;
        if !Self::holds_own_object(&data, &file) {
            return None;
        }

        // Pin the file's own metadata stream too, so that a chmod or chown
        // made while the file has no name is stored with the file, where a
        // lookup of another hard link reads it. Without it the change stays
        // in memory only.
        let stat_file = self
            .pin_owned_stat(path, current)
            .ok()
            .flatten()
            .filter(|stat_file| Self::holds_own_object(&data, stat_file));
        Some(PreparedOwnedUnlink {
            data,
            file,
            stat: current,
            stat_file,
        })
    }

    /// The host may have replaced the object at the inode's name since the
    /// guest looked it up: pinning that one would give the inode another file.
    fn holds_own_object(data: &InodeData, file: &File) -> bool {
        data.identity
            .is_none_or(|identity| mobility::file_identity(file).ok() == Some(identity))
    }

    /// Called with the inode table locked, by the table update that drops
    /// the name: a lookup between the two would see a retained inode that
    /// still has its name, finish it as replaced by the host and keep it
    /// (retained), and the update would then never reap it.
    fn retain_owned_unlink(&self, prepared: Option<PreparedOwnedUnlink>) -> Option<Arc<InodeData>> {
        let PreparedOwnedUnlink {
            data,
            file,
            stat,
            stat_file,
        } = prepared?;
        *data.virtual_meta.write().unwrap() = inode::VirtualMetadata {
            uid: stat.uid,
            gid: stat.gid,
            mode: Some(stat.mode),
            rdev: u64::from(stat.rdev),
        };
        *data.retained.lock().unwrap() = Some(file);
        *data.retained_stat.lock().unwrap() = stat_file;
        Some(data)
    }

    pub(super) fn remove_inode_path(&self, path: &Path) {
        self.finish_unlink_path(path, None);
    }

    /// Drop the name of a guest unlink, retaining the prepared inode under
    /// the same table lock.
    fn finish_unlink_path(&self, path: &Path, retained: Option<PreparedOwnedUnlink>) {
        let mut inodes = self.inodes.write().unwrap();
        let pinned = self.retain_owned_unlink(retained);
        let removed = inodes.by_path.remove(path);
        if let Some(data) = &removed {
            self.finish_removed_alias(&mut inodes, data);
        }
        Self::unpin_if_named(&inodes, pinned);
        drop(inodes);
        if let Some(data) = removed {
            self.reap_retained_inode(data.inode);
        }
    }

    /// A lookup inside the window can give the prepared inode another name
    /// (a hard link elsewhere) before the update runs: it is then not removed
    /// by it, and keeps its name, so it must not stay retained.
    fn unpin_if_named(inodes: &InodeTable, pinned: Option<Arc<InodeData>>) {
        let Some(data) = pinned else {
            return;
        };
        if let Some(path) = inodes
            .by_path
            .iter()
            .find_map(|(path, alias)| Arc::ptr_eq(alias, &data).then(|| path.clone()))
        {
            *data.path.write().unwrap() = path;
            *data.retained.lock().unwrap() = None;
            *data.retained_stat.lock().unwrap() = None;
        }
    }

    pub(super) fn finish_removed_alias(&self, inodes: &mut InodeTable, data: &Arc<InodeData>) {
        if let Some(path) = inodes
            .by_path
            .iter()
            .find_map(|(path, alias)| (alias.inode == data.inode).then(|| path.clone()))
        {
            *data.path.write().unwrap() = path;
            *data.retained.lock().unwrap() = None;
            *data.retained_stat.lock().unwrap() = None;
        } else if data.retained.lock().unwrap().is_none() && !self.retain_open_file(data) {
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

    /// Fallback when prepare_owned_unlink pinned nothing (its best-effort pin
    /// failed, or the handle was opened after it looked): keep the removed
    /// file reachable through the guest's handle. Called before the path's
    /// stat store entry is moved or removed.
    pub(super) fn retain_open_file(&self, data: &InodeData) -> bool {
        let file = self
            .handles
            .read()
            .unwrap()
            .values()
            .find(|handle| handle.inode == data.inode)
            .and_then(|handle| handle.file.lock().unwrap().try_clone().ok());
        let Some(file) = file else {
            return false;
        };
        // A handle opened by path after the host rename holds the replacing
        // file; pinning it would alias the old inode to the new object.
        if data
            .identity
            .is_some_and(|identity| mobility::file_identity(&file).ok() != Some(identity))
        {
            return false;
        }
        let Ok(metadata) = file.metadata() else {
            return false;
        };
        if metadata.is_dir() {
            return false;
        }
        // The override is read by path after the host operation; if it cannot
        // be read, the inode keeps its in-memory metadata, and the open file
        // is still pinned.
        if let Ok(stat) = self.current_override(&metadata, data) {
            *data.virtual_meta.write().unwrap() = inode::VirtualMetadata {
                uid: stat.uid,
                gid: stat.gid,
                mode: Some(stat.mode),
                rdev: u64::from(stat.rdev),
            };
        }
        *data.retained.lock().unwrap() = Some(file);
        true
    }

    pub(super) fn rename_inode_path(
        &self,
        old_path: &Path,
        new_path: &Path,
        retained: Option<PreparedOwnedUnlink>,
    ) {
        if old_path == new_path {
            // rename_file prepares nothing for a rename onto itself.
            debug_assert!(retained.is_none());
            return;
        }
        let mut inodes = self.inodes.write().unwrap();
        let pinned = self.retain_owned_unlink(retained);
        let replaced = inodes.by_path.remove(new_path);
        let moved = inodes
            .by_path
            .iter()
            .filter(|(path, _)| path.starts_with(old_path))
            .map(|(path, data)| (path.clone(), data.clone()))
            .collect::<Vec<_>>();
        for (path, data) in moved {
            inodes.by_path.remove(&path);
            // Cached descendants must follow directory renames on bind mounts too.
            // An unrelated destination inode keeps its retained pin.
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
        Self::unpin_if_named(&inodes, pinned);
        drop(inodes);
        if let Some(replaced) = replaced {
            self.reap_retained_inode(replaced.inode);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
fn after_host_unlink() {
    if let Some(hook) = AFTER_HOST_UNLINK.with(|hook| hook.borrow_mut().take()) {
        hook();
    }
}

#[cfg(not(test))]
fn after_host_unlink() {}
