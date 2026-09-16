//! File open operations for the Windows passthrough backend.

use super::*;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    pub(super) fn do_open(
        &self,
        inode: u64,
        kill_priv: bool,
        flags: u32,
    ) -> io::Result<(Option<u64>, OpenOptions)> {
        if self.cfg.inject_init && inode == INIT_INODE {
            return Ok((Some(INIT_HANDLE), OpenOptions::empty()));
        }
        if open_flags_write(flags) {
            self.require_writable()?;
            self.quota_ensure_baseline();
        }

        let data = self.inode(inode)?;
        let metadata = self.inode_metadata(&data)?;
        if metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_EISDIR));
        }

        let file = self.open_inode_file(&data, flags)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        if kill_priv && flags as i32 & LINUX_O_TRUNC != 0 {
            self.clear_priv_bits(data.as_ref())?;
        }
        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        self.handles.write().unwrap().insert(
            handle,
            Arc::new(HandleData {
                inode,
                flags,
                file: Mutex::new(file),
            }),
        );
        Ok((Some(handle), OpenOptions::empty()))
    }

    pub(super) fn open_inode_file(&self, data: &InodeData, flags: u32) -> io::Result<File> {
        use std::os::windows::io::{AsRawHandle, FromRawHandle};
        use windows_sys::Win32::Storage::FileSystem::ReOpenFile;

        let retained = data.retained.lock().unwrap();
        if let Some(file) = retained.as_ref() {
            let access = if open_flags_readable(flags) {
                0x8000_0000
            } else {
                0
            } | if open_flags_writable(flags) {
                0x4000_0000
            } else {
                0
            };
            // ReOpenFile gives an independent file pointer and preserves the pinned object,
            // even when its old path has been reused by a different file.
            let raw = unsafe {
                ReOpenFile(
                    file.as_raw_handle(),
                    access,
                    7,
                    FILE_FLAG_OPEN_REPARSE_POINT,
                )
            };
            if raw == windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE {
                return Err(host_error(io::Error::last_os_error()));
            }
            let reopened = unsafe { File::from_raw_handle(raw) };
            if flags & LINUX_O_TRUNC as u32 != 0 {
                reopened.set_len(0).map_err(host_error)?;
            }
            Ok(reopened)
        } else {
            open_options_from_flags(flags, false)?
                .open(data.path())
                .map_err(host_error)
        }
    }
}
