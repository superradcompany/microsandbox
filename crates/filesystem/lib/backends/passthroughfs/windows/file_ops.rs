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
        let metadata = self.safe_metadata(&data.path)?;
        if metadata.file_type().is_dir() {
            return Err(linux_error(LINUX_EISDIR));
        }

        let options = open_options_from_flags(flags, false)?;
        let file = options.open(&data.path).map_err(host_error)?;
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
}
