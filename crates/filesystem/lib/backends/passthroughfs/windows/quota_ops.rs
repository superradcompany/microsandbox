//! Windows inode lifetime integration for incremental quotas.

use std::os::windows::io::AsRawHandle;

use windows_sys::Win32::Storage::FileSystem::{
    BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
};

use super::*;
use crate::backends::passthroughfs::quota::QuotaInodes;

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    /// The pre-mutation baseline is needed only by restored legacy snapshots.
    pub(crate) fn quota_ensure_baseline(&self) {
        if let Some(quota) = &self.quota {
            quota.ensure_baseline();
        }
    }

    pub(crate) fn quota_mutate<T>(
        &self,
        inode: u64,
        file: &File,
        end: impl FnOnce(u64) -> u64,
        operation: impl FnOnce(u64) -> io::Result<T>,
    ) -> io::Result<T> {
        match &self.quota {
            Some(quota) => quota.mutate(self, inode, file, end, operation),
            None => operation(file.metadata()?.len()),
        }
    }

    pub(crate) fn quota_reconcile_inode(&self, inode: u64) {
        if let Some(quota) = &self.quota {
            quota.reconcile_inode(self, inode);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl QuotaInodes for PassthroughFs {
    fn pin(&self, inode: u64) -> io::Result<()> {
        self.inode(inode)?.lookups.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn unpin(&self, inode: u64) {
        if let Ok(data) = self.inode(inode) {
            data.lookups.fetch_sub(1, Ordering::AcqRel);
        }
        self.reap_owned_inode(inode);
    }

    fn live(&self, inode: u64) -> bool {
        (self.cfg.owned_checkpoint.is_some()
            && self
                .inode(inode)
                .is_ok_and(|data| data.lookups.load(Ordering::Acquire) > 1))
            || self
                .handles
                .read()
                .unwrap()
                .values()
                .any(|handle| handle.inode == inode)
            || self.dir_handles.read().unwrap().values().any(|handle| {
                handle
                    .snapshot
                    .lock()
                    .unwrap()
                    .as_ref()
                    .is_some_and(|entries| entries.iter().any(|entry| entry.inode == inode))
            })
    }

    fn observe(&self, inode: u64) -> io::Result<(u64, u64)> {
        let data = self.inode(inode)?;
        let file = self.open_inode_file(&data, 0)?;
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        // Query identity, size and link count through one handle. Separate path
        // queries could mistake a concurrent host replacement for the charged file.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
            return Err(host_error(io::Error::last_os_error()));
        }
        let info = unsafe { info.assume_init() };
        let identity = (
            info.dwVolumeSerialNumber,
            ((info.nFileIndexHigh as u64) << 32) | info.nFileIndexLow as u64,
        );
        if data.identity != Some(identity) {
            return Err(io::Error::from(io::ErrorKind::NotFound));
        }
        let size = ((info.nFileSizeHigh as u64) << 32) | info.nFileSizeLow as u64;
        Ok((size, info.nNumberOfLinks.into()))
    }
}
