//! Unix inode lifetime integration for incremental quotas.

use super::{PassthroughFs, inode};
use crate::backends::{passthroughfs::quota::QuotaInodes, shared::platform};
use std::{fs::File, io, os::fd::FromRawFd, sync::atomic::Ordering};

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
            None => operation(0),
        }
    }

    pub(crate) fn quota_reconcile_inode(&self, inode: u64) {
        if let Some(quota) = &self.quota {
            quota.reconcile_inode(self, inode);
        }
    }

    #[cfg(target_os = "linux")]
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn quota_fallocate<T>(
        &self,
        inode: u64,
        file: &File,
        mode: u32,
        offset: u64,
        length: u64,
        operation: impl FnOnce(u64) -> io::Result<T>,
    ) -> io::Result<T> {
        use super::super::quota::QuotaChange;
        let change = if mode == 0x20 {
            QuotaChange::Insert { offset, length }
        } else if mode == 0x08 {
            QuotaChange::Collapse { offset, length }
        } else {
            QuotaChange::Growth
        };
        let end = |before: u64| {
            if mode & (0x01 | 0x02 | 0x08) != 0 {
                before
            } else if mode == 0x20 {
                before.saturating_add(length)
            } else {
                offset.saturating_add(length)
            }
        };
        match &self.quota {
            Some(quota) => quota.mutate_with_change(self, inode, file, end, change, operation),
            None => operation(0),
        }
    }

    /// O_RDONLY|O_TRUNC still requires write permission. Reopen a write-capable
    /// descriptor for truncation without widening the returned guest handle.
    pub(crate) fn quota_truncate_on_open(
        &self,
        inode: u64,
        file: &File,
        flags: i32,
    ) -> io::Result<()> {
        if flags & libc::O_ACCMODE == libc::O_RDONLY {
            let fd = inode::open_inode_fd(
                self,
                inode,
                (flags & !(libc::O_ACCMODE | libc::O_CREAT | libc::O_EXCL | libc::O_TRUNC))
                    | libc::O_WRONLY,
            )?;
            let writable = unsafe { File::from_raw_fd(fd) };
            self.quota_mutate(
                inode,
                &writable,
                |_| 0,
                |_| writable.set_len(0).map_err(platform::linux_error),
            )
        } else {
            self.quota_mutate(
                inode,
                file,
                |_| 0,
                |_| file.set_len(0).map_err(platform::linux_error),
            )
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl QuotaInodes for PassthroughFs {
    fn pin(&self, inode: u64) -> io::Result<()> {
        let inodes = self.inodes.read().unwrap();
        let data = inodes.get(&inode).ok_or_else(platform::ebadf)?;
        // This extra reference is persisted with ordinary inode state. It keeps
        // hardlink identity stable after the kernel evicts its dentry cache.
        data.refcount.fetch_add(1, Ordering::AcqRel);
        Ok(())
    }

    fn unpin(&self, inode: u64) {
        inode::forget_one_locked(&mut self.inodes.write().unwrap(), inode, 1);
    }

    fn live(&self, inode: u64) -> bool {
        self.inodes
            .read()
            .unwrap()
            .get(&inode)
            .is_some_and(|data| data.refcount.load(Ordering::Acquire) > 1)
            || self
                .handles
                .read()
                .unwrap()
                .values()
                .any(|handle| handle.inode == inode)
    }

    fn observe(&self, inode: u64) -> io::Result<(u64, u64)> {
        let fd = inode::get_inode_fd(self, inode)?;
        let stat = platform::fstat(fd.raw())?;
        Ok((stat.st_size.max(0) as u64, stat.st_nlink as u64))
    }
}
