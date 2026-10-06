//! DAX window mappings for the Windows host.
//!
//! virtio-fs DAX lets the guest map a file region directly into the shared
//! memory window instead of issuing FUSE reads/writes. Windows cannot install
//! a stage-2 mapping from userspace, so it maps the file host-side with
//! `MapViewOfFile` and asks the VMM worker to install the mapping with
//! [`WorkerMessage::DaxAddMapping`], carrying whether it is writable so WHP can
//! omit `Write` for read-only mappings.

use std::sync::atomic::AtomicBool;
use std::sync::{Arc, Weak};

use crossbeam_channel::Sender;
use msb_krun_utils::worker_message::WorkerMessage;

use super::memory_mapping::{WindowsFileMappingAccess, WindowsFileMappingView};
use super::*;
use crate::backends::passthroughfs::window::{
    WindowMapping, remove_window_range, request_mapping, request_unmapping, window_addr,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `FUSE_SETUPMAPPING_FLAG_WRITE` (`linux/fuse.h`): the guest asked for a
/// writable mapping.
const SETUPMAPPING_FLAG_WRITE: u64 = 0x1;

/// Windows and WHP map file views at 4 KiB page boundaries.
const DAX_PAGE_SIZE: u64 = 4096;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Backing for a requested window. Only pages intersecting the file are
/// installed in the VMM; the rest of the requested slot stays unmapped until
/// a FUSE write grows the file. Splits retain the original file/guest offsets.
struct DaxBacking {
    view: Option<WindowsFileMappingView>,
    mapped_len: u64,
    guest_addr: u64,
    source: Option<DaxFile>,
}

#[derive(Clone)]
struct DaxFile {
    state: Arc<DaxFileState>,
    file: Arc<File>,
    offset: u64,
    access: WindowsFileMappingAccess,
    sender: Sender<WorkerMessage>,
}

/// Installed DAX slots and the backing that keeps their mapped pages alive.
#[derive(Default)]
pub(super) struct DaxWindows {
    slots: BTreeMap<u64, WindowMapping<Arc<DaxBacking>>>,
    /// Only ranges the worker has acknowledged as installed. Slots retain host
    /// backing even after a failed restore so a later operation can repair them.
    installed: BTreeMap<u64, WindowMapping<()>>,
}

/// Weak entries avoid keeping file identities alive after their mappings and
/// in-flight operations are gone (Windows can reuse IDs after file deletion).
#[derive(Default)]
pub(super) struct DaxFiles {
    files: Mutex<BTreeMap<(u32, u64), Weak<DaxFileState>>>,
}

/// Shared by all open paths to a host file, independently of FUSE inode numbers.
#[derive(Default)]
pub(super) struct DaxFileState {
    /// Acquire before handle.file or map_windows; never in the opposite order.
    pub(super) operation: Mutex<()>,
    has_mappings: AtomicBool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    /// Map `[foffset, foffset + len)` of `inode` and ask the VMM worker to install
    /// the stage-2 mapping at `guest_shm_base + moffset`.
    ///
    /// `FUSE_SETUPMAPPING` carries `fh = -1` (the kernel never fills the handle for
    /// DAX), so the request cannot be authorized against an open handle. The mount
    /// mode and the read-only init inode are the controls instead.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn do_setupmapping(
        &self,
        inode: u64,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        let write = flags & SETUPMAPPING_FLAG_WRITE != 0;
        // DAX bypasses the ordinary FUSE write/open checks, so a read-only mount
        // must refuse a writable mapping instead of relying on the guest.
        if self.cfg.readonly && write {
            return Err(linux_error(LINUX_EROFS));
        }
        // `init.krun` is read-only even on a writable mount.
        if self.cfg.inject_init && inode == INIT_INODE && write {
            return Err(linux_error(LINUX_EACCES));
        }
        let Some(sender) = map_sender else {
            return Err(linux_error(LINUX_ENOSYS));
        };
        let guest_addr = window_addr(moffset, len, guest_shm_base, shm_size)?;
        let len = usize::try_from(len).map_err(|_| linux_error(LINUX_EINVAL))?;
        let access = WindowsFileMappingAccess::from_dax_flags(flags);

        if len == 0
            || !guest_addr.is_multiple_of(DAX_PAGE_SIZE)
            || !(len as u64).is_multiple_of(DAX_PAGE_SIZE)
            || !foffset.is_multiple_of(DAX_PAGE_SIZE)
            || foffset.checked_add(len as u64).is_none()
            || guest_addr.checked_add(len as u64).is_none()
        {
            return Err(linux_error(LINUX_EINVAL));
        }

        let source = if self.cfg.inject_init && inode == INIT_INODE {
            None
        } else {
            let data = self.inode(inode)?;
            let file = self.open_mapping_file(&data, access)?;
            Some(DaxFile {
                state: self.dax_files.get(&file)?,
                file: Arc::new(file),
                offset: foffset,
                access,
                sender: sender.clone(),
            })
        };
        // Observe size and install the view under the host-file lock, including
        // aliases which have different FUSE inode numbers.
        let state = source.as_ref().map(|source| source.state.clone());
        let _operation = state
            .as_ref()
            .map(|state| state.operation.lock().unwrap_or_else(|p| p.into_inner()));
        let backing = if let Some(source) = source {
            DaxBacking::file(source, guest_addr, len as u64)?
        } else {
            DaxBacking::init(foffset, len, guest_addr)?
        };
        let mut windows = self.map_windows.lock().unwrap_or_else(|p| p.into_inner());
        windows.install_backing(sender, guest_addr, len as u64, backing, write)?;
        Ok(())
    }

    /// Tear down mappings the VMM worker installed and release the host views.
    ///
    /// A removal can cover only part of an installed window; the untouched slots
    /// (and their host backing) stay alive.
    pub(super) fn do_removemapping(
        &self,
        requests: &[crate::RemovemappingOne],
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        let Some(sender) = map_sender else {
            return Err(linux_error(LINUX_ENOSYS));
        };
        for request in requests {
            let guest_addr = window_addr(request.moffset, request.len, guest_shm_base, shm_size)?;
            if request.len == 0
                || !guest_addr.is_multiple_of(DAX_PAGE_SIZE)
                || !request.len.is_multiple_of(DAX_PAGE_SIZE)
                || guest_addr.checked_add(request.len).is_none()
            {
                return Err(linux_error(LINUX_EINVAL));
            }

            // Hold the registry lock across the worker round-trip and the update so a
            // concurrent setup cannot install a replacement between them that this
            // stale removal would then drop. The stage-2 mapping is torn down first
            // and the registry is only touched after the worker acknowledges, so a
            // failed removal retains the remaining backing for a retry.
            let mut windows = self.map_windows.lock().unwrap_or_else(|p| p.into_inner());
            windows.unmap_range(sender, guest_addr, request.len)?;
            // Windows cannot unmap part of a `MapViewOfFile`; dropping the removed
            // slot releases the whole view only once the last slot referencing it
            // is removed.
            remove_window_range(&mut windows.slots, guest_addr, request.len)?;
        }
        Ok(())
    }

    /// Windows requires all host views to be closed before SetEndOfFile. Keep
    /// each guest slot's file identity and offsets while withdrawing its backing,
    /// then restore the slots at the resulting size even if the operation fails.
    pub(super) fn resize_inode<T>(
        &self,
        inode: u64,
        resize: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let data = self.inode(inode)?;
        let file = self.open_inode_file(&data, LINUX_O_WRONLY as u32)?;
        let state = self.dax_files.get(&file)?;
        self.with_file_mappings_suspended(&state, resize)
    }

    /// Temporarily release views for a host operation that Windows refuses while
    /// mapped. Keep the file identity pinned and restore only surviving slots.
    pub(super) fn with_file_mappings_suspended<T>(
        &self,
        state: &Arc<DaxFileState>,
        change: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let _operation = state.operation.lock().unwrap_or_else(|p| p.into_inner());
        if !state.has_mappings() {
            return change();
        }
        let mut windows = self.map_windows.lock().unwrap_or_else(|p| p.into_inner());
        let keys = windows.file_windows(state);

        for key in keys {
            let window = &windows.slots[&key];
            let guest_addr = window.guest_addr;
            let len = window.len;
            let mut source = window
                .backing
                .source
                .as_ref()
                .expect("file backing")
                .clone();
            source.offset += guest_addr - window.backing.guest_addr;
            if let Err(error) = windows.unmap_range(&source.sender, guest_addr, len) {
                if let Err(restore) = windows.refresh_file(state) {
                    tracing::warn!(%restore, "failed to restore DAX mappings after unmap failure");
                }
                return Err(error);
            }

            let window = windows.slots.get_mut(&key).expect("retained slot");
            window.host_addr = 0;
            window.backing = Arc::new(DaxBacking {
                view: None,
                mapped_len: 0,
                guest_addr: window.guest_addr,
                source: Some(source),
            });
        }

        // The host-file lock prevents new views through any alias during the change.
        // Other files may do I/O or replace/remove guest slots in the meantime;
        // refresh only the slots that still belong to this host file afterward.
        drop(windows);
        let result = change();
        let mut windows = self.map_windows.lock().unwrap_or_else(|p| p.into_inner());
        windows.refresh_file(state)?;
        result
    }

    /// Open and pin the same validated host object used by ordinary file I/O.
    fn open_mapping_file(
        &self,
        data: &InodeData,
        access: WindowsFileMappingAccess,
    ) -> io::Result<File> {
        let flags = if access == WindowsFileMappingAccess::ReadWrite {
            LINUX_O_RDWR as u32
        } else {
            0
        };
        let file = self.open_inode_file(data, flags)?;
        reject_reparse_metadata(&file.metadata().map_err(host_error)?)?;
        if let Some(expected) = data.identity
            && mobility::file_identity(&file).map_err(host_error)? != expected
        {
            return Err(linux_error(LINUX_ESTALE));
        }
        Ok(file)
    }
}

impl DaxWindows {
    /// Refresh surviving slots after file growth, before acknowledging the write.
    /// The caller holds the host-file operation lock across file I/O and refresh,
    /// and map_windows only while updating the mappings.
    pub(super) fn refresh_file(&mut self, state: &Arc<DaxFileState>) -> io::Result<()> {
        let keys = self.file_windows(state);
        for key in keys {
            let window = &self.slots[&key];
            let mut source = window
                .backing
                .source
                .as_ref()
                .expect("file backing")
                .clone();

            source.offset += window.guest_addr - window.backing.guest_addr;
            let sender = source.sender.clone();
            let writable = source.access == WindowsFileMappingAccess::ReadWrite;
            let guest_addr = window.guest_addr;
            let len = window.len;
            let file_len = source.file.metadata().map_err(host_error)?.len();

            let needed = len
                .min(file_len.saturating_sub(source.offset))
                .next_multiple_of(DAX_PAGE_SIZE);
            if self.installed_bytes(guest_addr, needed) == needed
                && self.installed_bytes(guest_addr, len) == needed
            {
                continue;
            }

            let backing = DaxBacking::file(source, guest_addr, len)?;
            self.install_backing(&sender, guest_addr, len, backing, writable)?;
        }
        Ok(())
    }

    /// Replace a requested slot, retaining every old backing until the worker has
    /// acknowledged the replacement. Restore the old mapped intersections if the
    /// new worker mapping fails after unmapping the range.
    fn install_backing(
        &mut self,
        sender: &Sender<WorkerMessage>,
        guest_addr: u64,
        len: u64,
        backing: DaxBacking,
        writable: bool,
    ) -> io::Result<()> {
        let host_addr = backing
            .view
            .as_ref()
            .map_or(0, WindowsFileMappingView::host_addr);
        let previous = self.installed_intersections(guest_addr, len);
        self.unmap_range(sender, guest_addr, len)?;

        if backing.mapped_len != 0
            && let Err(error) =
                request_mapping(sender, host_addr, guest_addr, backing.mapped_len, writable)
        {
            // A rejected DaxAddMapping may already have unmapped its old range.
            // The registry still owns the old views, so restoring them is safe.
            for (start, size) in previous {
                let window = self
                    .slots
                    .range(..=start)
                    .next_back()
                    .expect("retained slot")
                    .1;
                let old = &window.backing;
                let host =
                    old.view.as_ref().expect("mapped backing").host_addr() + start - old.guest_addr;
                let writable = old
                    .source
                    .as_ref()
                    .is_some_and(|file| file.access == WindowsFileMappingAccess::ReadWrite);
                match request_mapping(sender, host, start, size, writable) {
                    Ok(()) => self.record_installed(start, size),
                    Err(restore) => {
                        // Keep the original error and try the remaining ranges.
                        // Missing ranges stay absent from installed for retry.
                        tracing::warn!(%restore, "failed to restore DAX mapping");
                    }
                }
            }
            return Err(error);
        }

        if backing.mapped_len != 0 {
            self.record_installed(guest_addr, backing.mapped_len);
        }
        if let Some(source) = &backing.source {
            source.state.has_mappings.store(true, Ordering::Release);
        }
        remove_window_range(&mut self.slots, guest_addr, len)?;
        self.slots.insert(
            guest_addr,
            WindowMapping {
                guest_addr,
                host_addr,
                len,
                backing: Arc::new(backing),
            },
        );
        Ok(())
    }

    fn installed_intersections(&self, guest_addr: u64, len: u64) -> Vec<(u64, u64)> {
        self.installed
            .range(..guest_addr)
            .next_back()
            .into_iter()
            .chain(self.installed.range(guest_addr..guest_addr + len))
            .filter_map(|(_, window)| {
                let start = guest_addr.max(window.guest_addr);
                let end = (guest_addr + len).min(window.guest_addr + window.len);
                (start < end).then_some((start, end.saturating_sub(start)))
            })
            .collect()
    }

    fn installed_bytes(&self, guest_addr: u64, len: u64) -> u64 {
        self.installed_intersections(guest_addr, len)
            .iter()
            .map(|(_, len)| len)
            .sum()
    }

    fn record_installed(&mut self, guest_addr: u64, len: u64) {
        self.installed.insert(
            guest_addr,
            WindowMapping {
                guest_addr,
                host_addr: 0,
                len,
                backing: (),
            },
        );
    }

    fn unmap_range(
        &mut self,
        sender: &Sender<WorkerMessage>,
        guest_addr: u64,
        len: u64,
    ) -> io::Result<()> {
        for (start, size) in self.installed_intersections(guest_addr, len) {
            request_unmapping(sender, start, size)?;
            // Record each acknowledgement even if a later removal fails.
            remove_window_range(&mut self.installed, start, size)?;
        }
        Ok(())
    }

    fn file_windows(&self, state: &Arc<DaxFileState>) -> Vec<u64> {
        self.slots
            .iter()
            .filter(|(_, window)| {
                window
                    .backing
                    .source
                    .as_ref()
                    .is_some_and(|file| Arc::ptr_eq(&file.state, state))
            })
            .map(|(key, _)| *key)
            .collect()
    }
}

impl DaxFiles {
    pub(super) fn get(&self, file: &File) -> io::Result<Arc<DaxFileState>> {
        let identity = mobility::file_identity(file)?;
        let mut files = self.files.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(state) = files.get(&identity).and_then(Weak::upgrade) {
            return Ok(state);
        }
        files.retain(|_, state| state.strong_count() != 0);
        let state = Arc::new(DaxFileState::default());
        files.insert(identity, Arc::downgrade(&state));
        Ok(state)
    }
}

impl DaxFileState {
    /// Called under operation, so setup cannot race the no-mappings fast path.
    pub(super) fn has_mappings(&self) -> bool {
        self.has_mappings.load(Ordering::Acquire)
    }
}

impl DaxBacking {
    /// Map existing bytes only. MapViewOfFile rounds the final host page up, so
    /// WHP can expose that page without extending the file's logical size. Pages
    /// wholly beyond EOF must not be backed by an independent anonymous copy.
    fn file(source: DaxFile, guest_addr: u64, len: u64) -> io::Result<Self> {
        let file_len = source.file.metadata().map_err(host_error)?.len();
        let bytes = len.min(file_len.saturating_sub(source.offset));

        let view = if bytes == 0 {
            None
        } else {
            Some(
                WindowsFileMappingView::map_file(
                    &source.file,
                    source.offset,
                    usize::try_from(bytes).map_err(|_| linux_error(LINUX_EINVAL))?,
                    source.access,
                )
                .map_err(host_error)?,
            )
        };

        Ok(Self {
            view,
            mapped_len: bytes.next_multiple_of(DAX_PAGE_SIZE),
            guest_addr,
            source: Some(source),
        })
    }

    /// Map the synthetic init binary anonymously and copy the requested region of
    /// its payload in.
    fn init(foffset: u64, len: usize, guest_addr: u64) -> io::Result<Self> {
        // Map read/write so the payload can be copied in; a write mapping of
        // `init.krun` was rejected above, so the guest mapping is read-only.
        let mut view =
            WindowsFileMappingView::map_anonymous(len, WindowsFileMappingAccess::ReadWrite)
                .map_err(host_error)?;
        if let Ok(start) = usize::try_from(foffset)
            && let Some(tail) = crate::agentd::agentd_bytes().get(start..)
        {
            let to_copy = len.min(tail.len());
            view.copy_from_slice(&tail[..to_copy]).map_err(host_error)?;
        }
        view.make_read_only().map_err(host_error)?;
        Ok(Self {
            view: Some(view),
            mapped_len: len as u64,
            guest_addr,
            source: None,
        })
    }
}

impl WindowsFileMappingAccess {
    /// Access mode implied by the FUSE mapping flags.
    fn from_dax_flags(flags: u64) -> Self {
        if flags & SETUPMAPPING_FLAG_WRITE != 0 {
            Self::ReadWrite
        } else {
            Self::ReadOnly
        }
    }
}
