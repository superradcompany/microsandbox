//! Windows memory-mapped views for the passthrough filesystem.
//!
//! virtio-fs DAX needs a host address for a mapped region that the VMM can
//! install into the guest's stage-2 tables. On Windows that address comes from
//! `MapViewOfFile`, whose view must stay alive (and be unmapped) as long as the
//! guest mapping references it.

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, MapViewOfFile,
    PAGE_READONLY, PAGE_READWRITE, UnmapViewOfFile, VirtualProtect,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Desired access for a Windows file mapping view.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum WindowsFileMappingAccess {
    /// Read-only view.
    ReadOnly,
    /// Read/write view.
    ReadWrite,
}

/// A mapped host view that stays alive until dropped.
pub(super) struct WindowsFileMappingView {
    /// The file-mapping object that owns the view; kept for its lifetime.
    _mapping: OwnedHandle,
    /// Base address returned by `MapViewOfFile` (before offset alignment).
    base_addr: *mut c_void,
    /// Difference between the requested offset and the page-aligned base.
    view_delta: usize,
    /// Requested view length in bytes.
    len: usize,
}

// Windows views are process-scoped mappings: the raw pointer stays valid until
// Drop unmaps it, and Windows permits unmapping from another thread.
unsafe impl Send for WindowsFileMappingView {}

// Shared references only read the mapped address; the view is mutated through
// `&mut self`, so it may be shared across threads (for example behind an `Arc`).
unsafe impl Sync for WindowsFileMappingView {}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WindowsFileMappingAccess {
    /// Page protection for `CreateFileMappingW`.
    fn page_protection(self) -> u32 {
        match self {
            Self::ReadOnly => PAGE_READONLY,
            Self::ReadWrite => PAGE_READWRITE,
        }
    }

    /// Desired view access for `MapViewOfFile`.
    fn file_map_access(self) -> u32 {
        match self {
            Self::ReadOnly => FILE_MAP_READ,
            Self::ReadWrite => FILE_MAP_READ | FILE_MAP_WRITE,
        }
    }
}

impl WindowsFileMappingView {
    /// Map an anonymous view of `len` bytes.
    pub(super) fn map_anonymous(len: usize, access: WindowsFileMappingAccess) -> io::Result<Self> {
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot map an empty Windows anonymous view",
            ));
        }

        let len_u64 = len as u64;
        let mapping = unsafe {
            CreateFileMappingW(
                INVALID_HANDLE_VALUE,
                ptr::null(),
                access.page_protection(),
                (len_u64 >> 32) as u32,
                len_u64 as u32,
                ptr::null(),
            )
        };
        if mapping.is_null() {
            return Err(io::Error::last_os_error());
        }

        let mapping = unsafe { OwnedHandle::from_raw_handle(mapping.cast()) };
        let base_addr = unsafe {
            MapViewOfFile(
                mapping.as_raw_handle() as HANDLE,
                access.file_map_access(),
                0,
                0,
                len,
            )
        };
        if base_addr.Value.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            _mapping: mapping,
            base_addr: base_addr.Value,
            view_delta: 0,
            len,
        })
    }

    /// Map `[offset, offset + len)` of `file`.
    pub(super) fn map_file(
        file: &File,
        offset: u64,
        len: usize,
        access: WindowsFileMappingAccess,
    ) -> io::Result<Self> {
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "cannot map an empty Windows file view",
            ));
        }

        // `MapViewOfFile` only accepts offsets aligned to the allocation
        // granularity; map from the aligned base and expose the requested
        // offset within it.
        let granularity = allocation_granularity() as u64;
        let aligned_offset = offset - (offset % granularity);
        let view_delta: usize = (offset - aligned_offset).try_into().map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("mapping offset alignment overflow: {err}"),
            )
        })?;
        let mapped_len = len.checked_add(view_delta).ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "mapping length overflow")
        })?;

        let mapping = unsafe {
            CreateFileMappingW(
                file.as_raw_handle() as HANDLE,
                ptr::null(),
                access.page_protection(),
                0,
                0,
                ptr::null(),
            )
        };
        if mapping.is_null() {
            return Err(io::Error::last_os_error());
        }

        let mapping = unsafe { OwnedHandle::from_raw_handle(mapping.cast()) };
        let base_addr = unsafe {
            MapViewOfFile(
                mapping.as_raw_handle() as HANDLE,
                access.file_map_access(),
                (aligned_offset >> 32) as u32,
                aligned_offset as u32,
                mapped_len,
            )
        };
        if base_addr.Value.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            _mapping: mapping,
            base_addr: base_addr.Value,
            view_delta,
            len,
        })
    }

    /// Host address of the requested view region.
    pub(super) fn host_addr(&self) -> u64 {
        self.host_ptr() as u64
    }

    /// Drop write access once the view's payload has been copied in.
    pub(super) fn make_read_only(&mut self) -> io::Result<()> {
        let len = self.view_delta + self.len;
        let mut old_protect = 0u32;
        // SAFETY: `base_addr` and `len` describe the mapped view.
        if unsafe { VirtualProtect(self.base_addr, len, PAGE_READONLY, &mut old_protect) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// Copy `data` into the start of the view.
    pub(super) fn copy_from_slice(&mut self, data: &[u8]) -> io::Result<()> {
        if data.len() > self.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source slice is larger than Windows file mapping view",
            ));
        }
        if !data.is_empty() {
            // SAFETY: the view is at least `len` bytes and `data.len() <= len`.
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), self.host_ptr(), data.len());
            }
        }
        Ok(())
    }

    /// Pointer to the requested view region.
    fn host_ptr(&self) -> *mut u8 {
        // SAFETY: `view_delta` was validated to fit the view when it was mapped.
        unsafe { self.base_addr.cast::<u8>().add(self.view_delta) }
    }
}

impl Drop for WindowsFileMappingView {
    fn drop(&mut self) {
        let ok = unsafe {
            UnmapViewOfFile(MEMORY_MAPPED_VIEW_ADDRESS {
                Value: self.base_addr,
            })
        };
        if ok == 0 {
            tracing::error!("UnmapViewOfFile failed: {}", io::Error::last_os_error());
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// System allocation granularity, the alignment `MapViewOfFile` requires.
fn allocation_granularity() -> usize {
    let mut info = SYSTEM_INFO::default();
    // SAFETY: `info` is a valid out-parameter for `GetSystemInfo`.
    unsafe {
        GetSystemInfo(&mut info);
    }
    info.dwAllocationGranularity as usize
}
