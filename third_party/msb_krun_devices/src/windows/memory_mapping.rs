// Copyright 2026 Super Rad Company.
// SPDX-License-Identifier: Apache-2.0

use std::ffi::c_void;
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::ptr;

use windows_sys::Win32::Foundation::{
    ERROR_INVALID_FUNCTION, ERROR_NOT_SUPPORTED, HANDLE, INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::System::Ioctl::{
    FILE_ZERO_DATA_INFORMATION, FSCTL_SET_SPARSE, FSCTL_SET_ZERO_DATA,
};
use windows_sys::Win32::System::Memory::{
    CreateFileMappingW, DiscardVirtualMemory, FlushViewOfFile, MapViewOfFile, UnmapViewOfFile,
    FILE_MAP_READ, FILE_MAP_WRITE, MEMORY_MAPPED_VIEW_ADDRESS, PAGE_READONLY, PAGE_READWRITE,
};
use windows_sys::Win32::System::SystemInformation::{GetSystemInfo, SYSTEM_INFO};
use windows_sys::Win32::System::IO::DeviceIoControl;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum WindowsFileMappingAccess {
    ReadOnly,
    ReadWrite,
}

pub(crate) struct WindowsFileMappingView {
    _mapping: OwnedHandle,
    base_addr: *mut c_void,
    view_delta: usize,
    len: usize,
}

// Windows views are process-scoped mappings. The raw pointer remains valid until Drop unmaps it, and
// Windows permits unmapping the view from a different thread in the same process.
unsafe impl Send for WindowsFileMappingView {}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WindowsFileMappingAccess {
    fn page_protection(self) -> u32 {
        match self {
            Self::ReadOnly => PAGE_READONLY,
            Self::ReadWrite => PAGE_READWRITE,
        }
    }

    fn file_map_access(self) -> u32 {
        match self {
            Self::ReadOnly => FILE_MAP_READ,
            Self::ReadWrite => FILE_MAP_READ | FILE_MAP_WRITE,
        }
    }
}

impl WindowsFileMappingView {
    pub(crate) fn map_anonymous(len: usize, access: WindowsFileMappingAccess) -> io::Result<Self> {
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

    pub(crate) fn map_file(
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
        let offset_high = (aligned_offset >> 32) as u32;
        let offset_low = aligned_offset as u32;
        let base_addr = unsafe {
            MapViewOfFile(
                mapping.as_raw_handle() as HANDLE,
                access.file_map_access(),
                offset_high,
                offset_low,
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

    pub(crate) fn host_addr(&self) -> u64 {
        self.host_ptr() as u64
    }

    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn flush(&self) -> io::Result<()> {
        let ok =
            unsafe { FlushViewOfFile(self.host_ptr().cast::<c_void>().cast_const(), self.len) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(crate) fn copy_from_slice(&mut self, data: &[u8]) -> io::Result<()> {
        if data.len() > self.len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "source slice is larger than Windows file mapping view",
            ));
        }

        if !data.is_empty() {
            unsafe {
                ptr::copy_nonoverlapping(data.as_ptr(), self.host_ptr(), data.len());
            }
        }

        Ok(())
    }

    fn host_ptr(&self) -> *mut u8 {
        unsafe { self.base_addr.cast::<u8>().add(self.view_delta) }
    }

    #[cfg(test)]
    unsafe fn as_slice(&self) -> &[u8] {
        std::slice::from_raw_parts(self.host_ptr(), self.len)
    }

    #[cfg(test)]
    unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        std::slice::from_raw_parts_mut(self.host_ptr(), self.len)
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
            error!("UnmapViewOfFile failed: {}", io::Error::last_os_error());
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn discard_file_range(file: &File, offset: u64, len: u64) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }

    mark_file_sparse(file)?;
    zero_file_range(file, offset, len)
}

#[allow(dead_code)]
pub(crate) unsafe fn discard_virtual_memory_range(addr: *mut c_void, len: usize) -> io::Result<()> {
    if len == 0 {
        return Ok(());
    }

    let result = DiscardVirtualMemory(addr, len);
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(result as i32))
    }
}

pub(crate) fn is_unsupported_discard_error(error: &io::Error) -> bool {
    matches!(
        error.raw_os_error(),
        Some(code) if code == ERROR_INVALID_FUNCTION as i32 || code == ERROR_NOT_SUPPORTED as i32
    )
}

fn allocation_granularity() -> usize {
    let mut info = SYSTEM_INFO::default();
    unsafe {
        GetSystemInfo(&mut info);
    }
    info.dwAllocationGranularity as usize
}

fn mark_file_sparse(file: &File) -> io::Result<()> {
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as HANDLE,
            FSCTL_SET_SPARSE,
            ptr::null(),
            0,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

fn zero_file_range(file: &File, offset: u64, len: u64) -> io::Result<()> {
    let beyond_final_zero = offset.checked_add(len).ok_or_else(|| {
        io::Error::new(io::ErrorKind::InvalidInput, "file discard range overflow")
    })?;
    let file_offset: i64 = offset.try_into().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("file discard offset overflow: {err}"),
        )
    })?;
    let beyond_final_zero: i64 = beyond_final_zero.try_into().map_err(|err| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("file discard end overflow: {err}"),
        )
    })?;

    let params = FILE_ZERO_DATA_INFORMATION {
        FileOffset: file_offset,
        BeyondFinalZero: beyond_final_zero,
    };
    let mut returned = 0u32;
    let ok = unsafe {
        DeviceIoControl(
            file.as_raw_handle() as HANDLE,
            FSCTL_SET_ZERO_DATA,
            (&params as *const FILE_ZERO_DATA_INFORMATION).cast::<c_void>(),
            std::mem::size_of_val(&params) as u32,
            ptr::null_mut(),
            0,
            &mut returned,
            ptr::null_mut(),
        )
    };
    if ok == 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs::{remove_file, OpenOptions};
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static TEMP_ID: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn file_mapping_view_handles_unaligned_offsets() {
        let path = temp_path("unaligned");
        let mut file = create_temp_file(&path, allocation_granularity() * 2);
        let offset = allocation_granularity() as u64 + 123;
        let expected = b"windows-dax-view";

        file.seek(SeekFrom::Start(offset)).unwrap();
        file.write_all(expected).unwrap();
        file.flush().unwrap();

        let view = WindowsFileMappingView::map_file(
            &file,
            offset,
            expected.len(),
            WindowsFileMappingAccess::ReadOnly,
        )
        .unwrap();

        unsafe {
            assert_eq!(view.as_slice(), expected);
        }
        assert_eq!(view.len(), expected.len());
        assert_ne!(view.host_addr(), 0);

        drop(file);
        remove_file(path).unwrap();
    }

    #[test]
    fn file_mapping_view_write_updates_file() {
        let path = temp_path("write");
        let mut file = create_temp_file(&path, allocation_granularity() * 2);
        let offset = allocation_granularity() as u64 + 7;
        let expected = b"DAX!";

        {
            let mut view = WindowsFileMappingView::map_file(
                &file,
                offset,
                expected.len(),
                WindowsFileMappingAccess::ReadWrite,
            )
            .unwrap();
            unsafe {
                view.as_mut_slice().copy_from_slice(expected);
            }
            view.flush().unwrap();
        }

        let mut actual = vec![0u8; expected.len()];
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read_exact(&mut actual).unwrap();
        assert_eq!(actual, expected);

        drop(file);
        remove_file(path).unwrap();
    }

    #[test]
    fn anonymous_mapping_view_can_be_seeded() {
        let expected = b"anonymous-dax";
        let mut view =
            WindowsFileMappingView::map_anonymous(4096, WindowsFileMappingAccess::ReadWrite)
                .unwrap();

        view.copy_from_slice(expected).unwrap();

        unsafe {
            assert_eq!(&view.as_slice()[..expected.len()], expected);
            assert!(view.as_slice()[expected.len()..64]
                .iter()
                .all(|byte| *byte == 0));
        }
        assert_eq!(view.len(), 4096);
        assert_ne!(view.host_addr(), 0);
    }

    #[test]
    fn discard_file_range_zeroes_file_data_when_supported() {
        let path = temp_path("discard");
        let mut file = create_temp_file(&path, 4096);
        let data = vec![0xff; 4096];
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        match discard_file_range(&file, 128, 64) {
            Ok(()) => {
                let mut actual = vec![0u8; 256];
                file.seek(SeekFrom::Start(0)).unwrap();
                file.read_exact(&mut actual).unwrap();
                assert_eq!(&actual[..128], &data[..128]);
                assert!(actual[128..192].iter().all(|byte| *byte == 0));
                assert_eq!(&actual[192..], &data[192..256]);
            }
            Err(err) if is_unsupported_discard_error(&err) => {}
            Err(err) => panic!("discard_file_range failed: {err}"),
        }

        drop(file);
        remove_file(path).unwrap();
    }

    fn create_temp_file(path: &PathBuf, len: usize) -> File {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.set_len(len as u64).unwrap();
        file
    }

    fn temp_path(name: &str) -> PathBuf {
        let id = TEMP_ID.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "msb-krun-windows-memory-mapping-{name}-{}-{id}",
            std::process::id()
        ))
    }
}
