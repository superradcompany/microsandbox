// Copyright 2026 Super Rad Company.
// SPDX-License-Identifier: Apache-2.0

//! Windows raw-file block I/O backed by overlapped operations and IOCP.

use std::cmp;
use std::fs::{File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::path::Path;
use std::ptr;
use std::sync::atomic::{AtomicU64, Ordering};

use vm_memory::VolatileSlice;
use windows_sys::Win32::Foundation::{
    ERROR_HANDLE_EOF, ERROR_INVALID_FUNCTION, ERROR_IO_PENDING, ERROR_NOT_SUPPORTED, HANDLE,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    FileAlignmentInfo, FileStorageInfo, FlushFileBuffers, GetFileInformationByHandleEx, ReadFile,
    WriteFile, FILE_ALIGNMENT_INFO, FILE_FLAG_NO_BUFFERING, FILE_FLAG_OVERLAPPED,
    FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_STORAGE_INFO,
};
use windows_sys::Win32::System::Ioctl::{FILE_ZERO_DATA_INFORMATION, FSCTL_SET_ZERO_DATA};
use windows_sys::Win32::System::IO::{
    CreateIoCompletionPort, DeviceIoControl, GetQueuedCompletionStatus, OVERLAPPED,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const INFINITE_TIMEOUT: u32 = u32::MAX;
const RAW_FILE_COMPLETION_KEY: usize = 1;
const RAW_FILE_SECTOR_ALIGNMENT: usize = 512;
const ZERO_WRITE_CHUNK_SIZE: usize = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct WindowsRawFile {
    file: File,
    completion_port: CompletionPort,
    size: AtomicU64,
    direct_io: bool,
    sector_alignment: usize,
    buffer_alignment: usize,
}

#[derive(Clone, Copy)]
pub(crate) struct WindowsRawFileBuffer {
    ptr: *mut u8,
    len: usize,
}

pub(crate) struct PendingWindowsRawFileOperation {
    operation: Box<OverlappedOperation>,
    buffer: WindowsRawFileOperationBuffer,
    direction: WindowsRawFileOperationDirection,
    requested_len: usize,
}

pub(crate) struct CompletedWindowsRawFileOperation {
    pub(super) bytes: usize,
    pub(super) buffer: Option<Vec<u8>>,
}

pub(crate) struct WindowsRawFileCompletion {
    key: usize,
    result: io::Result<usize>,
}

struct CompletionPort {
    handle: OwnedHandle,
}

enum WindowsRawFileOperationBuffer {
    Guest(WindowsRawFileBuffer),
    Bounce(AlignedBounceBuffer),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WindowsRawFileOperationDirection {
    Read,
    Write,
}

struct AlignedBounceBuffer {
    storage: Vec<u8>,
    offset: usize,
    len: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WindowsRawFileBuffer {
    /// # Safety
    ///
    /// The caller must keep `ptr..ptr+len` valid until the associated IOCP completion arrives.
    pub(super) unsafe fn new(ptr: *mut u8, len: usize) -> Self {
        Self { ptr, len }
    }

    pub(super) fn as_ptr(&self) -> *const u8 {
        self.ptr.cast_const()
    }

    pub(super) fn as_mut_ptr(&self) -> *mut u8 {
        self.ptr
    }

    pub(super) fn len(&self) -> usize {
        self.len
    }

    fn is_aligned_for_raw_io(&self, sector_alignment: usize, buffer_alignment: usize) -> bool {
        (self.ptr as usize).is_multiple_of(buffer_alignment)
            && self.len.is_multiple_of(sector_alignment)
    }
}

impl WindowsRawFile {
    pub(super) fn open<P: AsRef<Path>>(
        path: P,
        read_only: bool,
        direct_io: bool,
    ) -> io::Result<Self> {
        let mut flags = FILE_FLAG_OVERLAPPED;
        if direct_io {
            flags |= FILE_FLAG_NO_BUFFERING;
        }

        let file = OpenOptions::new()
            .read(true)
            .write(!read_only)
            .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
            .custom_flags(flags)
            .open(path)?;

        let size = file.metadata()?.len();
        let completion_port = CompletionPort::new()?;
        completion_port.associate(file.as_raw_handle() as HANDLE, RAW_FILE_COMPLETION_KEY)?;
        let (sector_alignment, buffer_alignment) = if direct_io {
            query_raw_io_alignment(&file)?
        } else {
            (1, 1)
        };

        Ok(Self {
            file,
            completion_port,
            size: AtomicU64::new(size),
            direct_io,
            sector_alignment,
            buffer_alignment,
        })
    }

    pub(super) fn can_submit_direct_buffer(
        &self,
        buffer: WindowsRawFileBuffer,
        offset: u64,
    ) -> bool {
        if buffer.len() > u32::MAX as usize {
            return false;
        }

        !self.direct_io
            || offset.is_multiple_of(self.sector_alignment as u64)
                && buffer.is_aligned_for_raw_io(self.sector_alignment, self.buffer_alignment)
    }

    pub(super) fn submit_read_buffer(
        &self,
        buffer: WindowsRawFileBuffer,
        offset: u64,
    ) -> io::Result<PendingWindowsRawFileOperation> {
        self.submit_read(
            WindowsRawFileOperationBuffer::Guest(buffer),
            buffer.as_mut_ptr(),
            buffer.len(),
            offset,
        )
    }

    pub(super) fn submit_write_buffer(
        &self,
        buffer: WindowsRawFileBuffer,
        offset: u64,
    ) -> io::Result<PendingWindowsRawFileOperation> {
        self.submit_write(
            WindowsRawFileOperationBuffer::Guest(buffer),
            buffer.as_ptr(),
            buffer.len(),
            offset,
        )
    }

    pub(super) fn submit_read_bounce(
        &self,
        offset: u64,
        len: usize,
    ) -> io::Result<PendingWindowsRawFileOperation> {
        let mut buffer = AlignedBounceBuffer::new(len, self.buffer_alignment)?;
        let ptr = buffer.as_mut_ptr();
        self.submit_read(
            WindowsRawFileOperationBuffer::Bounce(buffer),
            ptr,
            len,
            offset,
        )
    }

    pub(super) fn submit_write_bounce(
        &self,
        offset: u64,
        buffer: Vec<u8>,
    ) -> io::Result<PendingWindowsRawFileOperation> {
        let buffer = AlignedBounceBuffer::from_vec(buffer, self.buffer_alignment)?;
        let ptr = buffer.as_ptr();
        let len = buffer.len();
        self.submit_write(
            WindowsRawFileOperationBuffer::Bounce(buffer),
            ptr,
            len,
            offset,
        )
    }

    pub(super) fn wait_for_completion(&self) -> io::Result<WindowsRawFileCompletion> {
        self.completion_port.wait_any()
    }

    pub(super) fn flush(&self) -> io::Result<()> {
        let ok = unsafe { FlushFileBuffers(self.file.as_raw_handle() as HANDLE) };
        if ok == 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub(super) fn discard_to_any(&self, offset: u64, length: u64) -> io::Result<()> {
        let Some((offset, length)) = self.clamp_discard_range(offset, length)? else {
            return Ok(());
        };

        match self.zero_data(offset, length) {
            Ok(()) => Ok(()),
            Err(err) if is_unsupported_zero_data_error(&err) => Ok(()),
            Err(err) => Err(err),
        }
    }

    pub(super) fn discard_to_zero(&self, offset: u64, length: u64) -> io::Result<()> {
        self.write_zeroes(offset, length)
    }

    pub(super) fn write_zeroes(&self, offset: u64, length: u64) -> io::Result<()> {
        let Some((offset, length)) = self.validate_block_range(offset, length, "write zeroes")?
        else {
            return Ok(());
        };

        match self.zero_data(offset, length) {
            Ok(()) => Ok(()),
            Err(err) if is_unsupported_zero_data_error(&err) => {
                self.write_full_zeroes(offset, length)
            }
            Err(err) => Err(err),
        }
    }

    pub(super) fn read_vectored_at_volatile(
        &self,
        bufs: &[VolatileSlice],
        mut offset: u64,
    ) -> io::Result<usize> {
        let mut total = 0usize;

        for slice in bufs {
            let ptr_guard = slice.ptr_guard_mut();
            let mut slice_offset = 0usize;

            while slice_offset < ptr_guard.len() {
                let ptr = unsafe { ptr_guard.as_ptr().add(slice_offset) };
                let len = ptr_guard.len() - slice_offset;
                let read = self.read_at(ptr, len, offset)?;

                slice_offset = slice_offset
                    .checked_add(read)
                    .ok_or_else(|| io::Error::other("read length overflow"))?;
                offset = offset
                    .checked_add(read as u64)
                    .ok_or_else(|| io::Error::other("read offset overflow"))?;
                total = total
                    .checked_add(read)
                    .ok_or_else(|| io::Error::other("read length overflow"))?;
            }
        }

        Ok(total)
    }

    pub(super) fn write_vectored_at_volatile(
        &self,
        bufs: &[VolatileSlice],
        mut offset: u64,
    ) -> io::Result<usize> {
        let mut total = 0usize;

        for slice in bufs {
            let ptr_guard = slice.ptr_guard();
            let mut slice_offset = 0usize;

            while slice_offset < ptr_guard.len() {
                let ptr = unsafe { ptr_guard.as_ptr().add(slice_offset) };
                let len = ptr_guard.len() - slice_offset;
                let written = self.write_at(ptr, len, offset)?;

                if written == 0 {
                    return Err(io::ErrorKind::WriteZero.into());
                }

                slice_offset = slice_offset
                    .checked_add(written)
                    .ok_or_else(|| io::Error::other("write length overflow"))?;
                offset = offset
                    .checked_add(written as u64)
                    .ok_or_else(|| io::Error::other("write offset overflow"))?;
                total = total
                    .checked_add(written)
                    .ok_or_else(|| io::Error::other("write length overflow"))?;
                self.size.fetch_max(offset, Ordering::Relaxed);
            }
        }

        Ok(total)
    }

    fn read_at(&self, ptr: *mut u8, len: usize, offset: u64) -> io::Result<usize> {
        if len == 0 {
            return Ok(0);
        }

        let file_size = self.size.load(Ordering::Relaxed);
        if offset >= file_size {
            unsafe {
                ptr::write_bytes(ptr, 0, len);
            }
            return Ok(len);
        }

        let readable = (file_size - offset).min(len as u64) as usize;
        let requested = readable.min(u32::MAX as usize);
        let read = self.issue_read(ptr, requested, offset)?;

        if read < len {
            unsafe {
                ptr::write_bytes(ptr.add(read), 0, len - read);
            }
            return Ok(len);
        }

        Ok(read)
    }

    fn write_at(&self, ptr: *const u8, len: usize, offset: u64) -> io::Result<usize> {
        if len == 0 {
            return Ok(0);
        }

        self.issue_write(ptr, len.min(u32::MAX as usize), offset)
    }

    fn issue_read(&self, ptr: *mut u8, len: usize, offset: u64) -> io::Result<usize> {
        let mut operation = OverlappedOperation::new(offset);
        let ok = unsafe {
            ReadFile(
                self.file.as_raw_handle() as HANDLE,
                ptr,
                len as u32,
                ptr::null_mut(),
                operation.as_mut_ptr(),
            )
        };

        operation.finish(&self.completion_port, ok)
    }

    fn issue_write(&self, ptr: *const u8, len: usize, offset: u64) -> io::Result<usize> {
        let mut operation = OverlappedOperation::new(offset);
        let ok = unsafe {
            WriteFile(
                self.file.as_raw_handle() as HANDLE,
                ptr,
                len as u32,
                ptr::null_mut(),
                operation.as_mut_ptr(),
            )
        };

        operation.finish(&self.completion_port, ok)
    }

    fn submit_read(
        &self,
        buffer: WindowsRawFileOperationBuffer,
        ptr: *mut u8,
        len: usize,
        offset: u64,
    ) -> io::Result<PendingWindowsRawFileOperation> {
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero-length overlapped read",
            ));
        }
        if len > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "overlapped read is larger than Windows accepts",
            ));
        }
        self.validate_direct_io_alignment(offset, len, "read")?;

        let file_size = self.size.load(Ordering::Relaxed);
        if offset
            .checked_add(len as u64)
            .is_none_or(|end| end > file_size)
        {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "overlapped read exceeds raw image size",
            ));
        }

        let mut operation = Box::new(OverlappedOperation::new(offset));
        let ok = unsafe {
            ReadFile(
                self.file.as_raw_handle() as HANDLE,
                ptr,
                len as u32,
                ptr::null_mut(),
                operation.as_mut_ptr(),
            )
        };
        validate_overlapped_issue(ok)?;

        Ok(PendingWindowsRawFileOperation {
            operation,
            buffer,
            direction: WindowsRawFileOperationDirection::Read,
            requested_len: len,
        })
    }

    fn submit_write(
        &self,
        buffer: WindowsRawFileOperationBuffer,
        ptr: *const u8,
        len: usize,
        offset: u64,
    ) -> io::Result<PendingWindowsRawFileOperation> {
        if len == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "zero-length overlapped write",
            ));
        }
        if len > u32::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "overlapped write is larger than Windows accepts",
            ));
        }
        self.validate_direct_io_alignment(offset, len, "write")?;

        let end = offset
            .checked_add(len as u64)
            .ok_or_else(|| io::Error::other("write offset overflow"))?;
        if end > self.size.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "overlapped write exceeds raw image size",
            ));
        }

        let mut operation = Box::new(OverlappedOperation::new(offset));
        let ok = unsafe {
            WriteFile(
                self.file.as_raw_handle() as HANDLE,
                ptr,
                len as u32,
                ptr::null_mut(),
                operation.as_mut_ptr(),
            )
        };
        validate_overlapped_issue(ok)?;
        self.size.fetch_max(end, Ordering::Relaxed);

        Ok(PendingWindowsRawFileOperation {
            operation,
            buffer,
            direction: WindowsRawFileOperationDirection::Write,
            requested_len: len,
        })
    }

    fn validate_direct_io_alignment(&self, offset: u64, len: usize, op: &str) -> io::Result<()> {
        if !self.direct_io {
            return Ok(());
        }

        if !offset.is_multiple_of(self.sector_alignment as u64)
            || !len.is_multiple_of(self.sector_alignment)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "overlapped {op} is not aligned to Windows raw I/O sector size {}",
                    self.sector_alignment
                ),
            ));
        }

        Ok(())
    }

    fn validate_block_range(
        &self,
        offset: u64,
        length: u64,
        op: &str,
    ) -> io::Result<Option<(u64, u64)>> {
        if length == 0 {
            return Ok(None);
        }

        let end = offset
            .checked_add(length)
            .ok_or_else(|| io::Error::other(format!("{op} range overflow")))?;
        if end > self.size.load(Ordering::Relaxed) {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                format!("{op} range exceeds raw image size"),
            ));
        }

        Ok(Some((offset, length)))
    }

    fn clamp_discard_range(&self, offset: u64, length: u64) -> io::Result<Option<(u64, u64)>> {
        if length == 0 {
            return Ok(None);
        }

        let size = self.size.load(Ordering::Relaxed);
        if offset >= size {
            return Ok(None);
        }

        let end = offset.checked_add(length).unwrap_or(size).min(size);
        Ok(Some((offset, end - offset)))
    }

    fn zero_data(&self, offset: u64, length: u64) -> io::Result<()> {
        let beyond_final_zero = offset
            .checked_add(length)
            .ok_or_else(|| io::Error::other("zero range overflow"))?;
        let file_offset: i64 = offset
            .try_into()
            .map_err(|e| io::Error::other(format!("zero offset error: {e}")))?;
        let beyond_final_zero: i64 = beyond_final_zero
            .try_into()
            .map_err(|e| io::Error::other(format!("zero length error: {e}")))?;

        let params = FILE_ZERO_DATA_INFORMATION {
            FileOffset: file_offset,
            BeyondFinalZero: beyond_final_zero,
        };
        let mut returned = 0u32;
        let ok = unsafe {
            DeviceIoControl(
                self.file.as_raw_handle() as HANDLE,
                FSCTL_SET_ZERO_DATA,
                (&params as *const FILE_ZERO_DATA_INFORMATION).cast::<std::ffi::c_void>(),
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

    fn write_full_zeroes(&self, mut offset: u64, mut length: u64) -> io::Result<()> {
        let chunk_size = if self.direct_io {
            cmp::max(
                self.sector_alignment,
                ZERO_WRITE_CHUNK_SIZE - (ZERO_WRITE_CHUNK_SIZE % self.sector_alignment),
            )
        } else {
            ZERO_WRITE_CHUNK_SIZE
        };
        let mut buffer = AlignedBounceBuffer::new(chunk_size, self.buffer_alignment)?;
        buffer.as_mut_slice().fill(0);

        while length > 0 {
            let len = cmp::min(chunk_size as u64, length) as usize;
            self.validate_direct_io_alignment(offset, len, "write zeroes fallback")?;
            let written = self.issue_write(buffer.as_ptr(), len, offset)?;
            if written != len {
                return Err(io::ErrorKind::WriteZero.into());
            }

            offset = offset
                .checked_add(written as u64)
                .ok_or_else(|| io::Error::other("write zeroes offset overflow"))?;
            length -= written as u64;
        }

        Ok(())
    }
}

impl PendingWindowsRawFileOperation {
    pub(super) fn completion_key(&self) -> usize {
        self.operation.as_ptr() as usize
    }

    pub(super) fn complete(
        self,
        completion: WindowsRawFileCompletion,
    ) -> io::Result<CompletedWindowsRawFileOperation> {
        if completion.key != self.completion_key() {
            return Err(io::Error::other(
                "completion key does not match pending operation",
            ));
        }

        let bytes = completion.result?;
        if bytes > self.requested_len {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "overlapped operation completed more bytes than requested",
            ));
        }

        match self.direction {
            WindowsRawFileOperationDirection::Read => self.complete_read(bytes),
            WindowsRawFileOperationDirection::Write => self.complete_write(bytes),
        }
    }

    fn complete_read(mut self, bytes: usize) -> io::Result<CompletedWindowsRawFileOperation> {
        if bytes < self.requested_len {
            self.zero_read_tail(bytes);
        }

        Ok(CompletedWindowsRawFileOperation {
            bytes: self.requested_len,
            buffer: self.buffer.take_bounce(),
        })
    }

    fn complete_write(self, bytes: usize) -> io::Result<CompletedWindowsRawFileOperation> {
        if bytes != self.requested_len {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "overlapped write completed fewer bytes than requested",
            ));
        }

        Ok(CompletedWindowsRawFileOperation {
            bytes,
            buffer: None,
        })
    }

    fn zero_read_tail(&mut self, bytes: usize) {
        match &mut self.buffer {
            WindowsRawFileOperationBuffer::Guest(buffer) => unsafe {
                ptr::write_bytes(
                    buffer.as_mut_ptr().add(bytes),
                    0,
                    self.requested_len - bytes,
                );
            },
            WindowsRawFileOperationBuffer::Bounce(buffer) => {
                buffer.as_mut_slice()[bytes..self.requested_len].fill(0);
            }
        }
    }
}

impl WindowsRawFileCompletion {
    pub(super) fn key(&self) -> usize {
        self.key
    }
}

impl WindowsRawFileOperationBuffer {
    fn take_bounce(self) -> Option<Vec<u8>> {
        match self {
            Self::Guest(_) => None,
            Self::Bounce(buffer) => Some(buffer.into_vec()),
        }
    }
}

impl AlignedBounceBuffer {
    fn new(len: usize, alignment: usize) -> io::Result<Self> {
        if !alignment.is_power_of_two() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "bounce buffer alignment is not a power of two",
            ));
        }

        let alloc_len = len
            .checked_add(alignment)
            .ok_or_else(|| io::Error::other("bounce buffer length overflow"))?;
        let storage = vec![0; alloc_len];
        let base = storage.as_ptr() as usize;
        let aligned = align_up(base, alignment);

        Ok(Self {
            storage,
            offset: aligned - base,
            len,
        })
    }

    fn from_vec(buffer: Vec<u8>, alignment: usize) -> io::Result<Self> {
        let mut aligned = Self::new(buffer.len(), alignment)?;
        aligned.as_mut_slice().copy_from_slice(&buffer);
        Ok(aligned)
    }

    fn as_ptr(&self) -> *const u8 {
        self.as_slice().as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.as_mut_slice().as_mut_ptr()
    }

    fn as_slice(&self) -> &[u8] {
        &self.storage[self.offset..self.offset + self.len]
    }

    fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.storage[self.offset..self.offset + self.len]
    }

    fn len(&self) -> usize {
        self.len
    }

    fn into_vec(mut self) -> Vec<u8> {
        self.as_mut_slice().to_vec()
    }
}

impl CompletionPort {
    fn new() -> io::Result<Self> {
        let handle = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, ptr::null_mut(), 0, 0) };
        if handle.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(Self {
            handle: unsafe { OwnedHandle::from_raw_handle(handle as _) },
        })
    }

    fn associate(&self, handle: HANDLE, key: usize) -> io::Result<()> {
        let associated = unsafe {
            CreateIoCompletionPort(handle, self.handle.as_raw_handle() as HANDLE, key, 0)
        };
        if associated.is_null() {
            return Err(io::Error::last_os_error());
        }

        Ok(())
    }

    fn wait(&self, expected: *mut OVERLAPPED) -> io::Result<usize> {
        loop {
            let completion = self.wait_any()?;

            if completion.key != expected as usize {
                log::warn!("received completion for an unexpected overlapped operation");
                continue;
            }

            return completion.result;
        }
    }

    fn wait_any(&self) -> io::Result<WindowsRawFileCompletion> {
        let mut bytes = 0u32;
        let mut key = 0usize;
        let mut overlapped = ptr::null_mut();
        let ok = unsafe {
            GetQueuedCompletionStatus(
                self.handle.as_raw_handle() as HANDLE,
                &mut bytes,
                &mut key,
                &mut overlapped,
                INFINITE_TIMEOUT,
            )
        };

        if overlapped.is_null() {
            return Err(io::Error::last_os_error());
        }

        if key != RAW_FILE_COMPLETION_KEY {
            log::warn!("received completion with an unexpected key: {key}");
        }

        let result = if ok == 0 {
            let err = io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_HANDLE_EOF as i32) {
                Ok(0)
            } else {
                Err(err)
            }
        } else {
            Ok(bytes as usize)
        };

        Ok(WindowsRawFileCompletion {
            key: overlapped as usize,
            result,
        })
    }
}

struct OverlappedOperation {
    overlapped: OVERLAPPED,
}

impl OverlappedOperation {
    fn new(offset: u64) -> Self {
        let mut overlapped = OVERLAPPED::default();
        overlapped.Anonymous.Anonymous.Offset = offset as u32;
        overlapped.Anonymous.Anonymous.OffsetHigh = (offset >> 32) as u32;
        Self { overlapped }
    }

    fn as_mut_ptr(&mut self) -> *mut OVERLAPPED {
        &mut self.overlapped
    }

    fn as_ptr(&self) -> *mut OVERLAPPED {
        &self.overlapped as *const OVERLAPPED as *mut OVERLAPPED
    }

    fn finish(&mut self, completion_port: &CompletionPort, ok: i32) -> io::Result<usize> {
        if ok == 0 {
            let err = io::Error::last_os_error();
            match err.raw_os_error() {
                Some(code) if code == ERROR_IO_PENDING as i32 => {}
                Some(code) if code == ERROR_HANDLE_EOF as i32 => return Ok(0),
                _ => return Err(err),
            }
        }

        completion_port.wait(self.as_mut_ptr())
    }
}

fn validate_overlapped_issue(ok: i32) -> io::Result<()> {
    if ok != 0 {
        return Ok(());
    }

    let err = io::Error::last_os_error();
    match err.raw_os_error() {
        Some(code) if code == ERROR_IO_PENDING as i32 => Ok(()),
        Some(code) if code == ERROR_HANDLE_EOF as i32 => Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "overlapped operation reached EOF",
        )),
        _ => Err(err),
    }
}

fn is_unsupported_zero_data_error(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::Unsupported
        || matches!(
            err.raw_os_error(),
            Some(code)
                if code == ERROR_INVALID_FUNCTION as i32 || code == ERROR_NOT_SUPPORTED as i32
        )
}

fn query_raw_io_alignment(file: &File) -> io::Result<(usize, usize)> {
    let mut storage_info = FILE_STORAGE_INFO::default();
    let storage_ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileStorageInfo,
            &mut storage_info as *mut FILE_STORAGE_INFO as *mut _,
            std::mem::size_of::<FILE_STORAGE_INFO>() as u32,
        )
    };
    if storage_ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let mut alignment_info = FILE_ALIGNMENT_INFO::default();
    let alignment_ok = unsafe {
        GetFileInformationByHandleEx(
            file.as_raw_handle() as HANDLE,
            FileAlignmentInfo,
            &mut alignment_info as *mut FILE_ALIGNMENT_INFO as *mut _,
            std::mem::size_of::<FILE_ALIGNMENT_INFO>() as u32,
        )
    };
    if alignment_ok == 0 {
        return Err(io::Error::last_os_error());
    }

    let sector_alignment = normalize_alignment(
        storage_info.LogicalBytesPerSector as usize,
        RAW_FILE_SECTOR_ALIGNMENT,
    );
    let buffer_alignment = alignment_info
        .AlignmentRequirement
        .checked_add(1)
        .ok_or_else(|| io::Error::other("raw I/O buffer alignment overflow"))
        .map(|alignment| normalize_alignment(alignment as usize, 1))?;

    Ok((sector_alignment, buffer_alignment))
}

fn normalize_alignment(alignment: usize, default: usize) -> usize {
    let alignment = if alignment == 0 { default } else { alignment };
    alignment.next_power_of_two()
}

fn align_up(value: usize, alignment: usize) -> usize {
    debug_assert!(alignment.is_power_of_two());
    (value + alignment - 1) & !(alignment - 1)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::os::windows::fs::FileExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    use vm_memory::{Bytes, GuestAddress, GuestMemoryBackend, GuestMemoryMmap};

    use super::*;

    #[test]
    fn raw_file_exchanges_data_through_iocp() {
        let path = temp_image_path("roundtrip");
        let file = File::create(&path).unwrap();
        file.set_len(0x4000).unwrap();
        drop(file);

        let raw_file = WindowsRawFile::open(&path, false, false).unwrap();
        let mem: GuestMemoryMmap<()> =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x4000)]).unwrap();
        let payload = vec![0x5au8; 512];
        mem.write_slice(&payload, GuestAddress(0x100)).unwrap();

        let source = mem.get_slice(GuestAddress(0x100), payload.len()).unwrap();
        assert_eq!(
            raw_file
                .write_vectored_at_volatile(&[source], 0x1000)
                .unwrap(),
            payload.len()
        );

        let target = mem.get_slice(GuestAddress(0x800), payload.len()).unwrap();
        assert_eq!(
            raw_file
                .read_vectored_at_volatile(&[target], 0x1000)
                .unwrap(),
            payload.len()
        );

        let mut actual = vec![0u8; payload.len()];
        mem.read_slice(&mut actual, GuestAddress(0x800)).unwrap();
        assert_eq!(actual, payload);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn raw_file_zero_fills_reads_past_eof() {
        let path = temp_image_path("eof");
        let file = File::create(&path).unwrap();
        file.set_len(512).unwrap();
        drop(file);

        let raw_file = WindowsRawFile::open(&path, true, false).unwrap();
        let mem: GuestMemoryMmap<()> =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        mem.write_slice(&[0xff; 512], GuestAddress(0x200)).unwrap();

        let target = mem.get_slice(GuestAddress(0x200), 512).unwrap();
        assert_eq!(
            raw_file.read_vectored_at_volatile(&[target], 1024).unwrap(),
            512
        );

        let mut actual = vec![0xff; 512];
        mem.read_slice(&mut actual, GuestAddress(0x200)).unwrap();
        assert_eq!(actual, vec![0; 512]);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn raw_file_completes_multiple_pending_guest_ios() {
        let path = temp_image_path("pending");
        let file = File::create(&path).unwrap();
        file.set_len(0x8000).unwrap();
        drop(file);

        let raw_file = WindowsRawFile::open(&path, false, false).unwrap();
        let mem: GuestMemoryMmap<()> =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x8000)]).unwrap();
        let first = vec![0x11u8; 512];
        let second = vec![0x22u8; 512];
        mem.write_slice(&first, GuestAddress(0x1000)).unwrap();
        mem.write_slice(&second, GuestAddress(0x2000)).unwrap();

        let first_source = mem.get_slice(GuestAddress(0x1000), first.len()).unwrap();
        let first_guard = first_source.ptr_guard();
        let second_source = mem.get_slice(GuestAddress(0x2000), second.len()).unwrap();
        let second_guard = second_source.ptr_guard();
        let mut writes = HashMap::new();

        let first_write = raw_file
            .submit_write_buffer(
                unsafe {
                    WindowsRawFileBuffer::new(first_guard.as_ptr() as *mut u8, first_guard.len())
                },
                0x1000,
            )
            .unwrap();
        writes.insert(first_write.completion_key(), first_write);
        let second_write = raw_file
            .submit_write_buffer(
                unsafe {
                    WindowsRawFileBuffer::new(second_guard.as_ptr() as *mut u8, second_guard.len())
                },
                0x2000,
            )
            .unwrap();
        writes.insert(second_write.completion_key(), second_write);

        while !writes.is_empty() {
            let completion = raw_file.wait_for_completion().unwrap();
            let operation = writes.remove(&completion.key()).unwrap();
            assert_eq!(operation.complete(completion).unwrap().bytes, 512);
        }

        let first_target = mem.get_slice(GuestAddress(0x3000), first.len()).unwrap();
        let first_target_guard = first_target.ptr_guard_mut();
        let second_target = mem.get_slice(GuestAddress(0x4000), second.len()).unwrap();
        let second_target_guard = second_target.ptr_guard_mut();
        let mut reads = HashMap::new();

        let first_read = raw_file
            .submit_read_buffer(
                unsafe {
                    WindowsRawFileBuffer::new(first_target_guard.as_ptr(), first_target_guard.len())
                },
                0x1000,
            )
            .unwrap();
        reads.insert(first_read.completion_key(), first_read);
        let second_read = raw_file
            .submit_read_buffer(
                unsafe {
                    WindowsRawFileBuffer::new(
                        second_target_guard.as_ptr(),
                        second_target_guard.len(),
                    )
                },
                0x2000,
            )
            .unwrap();
        reads.insert(second_read.completion_key(), second_read);

        while !reads.is_empty() {
            let completion = raw_file.wait_for_completion().unwrap();
            let operation = reads.remove(&completion.key()).unwrap();
            assert_eq!(operation.complete(completion).unwrap().bytes, 512);
        }

        let mut first_actual = vec![0u8; first.len()];
        mem.read_slice(&mut first_actual, GuestAddress(0x3000))
            .unwrap();
        assert_eq!(first_actual, first);

        let mut second_actual = vec![0u8; second.len()];
        mem.read_slice(&mut second_actual, GuestAddress(0x4000))
            .unwrap();
        assert_eq!(second_actual, second);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn raw_file_flushes_after_write() {
        let path = temp_image_path("flush");
        let file = File::create(&path).unwrap();
        file.set_len(0x1000).unwrap();
        drop(file);

        let raw_file = WindowsRawFile::open(&path, false, false).unwrap();
        let mem: GuestMemoryMmap<()> =
            GuestMemoryMmap::from_ranges(&[(GuestAddress(0), 0x1000)]).unwrap();
        let payload = vec![0x33u8; 512];
        mem.write_slice(&payload, GuestAddress(0x100)).unwrap();
        let source = mem.get_slice(GuestAddress(0x100), payload.len()).unwrap();

        assert_eq!(
            raw_file
                .write_vectored_at_volatile(&[source], 0x200)
                .unwrap(),
            payload.len()
        );
        raw_file.flush().unwrap();

        let mut actual = vec![0u8; payload.len()];
        let disk = File::open(&path).unwrap();
        disk.seek_read(&mut actual, 0x200).unwrap();
        assert_eq!(actual, payload);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn raw_file_write_zeroes_clears_range() {
        let path = temp_image_path("zeroes");
        let file = File::create(&path).unwrap();
        file.set_len(0x2000).unwrap();
        file.seek_write(&vec![0xaau8; 0x2000], 0).unwrap();
        drop(file);

        let raw_file = WindowsRawFile::open(&path, false, false).unwrap();
        raw_file.write_zeroes(0x400, 0x800).unwrap();

        let disk = File::open(&path).unwrap();
        let mut actual = vec![0u8; 0x2000];
        disk.seek_read(&mut actual, 0).unwrap();
        assert_eq!(&actual[..0x400], vec![0xaa; 0x400]);
        assert_eq!(&actual[0x400..0xc00], vec![0; 0x800]);
        assert_eq!(&actual[0xc00..], vec![0xaa; 0x1400]);

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn raw_file_discard_to_any_accepts_valid_range() {
        let path = temp_image_path("discard");
        let file = File::create(&path).unwrap();
        file.set_len(0x2000).unwrap();
        drop(file);

        let raw_file = WindowsRawFile::open(&path, false, false).unwrap();
        raw_file.discard_to_any(0x400, 0x800).unwrap();

        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn raw_file_write_zeroes_rejects_past_end() {
        let path = temp_image_path("zeroes-past-end");
        let file = File::create(&path).unwrap();
        file.set_len(0x1000).unwrap();
        drop(file);

        let raw_file = WindowsRawFile::open(&path, false, false).unwrap();
        let err = raw_file.write_zeroes(0x800, 0x1000).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);

        std::fs::remove_file(path).unwrap();
    }

    fn temp_image_path(test_name: &str) -> std::path::PathBuf {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();

        std::env::temp_dir().join(format!(
            "libkrun-block-iocp-{test_name}-{}-{timestamp}.img",
            std::process::id()
        ))
    }
}
