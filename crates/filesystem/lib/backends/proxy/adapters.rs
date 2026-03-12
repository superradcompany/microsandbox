//! ZeroCopy adapters for buffered hook interception.
//!
//! `VecWriter` collects data into a `Vec<u8>` via `ZeroCopyWriter`,
//! used to capture inner backend read output for the `on_read` hook.
//!
//! `SliceReader` presents a `&[u8]` slice as a `ZeroCopyReader`,
//! used to feed transformed data from the `on_write` hook to the inner backend.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;

use crate::{ZeroCopyReader, ZeroCopyWriter};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Writer that collects data into a `Vec<u8>` buffer.
///
/// Implements `ZeroCopyWriter` by reading from the provided file descriptor
/// into an internal buffer via `pread`.
pub(crate) struct VecWriter {
    pub(crate) buf: Vec<u8>,
}

/// Reader that presents an in-memory slice as a `ZeroCopyReader`.
///
/// Implements `ZeroCopyReader` by writing from the internal buffer
/// to the provided file descriptor via `pwrite`.
pub(crate) struct SliceReader<'a> {
    data: &'a [u8],
    pos: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl VecWriter {
    pub(crate) fn new() -> Self {
        VecWriter { buf: Vec::new() }
    }
}

impl<'a> SliceReader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        SliceReader { data, pos: 0 }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl ZeroCopyWriter for VecWriter {
    fn write_from(&mut self, f: &File, count: usize, off: u64) -> io::Result<usize> {
        let mut tmp = vec![0u8; count];
        let n = unsafe {
            libc::pread(
                f.as_raw_fd(),
                tmp.as_mut_ptr() as *mut libc::c_void,
                count,
                off as i64,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        self.buf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }
}

impl ZeroCopyReader for SliceReader<'_> {
    fn read_to(&mut self, f: &File, count: usize, off: u64) -> io::Result<usize> {
        let remaining = &self.data[self.pos..];
        let to_write = std::cmp::min(count, remaining.len());
        if to_write == 0 {
            return Ok(0);
        }
        let n = unsafe {
            libc::pwrite(
                f.as_raw_fd(),
                remaining.as_ptr() as *const libc::c_void,
                to_write,
                off as i64,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        self.pos += n;
        Ok(n)
    }
}
