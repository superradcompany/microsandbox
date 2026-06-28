//! Shared request-size limits for RPC client and server dispatch.

use std::io;

use super::protocol::{MAX_IO_SIZE, MAX_READDIR_ENTRIES};
use crate::backends::shared::platform;

/// Clamp a read/write size to the wire maximum.
pub(crate) fn clamp_io_size(size: u32) -> io::Result<u32> {
    if size > MAX_IO_SIZE {
        return Err(platform::einval());
    }
    Ok(size)
}

/// Reject writes larger than the wire maximum.
pub(crate) fn clamp_write_len(len: usize) -> io::Result<()> {
    if len > MAX_IO_SIZE as usize {
        return Err(platform::einval());
    }
    Ok(())
}

/// Normalize a readdir page limit (0 means max).
pub(crate) fn clamp_readdir_limit(limit: u32) -> io::Result<usize> {
    if limit == 0 {
        return Ok(MAX_READDIR_ENTRIES);
    }
    if limit as usize > MAX_READDIR_ENTRIES {
        return Err(platform::einval());
    }
    Ok(limit as usize)
}
