//! Hook dispatch: access check, read interception, write interception.
//!
//! Hooks are called at specific FUSE operation points:
//! - `on_access`: Before open/create/opendir to enforce access control.
//! - `on_read`: After inner.read() to transform data before returning to guest.
//! - `on_write`: After reading from guest, before inner.write() to transform data.

use std::{io, os::fd::AsRawFd};

use super::{
    AccessMode, ProxyFs,
    adapters::{SliceReader, VecWriter},
};
use crate::{ZeroCopyReader, ZeroCopyWriter};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Check access via the on_access hook.
///
/// Maps FUSE open flags to `AccessMode` and calls the hook. For `O_RDWR`,
/// both Read and Write checks must pass.
pub(crate) fn check_access(fs: &ProxyFs, inode: u64, flags: u32) -> io::Result<()> {
    let on_access = match &fs.on_access {
        Some(hook) => hook,
        None => return Ok(()),
    };

    let path = fs
        .paths
        .read()
        .unwrap()
        .get(&inode)
        .cloned()
        .unwrap_or_default();

    let accmode = (flags as i32) & libc::O_ACCMODE;

    if accmode == libc::O_RDONLY {
        on_access(&path, AccessMode::Read)?;
    } else if accmode == libc::O_WRONLY {
        on_access(&path, AccessMode::Write)?;
    } else {
        // O_RDWR — both must succeed.
        on_access(&path, AccessMode::Read)?;
        on_access(&path, AccessMode::Write)?;
    }

    Ok(())
}

/// Check access for a path (used by create where the file doesn't exist yet).
pub(crate) fn check_access_by_path(fs: &ProxyFs, path: &str, mode: AccessMode) -> io::Result<()> {
    if let Some(ref on_access) = fs.on_access {
        on_access(path, mode)?;
    }
    Ok(())
}

/// Intercepted read: capture inner output, transform via hook, write to guest.
///
/// Uses the staging file to bridge between ZeroCopy traits and in-memory buffers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_intercepted_read(
    fs: &ProxyFs,
    ctx: crate::Context,
    ino: u64,
    handle: u64,
    w: &mut dyn ZeroCopyWriter,
    size: u32,
    offset: u64,
    lock_owner: Option<u64>,
    flags: u32,
) -> io::Result<usize> {
    let on_read = fs.on_read.as_ref().unwrap();
    let path = fs
        .handle_paths
        .read()
        .unwrap()
        .get(&handle)
        .cloned()
        .unwrap_or_default();

    // Step 1: Read from inner into VecWriter.
    let mut vec_writer = VecWriter::new();
    let n = fs.inner.read(
        ctx,
        ino,
        handle,
        &mut vec_writer,
        size,
        offset,
        lock_owner,
        flags,
    )?;

    if n == 0 {
        return Ok(0);
    }

    // Step 2: Transform through hook.
    let transformed = on_read(&path, &vec_writer.buf[..n]);

    if transformed.is_empty() {
        return Ok(0);
    }

    // Step 3: Write transformed data to real FUSE buffer via staging file.
    let staging = fs.staging_file.as_ref().unwrap().lock().unwrap();
    let written = unsafe {
        libc::pwrite(
            staging.as_raw_fd(),
            transformed.as_ptr() as *const libc::c_void,
            transformed.len(),
            0,
        )
    };
    if written < 0 {
        return Err(io::Error::last_os_error());
    }

    w.write_from(&staging, transformed.len(), 0)
}

/// Intercepted write: capture guest input, transform via hook, write to inner.
///
/// Uses the staging file to bridge between ZeroCopy traits and in-memory buffers.
#[allow(clippy::too_many_arguments)]
pub(crate) fn do_intercepted_write(
    fs: &ProxyFs,
    ctx: crate::Context,
    ino: u64,
    handle: u64,
    r: &mut dyn ZeroCopyReader,
    size: u32,
    offset: u64,
    lock_owner: Option<u64>,
    delayed_write: bool,
    kill_priv: bool,
    flags: u32,
) -> io::Result<usize> {
    let on_write = fs.on_write.as_ref().unwrap();
    let path = fs
        .handle_paths
        .read()
        .unwrap()
        .get(&handle)
        .cloned()
        .unwrap_or_default();

    // Step 1: Read guest data via staging file.
    let staging = fs.staging_file.as_ref().unwrap().lock().unwrap();
    let count = r.read_to(&staging, size as usize, 0)?;

    if count == 0 {
        return Ok(0);
    }

    let mut buf = vec![0u8; count];
    let read_back = unsafe {
        libc::pread(
            staging.as_raw_fd(),
            buf.as_mut_ptr() as *mut libc::c_void,
            count,
            0,
        )
    };
    drop(staging);

    if read_back < 0 {
        return Err(io::Error::last_os_error());
    }
    let n = read_back as usize;

    // Step 2: Transform through hook.
    let transformed = on_write(&path, &buf[..n]);

    // Step 3: Write transformed data to inner via SliceReader.
    let mut slice_reader = SliceReader::new(&transformed);
    fs.inner.write(
        ctx,
        ino,
        handle,
        &mut slice_reader,
        transformed.len() as u32,
        offset,
        lock_owner,
        delayed_write,
        kill_priv,
        flags,
    )?;

    // Return number of bytes consumed from guest's perspective.
    Ok(n)
}
