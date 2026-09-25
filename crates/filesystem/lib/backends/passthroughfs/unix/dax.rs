//! DAX window mappings.
//!
//! virtio-fs DAX lets the guest map a file region directly into the shared
//! memory window instead of issuing FUSE reads/writes. The VMM forwards
//! `FUSE_SETUPMAPPING`/`FUSE_REMOVEMAPPING` here.
//!
//! The file region is mapped into the process's own window with
//! `mmap(MAP_SHARED|MAP_FIXED)`.

use std::io;

use crate::backends::shared::platform;

#[cfg(target_os = "linux")]
mod linux {
    use super::super::{PassthroughFs, inode};
    use super::*;

    /// Map `[foffset, foffset + len)` of `inode` into the DAX window at
    /// `host_shm_base + moffset`.
    pub(crate) fn do_setupmapping(
        fs: &PassthroughFs,
        inode: u64,
        handle: u64,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        host_shm_base: u64,
        shm_size: u64,
    ) -> io::Result<()> {
        // DAX bypasses the ordinary FUSE write/open checks, so a read-only mount
        // must refuse a writable mapping instead of relying on the guest.
        if fs.cfg.readonly() && flags & SETUPMAPPING_FLAG_WRITE != 0 {
            return Err(platform::erofs());
        }
        // `init.krun` is read-only even on a writable mount.
        if fs.is_virtual_init_inode(inode) && flags & SETUPMAPPING_FLAG_WRITE != 0 {
            return Err(platform::eacces());
        }
        let write = flags & SETUPMAPPING_FLAG_WRITE != 0;
        // The handle's access mode still applies: a writable mapping must not
        // grant write access to a file the guest opened read-only.
        if write {
            fs.require_writable_mapping_handle(inode, handle)?;
        }
        let addr = window_addr(moffset, len, host_shm_base, shm_size)?;

        // The synthetic init binary has no backing host file; map anonymous
        // memory and copy the requested region of its payload in, matching the
        // non-DAX read path.
        if fs.is_virtual_init_inode(inode) {
            return map_init(addr, len, foffset);
        }

        let open_flags = if write { libc::O_RDWR } else { libc::O_RDONLY };
        let prot = if write {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };

        let fd = inode::open_inode_fd(fs, inode, open_flags)?;
        let ret = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                len as usize,
                prot,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                foffset as libc::off_t,
            )
        };
        let error = (ret == libc::MAP_FAILED).then(io::Error::last_os_error);
        // The mapping keeps the file alive after the fd is closed.
        unsafe { libc::close(fd) };
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Tear down previously established mappings by replacing them with a
    /// `PROT_NONE` anonymous mapping.
    pub(crate) fn do_removemapping(
        requests: &[crate::RemovemappingOne],
        host_shm_base: u64,
        shm_size: u64,
    ) -> io::Result<()> {
        for request in requests {
            let addr = window_addr(request.moffset, request.len, host_shm_base, shm_size)?;
            let ret = unsafe {
                libc::mmap(
                    addr as *mut libc::c_void,
                    request.len as usize,
                    libc::PROT_NONE,
                    libc::MAP_ANONYMOUS | libc::MAP_PRIVATE | libc::MAP_FIXED,
                    -1,
                    0,
                )
            };
            if ret == libc::MAP_FAILED {
                return Err(io::Error::last_os_error());
            }
        }
        Ok(())
    }

    /// Map the synthetic init binary into the window, copying the requested
    /// region of its payload.
    fn map_init(addr: u64, len: u64, foffset: u64) -> io::Result<()> {
        let ret = unsafe {
            libc::mmap(
                addr as *mut libc::c_void,
                len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED,
                -1,
                0,
            )
        };
        if ret == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        copy_init(addr as *mut libc::c_void, len, foffset);
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `FUSE_SETUPMAPPING_FLAG_WRITE` (`linux/fuse.h`): the guest asked for a
/// writable mapping.
const SETUPMAPPING_FLAG_WRITE: u64 = 0x1;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return the host address of a window region, rejecting out-of-window
/// mappings.
fn window_addr(moffset: u64, len: u64, shm_base: u64, shm_size: u64) -> io::Result<u64> {
    let end = moffset.checked_add(len).ok_or_else(platform::einval)?;
    if end > shm_size {
        return Err(platform::einval());
    }
    shm_base.checked_add(moffset).ok_or_else(platform::einval)
}

/// Copy `[foffset, foffset + len)` of the init-binary payload into an anonymous
/// mapping at `addr`.
#[cfg(target_os = "linux")]
fn copy_init(addr: *mut libc::c_void, len: u64, foffset: u64) {
    let Ok(start) = usize::try_from(foffset) else {
        return;
    };
    let data = crate::agentd::agentd_bytes();
    let Some(tail) = data.get(start..) else {
        return;
    };
    let to_copy = std::cmp::min(len as usize, tail.len());
    if to_copy > 0 {
        // SAFETY: `addr` is a writable mapping of at least `len` bytes and
        // `tail` is a valid slice of at least `to_copy` bytes.
        unsafe {
            libc::memcpy(addr, tail.as_ptr() as *const _, to_copy);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub(crate) use linux::{do_removemapping, do_setupmapping};
