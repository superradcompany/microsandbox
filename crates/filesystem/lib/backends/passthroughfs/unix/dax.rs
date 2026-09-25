//! DAX window mappings.
//!
//! virtio-fs DAX lets the guest map a file region directly into the shared
//! memory window instead of issuing FUSE reads/writes. The VMM forwards
//! `FUSE_SETUPMAPPING`/`FUSE_REMOVEMAPPING` here.
//!
//! Linux maps the file region into the process's own window with
//! `mmap(MAP_SHARED|MAP_FIXED)`. macOS cannot install a stage-2 mapping from
//! userspace, so it maps the file host-side and asks the VMM worker to install
//! it with [`WorkerMessage::DaxAddMapping`], carrying whether the mapping is
//! writable so HVF can omit `HV_MEMORY_WRITE` for read-only mappings.

#[cfg(target_os = "macos")]
use std::collections::BTreeMap;
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

#[cfg(target_os = "macos")]
mod macos {
    use std::ptr::null_mut;

    use crossbeam_channel::{Sender, unbounded};
    use msb_krun_utils::worker_message::WorkerMessage;

    use super::super::{PassthroughFs, inode};
    use super::*;

    /// Map `[foffset, foffset + len)` of `inode` host-side and ask the VMM
    /// worker to install the stage-2 mapping at `guest_shm_base + moffset`.
    pub(crate) fn do_setupmapping(
        fs: &PassthroughFs,
        inode: u64,
        handle: u64,
        foffset: u64,
        len: u64,
        flags: u64,
        moffset: u64,
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
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
        let Some(sender) = map_sender else {
            return Err(platform::enosys());
        };
        let guest_addr = window_addr(moffset, len, guest_shm_base, shm_size)?;

        let prot = if write {
            libc::PROT_READ | libc::PROT_WRITE
        } else {
            libc::PROT_READ
        };

        let host_addr = if fs.is_virtual_init_inode(inode) {
            map_init(len, foffset)?
        } else {
            let open_flags = if write { libc::O_RDWR } else { libc::O_RDONLY };
            let fd = inode::open_inode_fd(fs, inode, open_flags)?;
            let addr = unsafe {
                libc::mmap(
                    null_mut(),
                    len as usize,
                    prot,
                    libc::MAP_SHARED,
                    fd,
                    foffset as libc::off_t,
                )
            };
            let error = (addr == libc::MAP_FAILED).then(io::Error::last_os_error);
            unsafe { libc::close(fd) };
            match error {
                Some(error) => return Err(error),
                None => addr as u64,
            }
        };

        // `DaxAddMapping` carries writability so the HVF worker can install a
        // read-only stage-2 mapping. A failed send or rejected reply must
        // release the host mapping we just established.
        let (reply_tx, reply_rx) = unbounded();
        if sender
            .send(WorkerMessage::DaxAddMapping(
                reply_tx, host_addr, guest_addr, len, write,
            ))
            .is_err()
        {
            unsafe { libc::munmap(host_addr as *mut libc::c_void, len as usize) };
            return Err(platform::eio());
        }
        if !reply_rx.recv().unwrap_or(false) {
            unsafe { libc::munmap(host_addr as *mut libc::c_void, len as usize) };
            return Err(platform::einval());
        }
        fs.map_windows
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(
                guest_addr,
                WindowMapping {
                    guest_addr,
                    host_addr,
                    len,
                },
            );
        Ok(())
    }

    /// Tear down mappings the VMM worker installed, then release the host
    /// mappings.
    pub(crate) fn do_removemapping(
        fs: &PassthroughFs,
        requests: &[crate::RemovemappingOne],
        guest_shm_base: u64,
        shm_size: u64,
        map_sender: &Option<Sender<WorkerMessage>>,
    ) -> io::Result<()> {
        let Some(sender) = map_sender else {
            return Err(platform::enosys());
        };
        for request in requests {
            let guest_addr = window_addr(request.moffset, request.len, guest_shm_base, shm_size)?;

            // Tear down the stage-2 mapping first and only touch the host
            // registry once the worker has acknowledged, so a failed removal
            // leaves it intact for a retry.
            let (reply_tx, reply_rx) = unbounded();
            sender
                .send(WorkerMessage::GpuRemoveMapping(
                    reply_tx,
                    guest_addr,
                    request.len,
                ))
                .map_err(|_| platform::eio())?;
            if !reply_rx.recv().unwrap_or(false) {
                return Err(platform::einval());
            }

            let mut windows = fs.map_windows.lock().unwrap_or_else(|p| p.into_inner());
            unmap_host_range(&mut windows, guest_addr, request.len)?;
        }
        Ok(())
    }

    /// Map the synthetic init binary anonymously and copy the requested region
    /// of its payload.
    fn map_init(len: u64, foffset: u64) -> io::Result<u64> {
        let addr = unsafe {
            libc::mmap(
                null_mut(),
                len as usize,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            )
        };
        if addr == libc::MAP_FAILED {
            return Err(io::Error::last_os_error());
        }
        copy_init(addr, len, foffset);
        Ok(addr as u64)
    }
}

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// `FUSE_SETUPMAPPING_FLAG_WRITE` (`linux/fuse.h`): the guest asked for a
/// writable mapping.
const SETUPMAPPING_FLAG_WRITE: u64 = 0x1;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One installed macOS DAX window mapping.
#[cfg(target_os = "macos")]
#[derive(Clone)]
pub(crate) struct WindowMapping {
    /// Guest address the mapping starts at.
    pub guest_addr: u64,
    /// Host address the mapping starts at.
    pub host_addr: u64,
    /// Length of the mapping in bytes.
    pub len: u64,
}

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
#[cfg(any(target_os = "linux", target_os = "macos"))]
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

/// Release the host mappings covering `[guest_addr, guest_addr + len)` and
/// update the registry, splitting any mapping the range only partly covers.
#[cfg(target_os = "macos")]
fn unmap_host_range(
    windows: &mut BTreeMap<u64, WindowMapping>,
    guest_addr: u64,
    len: u64,
) -> io::Result<()> {
    let end = guest_addr.checked_add(len).ok_or_else(platform::einval)?;
    let overlapping: Vec<WindowMapping> = windows
        .range(..end)
        .filter(|(_, window)| window.guest_addr.saturating_add(window.len) > guest_addr)
        .map(|(_, window)| window.clone())
        .collect();

    for window in overlapping {
        let start = window.guest_addr.max(guest_addr);
        let stop = window.guest_addr.saturating_add(window.len).min(end);
        let offset = start - window.guest_addr;
        let overlap_len = stop - start;

        if unsafe {
            libc::munmap(
                (window.host_addr + offset) as *mut libc::c_void,
                overlap_len as usize,
            )
        } == -1
        {
            return Err(io::Error::last_os_error());
        }

        windows.remove(&window.guest_addr);
        if start > window.guest_addr {
            windows.insert(
                window.guest_addr,
                WindowMapping {
                    guest_addr: window.guest_addr,
                    host_addr: window.host_addr,
                    len: start - window.guest_addr,
                },
            );
        }
        if stop < window.guest_addr.saturating_add(window.len) {
            windows.insert(
                stop,
                WindowMapping {
                    guest_addr: stop,
                    host_addr: window.host_addr + (stop - window.guest_addr),
                    len: window.guest_addr.saturating_add(window.len) - stop,
                },
            );
        }
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
pub(crate) use linux::{do_removemapping, do_setupmapping};

#[cfg(target_os = "macos")]
pub(crate) use macos::{do_removemapping, do_setupmapping};
