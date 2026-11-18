//! DAX window bookkeeping shared by the platform passthrough backends.
//!
//! virtio-fs DAX maps a file region into a shared window. Linux installs the
//! mapping directly with `mmap(MAP_FIXED)`, while macOS and Windows map the file
//! host-side and ask the VMM worker to install the stage-2 mapping. The
//! worker-backed platforms must track installed windows so they can honor
//! partial `FUSE_REMOVEMAPPING` requests and replace a range the guest re-maps
//! (for example when it upgrades a read-only mapping to writable).

#[cfg(any(windows, target_os = "macos"))]
use std::collections::BTreeMap;
use std::io;

#[cfg(any(windows, target_os = "macos"))]
use crossbeam_channel::{Sender, unbounded};
#[cfg(any(windows, target_os = "macos"))]
use msb_krun_utils::worker_message::WorkerMessage;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Linux `EIO`, returned when the VMM worker channel is closed.
#[cfg(any(windows, target_os = "macos"))]
const LINUX_EIO: i32 = 5;
/// Linux `EINVAL`, the errno the FUSE protocol expects for a bad window range.
const LINUX_EINVAL: i32 = 22;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One installed worker-backed DAX window slot.
///
/// A partial removal can leave a single host mapping backing several slots, so
/// the backing is cloned into each retained slot and released when the last
/// slot referencing it is removed.
#[cfg(any(windows, target_os = "macos"))]
pub(crate) struct WindowMapping<B> {
    /// Guest address the slot starts at.
    pub(crate) guest_addr: u64,
    /// Host address the slot starts at.
    pub(crate) host_addr: u64,
    /// Length of the slot in bytes.
    pub(crate) len: u64,
    /// Platform backing kept alive until the slot is removed.
    pub(crate) backing: B,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return the guest address of a window region, rejecting out-of-window
/// mappings.
pub(crate) fn window_addr(moffset: u64, len: u64, shm_base: u64, shm_size: u64) -> io::Result<u64> {
    let end = moffset.checked_add(len).ok_or_else(einval)?;
    if end > shm_size {
        return Err(einval());
    }
    shm_base.checked_add(moffset).ok_or_else(einval)
}

/// Remove `[guest_addr, guest_addr + len)` from `windows`, splitting any slot
/// the range only partly covers.
///
/// Each slot shares an owned backing, so dropping the removed overlap only
/// releases the host mapping once no slot references it. The whole mapping is
/// never unmapped while another slot still points at it, and a removal cannot
/// fail after the worker acknowledged it.
#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn remove_window_range<B: Clone>(
    windows: &mut BTreeMap<u64, WindowMapping<B>>,
    guest_addr: u64,
    len: u64,
) -> io::Result<()> {
    let end = guest_addr.checked_add(len).ok_or_else(einval)?;
    let keys: Vec<u64> = windows
        .range(..end)
        .filter(|(_, window)| window.guest_addr.saturating_add(window.len) > guest_addr)
        .map(|(key, _)| *key)
        .collect();

    for key in keys {
        let Some(window) = windows.remove(&key) else {
            continue;
        };
        let window_end = window.guest_addr.saturating_add(window.len);
        let start = window.guest_addr.max(guest_addr);
        let stop = window_end.min(end);

        if start > window.guest_addr {
            windows.insert(
                window.guest_addr,
                WindowMapping {
                    guest_addr: window.guest_addr,
                    host_addr: window.host_addr,
                    len: start - window.guest_addr,
                    backing: window.backing.clone(),
                },
            );
        }
        if stop < window_end {
            windows.insert(
                stop,
                WindowMapping {
                    guest_addr: stop,
                    host_addr: window.host_addr + (stop - window.guest_addr),
                    len: window_end - stop,
                    backing: window.backing.clone(),
                },
            );
        }
        // `window.backing` drops here, releasing the host mapping once the last
        // slot referencing it is gone.
    }
    Ok(())
}

/// Ask the VMM worker to install the stage-2 mapping at `guest_addr`.
#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn request_mapping(
    sender: &Sender<WorkerMessage>,
    host_addr: u64,
    guest_addr: u64,
    len: u64,
    writable: bool,
) -> io::Result<()> {
    let (reply_tx, reply_rx) = unbounded();
    sender
        .send(WorkerMessage::DaxAddMapping(
            reply_tx, host_addr, guest_addr, len, writable,
        ))
        .map_err(|_| eio())?;
    if reply_rx.recv().unwrap_or(false) {
        Ok(())
    } else {
        Err(einval())
    }
}

/// Ask the VMM worker to remove the stage-2 mapping at `guest_addr`.
#[cfg(any(windows, target_os = "macos"))]
pub(crate) fn request_unmapping(
    sender: &Sender<WorkerMessage>,
    guest_addr: u64,
    len: u64,
) -> io::Result<()> {
    let (reply_tx, reply_rx) = unbounded();
    sender
        .send(WorkerMessage::GpuRemoveMapping(reply_tx, guest_addr, len))
        .map_err(|_| eio())?;
    if reply_rx.recv().unwrap_or(false) {
        Ok(())
    } else {
        Err(einval())
    }
}

/// Create an `io::Error` with Linux `EIO`.
#[cfg(any(windows, target_os = "macos"))]
fn eio() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EIO)
}

/// Create an `io::Error` with Linux `EINVAL`.
fn einval() -> io::Error {
    io::Error::from_raw_os_error(LINUX_EINVAL)
}
