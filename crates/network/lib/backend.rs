//! `SmoltcpBackend` — libkrun [`NetBackend`] implementation that bridges the
//! NetWorker thread to the smoltcp poll thread via lock-free queues.
//!
//! The NetWorker calls [`write_frame()`](NetBackend::write_frame) when the
//! guest sends a frame and [`read_frame()`](NetBackend::read_frame) to deliver
//! frames back to the guest. Frames flow through [`SharedState`]'s
//! `tx_ring`/`rx_ring` queues with [`WakePipe`](crate::shared::WakePipe)
//! notifications. Unix libkrun registers [`raw_socket_fd`](NetBackend::raw_socket_fd)
//! in edge-triggered mode, while Windows libkrun waits on an event source. Reads
//! must drain the wake primitive before returning.

#[cfg(unix)]
use std::os::fd::RawFd;
use std::sync::Arc;

use msb_krun::backends::net::{NetBackend, ReadError, WriteError};
#[cfg(windows)]
use msb_krun_utils::event::{EventSource, EventToken};

use crate::shared::SharedState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Size of the virtio-net header (`virtio_net_hdr_v1`): 12 bytes.
///
/// libkrun's NetWorker prepends this header to every frame buffer. The
/// backend must strip it on TX (guest → smoltcp) and prepend a zeroed
/// header on RX (smoltcp → guest).
const VIRTIO_NET_HDR_LEN: usize = 12;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Network backend that bridges libkrun's NetWorker to smoltcp via lock-free
/// queues.
///
/// - **TX path** (`write_frame`): strips the virtio-net header, pushes the
///   ethernet frame to `tx_ring`, wakes the smoltcp poll thread.
/// - **RX path** (`read_frame`): pops a frame from `rx_ring`, prepends a
///   zeroed virtio-net header for the guest.
/// - **Wake source**: returns `rx_wake`'s pollable fd on Unix or waitable
///   event handle on Windows so the NetWorker can detect new frames.
pub struct SmoltcpBackend {
    shared: Arc<SharedState>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SmoltcpBackend {
    /// Create a new backend connected to the given shared state.
    pub fn new(shared: Arc<SharedState>) -> Self {
        Self { shared }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl NetBackend for SmoltcpBackend {
    /// Guest is sending a frame. Strip the virtio-net header and enqueue
    /// the raw ethernet frame for smoltcp.
    fn write_frame(&mut self, hdr_len: usize, buf: &mut [u8]) -> Result<(), WriteError> {
        let ethernet_frame = buf[hdr_len..].to_vec();
        self.shared.add_tx_bytes(ethernet_frame.len());
        self.shared
            .tx_ring
            .push(ethernet_frame)
            .map_err(|_| WriteError::NothingWritten)?;
        self.shared.tx_wake.wake();
        Ok(())
    }

    /// Deliver a frame from smoltcp to the guest. Prepends a zeroed
    /// virtio-net header.
    fn read_frame(&mut self, buf: &mut [u8]) -> Result<usize, ReadError> {
        self.shared.rx_wake.drain();

        let frame = self.shared.rx_ring.pop().ok_or(ReadError::NothingRead)?;

        let total_len = VIRTIO_NET_HDR_LEN + frame.len();
        if total_len > buf.len() {
            // Frame too large for the buffer — drop it to avoid panicking.
            tracing::debug!(
                frame_len = frame.len(),
                buf_len = buf.len(),
                "dropping oversized frame from rx_ring"
            );
            return Err(ReadError::NothingRead);
        }

        // Prepend zeroed virtio-net header.
        buf[..VIRTIO_NET_HDR_LEN].fill(0);
        buf[VIRTIO_NET_HDR_LEN..total_len].copy_from_slice(&frame);

        Ok(total_len)
    }

    /// No partial writes — queue push is atomic.
    fn has_unfinished_write(&self) -> bool {
        false
    }

    /// No partial writes — nothing to finish.
    fn try_finish_write(&mut self, _hdr_len: usize, _buf: &[u8]) -> Result<(), WriteError> {
        Ok(())
    }

    /// File descriptor for NetWorker's epoll. Becomes readable when
    /// `rx_ring` has frames for the guest (i.e. when smoltcp's
    /// `SmoltcpDevice::transmit()` pushes a frame and wakes `rx_wake`).
    #[cfg(unix)]
    fn raw_socket_fd(&self) -> RawFd {
        self.shared.rx_wake.as_raw_fd()
    }

    /// Waitable event source for NetWorker on Windows.
    #[cfg(windows)]
    fn event_source(&self, token: EventToken) -> EventSource {
        EventSource::waitable_handle(self.shared.rx_wake.as_raw_handle(), token)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn read_frame_drains_rx_wake_pipe() {
        let shared = Arc::new(SharedState::new(4));
        let mut backend = SmoltcpBackend::new(shared.clone());
        let mut buf = [0u8; 64];

        assert!(shared.push_rx_frame_and_wake(vec![0xaa, 0xbb]));
        assert!(fd_is_readable(backend.raw_socket_fd()));

        let n = backend.read_frame(&mut buf).expect("frame should be read");
        assert_eq!(n, VIRTIO_NET_HDR_LEN + 2);
        assert_eq!(&buf[VIRTIO_NET_HDR_LEN..n], &[0xaa, 0xbb]);
        assert!(!fd_is_readable(backend.raw_socket_fd()));

        assert!(shared.push_rx_frame_and_wake(vec![0xcc]));
        assert!(fd_is_readable(backend.raw_socket_fd()));
    }

    fn fd_is_readable(fd: RawFd) -> bool {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };

        // SAFETY: `pfd` points to a valid pollfd for a live file descriptor.
        let ret = unsafe { libc::poll(&mut pfd, 1, 0) };
        assert!(ret >= 0, "poll failed: {}", std::io::Error::last_os_error());

        ret == 1 && pfd.revents & libc::POLLIN != 0
    }
}
