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
        let mut ethernet_frame = self.shared.take_frame_buffer(buf.len() - hdr_len);
        ethernet_frame.copy_from_slice(&buf[hdr_len..]);
        let frame_len = ethernet_frame.len();

        if let Err(ethernet_frame) = self.shared.tx_ring.push(ethernet_frame) {
            self.shared.recycle_frame_buffer(ethernet_frame);
            // This backend exposes a wake pipe to libkrun, not a real writable
            // socket. Returning NothingWritten would make the virtio worker
            // undo the TX pop and wait for write readiness that cannot signal
            // tx_ring capacity. Treat overflow like a lossy NIC queue instead:
            // drop the frame and let upper layers retransmit if needed.
            tracing::debug!("dropping guest network frame because tx_ring is full");
            return Ok(());
        }

        self.shared.add_tx_bytes(frame_len);
        self.shared.notify_tx();
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
            self.shared.recycle_frame_buffer(frame);
            return Err(ReadError::NothingRead);
        }

        // Prepend zeroed virtio-net header.
        buf[..VIRTIO_NET_HDR_LEN].fill(0);
        buf[VIRTIO_NET_HDR_LEN..total_len].copy_from_slice(&frame);
        self.shared.recycle_frame_buffer(frame);

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

    #[test]
    fn write_frame_enqueues_guest_frame_and_wakes_poll_loop() {
        let shared = Arc::new(SharedState::new(1));
        let mut backend = SmoltcpBackend::new(shared.clone());
        let mut buf = vec![0u8; VIRTIO_NET_HDR_LEN + 3];
        buf[VIRTIO_NET_HDR_LEN..].copy_from_slice(&[0xaa, 0xbb, 0xcc]);

        backend
            .write_frame(VIRTIO_NET_HDR_LEN, &mut buf)
            .expect("accepted frame should be queued");

        assert_eq!(shared.tx_bytes(), 3);
        assert!(fd_is_readable(shared.tx_wake.as_raw_fd()));
        assert_eq!(shared.tx_ring.pop(), Some(vec![0xaa, 0xbb, 0xcc]));
    }

    #[test]
    fn write_frame_drops_guest_frame_when_tx_ring_is_full() {
        let shared = Arc::new(SharedState::new(1));
        shared.tx_ring.push(vec![0x11]).unwrap();
        let mut backend = SmoltcpBackend::new(shared.clone());
        let mut buf = vec![0u8; VIRTIO_NET_HDR_LEN + 2];
        buf[VIRTIO_NET_HDR_LEN..].copy_from_slice(&[0xaa, 0xbb]);

        backend
            .write_frame(VIRTIO_NET_HDR_LEN, &mut buf)
            .expect("overflow should not stall the virtio TX queue");

        assert_eq!(shared.tx_bytes(), 0);
        assert_eq!(shared.tx_ring.pop(), Some(vec![0x11]));
        assert_eq!(shared.tx_ring.pop(), None);
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
