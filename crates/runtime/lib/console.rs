//! In-process console port backend for agent communication.
//!
//! Replaces the socketpair-based agent channel with lock-free ring buffers,
//! following the same pattern as the smoltcp [`SharedState`] in the network
//! crate. Data flows via `memcpy` (no syscalls on the data path); signaling
//! uses a [`WakePipe`] (1-byte pipe write per batch).
//!
//! [`SharedState`]: microsandbox_network::shared::SharedState

use std::collections::VecDeque;
use std::io;
use std::os::fd::RawFd;
use std::sync::{Arc, Mutex};

use crossbeam_queue::ArrayQueue;
use microsandbox_utils::wake_pipe::WakePipe;
use msb_krun::ConsolePortBackend;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default ring buffer capacity (number of byte-chunk entries).
const DEFAULT_QUEUE_CAPACITY: usize = 2048;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Shared state between the console port backend (libkrun threads) and the
/// agent relay (tokio background tasks).
///
/// Queue naming follows the **guest's perspective**: `tx_ring` = "bytes
/// transmitted by the guest agent", `rx_ring` = "bytes received by the guest
/// agent".
pub struct ConsoleSharedState {
    /// Guest → Host: console TX thread pushes byte chunks, relay pops them.
    pub tx_ring: ArrayQueue<Vec<u8>>,

    /// Host → Guest: relay pushes byte chunks, console RX thread pops them.
    pub rx_ring: ArrayQueue<Vec<u8>>,

    /// Wakes the relay: "tx_ring has data from the guest."
    pub tx_wake: WakePipe,

    /// Wakes the console RX thread: "rx_ring has data for the guest."
    pub rx_wake: WakePipe,
}

/// Console port backend backed by [`ConsoleSharedState`].
///
/// Passed to `VmBuilder::console(|c| c.custom("agent", backend))`. The
/// libkrun console device calls [`read`](ConsolePortBackend::read) from the
/// RX thread and [`write`](ConsolePortBackend::write) from the TX thread —
/// both via `&self`, so all operations are lock-free through the underlying
/// `ArrayQueue`.
pub struct AgentConsoleBackend {
    shared: Arc<ConsoleSharedState>,
    /// Leftover bytes from a previous read that didn't fit in the caller's
    /// buffer. Protected by a Mutex because `read(&self)` takes `&self`.
    /// Only the RX thread calls `read`, so contention is zero.
    pending: Mutex<VecDeque<u8>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ConsoleSharedState {
    /// Create shared state with the default queue capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_QUEUE_CAPACITY)
    }

    /// Create shared state with a specific queue capacity.
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            tx_ring: ArrayQueue::new(capacity),
            rx_ring: ArrayQueue::new(capacity),
            tx_wake: WakePipe::new(),
            rx_wake: WakePipe::new(),
        }
    }
}

impl AgentConsoleBackend {
    /// Create a new backend from shared state.
    pub fn new(shared: Arc<ConsoleSharedState>) -> Self {
        Self {
            shared,
            pending: Mutex::new(VecDeque::new()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ConsoleSharedState {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsolePortBackend for AgentConsoleBackend {
    /// Read bytes destined for the guest (host → guest).
    ///
    /// Serves from leftover bytes first, then pops from `rx_ring`. Returns
    /// `WouldBlock` if both are empty. Never truncates — excess bytes are
    /// buffered for the next call.
    fn read(&self, buf: &mut [u8]) -> io::Result<usize> {
        // Reset the wake pipe before checking queues so future host->guest
        // notifications are not lost if the VMM uses edge-triggered polling.
        self.shared.rx_wake.drain();

        let mut pending = self.pending.lock().unwrap();

        // Serve from leftover bytes first (use memcpy via slices).
        if !pending.is_empty() {
            let n = pending.len().min(buf.len());
            let (head, tail) = pending.as_slices();
            let from_head = n.min(head.len());
            buf[..from_head].copy_from_slice(&head[..from_head]);
            if from_head < n {
                let from_tail = n - from_head;
                buf[from_head..n].copy_from_slice(&tail[..from_tail]);
            }
            pending.drain(..n);
            return Ok(n);
        }

        // Pop a new chunk from the ring.
        match self.shared.rx_ring.pop() {
            Some(chunk) => {
                let n = chunk.len().min(buf.len());
                buf[..n].copy_from_slice(&chunk[..n]);
                // Buffer any remainder for subsequent reads.
                if chunk.len() > buf.len() {
                    pending.extend(&chunk[buf.len()..]);
                }
                Ok(n)
            }
            None => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    /// Write bytes from the guest (guest → host).
    ///
    /// Pushes a byte chunk to `tx_ring` and wakes the relay. Returns
    /// `WouldBlock` if the ring is full.
    fn write(&self, buf: &[u8]) -> io::Result<usize> {
        self.shared
            .tx_ring
            .push(buf.to_vec())
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        self.shared.tx_wake.wake();
        Ok(buf.len())
    }

    /// Returns the read end of `rx_wake` for `poll()`-based blocking in the
    /// console RX thread.
    fn read_wake_fd(&self) -> RawFd {
        self.shared.rx_wake.as_raw_fd()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_write_and_read_roundtrip() {
        let shared = Arc::new(ConsoleSharedState::new());
        let backend = AgentConsoleBackend::new(Arc::clone(&shared));

        // Guest writes "hello".
        assert_eq!(backend.write(b"hello").unwrap(), 5);

        // Relay pops from tx_ring.
        let chunk = shared.tx_ring.pop().unwrap();
        assert_eq!(chunk, b"hello");

        // Relay pushes response to rx_ring.
        shared.rx_ring.push(b"world".to_vec()).unwrap();
        shared.rx_wake.wake();

        // Guest reads.
        let mut buf = [0u8; 16];
        let n = backend.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"world");
    }

    #[test]
    fn backend_read_empty_returns_would_block() {
        let shared = Arc::new(ConsoleSharedState::new());
        let backend = AgentConsoleBackend::new(shared);

        let mut buf = [0u8; 16];
        let err = backend.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn backend_write_full_returns_would_block() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(1));
        let backend = AgentConsoleBackend::new(shared);

        // First push succeeds.
        assert!(backend.write(b"a").is_ok());
        // Second push fails — ring is full.
        let err = backend.write(b"b").unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn backend_read_drains_rx_wake_pipe() {
        let shared = Arc::new(ConsoleSharedState::new());
        let backend = AgentConsoleBackend::new(Arc::clone(&shared));

        shared.rx_ring.push(b"ping".to_vec()).unwrap();
        shared.rx_wake.wake();

        let mut pollfd = libc::pollfd {
            fd: backend.read_wake_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
        assert_eq!(ret, 1, "wake pipe should be readable before read()");
        assert_ne!(pollfd.revents & libc::POLLIN, 0);

        let mut buf = [0u8; 8];
        let n = backend.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"ping");

        pollfd.revents = 0;
        let ret = unsafe { libc::poll(&mut pollfd, 1, 0) };
        assert_eq!(ret, 0, "wake pipe should be drained by read()");
    }
}
