//! Shared state between the NetWorker thread, smoltcp poll thread, and tokio
//! proxy tasks.
//!
//! All inter-thread communication flows through [`SharedState`], which holds
//! lock-free frame queues and cross-platform [`WakePipe`] notifications.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use crossbeam_queue::ArrayQueue;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default frame queue capacity. Matches libkrun's virtio queue size.
pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Cross-platform wake notification built on `pipe()`.
///
/// Works on both Linux and macOS (unlike `eventfd` which is Linux-only).
/// The write end signals, the read end is pollable via `epoll`/`kqueue`/`poll`.
pub struct WakePipe {
    read_fd: OwnedFd,
    write_fd: OwnedFd,
}

/// All shared state between the three threads:
///
/// - **NetWorker** (libkrun) — pushes guest frames to `tx_ring`, pops
///   response frames from `rx_ring`.
/// - **smoltcp poll thread** — pops from `tx_ring`, processes through smoltcp,
///   pushes responses to `rx_ring`.
/// - **tokio proxy tasks** — relay data between smoltcp sockets and real
///   network connections.
///
/// Queue naming follows the **guest's perspective** (matching libkrun's
/// convention): `tx_ring` = "transmit from guest", `rx_ring` = "receive at
/// guest".
pub struct SharedState {
    /// Frames from guest → smoltcp (NetWorker writes, smoltcp reads).
    pub tx_ring: ArrayQueue<Vec<u8>>,

    /// Frames from smoltcp → guest (smoltcp writes, NetWorker reads).
    pub rx_ring: ArrayQueue<Vec<u8>>,

    /// Wakes NetWorker: "rx_ring has frames for the guest."
    /// Written by `SmoltcpDevice::transmit()`. Read end polled by NetWorker's
    /// epoll loop.
    pub rx_wake: WakePipe,

    /// Wakes smoltcp poll thread: "tx_ring has frames from the guest."
    /// Written by `SmoltcpBackend::write_frame()`. Read end polled by the
    /// poll loop.
    pub tx_wake: WakePipe,

    /// Wakes smoltcp poll thread: "proxy task has data to write to a smoltcp
    /// socket." Written by proxy tasks via channels. Read end polled by the
    /// poll loop.
    pub proxy_wake: WakePipe,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Default for WakePipe {
    fn default() -> Self {
        Self::new()
    }
}

impl WakePipe {
    /// Create a new wake pipe.
    ///
    /// Both ends are set to non-blocking and close-on-exec.
    pub fn new() -> Self {
        let mut fds = [0i32; 2];

        // SAFETY: pipe() is a standard POSIX call. We check the return value
        // and immediately wrap the raw fds in OwnedFd for RAII cleanup.
        let ret = unsafe { libc::pipe(fds.as_mut_ptr()) };
        assert!(
            ret == 0,
            "pipe() failed: {}",
            std::io::Error::last_os_error()
        );

        // Set non-blocking and close-on-exec on both ends.
        // SAFETY: fds are valid open file descriptors from the pipe() call above.
        unsafe {
            set_nonblock_cloexec(fds[0]);
            set_nonblock_cloexec(fds[1]);
        }

        Self {
            // SAFETY: fds are valid and not owned by anything else yet.
            read_fd: unsafe { OwnedFd::from_raw_fd(fds[0]) },
            write_fd: unsafe { OwnedFd::from_raw_fd(fds[1]) },
        }
    }

    /// Signal the reader. Safe to call from any thread, multiple times.
    ///
    /// Writes a single byte. If the pipe buffer is full the write is silently
    /// dropped — the reader will still wake because there are unread bytes.
    pub fn wake(&self) {
        // SAFETY: write_fd is a valid, non-blocking file descriptor.
        // Writing 1 byte to a pipe is atomic on all POSIX systems.
        unsafe {
            libc::write(self.write_fd.as_raw_fd(), [1u8].as_ptr().cast(), 1);
        }
    }

    /// Drain all pending wake signals. Call after processing to reset the
    /// pipe for the next edge-triggered notification.
    pub fn drain(&self) {
        let mut buf = [0u8; 64];
        loop {
            // SAFETY: read_fd is a valid, non-blocking file descriptor.
            let n =
                unsafe { libc::read(self.read_fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n <= 0 {
                break;
            }
        }
    }

    /// File descriptor for `epoll`/`kqueue`/`poll(2)` registration.
    ///
    /// Becomes readable when [`wake()`](Self::wake) has been called.
    pub fn as_raw_fd(&self) -> RawFd {
        self.read_fd.as_raw_fd()
    }
}

impl SharedState {
    /// Create shared state with the given queue capacity.
    pub fn new(queue_capacity: usize) -> Self {
        Self {
            tx_ring: ArrayQueue::new(queue_capacity),
            rx_ring: ArrayQueue::new(queue_capacity),
            rx_wake: WakePipe::new(),
            tx_wake: WakePipe::new(),
            proxy_wake: WakePipe::new(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Set `O_NONBLOCK` and `FD_CLOEXEC` on a file descriptor.
///
/// # Safety
///
/// `fd` must be a valid, open file descriptor.
unsafe fn set_nonblock_cloexec(fd: RawFd) {
    unsafe {
        // Set non-blocking.
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);

        // Set close-on-exec.
        let flags = libc::fcntl(fd, libc::F_GETFD);
        libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: wake/drain cycle doesn't panic or block, and the
    /// pipe is reusable after draining.
    #[test]
    fn wake_pipe_wake_and_drain() {
        let pipe = WakePipe::new();
        // Initially no data — drain is a no-op.
        pipe.drain();

        // Wake then drain.
        pipe.wake();
        pipe.wake();
        pipe.drain();

        // After drain, another wake should work.
        pipe.wake();
        pipe.drain();
    }

    #[test]
    fn wake_pipe_fd_is_valid() {
        let pipe = WakePipe::new();
        let fd = pipe.as_raw_fd();
        assert!(fd >= 0);
    }

    #[test]
    fn shared_state_queue_push_pop() {
        let state = SharedState::new(4);

        // Push frames to tx_ring.
        state.tx_ring.push(vec![1, 2, 3]).unwrap();
        state.tx_ring.push(vec![4, 5, 6]).unwrap();

        // Pop in FIFO order.
        assert_eq!(state.tx_ring.pop(), Some(vec![1, 2, 3]));
        assert_eq!(state.tx_ring.pop(), Some(vec![4, 5, 6]));
        assert_eq!(state.tx_ring.pop(), None);
    }

    #[test]
    fn shared_state_queue_full() {
        let state = SharedState::new(2);

        state.rx_ring.push(vec![1]).unwrap();
        state.rx_ring.push(vec![2]).unwrap();
        // Queue is full — push returns the frame back.
        assert!(state.rx_ring.push(vec![3]).is_err());
    }

    #[test]
    fn wake_pipe_nonblocking_read() {
        let pipe = WakePipe::new();
        // Reading from an empty non-blocking pipe should not block.
        // drain() handles this by checking n <= 0.
        pipe.drain();
    }
}
