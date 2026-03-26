//! Shared state between the NetWorker thread, smoltcp poll thread, and tokio
//! proxy tasks.
//!
//! All inter-thread communication flows through [`SharedState`], which holds
//! lock-free frame queues and cross-platform [`WakePipe`] notifications.

use crossbeam_queue::ArrayQueue;
pub use microsandbox_utils::wake_pipe::WakePipe;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Default frame queue capacity. Matches libkrun's virtio queue size.
pub const DEFAULT_QUEUE_CAPACITY: usize = 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

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
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

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
}
