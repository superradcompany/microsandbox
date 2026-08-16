//! In-process console port backend for agent communication.
//!
//! Replaces the socketpair-based agent channel with lock-free ring buffers,
//! following the same pattern as the smoltcp [`SharedState`] in the network
//! crate. Data flows via `memcpy` (no syscalls on the data path); signaling
//! uses a [`WakePipe`] (1-byte pipe write per batch).
//!
//! [`SharedState`]: microsandbox_network::shared::SharedState

#[cfg(windows)]
use std::ffi::OsString;
#[cfg(unix)]
use std::io;
#[cfg(unix)]
use std::os::fd::RawFd;
use std::sync::Arc;
#[cfg(unix)]
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::{Buf, Bytes};
use crossbeam_queue::ArrayQueue;
use microsandbox_utils::wake_pipe::WakePipe;
#[cfg(unix)]
use msb_krun::ConsolePortBackend;
#[cfg(windows)]
use tokio::io::{AsyncReadExt, AsyncWriteExt};
#[cfg(windows)]
use tokio::net::windows::named_pipe::{NamedPipeServer, PipeMode, ServerOptions};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum bytes admitted in either console direction.
const DEFAULT_QUEUE_BYTE_CAPACITY: usize = 32 * 1024 * 1024;

/// Maximum number of fragments in a console direction.
const MAX_QUEUE_ENTRIES: usize = 8192;

/// Estimated fragment size used to derive an entry bound from a byte budget.
const QUEUE_ENTRY_GRANULE: usize = 4096;

#[cfg(windows)]
const NAMED_PIPE_BRIDGE_BUFFER_SIZE: usize = 8192;

#[cfg(windows)]
const NAMED_PIPE_BRIDGE_WAIT_TIMEOUT: Duration = Duration::from_secs(60);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A lock-free fragment queue with an aggregate byte limit.
pub struct ByteQueue {
    entries: ArrayQueue<QueuedBytes>,
    queued_bytes: Arc<AtomicUsize>,
    high_water_bytes: AtomicUsize,
    full_events: AtomicU64,
    byte_capacity: usize,
}

/// One queue fragment whose charge follows unread bytes after it is popped.
pub struct QueuedBytes {
    bytes: Bytes,
    charge: ByteCharge,
}

/// Releases byte capacity incrementally as a consumer advances its fragment cursor.
struct ByteCharge {
    queued_bytes: Arc<AtomicUsize>,
    remaining: usize,
}

/// Point-in-time observability for one console byte queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteQueueSnapshot {
    /// Payload bytes currently retained.
    pub queued_bytes: usize,

    /// Largest observed retained-byte count.
    pub high_water_bytes: usize,

    /// Push attempts rejected by byte or entry capacity.
    pub full_events: u64,

    /// Configured aggregate payload limit.
    pub capacity: usize,
}

/// Shared state between the console port backend (libkrun threads) and the
/// agent relay (tokio background tasks).
///
/// Queue naming follows the **guest's perspective**: `tx_ring` = "bytes
/// transmitted by the guest agent", `rx_ring` = "bytes received by the guest
/// agent".
pub struct ConsoleSharedState {
    /// Guest → Host: console TX thread pushes byte chunks, relay pops them.
    pub tx_ring: ByteQueue,

    /// Host → Guest: relay pushes byte chunks, console RX thread pops them.
    pub rx_ring: ByteQueue,

    /// Wakes the relay: "tx_ring has data from the guest."
    pub tx_wake: WakePipe,

    /// Wakes the console RX thread: "rx_ring has data for the guest."
    pub rx_wake: WakePipe,

    /// Wakes a blocked guest→host producer after the relay frees `tx_ring` capacity.
    pub tx_capacity_wake: WakePipe,

    /// Wakes a blocked host→guest producer after libkrun frees `rx_ring` capacity.
    pub rx_capacity_wake: WakePipe,

    /// Stops blocked console producers during teardown.
    closed: AtomicBool,
}

/// Console port backend backed by [`ConsoleSharedState`].
///
/// Passed to `VmBuilder::console(|c| c.custom("agent", backend))`. The
/// libkrun console device calls [`read`](ConsolePortBackend::read) from the
/// RX thread and [`write`](ConsolePortBackend::write) from the TX thread —
/// both via `&self`, so all operations are lock-free through the underlying
/// `ArrayQueue`.
pub struct AgentConsoleBackend {
    #[cfg(unix)]
    shared: Arc<ConsoleSharedState>,
    /// Leftover bytes from a previous read that didn't fit in the caller's
    /// buffer. Protected by a Mutex because `read(&self)` takes `&self`.
    /// Only the RX thread calls `read`, so contention is zero.
    #[cfg(unix)]
    pending: Mutex<Option<QueuedBytes>>,

    /// Size of the guest descriptor that most recently found `tx_ring` full.
    #[cfg(unix)]
    blocked_write_len: AtomicUsize,
}

#[cfg(windows)]
pub(crate) struct AgentConsolePipeBridge {
    task: tokio::task::JoinHandle<()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ConsoleSharedState {
    /// Create shared state with the default queue capacity.
    pub fn new() -> Self {
        Self::with_capacity(DEFAULT_QUEUE_BYTE_CAPACITY)
    }

    /// Create shared state with a specific byte capacity in each direction.
    pub fn with_capacity(byte_capacity: usize) -> Self {
        Self {
            tx_ring: ByteQueue::new(byte_capacity),
            rx_ring: ByteQueue::new(byte_capacity),
            tx_wake: WakePipe::new(),
            rx_wake: WakePipe::new(),
            tx_capacity_wake: WakePipe::new(),
            rx_capacity_wake: WakePipe::new(),
            closed: AtomicBool::new(false),
        }
    }

    /// Unblock console producers because the runtime is shutting down.
    pub fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.tx_capacity_wake.wake();
        self.rx_capacity_wake.wake();
        self.tx_wake.wake();
        self.rx_wake.wake();
    }

    /// Return whether no more console data should be admitted.
    pub fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }
}

impl ByteQueue {
    /// Create a queue with an exact aggregate byte limit.
    pub fn new(byte_capacity: usize) -> Self {
        let entry_capacity = byte_capacity
            .div_ceil(QUEUE_ENTRY_GRANULE)
            .clamp(1, MAX_QUEUE_ENTRIES);
        Self {
            entries: ArrayQueue::new(entry_capacity),
            queued_bytes: Arc::new(AtomicUsize::new(0)),
            high_water_bytes: AtomicUsize::new(0),
            full_events: AtomicU64::new(0),
            byte_capacity,
        }
    }

    /// Push one owned byte region if both byte and entry capacity permit it.
    pub fn push(&self, bytes: impl Into<Bytes>) -> Result<(), Bytes> {
        let bytes = bytes.into();
        let len = bytes.len();

        let reserved_bytes = loop {
            let queued = self.queued_bytes.load(Ordering::Acquire);
            let Some(next) = queued.checked_add(len) else {
                self.full_events.fetch_add(1, Ordering::Relaxed);
                return Err(bytes);
            };
            if next > self.byte_capacity {
                self.full_events.fetch_add(1, Ordering::Relaxed);
                return Err(bytes);
            }
            if self
                .queued_bytes
                .compare_exchange_weak(queued, next, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                break next;
            }
        };
        self.high_water_bytes
            .fetch_max(reserved_bytes, Ordering::Relaxed);

        let queued = QueuedBytes {
            bytes,
            charge: ByteCharge {
                queued_bytes: Arc::clone(&self.queued_bytes),
                remaining: len,
            },
        };
        if let Err(queued) = self.entries.push(queued) {
            self.full_events.fetch_add(1, Ordering::Relaxed);
            return Err(queued.into_unqueued());
        }
        Ok(())
    }

    /// Pop one fragment. Its unread-byte charge follows the returned owner.
    pub fn pop(&self) -> Option<QueuedBytes> {
        self.entries.pop()
    }

    /// Return whether a fragment of `len` bytes can be admitted now.
    pub fn can_fit(&self, len: usize) -> bool {
        self.queued_bytes
            .load(Ordering::Acquire)
            .checked_add(len)
            .is_some_and(|next| next <= self.byte_capacity)
            && !self.entries.is_full()
    }

    /// Current queued payload bytes.
    pub fn queued_bytes(&self) -> usize {
        self.queued_bytes.load(Ordering::Acquire)
    }

    /// Configured aggregate byte capacity.
    pub fn capacity(&self) -> usize {
        self.byte_capacity
    }

    /// Capture bounded queue occupancy and saturation counters.
    pub fn snapshot(&self) -> ByteQueueSnapshot {
        ByteQueueSnapshot {
            queued_bytes: self.queued_bytes(),
            high_water_bytes: self.high_water_bytes.load(Ordering::Acquire),
            full_events: self.full_events.load(Ordering::Relaxed),
            capacity: self.capacity(),
        }
    }
}

impl QueuedBytes {
    /// Remaining unread bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Return whether the fragment cursor reached its end.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Copy and release up to `out.len()` bytes from the front of the fragment.
    #[cfg(unix)]
    fn copy_prefix_into(&mut self, out: &mut [u8]) -> usize {
        let len = self.len().min(out.len());
        out[..len].copy_from_slice(&self.bytes[..len]);
        self.bytes.advance(len);
        self.charge.release(len);
        len
    }

    /// Remove a failed queue admission while returning the caller's original bytes.
    fn into_unqueued(mut self) -> Bytes {
        let remaining = self.charge.remaining;
        self.charge.release(remaining);
        std::mem::take(&mut self.bytes)
    }
}

impl AsRef<[u8]> for QueuedBytes {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl std::ops::Deref for QueuedBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

impl ByteCharge {
    fn release(&mut self, bytes: usize) {
        debug_assert!(bytes <= self.remaining);
        if bytes == 0 {
            return;
        }
        self.remaining -= bytes;
        self.queued_bytes.fetch_sub(bytes, Ordering::AcqRel);
    }
}

impl Drop for ByteCharge {
    fn drop(&mut self) {
        self.release(self.remaining);
    }
}

impl AgentConsoleBackend {
    /// Create a new backend from shared state.
    pub fn new(shared: Arc<ConsoleSharedState>) -> Self {
        #[cfg(unix)]
        {
            Self {
                shared,
                pending: Mutex::new(None),
                blocked_write_len: AtomicUsize::new(0),
            }
        }

        #[cfg(windows)]
        {
            let _ = shared;
            Self {}
        }
    }
}

#[cfg(windows)]
impl AgentConsolePipeBridge {
    pub(crate) fn spawn(
        pipe_name: impl Into<OsString>,
        shared: Arc<ConsoleSharedState>,
        handle: &tokio::runtime::Handle,
    ) -> std::io::Result<Self> {
        let pipe_name = pipe_name.into();
        let server = {
            let _guard = handle.enter();
            ServerOptions::new()
                .first_pipe_instance(true)
                .pipe_mode(PipeMode::Byte)
                .create(&pipe_name)?
        };

        let task = handle.spawn(async move {
            if let Err(error) = run_agent_console_pipe_bridge(server, shared).await {
                tracing::warn!(error = %error, "agent console named-pipe bridge stopped");
            }
        });

        Ok(Self { task })
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

#[cfg(windows)]
impl Drop for AgentConsolePipeBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}

#[cfg(unix)]
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
        if let Some(chunk) = pending.as_mut() {
            let n = chunk.copy_prefix_into(buf);
            if chunk.is_empty() {
                pending.take();
            }
            self.shared.rx_capacity_wake.wake();
            return Ok(n);
        }

        // Pop a new chunk from the ring.
        match self.shared.rx_ring.pop() {
            Some(mut chunk) => {
                let n = chunk.copy_prefix_into(buf);
                if !chunk.is_empty() {
                    *pending = Some(chunk);
                }
                self.shared.rx_capacity_wake.wake();
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
        if self.shared.is_closed() {
            return Err(io::ErrorKind::BrokenPipe.into());
        }

        self.shared
            .tx_ring
            .push(Bytes::copy_from_slice(buf))
            .map_err(|_| {
                self.blocked_write_len.store(buf.len(), Ordering::Release);
                io::Error::from(io::ErrorKind::WouldBlock)
            })?;
        self.blocked_write_len.store(0, Ordering::Release);
        self.shared.tx_wake.wake();
        Ok(buf.len())
    }

    /// Returns the read end of `rx_wake` for `poll()`-based blocking in the
    /// console RX thread.
    fn read_wake_fd(&self) -> RawFd {
        self.shared.rx_wake.as_raw_fd()
    }

    fn wait_until_writable(&self) {
        loop {
            let blocked_len = self.blocked_write_len.load(Ordering::Acquire).max(1);
            if self.shared.is_closed() || self.shared.tx_ring.can_fit(blocked_len) {
                return;
            }

            // Drain then re-check before sleeping so a pop racing this transition cannot be lost.
            self.shared.tx_capacity_wake.drain();
            if self.shared.is_closed() || self.shared.tx_ring.can_fit(blocked_len) {
                return;
            }
            let _ = self
                .shared
                .tx_capacity_wake
                .wait_timeout(Duration::from_secs(60));
        }
    }
}

#[cfg(windows)]
async fn run_agent_console_pipe_bridge(
    server: NamedPipeServer,
    shared: Arc<ConsoleSharedState>,
) -> std::io::Result<()> {
    server.connect().await?;
    tracing::debug!("agent console named-pipe bridge connected");

    let (reader, writer) = tokio::io::split(server);
    let reader_shared = Arc::clone(&shared);
    let mut reader_task =
        tokio::spawn(async move { bridge_guest_to_host(reader, reader_shared).await });
    let mut writer_task = tokio::spawn(async move { bridge_host_to_guest(writer, shared).await });

    tokio::select! {
        result = &mut reader_task => {
            writer_task.abort();
            result.map_err(std::io::Error::other)?
        }
        result = &mut writer_task => {
            reader_task.abort();
            result.map_err(std::io::Error::other)?
        }
    }
}

#[cfg(windows)]
async fn bridge_guest_to_host(
    mut reader: tokio::io::ReadHalf<NamedPipeServer>,
    shared: Arc<ConsoleSharedState>,
) -> std::io::Result<()> {
    let mut buf = vec![0u8; NAMED_PIPE_BRIDGE_BUFFER_SIZE];

    loop {
        if shared.is_closed() {
            return Ok(());
        }
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            return Ok(());
        }

        push_queue_lossless(Arc::clone(&shared), Bytes::copy_from_slice(&buf[..n])).await;
        shared.tx_wake.wake();
    }
}

#[cfg(windows)]
async fn bridge_host_to_guest(
    mut writer: tokio::io::WriteHalf<NamedPipeServer>,
    shared: Arc<ConsoleSharedState>,
) -> std::io::Result<()> {
    loop {
        if shared.is_closed() {
            return Ok(());
        }
        let mut wrote = false;
        while let Some(chunk) = shared.rx_ring.pop() {
            writer.write_all(&chunk).await?;
            drop(chunk);
            shared.rx_capacity_wake.wake();
            wrote = true;
        }

        if wrote {
            writer.flush().await?;
            continue;
        }

        shared.rx_wake.drain();
        if shared.rx_ring.queued_bytes() != 0 {
            continue;
        }
        let shared_for_wait = Arc::clone(&shared);
        let _ = tokio::task::spawn_blocking(move || {
            shared_for_wait
                .rx_wake
                .wait_timeout(NAMED_PIPE_BRIDGE_WAIT_TIMEOUT)
        })
        .await;
    }
}

#[cfg(windows)]
async fn push_queue_lossless(shared: Arc<ConsoleSharedState>, mut chunk: Bytes) {
    loop {
        match shared.tx_ring.push(chunk) {
            Ok(()) => return,
            Err(returned) => {
                chunk = returned;
                if shared.is_closed() {
                    return;
                }

                // Drain then re-check before sleeping so a pop racing this transition cannot be lost.
                shared.tx_capacity_wake.drain();
                if shared.tx_ring.can_fit(chunk.len()) {
                    continue;
                }
                let shared_for_wait = Arc::clone(&shared);
                let _ = tokio::task::spawn_blocking(move || {
                    shared_for_wait
                        .tx_capacity_wake
                        .wait_timeout(NAMED_PIPE_BRIDGE_WAIT_TIMEOUT)
                })
                .await;
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(unix)]
    #[test]
    fn backend_write_and_read_roundtrip() {
        let shared = Arc::new(ConsoleSharedState::new());
        let backend = AgentConsoleBackend::new(Arc::clone(&shared));

        // Guest writes "hello".
        assert_eq!(backend.write(b"hello").unwrap(), 5);

        // Relay pops from tx_ring.
        let chunk = shared.tx_ring.pop().unwrap();
        assert_eq!(chunk.as_ref(), b"hello");

        // Relay pushes response to rx_ring.
        shared.rx_ring.push(b"world".to_vec()).unwrap();
        shared.rx_wake.wake();

        // Guest reads.
        let mut buf = [0u8; 16];
        let n = backend.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"world");
    }

    #[cfg(unix)]
    #[test]
    fn backend_read_empty_returns_would_block() {
        let shared = Arc::new(ConsoleSharedState::new());
        let backend = AgentConsoleBackend::new(shared);

        let mut buf = [0u8; 16];
        let err = backend.read(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);
    }

    #[cfg(unix)]
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
    fn byte_queue_releases_exact_capacity_on_pop() {
        let queue = ByteQueue::new(8);
        queue.push(Bytes::from_static(b"12345678")).unwrap();
        assert_eq!(queue.queued_bytes(), 8);
        assert!(queue.push(Bytes::from_static(b"x")).is_err());

        assert_eq!(queue.pop().unwrap().as_ref(), b"12345678");
        assert_eq!(queue.queued_bytes(), 0);
        queue.push(Bytes::from_static(b"x")).unwrap();
        assert_eq!(
            queue.snapshot(),
            ByteQueueSnapshot {
                queued_bytes: 1,
                high_water_bytes: 8,
                full_events: 1,
                capacity: 8,
            }
        );
    }

    #[cfg(unix)]
    #[test]
    fn backend_capacity_wait_sleeps_until_consumer_pops() {
        let shared = Arc::new(ConsoleSharedState::with_capacity(1));
        let backend = AgentConsoleBackend::new(Arc::clone(&shared));
        backend.write(b"a").unwrap();
        assert_eq!(
            backend.write(b"b").unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        let (done_tx, done_rx) = std::sync::mpsc::channel();
        let waiter = std::thread::spawn(move || {
            backend.wait_until_writable();
            done_tx.send(()).unwrap();
        });
        assert!(
            done_rx.recv_timeout(Duration::from_millis(25)).is_err(),
            "waiter returned while the byte queue was still full"
        );

        shared.tx_ring.pop().unwrap();
        shared.tx_capacity_wake.wake();
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        waiter.join().unwrap();
    }

    #[cfg(unix)]
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

    #[cfg(windows)]
    #[tokio::test]
    async fn named_pipe_bridge_exchanges_agent_bytes() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::windows::named_pipe::ClientOptions;

        let pipe_name = unique_named_pipe("console-bridge");
        let shared = Arc::new(ConsoleSharedState::new());
        let _bridge = AgentConsolePipeBridge::spawn(
            &pipe_name,
            Arc::clone(&shared),
            &tokio::runtime::Handle::current(),
        )
        .unwrap();
        let mut client = ClientOptions::new().open(&pipe_name).unwrap();

        client.write_all(b"guest-ready").await.unwrap();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if let Some(bytes) = shared.tx_ring.pop() {
                    assert_eq!(bytes.as_ref(), b"guest-ready");
                    return;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();

        shared.rx_ring.push(b"host-ack".to_vec()).unwrap();
        shared.rx_wake.wake();

        let mut buf = [0u8; 8];
        tokio::time::timeout(Duration::from_secs(1), client.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"host-ack");
    }

    #[cfg(windows)]
    fn unique_named_pipe(name: &str) -> String {
        let id =
            std::sync::atomic::AtomicU64::new(0).fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        format!(r"\\.\pipe\msb-runtime-{name}-{}-{id}", std::process::id())
    }
}
