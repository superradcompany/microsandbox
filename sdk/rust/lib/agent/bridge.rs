//! FFI-shaped façade around [`AgentClient`].
//!
//! [`AgentBridge`] exposes the raw transport with concrete, monomorphic types
//! suitable for crossing FFI boundaries. Streams identified by `u32` correlation
//! IDs are wrapped in opaque `u64` handles so foreign-language wrappers can
//! reference them without owning a tokio `Receiver`.
//!
//! No generics, no consuming-`self` methods, no callbacks across FFI. Each
//! method takes `&self` and is idempotent where the underlying operation
//! allows. CBOR (de)serialization happens entirely in the caller's language;
//! the bridge only moves bytes.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use microsandbox_protocol::codec::RawFrame;
use tokio::sync::Mutex;
use tokio::sync::Notify;
use tokio::sync::mpsc::Receiver;

use super::{AgentClient, connect_sandbox, connect_sandbox_with_timeout};
use microsandbox_agent_client::{AgentClientError, AgentClientResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Opaque handle identifying an open stream on an [`AgentBridge`].
pub type StreamHandle = u64;

/// FFI-friendly view of a [`RawFrame`]: id, flags, body bytes.
#[derive(Debug, Clone)]
pub struct BridgeFrame {
    /// Correlation ID from the frame header.
    pub id: u32,
    /// Frame flags from the frame header.
    pub flags: u8,
    /// Raw CBOR-encoded body bytes.
    pub body: Vec<u8>,
}

/// Bytes-in/bytes-out wrapper around [`AgentClient`].
///
/// One instance owns one Unix-socket connection to the relay. Multiple
/// concurrent streams are supported; each is identified by an opaque
/// [`StreamHandle`].
pub struct AgentBridge {
    inner: StdMutex<Option<Arc<AgentClient>>>,
    streams: Mutex<HashMap<StreamHandle, Arc<BridgeStream>>>,
    next_handle: AtomicU64,
    closed: AtomicBool,
    closed_notify: Notify,
}

struct BridgeStream {
    rx: Mutex<Receiver<RawFrame>>,
    closed: AtomicBool,
    closed_notify: Notify,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentBridge {
    /// Connect to a sandbox by name (resolves the socket path from SDK config).
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    pub async fn connect_sandbox(name: &str) -> AgentClientResult<Self> {
        let client = connect_sandbox(name).await?;
        Ok(Self::from_client(client))
    }

    /// Connect to a sandbox by name with an explicit handshake timeout.
    ///
    /// Sandbox names are limited to 128 UTF-8 bytes.
    pub async fn connect_sandbox_with_timeout(
        name: &str,
        timeout: Duration,
    ) -> AgentClientResult<Self> {
        let client = connect_sandbox_with_timeout(name, timeout).await?;
        Ok(Self::from_client(client))
    }

    /// Connect to an arbitrary agentd relay socket.
    pub async fn connect_path(path: &str) -> AgentClientResult<Self> {
        let client = AgentClient::connect(path).await?;
        Ok(Self::from_client(client))
    }

    /// Connect to an arbitrary agentd relay socket with an explicit handshake
    /// timeout.
    pub async fn connect_path_with_timeout(
        path: &str,
        timeout: Duration,
    ) -> AgentClientResult<Self> {
        let client = AgentClient::connect_with_timeout(path, timeout).await?;
        Ok(Self::from_client(client))
    }

    fn from_client(client: AgentClient) -> Self {
        Self {
            inner: StdMutex::new(Some(Arc::new(client))),
            streams: Mutex::new(HashMap::new()),
            next_handle: AtomicU64::new(1),
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
        }
    }

    /// One-shot request: send `(flags, body)` and wait for one response frame.
    pub async fn request(&self, flags: u8, body: Vec<u8>) -> AgentClientResult<BridgeFrame> {
        let inner = self.inner()?;
        let closed = self.closed_notify.notified();
        tokio::pin!(closed);
        if self.closed.load(Ordering::Acquire) {
            return Err(AgentClientError::Closed);
        }

        let frame = tokio::select! {
            frame = inner.request_raw(flags, body) => frame?,
            _ = &mut closed => return Err(AgentClientError::Closed),
        };

        Ok(BridgeFrame {
            id: frame.id,
            flags: frame.flags,
            body: frame.body,
        })
    }

    /// Send a follow-up frame on an existing correlation id.
    pub async fn send(&self, id: u32, flags: u8, body: Vec<u8>) -> AgentClientResult<()> {
        let inner = self.inner()?;
        let closed = self.closed_notify.notified();
        tokio::pin!(closed);
        if self.closed.load(Ordering::Acquire) {
            return Err(AgentClientError::Closed);
        }

        tokio::select! {
            result = inner.send_raw(id, flags, &body) => result,
            _ = &mut closed => Err(AgentClientError::Closed),
        }
    }

    /// Open a streaming session. Returns the protocol correlation id (for
    /// follow-up sends) and an opaque stream handle (for [`Self::stream_next`]
    /// and [`Self::stream_close`]).
    pub async fn stream_open(
        &self,
        flags: u8,
        body: Vec<u8>,
    ) -> AgentClientResult<(u32, StreamHandle)> {
        let inner = self.inner()?;
        let closed = self.closed_notify.notified();
        tokio::pin!(closed);
        if self.closed.load(Ordering::Acquire) {
            return Err(AgentClientError::Closed);
        }

        let (corr_id, rx) = tokio::select! {
            stream = inner.stream_raw(flags, body) => stream?,
            _ = &mut closed => return Err(AgentClientError::Closed),
        };

        let handle = self.next_handle.fetch_add(1, Ordering::Relaxed);
        let mut streams = self.streams.lock().await;
        if self.closed.load(Ordering::Acquire) {
            return Err(AgentClientError::Closed);
        }
        streams.insert(
            handle,
            Arc::new(BridgeStream {
                rx: Mutex::new(rx),
                closed: AtomicBool::new(false),
                closed_notify: Notify::new(),
            }),
        );
        Ok((corr_id, handle))
    }

    /// Pull the next frame from a stream. Returns `None` when the stream has
    /// ended (terminal frame already delivered, or stream closed/dropped).
    pub async fn stream_next(
        &self,
        handle: StreamHandle,
    ) -> AgentClientResult<Option<BridgeFrame>> {
        let closed = self.closed_notify.notified();
        tokio::pin!(closed);
        if self.closed.load(Ordering::Acquire) {
            return Err(AgentClientError::Closed);
        }

        let stream = match self.streams.lock().await.get(&handle).cloned() {
            Some(stream) => stream,
            None => return Ok(None),
        };

        let stream_closed = stream.closed_notify.notified();
        tokio::pin!(stream_closed);
        if self.closed.load(Ordering::Acquire) {
            return Err(AgentClientError::Closed);
        }
        if stream.closed.load(Ordering::Acquire) {
            return Ok(None);
        }

        let mut rx = stream.rx.lock().await;
        let frame = tokio::select! {
            frame = rx.recv() => frame,
            _ = &mut closed => return Err(AgentClientError::Closed),
            _ = &mut stream_closed => return Ok(None),
        };

        match frame {
            Some(f) => {
                let terminal = (f.flags & microsandbox_protocol::message::FLAG_TERMINAL) != 0;
                if terminal {
                    self.streams.lock().await.remove(&handle);
                }
                Ok(Some(BridgeFrame {
                    id: f.id,
                    flags: f.flags,
                    body: f.body,
                }))
            }
            None => Ok(None),
        }
    }

    /// Close a stream and drop its handle. Idempotent.
    pub async fn stream_close(&self, handle: StreamHandle) {
        if let Some(stream) = self.streams.lock().await.remove(&handle) {
            stream.closed.store(true, Ordering::Release);
            stream.closed_notify.notify_waiters();
        }
    }

    /// Cached handshake `core.ready` frame body bytes (CBOR).
    pub fn ready_bytes(&self) -> AgentClientResult<Vec<u8>> {
        Ok(self.inner()?.ready_bytes().to_vec())
    }

    /// Close the connection. Idempotent. After close, every operation except
    /// another close returns [`AgentClientError::Closed`].
    pub async fn close(&self) {
        if self.closed.swap(true, Ordering::AcqRel) {
            return;
        }

        self.closed_notify.notify_waiters();
        let streams = self
            .streams
            .lock()
            .await
            .drain()
            .map(|(_, stream)| stream)
            .collect::<Vec<_>>();
        for stream in streams {
            stream.closed.store(true, Ordering::Release);
            stream.closed_notify.notify_waiters();
        }
        if let Ok(mut inner) = self.inner.lock() {
            inner.take();
        }
    }

    fn inner(&self) -> AgentClientResult<Arc<AgentClient>> {
        if self.closed.load(Ordering::Acquire) {
            return Err(AgentClientError::Closed);
        }

        self.inner
            .lock()
            .ok()
            .and_then(|inner| inner.as_ref().map(Arc::clone))
            .ok_or(AgentClientError::Closed)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, AtomicU64};
    use std::time::Duration;

    use tokio::sync::Notify;
    use tokio::sync::mpsc;

    use super::*;

    #[tokio::test]
    async fn close_wakes_in_flight_stream_next() {
        let (tx, rx) = mpsc::channel(1);
        let bridge = Arc::new(AgentBridge {
            inner: StdMutex::new(None),
            streams: Mutex::new(HashMap::from([(
                1,
                Arc::new(BridgeStream {
                    rx: Mutex::new(rx),
                    closed: AtomicBool::new(false),
                    closed_notify: Notify::new(),
                }),
            )])),
            next_handle: AtomicU64::new(2),
            closed: AtomicBool::new(false),
            closed_notify: Notify::new(),
        });

        let waiter = {
            let bridge = Arc::clone(&bridge);
            tokio::spawn(async move { bridge.stream_next(1).await })
        };

        bridge.close().await;
        let result = tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .unwrap()
            .unwrap();

        assert!(matches!(result, Err(AgentClientError::Closed)));
        drop(tx);
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for AgentBridge {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgentBridge")
            .field("next_handle", &self.next_handle.load(Ordering::Relaxed))
            .finish_non_exhaustive()
    }
}

// Suppress unused import lints in builds where AgentClientError is only used
// transitively through `?`.
#[allow(dead_code)]
fn _assert_send_sync() {
    fn assert<T: Send + Sync>() {}
    assert::<AgentBridge>();
    assert::<AgentClientError>();
}
