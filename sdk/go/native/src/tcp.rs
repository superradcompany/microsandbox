//! Guest TCP connections handed to Go as one end of a Unix socket pair.
//!
//! Go reads and writes the socket directly, so a byte stream crosses the boundary without a call
//! per chunk. The Rust end is relayed by the SDK's [`GuestTcpRelay`], the same close sequence SSH
//! forwarding uses. Only control crosses as calls: a half-close or close announced before Go
//! shuts its socket down, an abort, and the cause of an abnormal end.

use std::collections::HashMap;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::raw::{c_char, c_uchar};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, RwLock};
use std::task::{Context, Poll, ready};

use microsandbox::{GuestTcpCleanup, GuestTcpConnection, GuestTcpRelay};
use tokio::io::{AsyncWrite, Interest};
use tokio::net::unix::OwnedWriteHalf;

use super::{FfiError, Handle, cstr, get, run, run_c};

#[cfg(feature = "tcp-test-fixture")]
mod test_fixture;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
const SEND_FLAGS: libc::c_int = libc::MSG_NOSIGNAL;
#[cfg(not(target_os = "linux"))]
const SEND_FLAGS: libc::c_int = 0;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Writes to Go's socket without raising SIGPIPE, which a Go host would not survive on a
/// non-Go thread once Go has closed its end.
struct SocketWriter(OwnedWriteHalf);

/// Keep the registry entry available to a concurrent abort signal throughout the cleanup wait.
/// Cancellation of that wait still removes ownership and requests abort.
struct ReleaseGuard {
    conn: Handle,
    relay: Arc<GuestTcpRelay>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl AsyncWrite for SocketWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let socket = self.0.as_ref();
        loop {
            ready!(socket.poll_write_ready(cx))?;
            let sent = socket.try_io(Interest::WRITABLE, || {
                // SAFETY: the socket is open while its write half lives, and `buf` is valid for
                // `buf.len()` bytes.
                let sent = unsafe {
                    libc::send(
                        socket.as_raw_fd(),
                        buf.as_ptr().cast(),
                        buf.len(),
                        SEND_FLAGS,
                    )
                };
                if sent < 0 {
                    Err(std::io::Error::last_os_error())
                } else {
                    Ok(sent as usize)
                }
            });
            match sent {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => continue,
                sent => return Poll::Ready(sent),
            }
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

impl Drop for SocketWriter {
    fn drop(&mut self) {
        // OwnedWriteHalf shuts output down before closing its descriptor. Stop peer writes
        // first, so that interval cannot expose a failed Read while still accepting input.
        // Ordinary half-close uses poll_shutdown instead and leaves input usable.
        let socket = self.0.as_ref();
        // SAFETY: the owned write half keeps this connected Unix socket open through shutdown.
        if unsafe { libc::shutdown(socket.as_raw_fd(), libc::SHUT_RD) } != 0 {
            eprintln!(
                "microsandbox: failed to shut down released guest TCP input: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

impl Drop for ReleaseGuard {
    fn drop(&mut self) {
        self.relay.request_abort();
        registry()
            .write()
            .expect("tcp registry poisoned")
            .remove(&self.conn);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Registry
//--------------------------------------------------------------------------------------------------

static NEXT_TCP_HANDLE: AtomicU64 = AtomicU64::new(1);

fn registry() -> &'static RwLock<HashMap<Handle, Arc<GuestTcpRelay>>> {
    static REG: OnceLock<RwLock<HashMap<Handle, Arc<GuestTcpRelay>>>> = OnceLock::new();
    REG.get_or_init(|| RwLock::new(HashMap::new()))
}

fn lookup(handle: Handle) -> Result<Arc<GuestTcpRelay>, FfiError> {
    registry()
        .read()
        .map_err(|_| FfiError::internal("tcp registry poisoned"))?
        .get(&handle)
        .cloned()
        .ok_or_else(|| FfiError::invalid_handle(handle))
}

fn cleanup_json(cleanup: GuestTcpCleanup, error: Option<FfiError>) -> String {
    let cleanup = match cleanup {
        GuestTcpCleanup::Acknowledged => "acknowledged",
        GuestTcpCleanup::Unknown => "unknown",
    };
    let error =
        error.map(|error| serde_json::json!({ "kind": error.kind, "message": error.message }));
    serde_json::json!({ "cleanup": cleanup, "error": error }).to_string()
}

fn socket_error(error: std::io::Error) -> FfiError {
    FfiError::internal(format!("guest TCP socket pair: {error}"))
}

fn relay_connection(connection: GuestTcpConnection) -> Result<String, FfiError> {
    let (ours, theirs) = std::os::unix::net::UnixStream::pair().map_err(socket_error)?;
    #[cfg(target_vendor = "apple")]
    {
        let on: libc::c_int = 1;
        // SAFETY: the socket is open and the option value is a valid `c_int`.
        let set = unsafe {
            libc::setsockopt(
                ours.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NOSIGPIPE,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if set != 0 {
            return Err(socket_error(std::io::Error::last_os_error()));
        }
    }
    ours.set_nonblocking(true).map_err(socket_error)?;
    let (reader, writer) = tokio::net::UnixStream::from_std(ours)
        .map_err(socket_error)?
        .into_split();
    let relay = Arc::new(connection.relay(reader, SocketWriter(writer)));
    let conn = NEXT_TCP_HANDLE.fetch_add(1, Ordering::Relaxed);
    registry()
        .write()
        .map_err(|_| FfiError::internal("tcp registry poisoned"))?
        .insert(conn, relay);
    let fd = theirs.into_raw_fd();
    Ok(serde_json::json!({ "conn": conn, "fd": fd }).to_string())
}

//--------------------------------------------------------------------------------------------------
// Functions: C ABI
//--------------------------------------------------------------------------------------------------

/// Open a TCP connection from inside the guest to `host:port`.
///
/// Returns `{"conn":<handle>,"fd":<fd>}`. Go owns `fd`, one end of a close-on-exec Unix stream
/// socket pair carrying the connection's bytes. Go's end of stream aborts the connection unless
/// `msb_tcp_conn_finish` announced it first. Release the handle with `msb_tcp_conn_close` or
/// `msb_tcp_conn_abort`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_sandbox_dial_tcp(
    cancel_id: u64,
    handle: Handle,
    host: *const c_char,
    port: u16,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let sandbox = get(handle)?;
        let host = unsafe { cstr(host) }?;
        Ok(Box::pin(async move {
            let connection = sandbox.connect_tcp(host, port).await?;
            relay_connection(connection)
        }))
    })
}

/// Announce Go's half-close: its socket's next end of stream finishes the guest stream in order.
/// Call it before shutting the socket's write side down.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_tcp_conn_finish(
    conn: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        lookup(conn)?.finish_write();
        Ok(r#"{"ok":true}"#.into())
    })
}

/// Why each direction ended, if not in order: `{"read_error":<string|null>,"write_error":...}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_tcp_conn_status(
    conn: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        let relay = lookup(conn)?;
        Ok(serde_json::json!({
            "read_error": relay.read_error(),
            "write_error": relay.write_error(),
        })
        .to_string())
    })
}

/// Orderly close, after `msb_tcp_conn_finish` and Go's half-close: deliver every byte Go wrote,
/// then release the guest connection without a reset. Returns
/// `{"cleanup":"acknowledged"|"unknown","error":<delivery error|null>}`. Cleanup acknowledgement
/// is reported independently of delivery failure. Invalid handles and call failures use the
/// ordinary FFI error return.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_tcp_conn_close(
    cancel_id: u64,
    conn: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let guard = ReleaseGuard {
            conn,
            relay: lookup(conn)?,
        };
        Ok(Box::pin(async move {
            let result = guard.relay.close().await;
            // Close has already awaited the final outcome, including on delivery failure.
            // Abort joins that same published outcome; it cannot cancel the stream a second time.
            let cleanup = match &result {
                Ok(cleanup) => *cleanup,
                Err(_) => guard.relay.abort().await,
            };
            Ok(cleanup_json(cleanup, result.err().map(FfiError::from)))
        }))
    })
}

/// Abort: discard unwritten bytes and reset the guest connection.
/// Returns `{"cleanup":"acknowledged"|"unknown"}`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_tcp_conn_abort(
    cancel_id: u64,
    conn: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run_c(cancel_id, buf, buf_len, || {
        let guard = ReleaseGuard {
            conn,
            relay: lookup(conn)?,
        };
        Ok(Box::pin(async move {
            let result = guard.relay.abort().await;
            Ok(cleanup_json(result, None))
        }))
    })
}

/// Interrupt a pending orderly close before joining its cleanup wait. An already released handle
/// needs no further interruption; handles are never reused.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn msb_tcp_conn_request_abort(
    conn: Handle,
    buf: *mut c_uchar,
    buf_len: usize,
) -> *mut c_char {
    run(buf, buf_len, || {
        if let Some(relay) = registry()
            .read()
            .map_err(|_| FfiError::internal("tcp registry poisoned"))?
            .get(&conn)
        {
            relay.request_abort();
        }
        Ok(r#"{"ok":true}"#.into())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn socket_writer_drop_stops_input_before_output_eof() {
        let (native, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let (reader, writer) = native.into_split();
        // Retain the read half so descriptor close cannot hide the interval between
        // OwnedWriteHalf's write shutdown and the underlying UnixStream's close.
        drop(SocketWriter(writer));
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        let write = peer.write(b"after failure").await;
        assert!(write.is_err(), "write after released output: {write:?}");
        drop(reader);
    }

    #[tokio::test]
    async fn socket_writer_half_close_keeps_input_readable() {
        let (native, mut peer) = tokio::net::UnixStream::pair().unwrap();
        let (mut reader, writer) = native.into_split();
        let mut writer = SocketWriter(writer);
        writer.shutdown().await.unwrap();
        let mut byte = [0];
        assert_eq!(peer.read(&mut byte).await.unwrap(), 0);
        peer.write_all(b"after EOF").await.unwrap();
        let mut input = [0; 9];
        reader.read_exact(&mut input).await.unwrap();
        assert_eq!(&input, b"after EOF");
    }
}
