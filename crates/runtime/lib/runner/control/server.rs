//! One endpoint, parser selection once, and bounded persistent framed sessions.

use std::collections::HashSet;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use microsandbox_protocol::{codec::RawFrame, control::*, wire::Envelope};
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::sync::{Semaphore, mpsc};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use super::dispatch::{
    Budget, CONNECTION_BYTES, Dispatcher, Input, Job, Lease, Outgoing, framed_reply, invalid,
};
use super::handler::{ControlContext, Reply};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const MAX_CONNECTIONS: usize = 128;
static NEXT_CONNECTION: AtomicU64 = AtomicU64::new(1);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct SessionGuard {
    dispatcher: Arc<Dispatcher>,
    id: u64,
    cancelled: CancellationToken,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.cancelled.cancel();
        self.dispatcher.cancel(self.id);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Spawn the host control listener, supporting old JSON and persistent CBOR.
#[cfg(unix)]
pub fn spawn_control_listener(socket_path: PathBuf, context: ControlContext) -> io::Result<()> {
    let _ = std::fs::remove_file(&socket_path);
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)?;
    listener.set_nonblocking(true)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    std::thread::Builder::new()
        .name("msb-control".into())
        .spawn(move || {
            runtime.block_on(async move {
                let listener = match tokio::net::UnixListener::from_std(listener) {
                    Ok(listener) => listener,
                    Err(error) => {
                        tracing::warn!("control: listener initialization failed: {error}");
                        return;
                    }
                };
                let dispatcher = Dispatcher::new(Arc::new(context));
                tokio::spawn(Arc::clone(&dispatcher).run());
                if let Err(error) = listen_unix(listener, dispatcher).await {
                    tracing::warn!("control: accept failed: {error}");
                }
            });
        })?;
    Ok(())
}

/// Serve the existing byte-mode Windows pipe name, including zero-byte probes.
#[cfg(windows)]
pub fn spawn_control_listener(pipe_name: PathBuf, context: ControlContext) -> io::Result<()> {
    use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    std::thread::Builder::new()
        .name("msb-control".into())
        .spawn(move || {
            runtime.block_on(async move {
                let dispatcher = Dispatcher::new(Arc::new(context));
                tokio::spawn(Arc::clone(&dispatcher).run());
                let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
                let mut first = true;
                loop {
                    let Ok(permit) = Arc::clone(&connections).acquire_owned().await else {
                        break;
                    };
                    let mut options = ServerOptions::new();
                    options.pipe_mode(PipeMode::Byte).first_pipe_instance(first);
                    let server = match options.create(&pipe_name) {
                        Ok(server) => server,
                        Err(error) => {
                            tracing::warn!("control: pipe create failed: {error}");
                            break;
                        }
                    };
                    first = false;
                    if let Err(error) = server.connect().await {
                        tracing::debug!("control: pipe connect failed: {error}");
                        continue;
                    }
                    let dispatcher = Arc::clone(&dispatcher);
                    tokio::spawn(async move {
                        if let Err(error) = super::windows::serve_named_pipe(
                            server,
                            dispatcher,
                            permit,
                            DEFAULT_REQUEST_TIMEOUT,
                        )
                        .await
                        {
                            tracing::debug!("control: connection ended: {error}");
                        }
                    });
                }
            });
        })?;
    Ok(())
}

#[cfg(unix)]
pub(crate) async fn listen_unix(
    listener: tokio::net::UnixListener,
    dispatcher: Arc<Dispatcher>,
) -> io::Result<()> {
    let connections = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let permit = Arc::clone(&connections)
            .acquire_owned()
            .await
            .map_err(|_| invalid())?;
        let (mut stream, _) = listener.accept().await?;
        let dispatcher = Arc::clone(&dispatcher);
        tokio::spawn(async move {
            let _permit = permit;
            #[cfg(target_os = "linux")]
            let result = serve_unix(&mut stream, dispatcher).await;
            #[cfg(not(target_os = "linux"))]
            let result = serve(&mut stream, dispatcher).await;
            if let Err(error) = result {
                tracing::debug!("control: connection ended: {error}");
            }
        });
    }
}

#[cfg(any(not(target_os = "linux"), test))]
pub(crate) async fn serve<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    dispatcher: Arc<Dispatcher>,
) -> io::Result<()> {
    serve_opened(stream, dispatcher, None).await
}

/// Receive ancillary rights before Tokio reads the first byte and discards them.
#[cfg(target_os = "linux")]
async fn serve_unix(
    stream: &mut tokio::net::UnixStream,
    dispatcher: Arc<Dispatcher>,
) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    let opening = timeout(
        DEFAULT_SETUP_TIMEOUT,
        stream.async_io(tokio::io::Interest::READABLE, || {
            crate::memory_handoff::receive_first(stream.as_raw_fd())
        }),
    )
    .await
    .map_err(|_| expired())??;
    let Some(opening) = opening else {
        return Ok(());
    };
    serve_opened(stream, dispatcher, Some(opening)).await
}

async fn serve_opened<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    dispatcher: Arc<Dispatcher>,
    opening: Option<(u8, Option<std::fs::File>)>,
) -> io::Result<()> {
    let id = NEXT_CONNECTION.fetch_add(1, Ordering::Relaxed);
    let cancelled = CancellationToken::new();
    let _guard = SessionGuard {
        dispatcher: Arc::clone(&dispatcher),
        id,
        cancelled: cancelled.clone(),
    };
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (first, memory) = match opening {
        Some((first, memory)) => (Some(first), memory),
        None => (
            timeout(DEFAULT_SETUP_TIMEOUT, first_byte(&mut reader))
                .await
                .map_err(|_| expired())??,
            None,
        ),
    };
    let Some(first) = first else {
        return Ok(());
    }; // Windows Path::exists probe
    if first != 0 {
        let mut reader = BufReader::with_capacity(4096, &mut reader);
        return json(
            &mut reader,
            &mut writer,
            first,
            dispatcher,
            id,
            cancelled,
            memory,
        )
        .await;
    }
    // Descriptor transfer is a one-shot JSON branch operation, never a framed handshake.
    if memory.is_some() {
        return Err(invalid());
    }
    let bytes = Arc::new(Semaphore::new(CONNECTION_BYTES));
    let (opening, _opening_budget) = timeout(
        DEFAULT_SETUP_TIMEOUT,
        frame_after_first(
            &mut reader,
            first,
            MAX_HANDSHAKE_FRAME_SIZE,
            &bytes,
            &dispatcher.bytes,
        ),
    )
    .await
    .map_err(|_| expired())??;
    let envelope = Envelope::decode(&opening.body).map_err(|_| invalid())?;
    let negotiated = if opening.id != 0
        || opening.flags != 0
        || envelope.v != 1
        || envelope.t != "control.hello"
    {
        Err(ControlError::rejected(
            "invalid_handshake",
            "expected control hello",
        ))
    } else {
        match envelope.payload::<ControlHello>() {
            Ok(hello) => ControlWelcome::negotiate(&hello, DEFAULT_MAX_IN_FLIGHT),
            Err(_) => Err(ControlError::rejected(
                "invalid_handshake",
                "invalid control hello",
            )),
        }
    };
    let selected = match negotiated {
        Ok(value) => value,
        Err(error) => {
            let _reserved = Budget::reserve_reply(&bytes, &dispatcher.bytes)?;
            writer
                .write_all(&framed_reply(&Reply::Error(error), 1, 0)?)
                .await?;
            writer.flush().await?;
            return Ok(());
        }
    };
    let welcome = Envelope::new(1, "control.welcome", &selected)
        .map_err(|_| invalid())?
        .frame(0, 1)
        .map_err(|_| invalid())?;
    {
        let _reserved = Budget::reserve_reply(&bytes, &dispatcher.bytes)?;
        microsandbox_protocol::codec::write_raw_frame(&mut writer, &welcome)
            .await
            .map_err(|_| invalid())?;
    }
    drop(envelope);
    drop(opening);
    drop(_opening_budget);
    let (reply, mut replies) = mpsc::channel(selected.max_in_flight as usize);
    let read_loop = framed_requests(
        &mut reader,
        dispatcher,
        id,
        bytes,
        selected,
        reply,
        cancelled.clone(),
    );
    let write_loop = async {
        while let Some(mut outgoing) = replies.recv().await {
            if let Some(lease) = &mut outgoing.lease {
                lease.terminal_admitted();
            }
            writer.write_all(&outgoing.bytes).await?;
            writer.flush().await?;
        }
        Ok(())
    };
    tokio::select! {
        result = read_loop => result,
        result = write_loop => result,
        _ = cancelled.cancelled() => Err(invalid()),
    }
}

async fn json<R: AsyncBufRead + Unpin, W: AsyncWrite + Unpin>(
    reader: &mut R,
    writer: &mut W,
    first: u8,
    dispatcher: Arc<Dispatcher>,
    id: u64,
    cancelled: CancellationToken,
    memory: Option<std::fs::File>,
) -> io::Result<()> {
    // Preserve the inspected byte and the historical unbounded line contract.
    // In particular a JSON batch larger than 4 MiB does not become a CBOR frame.
    let mut line = vec![first];
    if first != b'\n' {
        reader.read_until(b'\n', &mut line).await?;
    }
    let text = std::str::from_utf8(&line).map_err(|_| invalid())?;
    let request = match serde_json::from_str::<serde_json::Value>(text.trim()) {
        Ok(request) => request,
        Err(error) => {
            let response = crate::control::ControlResponse {
                ok: false,
                error_code: Some("invalid_json".into()),
                error: Some(format!("invalid control request: {error}")),
                ..Default::default()
            };
            let mut bytes = serde_json::to_vec(&response).map_err(|_| invalid())?;
            bytes.push(b'\n');
            writer.write_all(&bytes).await?;
            writer.flush().await?;
            return Ok(());
        }
    };
    let (reply, mut replies) = mpsc::channel(1);
    let job = Job {
        input: Input::JsonWire(request, memory),
        reply,
        output_budget: None,
        lease: None,
        cancelled,
    };
    if dispatcher.submit(id, job).is_err() {
        writer
            .write_all(b"{\"ok\":false,\"error\":\"control runtime is busy\"}\n")
            .await?;
    } else {
        let outgoing = replies.recv().await.ok_or_else(invalid)?;
        writer.write_all(&outgoing.bytes).await?;
    }
    writer.flush().await
}

async fn framed_requests<R: AsyncRead + Unpin>(
    reader: &mut R,
    dispatcher: Arc<Dispatcher>,
    id: u64,
    bytes: Arc<Semaphore>,
    selected: ControlWelcome,
    reply: mpsc::Sender<Outgoing>,
    cancelled: CancellationToken,
) -> io::Result<()> {
    let ids = Arc::new(Mutex::new(HashSet::new()));
    let capacity = Arc::new(Semaphore::new(selected.max_in_flight as usize));
    loop {
        // Complete idle sessions do not expire. Once a frame starts, its entire
        // read (including budget admission) shares an absolute deadline.
        let Some(first) = first_byte(reader).await? else {
            return Ok(());
        };
        let (frame, budget) = timeout(
            DEFAULT_SETUP_TIMEOUT,
            frame_after_first(
                reader,
                first,
                selected.max_frame_size,
                &bytes,
                &dispatcher.bytes,
            ),
        )
        .await
        .map_err(|_| expired())??;
        let lease = Lease::acquire(frame.id, &ids, &capacity)?;
        let output_budget = Budget::reserve_reply(&bytes, &dispatcher.bytes)?;
        let job = Job {
            input: Input::Framed {
                frame,
                generation: selected.generation,
                _budget: budget,
            },
            reply: reply.clone(),
            output_budget: Some(output_budget),
            lease: Some(lease),
            cancelled: cancelled.clone(),
        };
        if let Err(job) = dispatcher.submit(id, job) {
            let Input::Framed { frame, .. } = job.input else {
                unreachable!()
            };
            let payload = framed_reply(
                &Reply::Error(ControlError::rejected("busy", "control runtime is busy")),
                selected.generation,
                frame.id,
            )?;
            reply
                .try_send(Outgoing {
                    bytes: payload,
                    _budget: job.output_budget,
                    lease: job.lease,
                })
                .map_err(|_| invalid())?;
        }
    }
}

async fn first_byte<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Option<u8>> {
    let mut first = [0];
    match reader.read(&mut first).await? {
        0 => Ok(None),
        _ => Ok(Some(first[0])),
    }
}

async fn frame_after_first<R: AsyncRead + Unpin>(
    reader: &mut R,
    first: u8,
    max: u32,
    connection: &Arc<Semaphore>,
    runtime: &Arc<Semaphore>,
) -> io::Result<(RawFrame, Budget)> {
    let mut length = [first, 0, 0, 0];
    reader.read_exact(&mut length[1..]).await?;
    let length = u32::from_be_bytes(length);
    if !(5..=max).contains(&length) {
        return Err(invalid());
    }
    let budget = Budget::acquire(connection, runtime, length + 4).await?;
    let id = reader.read_u32().await?;
    let flags = reader.read_u8().await?;
    let mut body = vec![0; length as usize - 5];
    reader.read_exact(&mut body).await?;
    Ok((RawFrame { id, flags, body }, budget))
}

fn expired() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "control setup or frame deadline expired",
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, target_os = "linux"))]
mod descriptor_tests {
    use super::super::handler::{Handler, Response};
    use super::*;
    use std::os::fd::AsRawFd;
    use std::sync::atomic::AtomicBool;
    use std::time::Duration;

    struct MemoryHandler(Arc<AtomicBool>);

    impl Handler for MemoryHandler {
        fn handle(&self, _: ControlRequest) -> Response {
            panic!("expected JSON memory handoff")
        }

        fn handle_json_with_memory(
            &self,
            value: serde_json::Value,
            memory: Option<std::fs::File>,
        ) -> Vec<u8> {
            assert_eq!(value["op"], "branch_create_memfd");
            crate::memory_handoff::validate_empty(&memory.unwrap()).unwrap();
            self.0.store(true, Ordering::SeqCst);
            b"{\"ok\":true}\n".to_vec()
        }
    }

    #[tokio::test]
    async fn unix_listener_delivers_memory_with_the_first_json_byte() {
        let (mut sender, mut receiver) = tokio::net::UnixStream::pair().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let dispatcher = Dispatcher::new(Arc::new(MemoryHandler(called.clone())));
        let worker = tokio::spawn(dispatcher.clone().run());
        let server = tokio::spawn(async move { serve_unix(&mut receiver, dispatcher).await });
        let file = crate::memory_handoff::create().unwrap();
        sender
            .async_io(tokio::io::Interest::WRITABLE, || {
                crate::memory_handoff::send_first(sender.as_raw_fd(), &file, b'{')
            })
            .await
            .unwrap();
        // The queued job retains the descriptor after the sender closes its file handle.
        drop(file);
        sender
            .write_all(b"\"op\":\"branch_create_memfd\"}\n")
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(Duration::from_secs(5), sender.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(response, b"{\"ok\":true}\n");
        server.await.unwrap().unwrap();
        assert!(called.load(Ordering::SeqCst));
        worker.abort();
    }

    #[tokio::test]
    async fn framed_handshake_cannot_carry_memory() {
        let (sender, mut receiver) = tokio::net::UnixStream::pair().unwrap();
        let called = Arc::new(AtomicBool::new(false));
        let dispatcher = Dispatcher::new(Arc::new(MemoryHandler(called.clone())));
        let server = tokio::spawn(async move { serve_unix(&mut receiver, dispatcher).await });
        let file = crate::memory_handoff::create().unwrap();
        sender
            .async_io(tokio::io::Interest::WRITABLE, || {
                crate::memory_handoff::send_first(sender.as_raw_fd(), &file, 0)
            })
            .await
            .unwrap();
        assert!(
            timeout(Duration::from_secs(5), server)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(!called.load(Ordering::SeqCst));
    }
}
