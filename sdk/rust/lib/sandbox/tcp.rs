//! TCP connections from the host to an address the guest can reach, over raw bulk transfer.
//!
//! agentd dials the destination from inside the guest. Both directions are bounded by bulk
//! credit: the guest admits host bytes only up to the window it granted, and the host grants
//! guest bytes back only once its output has taken them. SSH direct-tcpip forwarding and
//! [`GuestTcpRelay`] share the relays and the close sequence defined here.

use std::pin::Pin;
use std::sync::{
    Arc, Mutex as SyncMutex,
    atomic::{AtomicBool, Ordering},
};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use microsandbox_agent_client::AgentFrame;
use microsandbox_protocol::{
    bulk::{
        BULK_FLOW_MASK_GUEST_TO_HOST, BULK_FLOW_MASK_HOST_TO_GUEST, BulkAccepted, BulkCancel,
        BulkCancelReason, BulkCredit, BulkFinish, BulkFlow, BulkKind, BulkOffer, BulkReceiveState,
        BulkRecord, BulkSendState,
    },
    message::{Message, MessageType},
    tcp::{TcpClosed, TcpConnect, TcpConnected, TcpFailed},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::sync::{Mutex, Notify, mpsc, watch};

use crate::{MicrosandboxError, MicrosandboxResult, Sandbox, agent::AgentClient};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// How long a closing connection may go without progress before it is cancelled: while its
/// input drains, credit for it; after the finish, the guest writing more of it; then the guest's
/// terminal reply.
pub const GUEST_TCP_CLOSE_IDLE_TIMEOUT: Duration = Duration::from_secs(2);

/// Mirrors agentd's largest session-output item queue. The negotiated receive window bounds raw
/// bytes; this item bound lets control credits pass while the output waits on its consumer.
pub(crate) const TCP_OUTPUT_QUEUE_CAPACITY: usize = 1024;

/// Largest read from a relayed reader handed to the guest stream at once; the sender splits it
/// into records within the negotiated record size.
const TCP_READ_CHUNK: usize = 256 * 1024;

/// Bytes each direction of a [`GuestTcpStream`]'s in-process pipe holds, on top of bulk credit.
const GUEST_TCP_STREAM_BUFFER: usize = 256 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-to-guest credit state shared by the input relay, the guest pump and the close sequence.
pub(crate) struct TcpBulkSender {
    state: Mutex<BulkSendState>,
    credit_ready: Notify,
    closed: AtomicBool,
}

/// Closes the sender when the guest pump ends, so no input waits on credit that cannot come.
struct TcpRelayCloseGuard(Arc<TcpBulkSender>);

/// A guest TCP connection with negotiated bulk transfer, before any relay runs.
pub(crate) struct TcpLink {
    pub(crate) id: u32,
    pub(crate) frames: mpsc::Receiver<AgentFrame>,
    pub(crate) sender: Arc<TcpBulkSender>,
    pub(crate) receiver: Arc<Mutex<BulkReceiveState>>,
}

/// One guest event for an output relay.
pub(crate) enum TcpOutput {
    Data {
        payload: Bytes,
        consumed_offset: u64,
    },
    Eof,
    Close,
}

/// How a relayed connection's supervision ended.
pub(crate) struct TcpRelayEnd {
    /// Whether the input relay ended, and whether it ended by finishing the stream in order.
    pub(crate) finished: Option<bool>,
    /// Whether the guest ended the stream with its terminal reply.
    pub(crate) terminated: bool,
    /// The guest future completed, even if it did not acknowledge cleanup. Never poll it again.
    pub(crate) guest_done: bool,
    pub(crate) output_done: bool,
}

/// Whether the guest confirmed that a closed connection released its socket.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuestTcpCleanup {
    /// The guest sent its terminal reply: its socket is closed or handed to an orderly drain.
    Acknowledged,
    /// No terminal reply arrived within [`GUEST_TCP_CLOSE_IDLE_TIMEOUT`] of the cancel, or the
    /// agent connection was lost first. The guest socket may still be open.
    Unknown,
}

/// A connected guest TCP stream, ready to be relayed.
pub struct GuestTcpConnection {
    client: Arc<AgentClient>,
    link: TcpLink,
}

/// A guest TCP connection relayed to a host reader and writer.
///
/// The reader's end of stream finishes the guest stream only after [`finish_write`]
/// (or [`close`]) asked for it; any other end of stream aborts the connection, so a dropped
/// owner can never pass for a complete one.
///
/// [`finish_write`]: Self::finish_write
/// [`close`]: Self::close
pub struct GuestTcpRelay {
    state: Arc<RelayState>,
}

/// A TCP connection agentd opened from inside the guest, as an in-process byte stream.
///
/// [`AsyncWriteExt::shutdown`] half-closes it. Reads report an error, not end of stream, when
/// the guest connection fails first. Release it with [`close`](Self::close) or
/// [`abort`](Self::abort); dropping it aborts the connection. Reads and writes are cancel-safe
/// as on any [`AsyncRead`] and [`AsyncWrite`].
pub struct GuestTcpStream {
    io: DuplexStream,
    relay: GuestTcpRelay,
}

/// What the owner asked of a relay, in increasing order of finality.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Intent {
    Open,
    Finish,
    Close,
    Abort,
}

struct RelayState {
    intent: watch::Sender<Intent>,
    /// Set once the owner no longer reads: on close, abort, a failed input, or the end of the
    /// output. The relay then enters its close sequence.
    stop: watch::Sender<bool>,
    outcome: watch::Sender<Option<RelayOutcome>>,
    read_error: SyncMutex<Option<String>>,
    write_error: SyncMutex<Option<String>>,
}

#[derive(Clone, Copy)]
struct RelayOutcome {
    /// The input finished in order and the guest wrote every byte of it to the destination.
    delivered: bool,
    cleanup: GuestTcpCleanup,
}

//--------------------------------------------------------------------------------------------------
// Methods: TcpBulkSender
//--------------------------------------------------------------------------------------------------

impl TcpBulkSender {
    fn new(state: BulkSendState) -> Self {
        Self {
            state: Mutex::new(state),
            credit_ready: Notify::new(),
            closed: AtomicBool::new(false),
        }
    }

    pub(crate) async fn send(
        &self,
        client: &AgentClient,
        id: u32,
        data: Bytes,
    ) -> MicrosandboxResult<()> {
        let mut remaining = data;
        while !remaining.is_empty() {
            if self.closed.load(Ordering::Acquire) {
                return Err(MicrosandboxError::Custom(
                    "TCP bulk stream is already closed".into(),
                ));
            }
            // Register the waiter before inspecting credit so an update cannot be lost between
            // the check and the await.
            let notified = self.credit_ready.notified();
            let next = {
                let mut state = self.state.lock().await;
                let len = remaining
                    .len()
                    .min(state.max_record_payload() as usize)
                    .min(state.available_credit() as usize);
                if len == 0 {
                    None
                } else {
                    let offset = state.admit(len).map_err(|error| {
                        MicrosandboxError::Custom(format!("admit TCP bulk record: {error}"))
                    })?;
                    Some((offset, len))
                }
            };

            let Some((offset, len)) = next else {
                if self.closed.load(Ordering::Acquire) {
                    return Err(MicrosandboxError::Custom(
                        "TCP bulk stream closed while waiting for credit".into(),
                    ));
                }
                notified.await;
                continue;
            };
            client
                .send_bulk(BulkRecord {
                    id,
                    kind: BulkKind::Tcp,
                    flow: BulkFlow::HostToGuest,
                    offset,
                    payload: remaining.split_to(len),
                })
                .await?;
        }
        Ok(())
    }

    async fn apply_credit(&self, credit: BulkCredit) -> MicrosandboxResult<()> {
        // Closing forbids new input, not validated credit already in flight before cancellation.
        let advanced = self
            .state
            .lock()
            .await
            .apply_credit(credit)
            .map_err(|error| {
                MicrosandboxError::Custom(format!("apply TCP bulk credit: {error}"))
            })?;
        // A repeated or stale grant is no progress, so it must not look like one.
        if advanced {
            self.credit_ready.notify_waiters();
        }
        Ok(())
    }

    /// Bytes the guest has reported written to its destination, and whether that is every byte
    /// sent to it.
    pub(crate) async fn consumed(&self) -> (u64, bool) {
        let state = self.state.lock().await;
        (
            state.consumed_offset(),
            state.consumed_offset() == state.next_offset(),
        )
    }

    pub(crate) async fn finish(&self, client: &AgentClient, id: u32) -> MicrosandboxResult<()> {
        if self.closed.load(Ordering::Acquire) {
            return Err(MicrosandboxError::Custom(
                "TCP bulk stream is already closed".into(),
            ));
        }
        let finish =
            self.state.lock().await.finish().map_err(|error| {
                MicrosandboxError::Custom(format!("finish TCP bulk flow: {error}"))
            })?;
        client.send(id, MessageType::BulkFinish, &finish).await?;
        Ok(())
    }

    pub(crate) fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.credit_ready.notify_waiters();
    }
}

impl Drop for TcpRelayCloseGuard {
    fn drop(&mut self) {
        self.0.close();
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: public API
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Open a TCP connection from inside the guest to `host:port`, for relaying to a host
    /// reader and writer with [`GuestTcpConnection::relay`].
    ///
    /// Each connection uses its own agent connection, so a misbehaving one cannot disturb other
    /// operations on the sandbox. `host` is resolved by the guest.
    pub async fn connect_tcp(
        &self,
        host: impl Into<String>,
        port: u16,
    ) -> MicrosandboxResult<GuestTcpConnection> {
        let client =
            Arc::new(super::fs::agent::connect_agent(self.backend().as_ref(), self.name()).await?);
        GuestTcpConnection::connect(client, host, port).await
    }

    /// Open a TCP connection from inside the guest to `host:port` as an in-process stream.
    pub async fn dial_tcp(
        &self,
        host: impl Into<String>,
        port: u16,
    ) -> MicrosandboxResult<GuestTcpStream> {
        Ok(self.connect_tcp(host, port).await?.into_stream())
    }
}

impl GuestTcpConnection {
    /// Open a TCP connection from inside the guest over an existing agent connection.
    pub async fn connect(
        client: Arc<AgentClient>,
        host: impl Into<String>,
        port: u16,
    ) -> MicrosandboxResult<Self> {
        let link = open_tcp(&client, &host.into(), port).await?;
        Ok(Self { client, link })
    }

    /// Relay the connection: bytes read from `reader` go to the destination, and the
    /// destination's bytes are written to `writer`, each bounded by bulk credit. The relay runs
    /// on the current Tokio runtime until the connection ends.
    pub fn relay<R, W>(self, reader: R, writer: W) -> GuestTcpRelay
    where
        R: AsyncRead + Unpin + Send + 'static,
        W: AsyncWrite + Unpin + Send + 'static,
    {
        let state = Arc::new(RelayState {
            intent: watch::Sender::new(Intent::Open),
            stop: watch::Sender::new(false),
            outcome: watch::Sender::new(None),
            read_error: SyncMutex::new(None),
            write_error: SyncMutex::new(None),
        });
        tokio::spawn(run_relay(
            self.client,
            self.link,
            reader,
            writer,
            Arc::clone(&state),
        ));
        GuestTcpRelay { state }
    }

    /// Relay the connection through an in-process pipe.
    pub fn into_stream(self) -> GuestTcpStream {
        let (io, far) = tokio::io::duplex(GUEST_TCP_STREAM_BUFFER);
        let (reader, writer) = tokio::io::split(far);
        GuestTcpStream {
            io,
            relay: self.relay(reader, writer),
        }
    }
}

impl GuestTcpRelay {
    /// Make the reader's next end of stream an orderly half-close: the guest shuts its write
    /// side down after every byte read before it. Reads from the destination continue.
    pub fn finish_write(&self) {
        self.state.raise(Intent::Finish);
    }

    /// Orderly close: deliver every byte the reader still yields up to its end of stream, finish
    /// the stream, and wait for the guest to write all of it and end the stream.
    ///
    /// Close the reader's source first, or its end of stream never comes. The wait is bounded by
    /// [`GUEST_TCP_CLOSE_IDLE_TIMEOUT`] of no progress, after which the connection is cancelled
    /// without a finish. This returns an error if any byte did not reach the destination, or the
    /// input failed.
    pub async fn close(&self) -> MicrosandboxResult<GuestTcpCleanup> {
        self.state.raise(Intent::Close);
        self.state.stop.send_replace(true);
        let outcome = self.state.wait().await;
        if let Some(error) = self.write_error() {
            return Err(MicrosandboxError::Custom(format!(
                "guest TCP close: {error}"
            )));
        }
        if !outcome.delivered {
            return Err(MicrosandboxError::Custom(
                "guest TCP close: not every byte reached the destination".into(),
            ));
        }
        Ok(outcome.cleanup)
    }

    /// Abort: discard unwritten bytes and cancel the connection now. The destination sees a reset
    /// unless the guest had already written every byte and the finish.
    pub async fn abort(&self) -> GuestTcpCleanup {
        self.request_abort();
        self.state.wait().await.cleanup
    }

    /// Interrupt an orderly close without waiting for cleanup. [`abort`](Self::abort) waits for
    /// the same outcome; this lets synchronous owners signal abort before joining a closer.
    pub fn request_abort(&self) {
        self.state.raise(Intent::Abort);
        self.state.stop.send_replace(true);
    }

    /// Why the destination's bytes stopped before the destination ended its side, if they did.
    pub fn read_error(&self) -> Option<String> {
        self.state
            .read_error
            .lock()
            .expect("relay state poisoned")
            .clone()
    }

    /// Why bytes from the reader stopped reaching the guest, if they did.
    pub fn write_error(&self) -> Option<String> {
        self.state
            .write_error
            .lock()
            .expect("relay state poisoned")
            .clone()
    }
}

impl GuestTcpStream {
    /// Orderly close: deliver every byte written, finish the stream, and wait for the guest to
    /// write all of it. See [`GuestTcpRelay::close`].
    pub async fn close(mut self) -> MicrosandboxResult<GuestTcpCleanup> {
        self.relay.finish_write();
        // Shutting the pipe down cannot fail; its far end reads the end of stream.
        let _ = self.io.shutdown().await;
        self.relay.close().await
    }

    /// Abort the connection. See [`GuestTcpRelay::abort`].
    pub async fn abort(self) -> GuestTcpCleanup {
        self.relay.abort().await
    }
}

impl AsyncRead for GuestTcpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let polled = Pin::new(&mut self.io).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = polled
            && buf.filled().len() == before
            && buf.remaining() > 0
            && let Some(error) = self.relay.read_error()
        {
            return Poll::Ready(Err(std::io::Error::other(error)));
        }
        polled
    }
}

impl AsyncWrite for GuestTcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        match Pin::new(&mut self.io).poll_write(cx, buf) {
            Poll::Ready(Err(error)) => Poll::Ready(Err(match self.relay.write_error() {
                Some(cause) => std::io::Error::new(error.kind(), cause),
                None => error,
            })),
            polled => polled,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.io).poll_flush(cx)
    }

    /// Half-close: the destination reads end of stream after every byte written before it.
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.relay.finish_write();
        Pin::new(&mut self.io).poll_shutdown(cx)
    }
}

impl Drop for GuestTcpStream {
    fn drop(&mut self) {
        // The relay task retains its state senders. Pipe EOF alone cannot release an owner that
        // already half-closed, because the input future has finished and no longer reads the pipe.
        self.relay.request_abort();
    }
}

impl RelayState {
    fn raise(&self, intent: Intent) {
        self.intent.send_if_modified(|current| {
            let raised = intent > *current;
            if raised {
                *current = intent;
            }
            raised
        });
    }

    async fn wait(&self) -> RelayOutcome {
        let mut outcome = self.outcome.subscribe();
        let outcome = outcome
            .wait_for(Option::is_some)
            .await
            .expect("the relay state owns the outcome sender");
        outcome.expect("waited for an outcome")
    }

    fn record(slot: &SyncMutex<Option<String>>, error: impl ToString) {
        slot.lock()
            .expect("relay state poisoned")
            .get_or_insert_with(|| error.to_string());
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: shared relays
//--------------------------------------------------------------------------------------------------

/// Open a guest TCP connection and negotiate its bulk transfer.
pub(crate) async fn open_tcp(
    client: &AgentClient,
    host: &str,
    port: u16,
) -> MicrosandboxResult<TcpLink> {
    if !client.supports(MessageType::BulkAccepted) {
        return Err(MicrosandboxError::Custom(
            "guest agent cannot carry bulk TCP; restart the sandbox with the current runtime"
                .into(),
        ));
    }
    let offer = BulkOffer::tcp();
    let (id, mut frames) = client
        .stream_frames(
            MessageType::TcpConnect,
            &TcpConnect {
                host: host.to_string(),
                port,
                bulk: Some(offer),
            },
        )
        .await?;
    let refused = |detail: String| {
        MicrosandboxError::Custom(format!("guest TCP connect to {host}:{port}: {detail}"))
    };
    let first = next_control(&mut frames).await.map_err(refused)?;
    match first.t {
        MessageType::TcpConnected => {
            first.payload::<TcpConnected>()?;
        }
        MessageType::TcpFailed => return Err(refused(first.payload::<TcpFailed>()?.error)),
        other => return Err(refused(format!("unexpected reply {}", other.as_str()))),
    }
    let negotiated = async {
        let accepted = next_control(&mut frames).await.map_err(refused)?;
        if accepted.t != MessageType::BulkAccepted {
            return Err(refused(format!(
                "expected bulk acceptance, got {}",
                accepted.t.as_str()
            )));
        }
        let accepted = accepted
            .payload::<BulkAccepted>()?
            .validate_against(
                offer,
                BulkKind::Tcp,
                BULK_FLOW_MASK_HOST_TO_GUEST | BULK_FLOW_MASK_GUEST_TO_HOST,
            )
            .map_err(|error| bulk_error("invalid TCP bulk acceptance", error))?;
        let sender = BulkSendState::new(
            BulkKind::Tcp,
            BulkFlow::HostToGuest,
            accepted.max_record_payload,
            accepted.host_to_guest_credit_limit,
        )
        .map_err(|error| bulk_error("create TCP bulk send state", error))?;
        let receiver = BulkReceiveState::new(
            BulkKind::Tcp,
            BulkFlow::GuestToHost,
            accepted.max_record_payload,
            accepted.guest_to_host_credit_limit,
            offer.guest_to_host_credit_limit,
        )
        .map_err(|error| bulk_error("create TCP bulk receive state", error))?;
        Ok((sender, receiver))
    }
    .await;
    match negotiated {
        Ok((sender, receiver)) => Ok(TcpLink {
            id,
            frames,
            sender: Arc::new(TcpBulkSender::new(sender)),
            receiver: Arc::new(Mutex::new(receiver)),
        }),
        Err(error) => {
            // The guest connected: release its socket before reporting the failure.
            let _ = client
                .cancel_bulk(id, &cancel_message("bulk TCP negotiation failed"))
                .await;
            Err(error)
        }
    }
}

/// Supervise one relayed connection until its guest stream should be released.
///
/// Relays that finish before `stop` still leave the guest stream to close once it fires. Then the
/// relays keep running: the guest pump applies credit and the output relay discards and credits
/// guest output. The deadline is idle time. While the input drains, every credit grant re-arms
/// it; after the finish only the guest reporting more bytes written does, until it has written
/// all of them. From then on it bounds the wait for the guest's terminal reply. A stream whose
/// input was fully written is never cancelled for that alone; only its terminal reply or the
/// deadline ends the wait.
pub(crate) async fn supervise_tcp<I, O, G, A>(
    sender: &TcpBulkSender,
    mut input: Pin<&mut I>,
    mut output: Pin<&mut O>,
    mut guest: Pin<&mut G>,
    stop: &mut watch::Receiver<bool>,
    abort: A,
) -> TcpRelayEnd
where
    I: Future<Output = bool>,
    O: Future<Output = ()>,
    G: Future<Output = bool>,
    A: Future<Output = ()>,
{
    tokio::pin!(abort);
    let mut finished = None;
    let mut terminated = None;
    let mut output_done = false;
    loop {
        tokio::select! {
            delivered = &mut input, if finished.is_none() => finished = Some(delivered),
            () = &mut output, if !output_done => output_done = true,
            terminal = &mut guest, if terminated.is_none() => terminated = Some(terminal),
            () = stopped(stop) => break,
        }
    }
    let mut deadline = tokio::time::Instant::now() + GUEST_TCP_CLOSE_IDLE_TIMEOUT;
    let mut last_consumed = 0;
    loop {
        // The guest can reply before the writer's finish acknowledgement is polled. Cleanup
        // does not certify input completion: retain the reply and join input within the idle
        // bound before deciding whether every byte was delivered.
        if terminated == Some(false) || (terminated.is_some() && finished.is_some()) {
            break;
        }
        if finished == Some(false) {
            break;
        }
        // Create the waiter before reading the state a grant changes: a `Notified` receives
        // `notify_waiters` from its creation on, so a grant in between still wakes it.
        let credit_ready = sender.credit_ready.notified();
        let awaiting_credit = finished.is_none() || !sender.consumed().await.1;
        let credited = async {
            if awaiting_credit {
                credit_ready.await;
            } else {
                std::future::pending().await
            }
        };
        tokio::select! {
            () = &mut abort => break,
            delivered = &mut input, if finished.is_none() => {
                finished = Some(delivered);
                deadline = tokio::time::Instant::now() + GUEST_TCP_CLOSE_IDLE_TIMEOUT;
            }
            () = &mut output, if !output_done => output_done = true,
            terminal = &mut guest, if terminated.is_none() => terminated = Some(terminal),
            () = credited => {
                let (consumed, _) = sender.consumed().await;
                if finished.is_none() || consumed > last_consumed {
                    deadline = tokio::time::Instant::now() + GUEST_TCP_CLOSE_IDLE_TIMEOUT;
                }
                last_consumed = consumed;
            }
            () = tokio::time::sleep_until(deadline) => break,
        }
    }
    TcpRelayEnd {
        finished,
        terminated: terminated.unwrap_or(false),
        guest_done: terminated.is_some(),
        output_done,
    }
}

/// Cancel a guest stream that did not end with its terminal reply. agentd resets the
/// destination unless every host byte and the finish were already written.
pub(crate) async fn cancel_tcp(client: &AgentClient, id: u32, sender: &TcpBulkSender, why: &str) {
    sender.close();
    // A connection that cannot carry the cancel is lost; nothing remains to release.
    let _ = client.cancel_bulk(id, &cancel_message(why)).await;
}

/// Drain guest TCP data into `writer`, crediting each payload once written.
///
/// Once `stop` fires the output has nowhere to go: guest data is discarded but still credited,
/// so the guest keeps reading its destination while the connection closes. Returns whether the
/// guest's output ended in order; the caller shuts the writer down once it has recorded that.
pub(crate) async fn relay_tcp_output<W>(
    tcp_id: u32,
    mut output: mpsc::Receiver<TcpOutput>,
    writer: &mut W,
    client: Arc<AgentClient>,
    receiver: Arc<Mutex<BulkReceiveState>>,
    mut stop: watch::Receiver<bool>,
) -> bool
where
    W: AsyncWrite + Unpin,
{
    let mut open = true;
    let mut eof = false;
    while let Some(event) = output.recv().await {
        match event {
            TcpOutput::Data {
                payload,
                consumed_offset,
            } => {
                if open {
                    // A closed output may never take the bytes this write waits on.
                    open = tokio::select! {
                        written = writer.write_all(&payload) => written.is_ok(),
                        () = stopped(&mut stop) => false,
                    };
                }
                let credit = match receiver.lock().await.consume(consumed_offset) {
                    Ok(credit) => credit,
                    Err(error) => {
                        tracing::warn!("guest TCP: failed to advance bulk credit: {error}");
                        break;
                    }
                };
                if let Some(credit) = credit
                    && let Err(error) = client.send(tcp_id, MessageType::BulkCredit, &credit).await
                {
                    tracing::warn!("guest TCP: failed to replenish bulk credit: {error}");
                    break;
                }
            }
            TcpOutput::Eof => {
                eof = true;
                if open && writer.shutdown().await.is_err() {
                    open = false;
                }
            }
            TcpOutput::Close => break,
        }
    }
    eof && open
}

/// Pump agent frames without waiting on the output's consumer. The bounded output queue can
/// hold agentd's complete per-flow record queue, while negotiated credit independently bounds
/// its payload bytes.
///
/// Once the output relay is discarding, this keeps applying host-to-guest credit, so input sent
/// before a close can still drain. Returns whether the guest ended the stream with a terminal
/// reply.
pub(crate) async fn pump_tcp(
    mut tcp_rx: mpsc::Receiver<AgentFrame>,
    output: mpsc::Sender<TcpOutput>,
    sender: Arc<TcpBulkSender>,
    receiver: Arc<Mutex<BulkReceiveState>>,
) -> bool {
    let _close_guard = TcpRelayCloseGuard(Arc::clone(&sender));
    // A protocol failure ends byte I/O, but keeps the route open for the caller's cancellation
    // and the guest's terminal reply. Otherwise even acknowledged cleanup would be lost.
    let mut terminal = false;
    loop {
        let Some(frame) = tcp_rx.recv().await else {
            break;
        };
        match frame {
            AgentFrame::Bulk(record) => {
                let accepted = receiver.lock().await.accept_record(&record);
                let end = match accepted {
                    Ok(end) => end,
                    Err(error) => {
                        tracing::warn!("guest TCP: invalid raw record: {error}");
                        stop_tcp_output(&output, &sender).await;
                        continue;
                    }
                };
                forward(
                    &output,
                    TcpOutput::Data {
                        payload: record.payload,
                        consumed_offset: end,
                    },
                )
                .await;
            }
            AgentFrame::Control(msg) => match msg.t {
                MessageType::BulkCredit => {
                    let credit = match msg.payload::<BulkCredit>() {
                        Ok(credit) => credit,
                        Err(error) => {
                            tracing::warn!("guest TCP: failed to decode bulk credit: {error}");
                            stop_tcp_output(&output, &sender).await;
                            continue;
                        }
                    };
                    if let Err(error) = sender.apply_credit(credit).await {
                        tracing::warn!("guest TCP: invalid bulk credit: {error}");
                        stop_tcp_output(&output, &sender).await;
                    }
                }
                MessageType::BulkFinish => {
                    let finish = match msg.payload::<BulkFinish>() {
                        Ok(finish) => finish,
                        Err(error) => {
                            tracing::warn!("guest TCP: failed to decode bulk finish: {error}");
                            stop_tcp_output(&output, &sender).await;
                            continue;
                        }
                    };
                    let accepted = receiver.lock().await.accept_finish(finish);
                    if let Err(error) = accepted {
                        tracing::warn!("guest TCP: invalid bulk finish: {error}");
                        stop_tcp_output(&output, &sender).await;
                        continue;
                    }
                    forward(&output, TcpOutput::Eof).await;
                }
                MessageType::BulkCancel => {
                    match msg.payload::<BulkCancel>() {
                        Ok(cancel) => tracing::debug!(
                            reason = ?cancel.reason,
                            message = cancel.message,
                            "guest TCP: guest cancelled the bulk stream"
                        ),
                        Err(error) => {
                            tracing::warn!("guest TCP: failed to decode bulk cancellation: {error}")
                        }
                    }
                    // agentd sends the cancel before TcpFailed. End both byte directions now,
                    // but keep the route alive to receive its terminal cleanup acknowledgement.
                    stop_tcp_output(&output, &sender).await;
                }
                MessageType::TcpClosed => {
                    terminal = match msg.payload::<TcpClosed>() {
                        Ok(_) => true,
                        Err(error) => {
                            tracing::warn!("guest TCP: failed to decode tcp closed: {error}");
                            false
                        }
                    };
                    break;
                }
                MessageType::TcpFailed => {
                    match msg.payload::<TcpFailed>() {
                        Ok(failed) => {
                            tracing::debug!(error = failed.error, "guest TCP stream failed");
                            terminal = true;
                        }
                        Err(error) => {
                            tracing::warn!("guest TCP: failed to decode tcp failed: {error}")
                        }
                    }
                    break;
                }
                other => {
                    tracing::warn!(
                        message_type = other.as_str(),
                        "guest TCP: unexpected message after bulk acceptance"
                    );
                    stop_tcp_output(&output, &sender).await;
                }
            },
        }
    }

    forward(&output, TcpOutput::Close).await;
    terminal
}

/// Hand one guest event to the output relay. Once the output relay is gone the event has
/// nowhere to go.
async fn forward(output: &mpsc::Sender<TcpOutput>, event: TcpOutput) {
    let _ = output.send(event).await;
}

/// End byte delivery without ending the guest-frame consumer that owns cleanup acknowledgement.
async fn stop_tcp_output(output: &mpsc::Sender<TcpOutput>, sender: &TcpBulkSender) {
    sender.close();
    forward(output, TcpOutput::Close).await;
}

/// Wait until `stop` fires. A dropped sender is a dropped owner.
pub(crate) async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|stopped| *stopped).await;
}

//--------------------------------------------------------------------------------------------------
// Functions: reader relay
//--------------------------------------------------------------------------------------------------

/// Run one [`GuestTcpRelay`] until its guest stream is released, then publish the outcome.
async fn run_relay<R, W>(
    client: Arc<AgentClient>,
    link: TcpLink,
    reader: R,
    writer: W,
    state: Arc<RelayState>,
) where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let TcpLink {
        id,
        frames,
        sender,
        receiver,
    } = link;
    let (output_tx, output_rx) = mpsc::channel(TCP_OUTPUT_QUEUE_CAPACITY);
    let mut stop = state.stop.subscribe();
    let mut input = Box::pin(relay_reader_to_tcp(
        reader,
        Arc::clone(&client),
        id,
        Arc::clone(&sender),
        Arc::clone(&state),
    ));
    let output_stop = state.stop.subscribe();
    let output_state = Arc::clone(&state);
    let output_client = Arc::clone(&client);
    let output_receiver = Arc::clone(&receiver);
    let mut writer = writer;
    let output_writer = &mut writer;
    let mut output = Box::pin(async move {
        let eof = relay_tcp_output(
            id,
            output_rx,
            output_writer,
            output_client,
            output_receiver,
            output_stop,
        )
        .await;
        // Concurrent reads still need the truncation cause when Close stopped output delivery.
        if !eof {
            RelayState::record(
                &output_state.read_error,
                "guest TCP stream ended before the destination finished",
            );
        }
        // Output ended: start closing even if input is still waiting for bytes.
        output_state.stop.send_replace(true);
    });
    let mut guest = Box::pin(pump_tcp(frames, output_tx, Arc::clone(&sender), receiver));
    let mut intent = state.intent.subscribe();
    let end = supervise_tcp(
        &sender,
        input.as_mut(),
        output.as_mut(),
        guest.as_mut(),
        &mut stop,
        async {
            let _ = intent.wait_for(|intent| *intent == Intent::Abort).await;
        },
    )
    .await;
    // Record why before the reader and writer close: the owner asks once it sees them end.
    let delivered = end.finished == Some(true) && sender.consumed().await.1;
    if !delivered && *state.intent.borrow() != Intent::Abort {
        RelayState::record(
            &state.write_error,
            "guest TCP stream ended before every byte reached the destination",
        );
    }
    // The pump must reach the terminal reply below without waiting on an output nobody drains.
    if !end.output_done {
        RelayState::record(
            &state.read_error,
            "guest TCP output was closed before delivery finished",
        );
    }
    // Stop input before exposing a failed output's end to the owner. Otherwise Read can
    // report failure while the socket pair or duplex pipe still accepts a later Write.
    // Ordered guest EOF already half-closed output in relay_tcp_output and leaves input usable.
    drop(input);
    drop(output);
    drop(writer);
    let terminated = end.terminated || {
        let released = async {
            cancel_tcp(&client, id, &sender, "guest TCP connection released").await;
            if end.guest_done { false } else { guest.await }
        };
        tokio::time::timeout(GUEST_TCP_CLOSE_IDLE_TIMEOUT, released)
            .await
            .unwrap_or(false)
    };
    state.outcome.send_replace(Some(RelayOutcome {
        delivered,
        cleanup: if terminated {
            GuestTcpCleanup::Acknowledged
        } else {
            GuestTcpCleanup::Unknown
        },
    }));
}

/// Forward the reader's bytes to the guest. Its end of stream finishes the guest stream only
/// when the owner asked for that first; otherwise it aborts. Returns whether the stream was
/// finished in order.
async fn relay_reader_to_tcp<R>(
    mut reader: R,
    client: Arc<AgentClient>,
    id: u32,
    sender: Arc<TcpBulkSender>,
    state: Arc<RelayState>,
) -> bool
where
    R: AsyncRead + Unpin,
{
    let mut intent = state.intent.subscribe();
    let mut buffer = vec![0; TCP_READ_CHUNK];
    let failure = loop {
        let read = tokio::select! {
            biased;
            _ = intent.wait_for(|intent| *intent == Intent::Abort) => return false,
            read = reader.read(&mut buffer) => read,
        };
        match read {
            Ok(0) => {
                if *intent.borrow() < Intent::Finish {
                    // A dropped or lost owner is not an orderly end; never finish for it.
                    state.raise(Intent::Abort);
                    state.stop.send_replace(true);
                    return false;
                }
                match sender.finish(&client, id).await {
                    Ok(()) => return true,
                    Err(error) => break error.to_string(),
                }
            }
            Ok(read) => {
                let sent = tokio::select! {
                    biased;
                    _ = intent.wait_for(|intent| *intent == Intent::Abort) => return false,
                    sent = sender.send(&client, id, Bytes::copy_from_slice(&buffer[..read])) => sent,
                };
                if let Err(error) = sent {
                    break error.to_string();
                }
            }
            Err(error) => break format!("read from the relayed reader: {error}"),
        }
    };
    RelayState::record(&state.write_error, failure);
    sender.close();
    state.stop.send_replace(true);
    false
}

async fn next_control(frames: &mut mpsc::Receiver<AgentFrame>) -> Result<Message, String> {
    match frames.recv().await {
        Some(AgentFrame::Control(message)) => Ok(message),
        Some(AgentFrame::Bulk(_)) => Err("raw data arrived before the connect reply".into()),
        None => Err("agent stream closed before the connect reply".into()),
    }
}

fn cancel_message(message: &str) -> BulkCancel {
    BulkCancel {
        kind: BulkKind::Tcp,
        reason: BulkCancelReason::CallerCancelled,
        message: message.into(),
    }
}

fn bulk_error(context: &str, error: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::Custom(format!("{context}: {error}"))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
#[path = "tcp_test_agent.rs"]
pub(crate) mod test_agent;

#[cfg(test)]
#[path = "tcp_tests.rs"]
mod tests;
