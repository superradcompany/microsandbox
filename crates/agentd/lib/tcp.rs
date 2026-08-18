//! Guest-side TCP stream session handling.
//!
//! Handles `core.tcp.*` protocol messages by opening TCP sockets from
//! inside the guest and relaying bytes between those sockets and the host.

use std::time::Duration;

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;

use microsandbox_protocol::bulk::{
    BULK_FLOW_MASK_GUEST_TO_HOST, BULK_FLOW_MASK_HOST_TO_GUEST, BulkAccepted, BulkCredit,
    BulkFinish, BulkFlow, BulkKind, BulkOffer, BulkReceiveState, BulkRecord, BulkSendState,
    DEFAULT_BULK_RECORD_PAYLOAD, DEFAULT_BULK_WINDOW, MIN_BULK_RECORD_PAYLOAD,
};
use microsandbox_protocol::codec;
use microsandbox_protocol::message::{Message, MessageType};
use microsandbox_protocol::tcp::{TcpClosed, TcpConnect, TcpConnected, TcpData, TcpEof, TcpFailed};

#[cfg(test)]
use crate::session::SessionOutputEnvelope;
use crate::session::{
    BulkSessionOutput, RawActivity, RawSessionCompletion, RawSessionOutput, SessionOutput,
    SessionOutputPermit, SessionOutputSender,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// TCP stream read chunk size.
const TCP_CHUNK_SIZE: usize = 64 * 1024;

/// Capacity reserved before cloning and encoding one TCP data chunk.
///
/// The factor of two covers CBOR/framing overhead and allocator growth while keeping hundreds of
/// TCP chunks eligible under the aggregate 32 MiB output budget.
const TCP_OUTPUT_RESERVATION: usize = 2 * TCP_CHUNK_SIZE;

/// Enough host-to-guest data slots for the default byte window at the smallest negotiated record.
/// Lifecycle and absolute-credit updates use separate channels and cannot consume these slots.
const TCP_COMMAND_CAPACITY: usize = DEFAULT_BULK_WINDOW as usize / MIN_BULK_RECORD_PAYLOAD as usize;

/// Upper bound on a single guest-side connect attempt. The connect runs in the
/// per-session task, so this only bounds that task's lifetime; it never blocks
/// the agent's serial loop.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Tracks an active guest-originated TCP stream.
pub struct TcpSession {
    owner_id: u32,
    commands: mpsc::Sender<TcpCommand>,
    bulk_control: Option<TcpBulkControlSenders>,
    task: JoinHandle<()>,
    bulk: bool,
}

enum TcpCommand {
    Data(Vec<u8>),
    Eof,
    BulkRecord(BulkRecord),
}

/// Coalescing lifecycle channels that cannot be starved by a full TCP data queue.
struct TcpBulkControlSenders {
    credit: watch::Sender<Option<BulkCredit>>,
    finish: mpsc::Sender<BulkFinish>,
}

struct TcpBulkControlReceivers {
    credit: watch::Receiver<Option<BulkCredit>>,
    finish: mpsc::Receiver<BulkFinish>,
}

struct TcpBulkState {
    send: BulkSendState,
    receive: BulkReceiveState,
}

/// One ordered host-to-guest record being written incrementally. Keeping at most one record here
/// preserves credit semantics while allowing the opposite TCP half to keep reading concurrently.
struct PendingTcpWrite {
    payload: Bytes,
    written: usize,
    bulk_end: Option<u64>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl TcpSession {
    /// Correlation ID whose relay client owns this TCP stream.
    pub fn owner_id(&self) -> u32 {
        self.owner_id
    }

    /// Queue stream data to write to the guest socket.
    ///
    /// Awaits queue space when the per-session relay is behind, so a stalled
    /// destination backpressures the caller instead of growing memory.
    pub async fn write_data(&self, data: Vec<u8>) -> Result<(), String> {
        if self.bulk {
            return Err("CBOR TCP data is invalid after raw bulk acceptance".into());
        }
        self.commands
            .send(TcpCommand::Data(data))
            .await
            .map_err(|_| "TCP session is closed".to_string())
    }

    /// Close the guest socket write half.
    ///
    /// Ordered after any queued data, so the destination sees the write shutdown
    /// only once it has received everything sent before it.
    pub async fn close_write(&self) -> Result<(), String> {
        if self.bulk {
            return Err("CBOR TCP EOF is invalid after raw bulk acceptance".into());
        }
        self.commands
            .send(TcpCommand::Eof)
            .await
            .map_err(|_| "TCP session is closed".to_string())
    }

    /// Queue one host-to-guest raw bulk record.
    pub async fn write_bulk(&self, record: BulkRecord) -> Result<(), String> {
        if !self.bulk {
            return Err("raw bulk record sent to a generation-6 TCP stream".into());
        }
        self.commands
            .try_send(TcpCommand::BulkRecord(record))
            .map_err(|error| format!("TCP bulk input queue is unavailable: {error}"))
    }

    /// Deliver an absolute guest-to-host credit update.
    pub async fn apply_credit(&self, credit: BulkCredit) -> Result<(), String> {
        if !self.bulk {
            return Err("bulk credit sent to a generation-6 TCP stream".into());
        }
        let control = self
            .bulk_control
            .as_ref()
            .ok_or_else(|| "TCP bulk control path is unavailable".to_string())?;
        if control.credit.is_closed() {
            return Err("TCP session is closed".into());
        }
        control.credit.send_replace(Some(credit));
        Ok(())
    }

    /// Queue the exact host-to-guest half-close marker.
    pub async fn finish_bulk(&self, finish: BulkFinish) -> Result<(), String> {
        if !self.bulk {
            return Err("bulk finish sent to a generation-6 TCP stream".into());
        }
        let control = self
            .bulk_control
            .as_ref()
            .ok_or_else(|| "TCP bulk control path is unavailable".to_string())?;
        control
            .finish
            .try_send(finish)
            .map_err(|error| format!("TCP bulk finish path is unavailable: {error}"))
    }

    /// Whether this TCP session negotiated generation-7 raw bulk.
    pub fn is_bulk(&self) -> bool {
        self.bulk
    }

    /// Tear down the TCP session.
    ///
    /// Aborts the relay task directly rather than queuing a command, so teardown
    /// never waits behind a full command queue. Dropping the task closes the
    /// guest socket. The host has already closed its side before asking for this,
    /// so no terminal frame is owed back to it.
    pub fn close(&self) {
        self.task.abort();
    }

    /// Returns whether the background relay task has finished.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Open a TCP stream from inside the guest and start relaying it.
    ///
    /// The OS connect runs inside the spawned task, not on the caller's serial
    /// loop, so a hanging or slow destination can never wedge the agent. The
    /// task reports `core.tcp.connected` on success or a terminal
    /// `core.tcp.failed` on error/timeout over `session_tx`; the host correlates
    /// either reply by id. The returned session is live immediately, with
    /// commands queued until the connect completes.
    pub fn open(id: u32, req: TcpConnect, session_tx: &SessionOutputSender) -> Self {
        let bulk = req.bulk.is_some();
        let (commands_tx, commands_rx) = mpsc::channel(TCP_COMMAND_CAPACITY);
        let (bulk_control, bulk_control_rx) = if bulk {
            let (credit_tx, credit_rx) = watch::channel(None);
            let (finish_tx, finish_rx) = mpsc::channel(1);
            (
                Some(TcpBulkControlSenders {
                    credit: credit_tx,
                    finish: finish_tx,
                }),
                Some(TcpBulkControlReceivers {
                    credit: credit_rx,
                    finish: finish_rx,
                }),
            )
        } else {
            (None, None)
        };
        let output_tx = session_tx.clone();
        let task = tokio::spawn(async move {
            connect_and_relay(id, req, commands_rx, bulk_control_rx, output_tx).await;
        });

        Self {
            owner_id: id,
            commands: commands_tx,
            bulk_control,
            task,
            bulk,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Connects to the destination, reports the outcome, then relays the stream.
///
/// Runs entirely inside the per-session task. On a connect error or timeout it
/// emits a terminal `core.tcp.failed`; the agent loop removes the session when
/// that frame flows past. On success it emits `core.tcp.connected` and hands off
/// to the relay loop.
async fn connect_and_relay(
    id: u32,
    req: TcpConnect,
    commands: mpsc::Receiver<TcpCommand>,
    bulk_control: Option<TcpBulkControlReceivers>,
    tx: SessionOutputSender,
) {
    let TcpConnect { host, port, bulk } = req;
    let connect = TcpStream::connect((host.as_str(), port));
    let stream = match tokio::time::timeout(TCP_CONNECT_TIMEOUT, connect).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            send_raw_tcp_message(
                id,
                MessageType::TcpFailed,
                &TcpFailed {
                    error: format!("connect {host}:{port}: {e}"),
                },
                RawActivity::guest_message(),
                Some(RawSessionCompletion::Tcp),
                &tx,
            )
            .await;
            return;
        }
        Err(_elapsed) => {
            send_raw_tcp_message(
                id,
                MessageType::TcpFailed,
                &TcpFailed {
                    error: format!("connect {host}:{port} timed out"),
                },
                RawActivity::guest_message(),
                Some(RawSessionCompletion::Tcp),
                &tx,
            )
            .await;
            return;
        }
    };

    if !send_raw_tcp_message(
        id,
        MessageType::TcpConnected,
        &TcpConnected {},
        RawActivity::guest_message(),
        None,
        &tx,
    )
    .await
    {
        return;
    }

    let bulk = match bulk {
        Some(offer) => {
            let accepted = match accept_tcp_offer(offer) {
                Ok(accepted) => accepted,
                Err(error) => {
                    send_raw_tcp_message(
                        id,
                        MessageType::TcpFailed,
                        &TcpFailed { error },
                        RawActivity::guest_message(),
                        Some(RawSessionCompletion::Tcp),
                        &tx,
                    )
                    .await;
                    return;
                }
            };
            if !send_raw_tcp_message(
                id,
                MessageType::BulkAccepted,
                &accepted,
                RawActivity::guest_message(),
                None,
                &tx,
            )
            .await
            {
                return;
            }
            let send = match BulkSendState::new(
                BulkKind::Tcp,
                BulkFlow::GuestToHost,
                accepted.max_record_payload,
                accepted.guest_to_host_credit_limit,
            ) {
                Ok(send) => send,
                Err(error) => {
                    eprintln!("failed to create TCP bulk send state for {id}: {error}");
                    return;
                }
            };
            let receive = match BulkReceiveState::new(
                BulkKind::Tcp,
                BulkFlow::HostToGuest,
                accepted.max_record_payload,
                accepted.host_to_guest_credit_limit,
                DEFAULT_BULK_WINDOW,
            ) {
                Ok(receive) => receive,
                Err(error) => {
                    eprintln!("failed to create TCP bulk receive state for {id}: {error}");
                    return;
                }
            };
            Some(TcpBulkState { send, receive })
        }
        None => None,
    };

    relay_tcp_session(id, stream, commands, bulk_control, tx, bulk).await;
}

fn accept_tcp_offer(offer: BulkOffer) -> Result<BulkAccepted, String> {
    let offer = offer
        .validate()
        .map_err(|error| format!("invalid TCP bulk offer: {error}"))?;
    if offer.guest_to_host_credit_limit == 0 {
        return Err("TCP bulk offer must grant guest-to-host credit".into());
    }
    Ok(BulkAccepted {
        kind: BulkKind::Tcp,
        flows: BULK_FLOW_MASK_HOST_TO_GUEST | BULK_FLOW_MASK_GUEST_TO_HOST,
        format: offer.format,
        max_record_payload: offer.max_record_payload.min(DEFAULT_BULK_RECORD_PAYLOAD),
        host_to_guest_credit_limit: DEFAULT_BULK_WINDOW,
        guest_to_host_credit_limit: offer.guest_to_host_credit_limit,
    })
}

/// Receive lifecycle data without making a non-bulk session's select loop spin.
async fn recv_optional_mpsc<T>(receiver: &mut Option<mpsc::Receiver<T>>) -> Option<T> {
    loop {
        let Some(active) = receiver.as_mut() else {
            return std::future::pending().await;
        };
        match active.recv().await {
            Some(value) => return Some(value),
            None => *receiver = None,
        }
    }
}

/// Return only the newest absolute credit update; intermediate grants are intentionally coalesced.
async fn recv_optional_credit(
    receiver: &mut Option<watch::Receiver<Option<BulkCredit>>>,
) -> Option<BulkCredit> {
    loop {
        let Some(active) = receiver.as_mut() else {
            return std::future::pending().await;
        };
        if active.changed().await.is_err() {
            *receiver = None;
            continue;
        }
        if let Some(credit) = *active.borrow_and_update() {
            return Some(credit);
        }
    }
}

/// Apply an overtaking half-close only after the data worker has consumed every prior record.
async fn apply_pending_tcp_finish<W>(
    stream: &mut W,
    state: &mut TcpBulkState,
    pending: &mut Option<BulkFinish>,
) -> Result<(), String>
where
    W: AsyncWrite + Unpin,
{
    let Some(finish) = *pending else {
        return Ok(());
    };
    if finish.kind != BulkKind::Tcp || finish.flow != BulkFlow::HostToGuest {
        return Err("bulk finish does not describe the TCP host-to-guest flow".into());
    }
    if finish.final_offset > state.receive.next_expected_offset() {
        return Ok(());
    }
    state
        .receive
        .accept_finish(finish)
        .map_err(|error| error.to_string())?;
    stream
        .shutdown()
        .await
        .map_err(|error| format!("shutdown TCP stream: {error}"))?;
    *pending = None;
    Ok(())
}

async fn relay_tcp_session(
    id: u32,
    stream: TcpStream,
    mut commands: mpsc::Receiver<TcpCommand>,
    bulk_control: Option<TcpBulkControlReceivers>,
    tx: SessionOutputSender,
    mut bulk: Option<TcpBulkState>,
) {
    // A single task still owns protocol state, but independent socket halves let a blocked
    // destination write make progress concurrently with guest-to-host reads.
    let (mut reader, mut writer) = stream.into_split();
    let (mut credit_rx, mut finish_rx) = match bulk_control {
        Some(control) => (Some(control.credit), Some(control.finish)),
        None => (None, None),
    };
    let mut pending_finish = None;
    let read_capacity = bulk.as_ref().map_or(TCP_CHUNK_SIZE, |state| {
        state.send.max_record_payload() as usize
    });
    let mut read_buf = vec![0u8; read_capacity];
    let mut terminal_sent = false;
    let mut pending_write: Option<PendingTcpWrite> = None;
    let mut write_shutdown = false;
    // The destination half-closed its write side. We stop reading but keep the
    // loop alive so host->destination data still flows until the host closes.
    let mut read_eof = false;

    loop {
        let read_limit = bulk.as_ref().map_or(TCP_CHUNK_SIZE, |state| {
            state
                .send
                .available_credit()
                .min(state.send.max_record_payload() as u64) as usize
        });
        tokio::select! {
            Some(finish) = recv_optional_mpsc(&mut finish_rx) => {
                if pending_finish.replace(finish).is_some() {
                    terminal_sent = send_tcp_failure(
                        id,
                        "duplicate TCP bulk finish".into(),
                        &tx,
                    )
                    .await;
                    break;
                }
                let Some(state) = bulk.as_mut() else {
                    terminal_sent = send_tcp_failure(
                        id,
                        "bulk finish received on a generation-6 TCP stream".into(),
                        &tx,
                    )
                    .await;
                    break;
                };
                if pending_write.is_none() {
                    if let Err(error) = apply_pending_tcp_finish(
                        &mut writer,
                        state,
                        &mut pending_finish,
                    ).await {
                        terminal_sent = send_tcp_failure(
                            id,
                            format!("invalid TCP bulk finish: {error}"),
                            &tx,
                        )
                        .await;
                        break;
                    }
                    write_shutdown = pending_finish.is_none();
                }
            }
            Some(credit) = recv_optional_credit(&mut credit_rx) => {
                let Some(state) = bulk.as_mut() else {
                    terminal_sent = send_tcp_failure(
                        id,
                        "bulk credit received on a generation-6 TCP stream".into(),
                        &tx,
                    )
                    .await;
                    break;
                };
                if let Err(error) = state.send.apply_credit(credit) {
                    terminal_sent = send_tcp_failure(
                        id,
                        format!("invalid TCP bulk credit: {error}"),
                        &tx,
                    )
                    .await;
                    break;
                }
            }
            read = reader.read(&mut read_buf[..read_limit]), if !read_eof && read_limit != 0 => {
                match read {
                    Ok(0) => {
                        if let Some(state) = bulk.as_mut() {
                            match state.send.finish() {
                                Ok(finish) => {
                                    send_raw_tcp_message(
                                        id,
                                        MessageType::BulkFinish,
                                        &finish,
                                        RawActivity::guest_message(),
                                        None,
                                        &tx,
                                    )
                                    .await;
                                }
                                Err(error) => {
                                    eprintln!("failed to finish TCP bulk receive flow {id}: {error}");
                                    break;
                                }
                            }
                        } else {
                            send_raw_tcp_message(
                                id,
                                MessageType::TcpEof,
                                &TcpEof {},
                                RawActivity::guest_message(),
                                None,
                                &tx,
                            )
                            .await;
                        }
                        read_eof = true;
                    }
                    Ok(n) => {
                        if let Some(state) = bulk.as_mut() {
                            let offset = match state.send.admit(n) {
                                Ok(offset) => offset,
                                Err(error) => {
                                    eprintln!("failed to admit TCP bulk record {id}: {error}");
                                    break;
                                }
                            };
                            let Some(permit) = tx.reserve_bulk(n).await else {
                                break;
                            };
                            let record = BulkRecord {
                                id,
                                kind: BulkKind::Tcp,
                                flow: BulkFlow::GuestToHost,
                                offset,
                                payload: Bytes::copy_from_slice(&read_buf[..n]),
                            };
                            if !tx
                                .send_reserved(
                                    id,
                                    SessionOutput::Bulk(BulkSessionOutput::new(
                                        record,
                                        RawActivity::tcp_bytes(n),
                                    )),
                                    permit,
                                )
                                .await
                            {
                                break;
                            }
                        } else {
                            let Some(permit) = tx.reserve(TCP_OUTPUT_RESERVATION).await else {
                                break;
                            };
                            let data = read_buf[..n].to_vec();
                            if !send_raw_tcp_data(id, data, n, permit, &tx).await {
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        terminal_sent = send_raw_tcp_message(
                            id,
                            MessageType::TcpFailed,
                            &TcpFailed {
                                error: format!("read TCP stream: {e}"),
                            },
                            RawActivity::guest_message(),
                            Some(RawSessionCompletion::Tcp),
                            &tx,
                        )
                        .await;
                        break;
                    }
                }
            }
            write = async {
                let pending = pending_write.as_ref().expect("guarded pending TCP write");
                writer.write(&pending.payload[pending.written..]).await
            }, if pending_write.is_some() => {
                match write {
                    Ok(0) => {
                        terminal_sent = send_tcp_failure(
                            id,
                            "write TCP stream made no progress".into(),
                            &tx,
                        )
                        .await;
                        break;
                    }
                    Ok(written) => {
                        let pending = pending_write.as_mut().expect("guarded pending TCP write");
                        pending.written += written;
                        if pending.written != pending.payload.len() {
                            continue;
                        }

                        let completed = pending_write.take().expect("completed TCP write exists");
                        if let Some(end) = completed.bulk_end {
                            let Some(state) = bulk.as_mut() else {
                                terminal_sent = send_tcp_failure(
                                    id,
                                    "bulk TCP write lost its protocol state".into(),
                                    &tx,
                                )
                                .await;
                                break;
                            };
                            match state.receive.consume(end) {
                                Ok(Some(credit)) => {
                                    if !send_raw_tcp_message(
                                        id,
                                        MessageType::BulkCredit,
                                        &credit,
                                        RawActivity::guest_message(),
                                        None,
                                        &tx,
                                    )
                                    .await
                                    {
                                        break;
                                    }
                                }
                                Ok(None) => {}
                                Err(error) => {
                                    terminal_sent = send_tcp_failure(
                                        id,
                                        format!("advance TCP bulk credit: {error}"),
                                        &tx,
                                    )
                                    .await;
                                    break;
                                }
                            }
                            let finish_was_pending = pending_finish.is_some();
                            if let Err(error) = apply_pending_tcp_finish(
                                &mut writer,
                                state,
                                &mut pending_finish,
                            ).await {
                                terminal_sent = send_tcp_failure(
                                    id,
                                    format!("invalid TCP bulk finish: {error}"),
                                    &tx,
                                )
                                .await;
                                break;
                            }
                            if finish_was_pending && pending_finish.is_none() {
                                write_shutdown = true;
                            }
                        }
                    }
                    Err(error) => {
                        terminal_sent = send_raw_tcp_message(
                            id,
                            MessageType::TcpFailed,
                            &TcpFailed {
                                error: format!("write TCP stream: {error}"),
                            },
                            RawActivity::guest_message(),
                            Some(RawSessionCompletion::Tcp),
                            &tx,
                        )
                        .await;
                        break;
                    }
                }
            }
            command = commands.recv(), if pending_write.is_none() && !write_shutdown => {
                match command {
                    Some(TcpCommand::Data(data)) => {
                        if bulk.is_some() {
                            terminal_sent = send_tcp_failure(
                                id,
                                "CBOR TCP data received after raw bulk acceptance".into(),
                                &tx,
                            )
                            .await;
                            break;
                        }
                        pending_write = Some(PendingTcpWrite {
                            payload: Bytes::from(data),
                            written: 0,
                            bulk_end: None,
                        });
                    }
                    Some(TcpCommand::Eof) => {
                        if bulk.is_some() {
                            terminal_sent = send_tcp_failure(
                                id,
                                "CBOR TCP EOF received after raw bulk acceptance".into(),
                                &tx,
                            )
                            .await;
                            break;
                        }
                        if let Err(e) = writer.shutdown().await {
                            terminal_sent = send_raw_tcp_message(
                                id,
                                MessageType::TcpFailed,
                                &TcpFailed {
                                    error: format!("shutdown TCP stream: {e}"),
                                },
                                RawActivity::guest_message(),
                                Some(RawSessionCompletion::Tcp),
                                &tx,
                            )
                            .await;
                            break;
                        }
                        write_shutdown = true;
                    }
                    None => {
                        break;
                    }
                    Some(TcpCommand::BulkRecord(record)) => {
                        let Some(state) = bulk.as_mut() else {
                            terminal_sent = send_tcp_failure(
                                id,
                                "raw bulk record received on a generation-6 TCP stream".into(),
                                &tx,
                            )
                            .await;
                            break;
                        };
                        let end = match state.receive.accept_record(&record) {
                            Ok(end) => end,
                            Err(error) => {
                                terminal_sent = send_tcp_failure(
                                    id,
                                    format!("invalid TCP bulk record: {error}"),
                                    &tx,
                                )
                                .await;
                                break;
                            }
                        };
                        pending_write = Some(PendingTcpWrite {
                            payload: record.payload,
                            written: 0,
                            bulk_end: Some(end),
                        });
                    }
                }
            }
        }
    }

    if !terminal_sent {
        send_raw_tcp_message(
            id,
            MessageType::TcpClosed,
            &TcpClosed {},
            RawActivity::guest_message(),
            Some(RawSessionCompletion::Tcp),
            &tx,
        )
        .await;
    }
}

async fn send_tcp_failure(id: u32, error: String, tx: &SessionOutputSender) -> bool {
    send_raw_tcp_message(
        id,
        MessageType::TcpFailed,
        &TcpFailed { error },
        RawActivity::guest_message(),
        Some(RawSessionCompletion::Tcp),
        tx,
    )
    .await
}

fn encode_tcp_message<T: serde::Serialize>(
    id: u32,
    t: MessageType,
    payload: &T,
    out_buf: &mut Vec<u8>,
) -> Result<(), String> {
    let msg = Message::with_payload(t, id, payload).map_err(|e| format!("encode tcp: {e}"))?;
    codec::encode_to_buf(&msg, out_buf).map_err(|e| format!("encode tcp frame: {e}"))?;
    Ok(())
}

async fn send_raw_tcp_message<T: serde::Serialize>(
    id: u32,
    t: MessageType,
    payload: &T,
    activity: RawActivity,
    completion: Option<RawSessionCompletion>,
    tx: &SessionOutputSender,
) -> bool {
    let mut buf = Vec::new();
    match encode_tcp_message(id, t, payload, &mut buf) {
        Ok(()) => {
            tx.send(
                id,
                SessionOutput::Raw(RawSessionOutput::new(buf, activity, completion)),
            )
            .await
        }
        Err(e) => {
            eprintln!("failed to encode tcp message for {id}: {e}");
            false
        }
    }
}

/// Encode a TCP data event only after its retained allocation has reserved capacity.
async fn send_raw_tcp_data(
    id: u32,
    data: Vec<u8>,
    byte_count: usize,
    permit: SessionOutputPermit,
    tx: &SessionOutputSender,
) -> bool {
    let mut buf = Vec::new();
    match encode_tcp_message(id, MessageType::TcpData, &TcpData { data }, &mut buf) {
        Ok(()) => {
            tx.send_reserved(
                id,
                SessionOutput::Raw(RawSessionOutput::new(
                    buf,
                    RawActivity::tcp_bytes(byte_count),
                    None,
                )),
                permit,
            )
            .await
        }
        Err(error) => {
            eprintln!("failed to encode TCP data for {id}: {error}");
            false
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use microsandbox_protocol::message::FLAG_TERMINAL;
    use tokio::net::TcpListener;

    use super::*;

    #[tokio::test]
    async fn connect_failure_sends_terminal_failed() {
        let (session_tx, mut session_rx) = SessionOutputSender::channel();

        let session = TcpSession::open(
            7,
            TcpConnect {
                host: "127.0.0.1".to_string(),
                port: 0,
                bulk: None,
            },
            &session_tx,
        );

        // The connect runs in the task and reports failure over session_tx.
        let msg = recv_message(&mut session_rx).await;
        assert_eq!(msg.t, MessageType::TcpFailed);
        assert_eq!(msg.flags, FLAG_TERMINAL);
        let failed: TcpFailed = msg.payload().unwrap();
        assert!(failed.error.contains("connect 127.0.0.1:0"));

        wait_finished(&session).await;
    }

    #[tokio::test]
    async fn close_request_finishes_session_task() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (session_tx, mut session_rx) = SessionOutputSender::channel();
        let accept_task = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let session = TcpSession::open(
            9,
            TcpConnect {
                host: "127.0.0.1".to_string(),
                port,
                bulk: None,
            },
            &session_tx,
        );

        let connected = recv_message(&mut session_rx).await;
        assert_eq!(connected.t, MessageType::TcpConnected);

        session.close();
        wait_finished(&session).await;

        accept_task.abort();
    }

    #[tokio::test]
    async fn destination_eof_keeps_session_open_for_host_writes() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (session_tx, mut session_rx) = SessionOutputSender::channel();

        // The destination half-closes its write side, then keeps reading so it
        // still receives whatever the host sends after the EOF.
        let (got_tx, got_rx) = tokio::sync::oneshot::channel();
        let accept_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.shutdown().await.unwrap();
            let mut buf = Vec::new();
            socket.read_to_end(&mut buf).await.unwrap();
            let _ = got_tx.send(buf);
        });

        let session = TcpSession::open(
            11,
            TcpConnect {
                host: "127.0.0.1".to_string(),
                port,
                bulk: None,
            },
            &session_tx,
        );

        let connected = recv_message(&mut session_rx).await;
        assert_eq!(connected.t, MessageType::TcpConnected);

        // The destination's FIN surfaces as a non-terminal TcpEof, and the
        // session stays alive.
        let eof = recv_message(&mut session_rx).await;
        assert_eq!(eof.t, MessageType::TcpEof);
        assert_ne!(eof.flags, FLAG_TERMINAL);
        assert!(!session.is_finished());

        // The host can still reach the destination after that EOF.
        session.write_data(b"after-eof".to_vec()).await.unwrap();
        session.close_write().await.unwrap();
        let received = tokio::time::timeout(Duration::from_secs(1), got_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, b"after-eof");

        // An explicit close tears the session down.
        session.close();
        wait_finished(&session).await;

        accept_task.await.unwrap();
    }

    #[tokio::test]
    async fn raw_bulk_tcp_relays_both_directions_and_exact_half_closes() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (session_tx, mut session_rx) = SessionOutputSender::channel();
        let (got_tx, got_rx) = tokio::sync::oneshot::channel();
        let accept_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(b"from-destination").await.unwrap();
            socket.shutdown().await.unwrap();
            let mut received = Vec::new();
            socket.read_to_end(&mut received).await.unwrap();
            got_tx.send(received).unwrap();
        });

        let session = TcpSession::open(
            13,
            TcpConnect {
                host: "127.0.0.1".to_string(),
                port,
                bulk: Some(BulkOffer::tcp()),
            },
            &session_tx,
        );
        assert_eq!(
            recv_message(&mut session_rx).await.t,
            MessageType::TcpConnected
        );
        assert_eq!(
            recv_message(&mut session_rx).await.t,
            MessageType::BulkAccepted
        );

        let host_payload = Bytes::from_static(b"from-host");
        session
            .write_bulk(BulkRecord {
                id: 13,
                kind: BulkKind::Tcp,
                flow: BulkFlow::HostToGuest,
                offset: 0,
                payload: host_payload.clone(),
            })
            .await
            .unwrap();
        session
            .finish_bulk(BulkFinish {
                kind: BulkKind::Tcp,
                flow: BulkFlow::HostToGuest,
                final_offset: host_payload.len() as u64,
            })
            .await
            .unwrap();

        let record = recv_bulk(&mut session_rx).await;
        assert_eq!(record.flow, BulkFlow::GuestToHost);
        assert_eq!(record.offset, 0);
        assert_eq!(record.payload, Bytes::from_static(b"from-destination"));
        let finish = recv_message(&mut session_rx).await;
        assert_eq!(finish.t, MessageType::BulkFinish);
        let finish: BulkFinish = finish.payload().unwrap();
        assert_eq!(finish.final_offset, b"from-destination".len() as u64);

        let received = tokio::time::timeout(Duration::from_secs(1), got_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received, host_payload);
        session.close();
        wait_finished(&session).await;
        accept_task.await.unwrap();
    }

    #[tokio::test]
    async fn blocked_host_to_guest_write_does_not_stop_guest_to_host_reads() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (session_tx, mut session_rx) = SessionOutputSender::channel();
        let host_payload = Bytes::from(vec![0x3c; DEFAULT_BULK_RECORD_PAYLOAD as usize]);
        let guest_payload = vec![0x7a; DEFAULT_BULK_WINDOW as usize];
        let expected_guest_payload = guest_payload.clone();
        let expected_host_payload = host_payload.clone();
        let host_payload_len = host_payload.len();
        let (got_tx, got_rx) = tokio::sync::oneshot::channel();

        // Both peers deliberately fill their send side before reading the other direction. A
        // single write_all/read loop deadlocks here once the kernel buffers fill; split halves do
        // not, because agentd keeps draining the destination while its write is pending.
        let accept_task = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut received = vec![0u8; host_payload_len];
            socket.read_exact(&mut received[..1]).await.unwrap();
            socket.write_all(&guest_payload).await.unwrap();
            socket.read_exact(&mut received[1..]).await.unwrap();
            got_tx.send(received).unwrap();
        });

        let session = TcpSession::open(
            17,
            TcpConnect {
                host: "127.0.0.1".to_string(),
                port,
                bulk: Some(BulkOffer::tcp()),
            },
            &session_tx,
        );
        assert_eq!(
            recv_message(&mut session_rx).await.t,
            MessageType::TcpConnected
        );
        assert_eq!(
            recv_message(&mut session_rx).await.t,
            MessageType::BulkAccepted
        );

        session
            .write_bulk(BulkRecord {
                id: 17,
                kind: BulkKind::Tcp,
                flow: BulkFlow::HostToGuest,
                offset: 0,
                payload: host_payload,
            })
            .await
            .unwrap();

        let received_guest_payload = tokio::time::timeout(Duration::from_secs(5), async {
            let mut received = Vec::with_capacity(expected_guest_payload.len());
            while received.len() < expected_guest_payload.len() {
                let record = recv_bulk(&mut session_rx).await;
                assert_eq!(record.offset, received.len() as u64);
                received.extend_from_slice(&record.payload);
            }
            received
        })
        .await
        .expect("guest-to-host reads must progress while the opposite write is blocked");
        assert_eq!(received_guest_payload, expected_guest_payload);

        let received_host_payload = tokio::time::timeout(Duration::from_secs(5), got_rx)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(received_host_payload, expected_host_payload);

        session.close();
        wait_finished(&session).await;
        accept_task.await.unwrap();
    }

    #[tokio::test]
    async fn full_bulk_data_queue_does_not_starve_credit_or_finish() {
        let (commands, _commands_rx) = mpsc::channel(TCP_COMMAND_CAPACITY);
        let (credit, mut credit_rx) = watch::channel(None);
        let (finish, mut finish_rx) = mpsc::channel(1);
        let task = tokio::spawn(std::future::pending());
        let session = TcpSession {
            owner_id: 29,
            commands,
            bulk_control: Some(TcpBulkControlSenders { credit, finish }),
            task,
            bulk: true,
        };
        let payload = Bytes::from(vec![0u8; MIN_BULK_RECORD_PAYLOAD as usize]);

        for index in 0..TCP_COMMAND_CAPACITY {
            session
                .write_bulk(BulkRecord {
                    id: 29,
                    kind: BulkKind::Tcp,
                    flow: BulkFlow::HostToGuest,
                    offset: (index * MIN_BULK_RECORD_PAYLOAD as usize) as u64,
                    payload: payload.clone(),
                })
                .await
                .unwrap();
        }
        assert_eq!(session.commands.capacity(), 0);

        let credit_update = BulkCredit {
            kind: BulkKind::Tcp,
            flow: BulkFlow::GuestToHost,
            consumed_offset: 4,
            credit_limit: 8,
        };
        session.apply_credit(credit_update).await.unwrap();
        credit_rx.changed().await.unwrap();
        assert_eq!(*credit_rx.borrow_and_update(), Some(credit_update));

        let finish_update = BulkFinish {
            kind: BulkKind::Tcp,
            flow: BulkFlow::HostToGuest,
            final_offset: DEFAULT_BULK_WINDOW,
        };
        session.finish_bulk(finish_update).await.unwrap();
        assert_eq!(finish_rx.recv().await, Some(finish_update));

        session.close();
    }

    async fn wait_finished(session: &TcpSession) {
        tokio::time::timeout(Duration::from_secs(1), async {
            while !session.is_finished() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();
    }

    fn decode_one_message(buf: &mut Vec<u8>) -> Message {
        codec::try_decode_from_buf(buf).unwrap().unwrap()
    }

    async fn recv_message(rx: &mut mpsc::Receiver<SessionOutputEnvelope>) -> Message {
        let envelope = rx.recv().await.unwrap();
        let SessionOutput::Raw(mut output) = envelope.output else {
            panic!("expected SessionOutput::Raw frame");
        };
        decode_one_message(&mut output.frame)
    }

    async fn recv_bulk(rx: &mut mpsc::Receiver<SessionOutputEnvelope>) -> BulkRecord {
        let envelope = rx.recv().await.unwrap();
        let SessionOutput::Bulk(output) = envelope.output else {
            panic!("expected SessionOutput::Bulk record");
        };
        output.record
    }
}
