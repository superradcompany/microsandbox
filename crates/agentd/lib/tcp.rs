//! Guest-side TCP stream session handling.
//!
//! Handles `core.tcp.*` protocol messages by opening TCP sockets from
//! inside the guest and relaying bytes between those sockets and the host.

use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use microsandbox_protocol::codec;
use microsandbox_protocol::message::{Message, MessageType};
use microsandbox_protocol::tcp::{TcpClosed, TcpConnect, TcpConnected, TcpData, TcpEof, TcpFailed};

use crate::session::SessionOutput;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// TCP stream read chunk size.
const TCP_CHUNK_SIZE: usize = 64 * 1024;

/// How many host->guest command frames may queue before the agent loop has to
/// wait. Bounding this turns a slow or stalled destination into backpressure
/// (the serial reader pauses, which throttles the SSH window) instead of
/// unbounded guest memory growth.
const TCP_COMMAND_CAPACITY: usize = 32;

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
    task: JoinHandle<()>,
}

enum TcpCommand {
    Data(Vec<u8>),
    Eof,
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
        self.commands
            .send(TcpCommand::Eof)
            .await
            .map_err(|_| "TCP session is closed".to_string())
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
    pub fn open(
        id: u32,
        req: TcpConnect,
        session_tx: &mpsc::UnboundedSender<(u32, SessionOutput)>,
    ) -> Self {
        let (commands_tx, commands_rx) = mpsc::channel(TCP_COMMAND_CAPACITY);
        let output_tx = session_tx.clone();
        let task = tokio::spawn(async move {
            connect_and_relay(id, req, commands_rx, output_tx).await;
        });

        Self {
            owner_id: id,
            commands: commands_tx,
            task,
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
    tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
) {
    let connect = TcpStream::connect((req.host.as_str(), req.port));
    let stream = match tokio::time::timeout(TCP_CONNECT_TIMEOUT, connect).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            send_raw_tcp_message(
                id,
                MessageType::TcpFailed,
                &TcpFailed {
                    error: format!("connect {}:{}: {e}", req.host, req.port),
                },
                &tx,
            );
            return;
        }
        Err(_elapsed) => {
            send_raw_tcp_message(
                id,
                MessageType::TcpFailed,
                &TcpFailed {
                    error: format!("connect {}:{} timed out", req.host, req.port),
                },
                &tx,
            );
            return;
        }
    };

    if !send_raw_tcp_message(id, MessageType::TcpConnected, &TcpConnected {}, &tx) {
        return;
    }

    relay_tcp_session(id, stream, commands, tx).await;
}

async fn relay_tcp_session(
    id: u32,
    mut stream: TcpStream,
    mut commands: mpsc::Receiver<TcpCommand>,
    tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
) {
    let mut read_buf = vec![0u8; TCP_CHUNK_SIZE];
    let mut terminal_sent = false;
    // The destination half-closed its write side. We stop reading but keep the
    // loop alive so host->destination data still flows until the host closes.
    let mut read_eof = false;

    loop {
        tokio::select! {
            read = stream.read(&mut read_buf), if !read_eof => {
                match read {
                    Ok(0) => {
                        send_raw_tcp_message(id, MessageType::TcpEof, &TcpEof {}, &tx);
                        read_eof = true;
                    }
                    Ok(n) => {
                        if !send_raw_tcp_message(
                            id,
                            MessageType::TcpData,
                            &TcpData {
                                data: read_buf[..n].to_vec(),
                            },
                            &tx,
                        ) {
                            break;
                        }
                    }
                    Err(e) => {
                        terminal_sent = send_raw_tcp_message(
                            id,
                            MessageType::TcpFailed,
                            &TcpFailed {
                                error: format!("read TCP stream: {e}"),
                            },
                            &tx,
                        );
                        break;
                    }
                }
            }
            command = commands.recv() => {
                match command {
                    Some(TcpCommand::Data(data)) => {
                        if let Err(e) = stream.write_all(&data).await {
                            terminal_sent = send_raw_tcp_message(
                                id,
                                MessageType::TcpFailed,
                                &TcpFailed {
                                    error: format!("write TCP stream: {e}"),
                                },
                                &tx,
                            );
                            break;
                        }
                    }
                    Some(TcpCommand::Eof) => {
                        if let Err(e) = stream.shutdown().await {
                            terminal_sent = send_raw_tcp_message(
                                id,
                                MessageType::TcpFailed,
                                &TcpFailed {
                                    error: format!("shutdown TCP stream: {e}"),
                                },
                                &tx,
                            );
                            break;
                        }
                    }
                    None => {
                        break;
                    }
                }
            }
        }
    }

    if !terminal_sent {
        send_raw_tcp_message(id, MessageType::TcpClosed, &TcpClosed {}, &tx);
    }
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

fn send_raw_tcp_message<T: serde::Serialize>(
    id: u32,
    t: MessageType,
    payload: &T,
    tx: &mpsc::UnboundedSender<(u32, SessionOutput)>,
) -> bool {
    let mut buf = Vec::new();
    match encode_tcp_message(id, t, payload, &mut buf) {
        Ok(()) => tx.send((id, SessionOutput::Raw(buf))).is_ok(),
        Err(e) => {
            eprintln!("failed to encode tcp message for {id}: {e}");
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
        let (session_tx, mut session_rx) = mpsc::unbounded_channel();

        let session = TcpSession::open(
            7,
            TcpConnect {
                host: "127.0.0.1".to_string(),
                port: 0,
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
        let (session_tx, mut session_rx) = mpsc::unbounded_channel();
        let accept_task = tokio::spawn(async move {
            let (_socket, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(5)).await;
        });

        let session = TcpSession::open(
            9,
            TcpConnect {
                host: "127.0.0.1".to_string(),
                port,
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
        let (session_tx, mut session_rx) = mpsc::unbounded_channel();

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

    async fn recv_message(rx: &mut mpsc::UnboundedReceiver<(u32, SessionOutput)>) -> Message {
        let (_id, output) = rx.recv().await.unwrap();
        let SessionOutput::Raw(mut bytes) = output else {
            panic!("expected SessionOutput::Raw frame");
        };
        decode_one_message(&mut bytes)
    }
}
