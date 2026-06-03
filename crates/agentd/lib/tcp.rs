//! Guest-side TCP stream session handling.
//!
//! Handles `core.tcp.*` protocol messages by opening TCP sockets from
//! inside the guest and relaying bytes between those sockets and the host.

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

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Tracks an active guest-originated TCP stream.
pub struct TcpSession {
    owner_id: u32,
    commands: mpsc::UnboundedSender<TcpCommand>,
    task: JoinHandle<()>,
}

enum TcpCommand {
    Data(Vec<u8>),
    Eof,
    Close,
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
    pub fn write_data(&self, data: Vec<u8>) -> Result<(), String> {
        self.commands
            .send(TcpCommand::Data(data))
            .map_err(|_| "TCP session is closed".to_string())
    }

    /// Close the guest socket write half.
    pub fn close_write(&self) -> Result<(), String> {
        self.commands
            .send(TcpCommand::Eof)
            .map_err(|_| "TCP session is closed".to_string())
    }

    /// Request that the TCP session close.
    pub fn close(&self) {
        let _ = self.commands.send(TcpCommand::Close);
    }

    /// Returns whether the background relay task has finished.
    pub fn is_finished(&self) -> bool {
        self.task.is_finished()
    }

    /// Open a TCP stream from inside the guest and start relaying it.
    ///
    /// Sends `core.tcp.connected` on success, or `core.tcp.failed` on a connect
    /// error (returning `Ok(None)` in that case, since no live session results).
    pub async fn open(
        id: u32,
        req: TcpConnect,
        out_buf: &mut Vec<u8>,
        session_tx: &mpsc::UnboundedSender<(u32, SessionOutput)>,
    ) -> Result<Option<Self>, String> {
        let stream = match TcpStream::connect((req.host.as_str(), req.port)).await {
            Ok(stream) => stream,
            Err(e) => {
                encode_tcp_message(
                    id,
                    MessageType::TcpFailed,
                    &TcpFailed {
                        error: format!("connect {}:{}: {e}", req.host, req.port),
                    },
                    out_buf,
                )?;
                return Ok(None);
            }
        };

        encode_tcp_message(id, MessageType::TcpConnected, &TcpConnected {}, out_buf)?;

        let (commands_tx, commands_rx) = mpsc::unbounded_channel();
        let output_tx = session_tx.clone();
        let task = tokio::spawn(async move {
            relay_tcp_session(id, stream, commands_rx, output_tx).await;
        });

        Ok(Some(Self {
            owner_id: id,
            commands: commands_tx,
            task,
        }))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

async fn relay_tcp_session(
    id: u32,
    mut stream: TcpStream,
    mut commands: mpsc::UnboundedReceiver<TcpCommand>,
    tx: mpsc::UnboundedSender<(u32, SessionOutput)>,
) {
    let mut read_buf = vec![0u8; TCP_CHUNK_SIZE];
    let mut terminal_sent = false;

    loop {
        tokio::select! {
            read = stream.read(&mut read_buf) => {
                match read {
                    Ok(0) => {
                        send_raw_tcp_message(id, MessageType::TcpEof, &TcpEof {}, &tx);
                        terminal_sent = send_raw_tcp_message(id, MessageType::TcpClosed, &TcpClosed {}, &tx);
                        break;
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
                    Some(TcpCommand::Close) | None => {
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
        let (session_tx, _session_rx) = mpsc::unbounded_channel();
        let mut out_buf = Vec::new();

        let session = TcpSession::open(
            7,
            TcpConnect {
                host: "127.0.0.1".to_string(),
                port: 0,
            },
            &mut out_buf,
            &session_tx,
        )
        .await
        .unwrap();

        assert!(session.is_none());
        let msg = decode_one_message(&mut out_buf);
        assert_eq!(msg.t, MessageType::TcpFailed);
        assert_eq!(msg.flags, FLAG_TERMINAL);
        let failed: TcpFailed = msg.payload().unwrap();
        assert!(failed.error.contains("connect 127.0.0.1:0"));
    }

    #[tokio::test]
    async fn close_request_finishes_session_task() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (session_tx, mut session_rx) = mpsc::unbounded_channel();
        let mut out_buf = Vec::new();
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
            &mut out_buf,
            &session_tx,
        )
        .await
        .unwrap()
        .unwrap();

        let connected = decode_one_message(&mut out_buf);
        assert_eq!(connected.t, MessageType::TcpConnected);

        session.close();
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                if session.is_finished() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap();

        let (_id, output) = session_rx.recv().await.unwrap();
        let SessionOutput::Raw(mut frame_bytes) = output else {
            panic!("expected SessionOutput::Raw frame");
        };
        let closed = decode_one_message(&mut frame_bytes);
        assert_eq!(closed.t, MessageType::TcpClosed);
        assert_eq!(closed.flags, FLAG_TERMINAL);

        accept_task.abort();
    }

    fn decode_one_message(buf: &mut Vec<u8>) -> Message {
        codec::try_decode_from_buf(buf).unwrap().unwrap()
    }
}
