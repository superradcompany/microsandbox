//! [`GuestTcpStream`] over a real loopback agent connection, against the scripted agent in
//! [`super::test_agent`], which relays real loopback destination sockets the way agentd does.

use std::sync::Arc;

use super::test_agent::*;
use super::*;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

/// How long a test waits to prove that something does not happen.
const SETTLE: Duration = Duration::from_millis(300);

//--------------------------------------------------------------------------------------------------
// Fixture
//--------------------------------------------------------------------------------------------------

struct Fixture {
    client: Arc<AgentClient>,
    destination: TcpListener,
    agent: tokio::task::JoinHandle<()>,
}

/// How the scripted guest treats the fixture's destination.
#[derive(Clone, Copy)]
enum Guest {
    Prompt,
    /// Never writes host bytes, so never returns credit.
    Stalled,
    /// Returns a little credit at a time, steadily.
    Paced,
}

impl Fixture {
    async fn new(guest: Guest) -> Self {
        let destination = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = Some(destination.local_addr().unwrap().port());
        let ports = match guest {
            Guest::Prompt => GuestPorts::default(),
            Guest::Stalled => GuestPorts {
                stalled: port,
                ..Default::default()
            },
            Guest::Paced => GuestPorts {
                paced: port,
                ..Default::default()
            },
        };
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let agent = tokio::spawn(run_agent(listener, ports));
        let client = Arc::new(
            AgentClient::connect_stream_with_timeout(
                TcpStream::connect(address).await.unwrap(),
                Duration::from_secs(2),
            )
            .await
            .unwrap(),
        );
        assert!(client.supports(MessageType::BulkAccepted));
        Self {
            client,
            destination,
            agent,
        }
    }

    fn port(&self) -> u16 {
        self.destination.local_addr().unwrap().port()
    }

    async fn connect(&self) -> GuestTcpStream {
        GuestTcpConnection::connect(Arc::clone(&self.client), "127.0.0.1", self.port())
            .await
            .unwrap()
            .into_stream()
    }

    /// Dial the destination and accept the guest's connection to it.
    async fn dial(&self) -> (GuestTcpStream, TcpStream) {
        let stream = self.connect().await;
        let (peer, _) = self.destination.accept().await.unwrap();
        (stream, peer)
    }

    /// Drop the agent connection and wait for the agent, which ends only once the host hung up.
    async fn finish(self) {
        drop(self.client);
        self.agent.await.unwrap();
    }
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

/// The writer has sent the finish, but its acknowledgement becomes observable only when the
/// guest terminal future completes. This forces the supervisor to select the terminal before
/// it can select input completion, independently of Tokio's randomized branch order.
async fn terminal_before_input_completion(input_result: Option<bool>) -> TcpRelayEnd {
    let sender = TcpBulkSender::new(
        BulkSendState::new(
            BulkKind::Tcp,
            BulkFlow::HostToGuest,
            64 * 1024,
            AGENT_CREDIT,
        )
        .unwrap(),
    );
    sender.state.lock().await.admit(1).unwrap();
    let (written, completion) = tokio::sync::oneshot::channel();
    let (reply, terminal) = tokio::sync::oneshot::channel();
    let input = async {
        completion.await.unwrap();
        match input_result {
            Some(result) => result,
            None => std::future::pending().await,
        }
    };
    let output = std::future::pending();
    let guest = async {
        terminal.await.unwrap();
        sender
            .apply_credit(BulkCredit {
                kind: BulkKind::Tcp,
                flow: BulkFlow::HostToGuest,
                consumed_offset: 1,
                credit_limit: AGENT_CREDIT,
            })
            .await
            .unwrap();
        written.send(()).unwrap();
        sender.close();
        true
    };
    tokio::pin!(input, output, guest);
    let stop = watch::Sender::new(true);
    let mut stopped = stop.subscribe();
    let supervision = supervise_tcp(
        &sender,
        input.as_mut(),
        output.as_mut(),
        guest.as_mut(),
        &mut stopped,
        std::future::pending(),
    );
    tokio::pin!(supervision);
    // Only stop is initially ready. Drive the supervisor into its closing loop before
    // making the terminal ready; the input cannot complete until that terminal is polled.
    assert!(futures::poll!(&mut supervision).is_pending());
    reply.send(()).unwrap();
    tokio::time::timeout(3 * GUEST_TCP_CLOSE_IDLE_TIMEOUT, supervision)
        .await
        .expect("close supervision must stay bounded")
}

#[tokio::test]
async fn terminal_reply_does_not_overtake_successful_input_completion() {
    let end = terminal_before_input_completion(Some(true)).await;
    assert!(end.terminated, "guest acknowledged cleanup");
    assert!(end.guest_done);
    assert_eq!(end.finished, Some(true), "finish completion was lost");
}

#[tokio::test]
async fn terminal_reply_does_not_certify_failed_input_completion() {
    let end = terminal_before_input_completion(Some(false)).await;
    assert!(
        end.terminated,
        "input failure cannot undo acknowledged cleanup"
    );
    assert!(end.guest_done);
    assert_eq!(end.finished, Some(false));
}

#[tokio::test]
async fn terminal_reply_does_not_wait_forever_for_input_completion() {
    let start = tokio::time::Instant::now();
    let end = terminal_before_input_completion(None).await;
    assert!(start.elapsed() >= GUEST_TCP_CLOSE_IDLE_TIMEOUT);
    assert!(end.terminated, "timeout cannot undo acknowledged cleanup");
    assert!(end.guest_done);
    assert_eq!(end.finished, None, "unconfirmed finish is not delivery");
}

/// Read the destination to its end; a reset is an error.
async fn read_peer(mut peer: TcpStream) -> std::io::Result<Vec<u8>> {
    let mut received = Vec::new();
    peer.read_to_end(&mut received).await.map(|_| received)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn transfers_far_beyond_the_credit_window_in_both_directions() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let (mut stream, peer) = fixture.dial().await;
    // Larger than both windows: the host's offer to the guest and the guest's AGENT_CREDIT.
    let upload = pattern(16 * AGENT_CREDIT as usize, 7);
    let download = pattern(
        BulkOffer::tcp().guest_to_host_credit_limit as usize + 300_000,
        3,
    );

    let (mut peer_read, mut peer_write) = peer.into_split();
    let destination = {
        let download = download.clone();
        tokio::spawn(async move {
            let writing = async {
                peer_write.write_all(&download).await.unwrap();
                peer_write.shutdown().await.unwrap();
            };
            let mut received = Vec::new();
            let reading = peer_read.read_to_end(&mut received);
            let ((), read) = tokio::join!(writing, reading);
            read.unwrap();
            received
        })
    };
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let mut received = Vec::new();
    let (written, read) = tokio::join!(
        async {
            writer.write_all(&upload).await?;
            writer.shutdown().await
        },
        reader.read_to_end(&mut received),
    );
    written.unwrap();
    read.unwrap();
    assert_eq!(received, download);
    assert_eq!(destination.await.unwrap(), upload);
    assert_eq!(stream.close().await.unwrap(), GuestTcpCleanup::Acknowledged);
    fixture.finish().await;
}

#[tokio::test]
async fn a_stalled_destination_stops_the_writer_and_an_abort_resets_it() {
    let fixture = Fixture::new(Guest::Stalled).await;
    let (mut stream, mut peer) = fixture.dial().await;

    let written = tokio::time::timeout(
        SETTLE,
        stream.write_all(&pattern(16 * AGENT_CREDIT as usize, 1)),
    )
    .await;
    assert!(
        written.is_err(),
        "a write past the window must wait for credit"
    );

    let started = tokio::time::Instant::now();
    assert_eq!(stream.abort().await, GuestTcpCleanup::Acknowledged);
    assert!(started.elapsed() < GUEST_TCP_CLOSE_IDLE_TIMEOUT);
    let reset = peer.read(&mut [0; 1]).await;
    assert!(
        reset.is_err(),
        "an aborted connection resets its destination: {reset:?}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn an_abort_returns_promptly_with_unread_guest_output() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let (stream, mut peer) = fixture.dial().await;
    // Far more than the in-process pipe holds, and never read.
    let flood = tokio::spawn(async move {
        let _ = peer.write_all(&pattern(64 << 20, 4)).await;
    });
    tokio::time::sleep(SETTLE).await;
    let aborted = tokio::time::timeout(GUEST_TCP_CLOSE_IDLE_TIMEOUT, stream.abort()).await;
    assert_eq!(aborted.unwrap(), GuestTcpCleanup::Acknowledged);
    flood.await.unwrap();
    fixture.finish().await;
}

#[tokio::test]
async fn host_half_close_leaves_the_guest_side_readable() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let (mut stream, mut peer) = fixture.dial().await;

    stream.write_all(b"request").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut request = Vec::new();
    peer.read_to_end(&mut request).await.unwrap();
    assert_eq!(request, b"request");

    peer.write_all(b"response").await.unwrap();
    peer.shutdown().await.unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.unwrap();
    assert_eq!(response, b"response");
    assert_eq!(stream.close().await.unwrap(), GuestTcpCleanup::Acknowledged);
    fixture.finish().await;
}

#[tokio::test]
async fn guest_half_close_leaves_the_host_side_writable() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let (mut stream, mut peer) = fixture.dial().await;

    peer.write_all(b"banner").await.unwrap();
    peer.shutdown().await.unwrap();
    let mut banner = Vec::new();
    stream.read_to_end(&mut banner).await.unwrap();
    assert_eq!(banner, b"banner");

    stream.write_all(b"after eof").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut received = Vec::new();
    peer.read_to_end(&mut received).await.unwrap();
    assert_eq!(received, b"after eof");
    assert_eq!(stream.close().await.unwrap(), GuestTcpCleanup::Acknowledged);
    fixture.finish().await;
}

#[tokio::test]
async fn close_finishes_in_order_while_the_destination_stays_open() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let (mut stream, peer) = fixture.dial().await;
    let upload = pattern(8 * AGENT_CREDIT as usize, 9);

    stream.write_all(&upload).await.unwrap();
    let reading = tokio::spawn(read_peer(peer));
    // The destination never ends its side, so after the finish the close waits out its idle
    // bound and cancels a drained stream, which ends in order rather than with a reset.
    assert_eq!(stream.close().await.unwrap(), GuestTcpCleanup::Acknowledged);
    assert_eq!(reading.await.unwrap().unwrap(), upload);
    fixture.finish().await;
}

#[tokio::test]
async fn a_close_after_every_byte_was_written_still_finishes_without_a_reset() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let (mut stream, mut peer) = fixture.dial().await;
    let upload = pattern(4 << 20, 5);

    // Wait until the destination has every byte, so nothing is in flight when the close starts.
    let mut received = vec![0; upload.len()];
    let (written, read) = tokio::join!(stream.write_all(&upload), peer.read_exact(&mut received));
    written.unwrap();
    read.unwrap();
    assert_eq!(received, upload);
    let reading = tokio::spawn(read_peer(peer));
    assert_eq!(stream.close().await.unwrap(), GuestTcpCleanup::Acknowledged);
    assert!(reading.await.unwrap().unwrap().is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn close_on_a_stalled_destination_returns_an_error_within_the_bound() {
    let fixture = Fixture::new(Guest::Stalled).await;
    let (mut stream, peer) = fixture.dial().await;
    // Exactly the guest's window: admitted, but never written to the destination.
    stream
        .write_all(&pattern(AGENT_CREDIT as usize, 2))
        .await
        .unwrap();
    let started = tokio::time::Instant::now();
    let error = stream.close().await.unwrap_err();
    let elapsed = started.elapsed();
    assert!(error.to_string().contains("destination"), "{error}");
    assert!(elapsed >= GUEST_TCP_CLOSE_IDLE_TIMEOUT, "{elapsed:?}");
    assert!(elapsed < 3 * GUEST_TCP_CLOSE_IDLE_TIMEOUT, "{elapsed:?}");
    // No finish was sent for undelivered bytes: the destination is reset, not ended in order.
    let reset = read_peer(peer).await;
    assert!(
        reset.is_err(),
        "a truncated stream must not end in order: {reset:?}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn close_delivers_everything_to_a_slow_but_steady_destination() {
    let fixture = Fixture::new(Guest::Paced).await;
    let (mut stream, peer) = fixture.dial().await;
    // Draining this at PACED_CREDIT per CREDIT_PACE takes several idle bounds in total.
    let upload = pattern(AGENT_CREDIT as usize + 8 * PACED_CREDIT as usize, 6);
    let grants = upload.len() as u64 / PACED_CREDIT;
    assert!(CREDIT_PACE * grants as u32 >= 2 * GUEST_TCP_CLOSE_IDLE_TIMEOUT);
    let reading = tokio::spawn(read_peer(peer));
    stream.write_all(&upload).await.unwrap();
    assert_eq!(stream.close().await.unwrap(), GuestTcpCleanup::Acknowledged);
    assert_eq!(reading.await.unwrap().unwrap(), upload);
    fixture.finish().await;
}

#[tokio::test]
async fn a_refused_destination_fails_the_dial() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let port = fixture.port();
    let Fixture {
        client,
        destination,
        agent,
    } = fixture;
    drop(destination);
    let error = GuestTcpConnection::connect(Arc::clone(&client), "127.0.0.1", port)
        .await
        .err()
        .expect("nothing listens on the port");
    assert!(error.to_string().contains("guest TCP connect"), "{error}");
    drop(client);
    agent.await.unwrap();
}

#[tokio::test]
async fn dropping_a_stream_aborts_instead_of_finishing() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let (mut stream, peer) = fixture.dial().await;
    stream.write_all(b"partial").await.unwrap();
    drop(stream);
    let reset = read_peer(peer).await;
    assert!(
        reset.is_err(),
        "a dropped stream must not end in order: {reset:?}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn dropping_a_half_closed_stream_releases_an_idle_destination_and_relay() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let (mut stream, mut peer) = fixture.dial().await;
    stream.write_all(b"finished input").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut input = Vec::new();
    peer.read_to_end(&mut input).await.unwrap();
    assert_eq!(input, b"finished input");
    // Retain only a non-owning observation of the task state. The destination stays idle/open.
    let state = Arc::downgrade(&stream.relay.state);
    let mut outcome = stream.relay.state.outcome.subscribe();
    drop(stream);
    let published = tokio::time::timeout(
        GUEST_TCP_CLOSE_IDLE_TIMEOUT,
        outcome.wait_for(Option::is_some),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(published.unwrap().cleanup, GuestTcpCleanup::Acknowledged);
    drop(published);
    drop(outcome);
    // Releasing the client joins the scripted agent, so the relay and its socket are gone.
    fixture.finish().await;
    assert!(
        state.upgrade().is_none(),
        "dropped owner left the relay state alive"
    );
    assert_eq!(peer.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn concurrent_dials_stay_independent() {
    const CONNECTIONS: usize = 16;
    let fixture = Arc::new(Fixture::new(Guest::Prompt).await);
    let acceptor = {
        let fixture = Arc::clone(&fixture);
        tokio::spawn(async move {
            let mut echoes = JoinSet::new();
            for _ in 0..CONNECTIONS {
                let (mut peer, _) = fixture.destination.accept().await.unwrap();
                echoes.spawn(async move {
                    let (mut read, mut write) = peer.split();
                    tokio::io::copy(&mut read, &mut write).await.unwrap();
                    write.shutdown().await.unwrap();
                });
            }
            while let Some(echo) = echoes.join_next().await {
                echo.unwrap();
            }
        })
    };
    let mut dials = JoinSet::new();
    for seed in 0..CONNECTIONS {
        let fixture = Arc::clone(&fixture);
        dials.spawn(async move {
            let mut stream = fixture.connect().await;
            let payload = pattern(3 * AGENT_CREDIT as usize + seed, seed as u8);
            let (mut reader, mut writer) = tokio::io::split(&mut stream);
            let mut echoed = Vec::new();
            let (written, read) = tokio::join!(
                async {
                    writer.write_all(&payload).await?;
                    writer.shutdown().await
                },
                reader.read_to_end(&mut echoed),
            );
            written.unwrap();
            read.unwrap();
            assert_eq!(echoed, payload);
            assert_eq!(stream.close().await.unwrap(), GuestTcpCleanup::Acknowledged);
        });
    }
    while let Some(dial) = dials.join_next().await {
        dial.unwrap();
    }
    acceptor.await.unwrap();
    Arc::into_inner(fixture).unwrap().finish().await;
}

#[tokio::test]
async fn guest_reset_ends_blocked_read_and_write_and_acknowledges_cleanup() {
    let fixture = Fixture::new(Guest::Stalled).await;
    let (mut stream, peer) = fixture.dial().await;
    let upload = pattern(16 * AGENT_CREDIT as usize, 1);
    let (mut reader, mut writer) = tokio::io::split(&mut stream);
    let mut byte = [0];
    let read = reader.read(&mut byte);
    let write = writer.write_all(&upload);
    tokio::pin!(read, write);
    // Poll both calls into a blocked state before resetting the real destination socket.
    assert!(tokio::time::timeout(SETTLE, &mut read).await.is_err());
    assert!(tokio::time::timeout(SETTLE, &mut write).await.is_err());
    peer.set_zero_linger().unwrap();
    drop(peer);
    let (read, write) = tokio::time::timeout(GUEST_TCP_CLOSE_IDLE_TIMEOUT, async {
        tokio::join!(&mut read, &mut write)
    })
    .await
    .unwrap();
    assert!(read.is_err(), "reset must not become EOF: {read:?}");
    assert!(write.is_err(), "reset must end a blocked write: {write:?}");
    drop((read, write));
    // The pump consumed both BulkCancel and TcpFailed, and published an outcome without panic.
    assert_eq!(
        tokio::time::timeout(GUEST_TCP_CLOSE_IDLE_TIMEOUT, stream.abort())
            .await
            .unwrap(),
        GuestTcpCleanup::Acknowledged
    );
    fixture.finish().await;
}

#[tokio::test]
async fn guest_reset_read_failure_prevents_a_subsequent_write() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let (mut stream, peer) = fixture.dial().await;
    // No host input is pending: the input relay is waiting on its reader, not guest credit.
    // A failure exposed by Read must already have stopped this otherwise-writable input.
    peer.set_zero_linger().unwrap();
    drop(peer);
    let mut byte = [0];
    let read = tokio::time::timeout(3 * GUEST_TCP_CLOSE_IDLE_TIMEOUT, stream.read(&mut byte))
        .await
        .expect("guest reset must end Read");
    assert!(read.is_err(), "reset must not become EOF: {read:?}");
    let write = stream.write(b"after failure").await;
    assert!(
        write.is_err(),
        "write after reported guest failure: {write:?}"
    );
    assert_eq!(stream.abort().await, GuestTcpCleanup::Acknowledged);
    fixture.finish().await;
}

#[tokio::test]
async fn stopped_output_reports_truncation_even_if_the_guest_later_finishes() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let connection =
        GuestTcpConnection::connect(Arc::clone(&fixture.client), "127.0.0.1", fixture.port())
            .await
            .unwrap();
    let (mut peer, _) = fixture.destination.accept().await.unwrap();
    let (source, reader) = tokio::io::duplex(1);
    let (writer, mut output) = tokio::io::duplex(1);
    let relay = connection.relay(reader, writer);
    // Close has stopped output delivery before this guest output and ordered EOF arrive.
    relay.state.stop.send_replace(true);
    peer.write_all(b"truncated").await.unwrap();
    peer.shutdown().await.unwrap();
    let read = tokio::time::timeout(
        3 * GUEST_TCP_CLOSE_IDLE_TIMEOUT,
        output.read_to_end(&mut Vec::new()),
    )
    .await
    .unwrap();
    read.unwrap();
    assert!(
        relay.read_error().is_some(),
        "discarded output must not certify EOF"
    );
    drop(source);
    assert_eq!(relay.abort().await, GuestTcpCleanup::Acknowledged);
    fixture.finish().await;
}

#[tokio::test]
async fn discarding_guest_bytes_cannot_turn_a_later_finish_into_clean_eof() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let mut receiver = BulkReceiveState::new(
        BulkKind::Tcp,
        BulkFlow::GuestToHost,
        64 * 1024,
        AGENT_CREDIT,
        AGENT_CREDIT,
    )
    .unwrap();
    let record = BulkRecord {
        id: 1,
        kind: BulkKind::Tcp,
        flow: BulkFlow::GuestToHost,
        offset: 0,
        payload: Bytes::from_static(b"truncated"),
    };
    let end = receiver.accept_record(&record).unwrap();
    receiver
        .accept_finish(BulkFinish {
            kind: BulkKind::Tcp,
            flow: BulkFlow::GuestToHost,
            final_offset: end,
        })
        .unwrap();
    let (events, output) = mpsc::channel(3);
    assert!(
        events
            .send(TcpOutput::Data {
                payload: record.payload,
                consumed_offset: end
            })
            .await
            .is_ok()
    );
    assert!(events.send(TcpOutput::Eof).await.is_ok());
    assert!(events.send(TcpOutput::Close).await.is_ok());
    let stop = watch::Sender::new(true);
    let (mut writer, _unread) = tokio::io::duplex(1);
    let clean_eof = relay_tcp_output(
        1,
        output,
        &mut writer,
        Arc::clone(&fixture.client),
        Arc::new(Mutex::new(receiver)),
        stop.subscribe(),
    )
    .await;
    assert!(!clean_eof, "discarded bytes must not become clean EOF");
    fixture.finish().await;
}

#[tokio::test]
async fn a_closed_sender_validates_late_credit_without_reopening_input() {
    let fixture = Fixture::new(Guest::Prompt).await;
    let sender = TcpBulkSender::new(
        BulkSendState::new(
            BulkKind::Tcp,
            BulkFlow::HostToGuest,
            64 * 1024,
            AGENT_CREDIT,
        )
        .unwrap(),
    );
    sender.state.lock().await.admit(64).unwrap();
    sender.close();
    sender
        .apply_credit(BulkCredit {
            kind: BulkKind::Tcp,
            flow: BulkFlow::HostToGuest,
            consumed_offset: 64,
            credit_limit: AGENT_CREDIT + 64,
        })
        .await
        .unwrap();
    assert_eq!(sender.consumed().await, (64, true));
    assert!(
        sender
            .apply_credit(BulkCredit {
                kind: BulkKind::Tcp,
                flow: BulkFlow::HostToGuest,
                consumed_offset: 65,
                credit_limit: AGENT_CREDIT + 65
            })
            .await
            .is_err()
    );
    assert!(
        sender
            .send(&fixture.client, 1, Bytes::from_static(b"no more input"))
            .await
            .is_err()
    );
    fixture.finish().await;
}
