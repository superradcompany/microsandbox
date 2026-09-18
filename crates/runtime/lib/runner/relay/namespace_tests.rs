//! Exercise the actual reader boundary, including its disconnect cleanup.

use super::*;
use microsandbox_protocol::wire::Envelope;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, DuplexStream};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn packet(name: &str, id: u32, flags: u8) -> Vec<u8> {
    let envelope = Envelope::new(1, name, &serde_json::json!({"value": "test-only"})).unwrap();
    let mut bytes = Vec::new();
    codec::encode_raw_to_buf(&envelope.frame(id, flags).unwrap(), &mut bytes).unwrap();
    bytes
}

async fn write_fragmented(client: &mut DuplexStream, bytes: &[u8]) {
    for chunk in bytes.chunks(3) {
        client.write_all(chunk).await.unwrap();
    }
}

#[allow(clippy::too_many_arguments)]
async fn client_reader_task(
    slot: u32,
    reader: DuplexStream,
    agent_tx: ControlWriter,
    clients: Arc<Mutex<HashMap<u32, ClientState>>>,
    used_slots: Arc<Mutex<HashSet<u32>>>,
    drain_tx: mpsc::Sender<()>,
    session_registry: Arc<SessionRegistry>,
    next_session_id: Arc<AtomicU64>,
    start: u32,
    end: u32,
) {
    let (merge_tx, _merge_rx) = mpsc::channel(1);
    let (write_tx, _write_rx) = mpsc::unbounded_channel();
    let (_disconnect_tx, disconnect_rx) = watch::channel(false);
    #[cfg(unix)]
    let (local_write_tx, _local_write_rx) = mpsc::unbounded_channel();
    super::client_reader_task(
        slot,
        reader,
        agent_tx,
        clients,
        used_slots,
        drain_tx,
        session_registry,
        next_session_id,
        None,
        None,
        merge_tx,
        Arc::new(Mutex::new(HashMap::new())),
        start,
        end,
        None,
        Arc::new(std::sync::Mutex::new(HashMap::new())),
        write_tx,
        Arc::new(Semaphore::new(CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY)),
        disconnect_rx,
        Arc::new(std::sync::atomic::AtomicBool::new(false)),
        #[cfg(unix)]
        local_write_tx,
    )
    .await;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn control_names_never_trigger_shutdown_or_new_sessions() {
    tokio::time::timeout(Duration::from_secs(10), async {
        for name in [
            "control.capabilities",
            "control.memory.state",
            "control.memory.target",
            "control.cpu.state",
            "control.cpu.target",
            "control.secrets.update",
            "control.future",
        ] {
            for flags in [0, FLAG_SESSION_START, FLAG_SHUTDOWN, FLAG_TERMINAL] {
                let (mut client, reader) = tokio::io::duplex(8192);
                let (agent_tx, mut agent_rx) = ControlWriter::new();
                let (drain_tx, mut drain_rx) = mpsc::channel(1);
                let (write_tx, _write_rx) = mpsc::unbounded_channel();
                let clients = Arc::new(Mutex::new(HashMap::from([(
                    0,
                    ClientState {
                        incarnation: None,
                        active_sessions: HashSet::from([11]),
                        active_bulk: Arc::new(std::sync::Mutex::new(HashMap::new())),
                        write_tx,
                        write_budget: Arc::new(Semaphore::new(
                            CLIENT_OUTPUT_PER_CLIENT_BYTE_CAPACITY,
                        )),
                        disconnect_tx: watch::channel(false).0,
                        #[cfg(unix)]
                        local_outbound: None,
                    },
                )])));
                let slots = Arc::new(Mutex::new(HashSet::from([0, 1])));
                let registry = Arc::new(std::sync::Mutex::new(HashMap::new()));
                let sequence = Arc::new(AtomicU64::new(7));
                let task = tokio::spawn(client_reader_task(
                    0,
                    reader,
                    agent_tx,
                    clients.clone(),
                    slots.clone(),
                    drain_tx,
                    registry.clone(),
                    sequence.clone(),
                    10,
                    20,
                ));
                let id = if flags == FLAG_SHUTDOWN { 0 } else { 10 };
                write_fragmented(&mut client, &packet(name, id, flags)).await;
                task.await.unwrap();
                assert!(
                    drain_rx.try_recv().is_err(),
                    "{name} triggered host shutdown"
                );
                assert!(registry.lock().unwrap().is_empty());
                assert_eq!(sequence.load(Ordering::SeqCst), 7);
                assert!(clients.lock().await.is_empty());
                assert_eq!(*slots.lock().await, HashSet::from([1]));
                // Existing sessions still receive the established disconnect
                // cleanup. No caller-supplied control bytes enter this queue.
                let kill = decode_frame(&agent_rx.recv().await.unwrap().data).unwrap();
                assert_eq!(kill.t, MessageType::ExecSignal);
                assert_eq!(kill.id, 11);
                let disconnected = decode_frame(&agent_rx.recv().await.unwrap().data).unwrap();
                assert_eq!(disconnected.t, MessageType::RelayClientDisconnected);
                assert!(agent_rx.recv().await.is_none());
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn forwards_future_agent_bytes_and_reserved_shutdown_unchanged() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (mut client, reader) = tokio::io::duplex(8192);
        let (agent_tx, mut agent_rx) = ControlWriter::new();
        let (drain_tx, mut drain_rx) = mpsc::channel(1);
        let task = tokio::spawn(client_reader_task(
            0,
            reader,
            agent_tx,
            Arc::new(Mutex::new(HashMap::new())),
            Arc::new(Mutex::new(HashSet::from([0]))),
            drain_tx,
            Arc::new(std::sync::Mutex::new(HashMap::new())),
            Arc::new(AtomicU64::new(0)),
            10,
            20,
        ));
        let mut future = packet("core.future", 10, 0);
        // Keep a future field in the exact frame to catch decode/re-encode.
        future[9] += 1;
        future.extend_from_slice(b"\x61x\x01");
        let len = (future.len() - 4) as u32;
        future[..4].copy_from_slice(&len.to_be_bytes());
        write_fragmented(&mut client, &future).await;
        assert_eq!(agent_rx.recv().await.unwrap().data.as_ref(), future);
        let shutdown = Message::with_payload(MessageType::Shutdown, 0, &()).unwrap();
        let mut bytes = Vec::new();
        codec::encode_to_buf(&shutdown, &mut bytes).unwrap();
        write_fragmented(&mut client, &bytes).await;
        assert_eq!(agent_rx.recv().await.unwrap().data.as_ref(), bytes);
        assert_eq!(drain_rx.recv().await, Some(()));
        drop(client);
        task.await.unwrap();
    })
    .await
    .unwrap();
}
