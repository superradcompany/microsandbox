//! Live tests for the limits of raw bulk filesystem streams.
//!
//! Every sandbox here has one vCPU, so stream cleanup, flow control, and command handling all
//! compete for the same guest CPU.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use bytes::Bytes;
use microsandbox::sandbox::{FsOpenOptions, FsReadStream, FsWriteSink, SandboxStatus};
use microsandbox::{MicrosandboxError, MicrosandboxResult, Sandbox};
use test_utils::msb_test;
use tokio::task::JoinHandle;
use tokio::time::{sleep, timeout};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Raw bulk operations one agent client may hold open at once.
const PER_CLIENT_BULK_LIMIT: usize = 64;

/// Sparse file large enough that no read stream reaches its end during a test.
const ENDLESS_FILE: &str = "/tmp/endless";

/// File with known content for byte-exact checks.
const KNOWN_FILE: &str = "/tmp/known";

const IMAGE: &str = "mirror.gcr.io/library/alpine";
const STEP_TIMEOUT: Duration = Duration::from_secs(30);
const COMMAND_TIMEOUT: Duration = Duration::from_secs(10);

/// How long a released slot may take to become reusable; release is asynchronous.
const RELEASE_DEADLINE: Duration = Duration::from_secs(10);

const WRITE_CHUNK: usize = 64 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Counts commands run on a separate client for the length of a test.
struct Observer {
    stop: Arc<AtomicBool>,
    runs: Arc<AtomicUsize>,
    task: JoinHandle<usize>,
}

struct ObserverTally {
    runs: usize,
    failures: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Observer {
    fn start(client: Sandbox) -> Self {
        let stop = Arc::new(AtomicBool::new(false));
        let runs = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn({
            let (stop, runs) = (Arc::clone(&stop), Arc::clone(&runs));
            async move {
                let mut failures = 0;
                while !stop.load(Ordering::Relaxed) {
                    match timeout(COMMAND_TIMEOUT, client.shell("true")).await {
                        Ok(Ok(output)) if output.status().success => {
                            runs.fetch_add(1, Ordering::Relaxed);
                        }
                        _ => failures += 1,
                    }
                    sleep(Duration::from_millis(20)).await;
                }
                failures
            }
        });
        Self { stop, runs, task }
    }

    fn runs(&self) -> usize {
        self.runs.load(Ordering::Relaxed)
    }

    async fn finish(self) -> ObserverTally {
        self.stop.store(true, Ordering::Relaxed);
        let failures = timeout(STEP_TIMEOUT, self.task)
            .await
            .expect("observer did not stop")
            .unwrap();
        ObserverTally {
            runs: self.runs.load(Ordering::Relaxed),
            failures,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn create_sandbox(name: &str, memory: u32) -> Sandbox {
    let sandbox = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .memory(memory)
        .replace()
        .create()
        .await
        .unwrap();
    let output = sandbox
        .shell(format!("truncate -s 64G {ENDLESS_FILE}"))
        .await
        .unwrap();
    assert!(output.status().success);
    sandbox
}

/// Open a new agent client. Each client has its own bulk allowance.
async fn connect(name: &str) -> Sandbox {
    timeout(STEP_TIMEOUT, Sandbox::get_running(name))
        .await
        .expect("connecting to the sandbox stalled")
        .expect("connecting to the sandbox failed")
}

async fn open_read(client: &Sandbox, path: &str) -> MicrosandboxResult<FsReadStream> {
    let fs = client.fs();
    let options = FsOpenOptions {
        read: true,
        ..Default::default()
    };
    let handle = with_timeout(fs.open_file(path, options)).await?;

    let stream = with_timeout(fs.read_handle_stream(&handle, 0, None)).await;
    if stream.is_err() {
        let _ = with_timeout(fs.close_handle(handle)).await;
    }
    stream
}

async fn open_write(client: &Sandbox, path: &str) -> MicrosandboxResult<FsWriteSink> {
    let fs = client.fs();
    let options = FsOpenOptions {
        write: true,
        create: true,
        truncate: true,
        ..Default::default()
    };
    let handle = with_timeout(fs.open_file(path, options)).await?;

    let sink = with_timeout(fs.write_handle_stream(&handle, 0, None)).await;
    if sink.is_err() {
        let _ = with_timeout(fs.close_handle(handle)).await;
    }
    sink
}

/// Open a read stream, retrying while a just-released slot is still held.
async fn open_read_once_released(client: &Sandbox) -> FsReadStream {
    let deadline = Instant::now() + RELEASE_DEADLINE;
    loop {
        match open_read(client, ENDLESS_FILE).await {
            Ok(stream) => return stream,
            Err(error) if is_limit_refusal(&error) && Instant::now() < deadline => {
                sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("released bulk slot was not reusable: {error}"),
        }
    }
}

async fn read_file(client: &Sandbox, path: &str) -> Bytes {
    let stream = open_read(client, path).await.unwrap();
    timeout(STEP_TIMEOUT, stream.collect())
        .await
        .expect("reading the file stalled")
        .unwrap()
}

/// Read a stream to its end in the background, counting it once its first chunk arrives.
fn drain(mut stream: FsReadStream, started: &Arc<AtomicUsize>) -> JoinHandle<()> {
    let started = Arc::clone(started);
    tokio::spawn(async move {
        let mut first = true;
        while let Ok(Some(_)) = stream.recv().await {
            if std::mem::take(&mut first) {
                started.fetch_add(1, Ordering::Relaxed);
            }
        }
    })
}

async fn wait_for_count(counter: &AtomicUsize, expected: usize) {
    let deadline = Instant::now() + STEP_TIMEOUT;
    while counter.load(Ordering::Relaxed) < expected {
        assert!(
            Instant::now() < deadline,
            "only {} of {expected} streams delivered data",
            counter.load(Ordering::Relaxed)
        );
        sleep(Duration::from_millis(10)).await;
    }
}

async fn assert_serving(sandbox: &Sandbox) {
    assert!(
        matches!(sandbox.status().await.unwrap(), SandboxStatus::Running),
        "sandbox is not running"
    );
    let output = timeout(COMMAND_TIMEOUT, sandbox.shell("true"))
        .await
        .expect("command stalled")
        .unwrap();
    assert!(output.status().success);
}

fn assert_limit_refusal(error: Option<MicrosandboxError>) {
    let error = error.expect("a bulk stream beyond the per-client limit was admitted");
    assert!(
        is_limit_refusal(&error),
        "expected the per-client limit error, got: {error}"
    );
}

fn is_limit_refusal(error: &MicrosandboxError) -> bool {
    error.to_string().contains(&format!(
        "maximum of {PER_CLIENT_BULK_LIMIT} active bulk operations"
    ))
}

async fn with_timeout<T>(
    operation: impl Future<Output = MicrosandboxResult<T>>,
) -> MicrosandboxResult<T> {
    timeout(STEP_TIMEOUT, operation)
        .await
        .expect("filesystem operation stalled")
}

fn written_path(index: usize) -> String {
    format!("/tmp/written-{index}")
}

/// Deterministic content that varies with the offset and the seed.
fn known_bytes(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|offset| ((offset as u64).wrapping_mul(2_654_435_761) >> 11) as u8 ^ seed)
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn bulk_admission_is_per_client_and_released_slots_are_reusable() {
    let name = "bulk-limits-admission";
    let sandbox = create_sandbox(name, 512).await;
    let first = connect(name).await;
    let second = connect(name).await;
    let started = Arc::new(AtomicUsize::new(0));

    // Reads and writes draw on the same allowance, so fill it with both.
    let mut readers = Vec::new();
    for _ in 0..PER_CLIENT_BULK_LIMIT - 1 {
        let stream = open_read(&first, ENDLESS_FILE)
            .await
            .expect("read stream within the limit was refused");
        readers.push(drain(stream, &started));
    }
    let sink = open_write(&first, "/tmp/admission-write")
        .await
        .expect("write stream within the limit was refused");
    wait_for_count(&started, PER_CLIENT_BULK_LIMIT - 1).await;

    assert_limit_refusal(open_read(&first, ENDLESS_FILE).await.err());
    assert_limit_refusal(open_write(&first, "/tmp/refused-write").await.err());

    // The limit belongs to the client, not the sandbox.
    let mut other = open_read(&second, ENDLESS_FILE)
        .await
        .expect("a second client was refused while the first was at its limit");
    let chunk = timeout(STEP_TIMEOUT, other.recv())
        .await
        .expect("second client's stream stalled")
        .expect("second client's stream failed");
    assert!(chunk.is_some_and(|chunk| !chunk.is_empty()));
    drop(other);

    // A completed write and a cancelled read each return their slot.
    sink.write(b"admission").await.unwrap();
    timeout(STEP_TIMEOUT, sink.close())
        .await
        .expect("closing the write stream stalled")
        .unwrap();
    let replacement = open_read_once_released(&first).await;
    readers.push(drain(replacement, &started));

    readers.pop().unwrap().abort();
    let replacement = open_read_once_released(&first).await;
    readers.push(drain(replacement, &started));

    // Releasing a slot does not raise the limit: the client is full again.
    assert_limit_refusal(open_read(&first, ENDLESS_FILE).await.err());
    let written = read_file(&second, "/tmp/admission-write").await;
    assert_eq!(&written[..], b"admission");

    for reader in &readers {
        reader.abort();
    }
    drop((first, second));
    assert_serving(&sandbox).await;
    sandbox.stop().await.unwrap();
    Sandbox::remove(name).await.unwrap();
}

#[msb_test]
async fn clients_at_the_bulk_limit_disconnecting_together_leave_the_sandbox_serving() {
    const CLIENTS: usize = 8;

    let name = "bulk-limits-disconnect";
    let sandbox = create_sandbox(name, 2048).await;
    let expected = known_bytes(4 * 1024 * 1024, 1);
    sandbox.fs().write(KNOWN_FILE, &expected).await.unwrap();
    let observer = Observer::start(connect(name).await);

    let started = Arc::new(AtomicUsize::new(0));
    let mut clients = Vec::new();
    let mut readers = Vec::new();
    for _ in 0..CLIENTS {
        let client = connect(name).await;
        for _ in 0..PER_CLIENT_BULK_LIMIT {
            let stream = open_read(&client, ENDLESS_FILE)
                .await
                .expect("read stream within the limit was refused");
            readers.push(drain(stream, &started));
        }
        clients.push(client);
    }
    wait_for_count(&started, CLIENTS * PER_CLIENT_BULK_LIMIT).await;
    sleep(Duration::from_secs(1)).await;

    // Drop every stream and every client at once.
    let runs_before_disconnect = observer.runs();
    for reader in &readers {
        reader.abort();
    }
    for reader in readers {
        let _ = reader.await;
    }
    drop(clients);
    sleep(Duration::from_secs(5)).await;

    let tally = observer.finish().await;
    assert_eq!(tally.failures, 0, "commands failed during the disconnect");
    assert!(
        tally.runs > runs_before_disconnect,
        "no command completed after the disconnect"
    );
    assert_serving(&sandbox).await;

    // A new client still gets its full allowance, and a read after the disconnect is intact.
    let fresh = connect(name).await;
    let mut streams = Vec::new();
    for _ in 0..PER_CLIENT_BULK_LIMIT {
        let stream = open_read(&fresh, ENDLESS_FILE)
            .await
            .expect("a new client was refused after the others disconnected");
        streams.push(stream);
    }
    drop((streams, fresh));
    let copy = read_file(&connect(name).await, KNOWN_FILE).await;
    assert!(
        copy == expected,
        "file read after the disconnect does not match"
    );

    sandbox.stop().await.unwrap();
    Sandbox::remove(name).await.unwrap();
}

#[msb_test]
async fn unconsumed_streams_hold_back_only_their_own_client() {
    let name = "bulk-limits-unconsumed";
    let sandbox = create_sandbox(name, 1024).await;
    let expected = known_bytes(16 * 1024 * 1024, 2);
    sandbox.fs().write(KNOWN_FILE, &expected).await.unwrap();

    let stalled = connect(name).await;
    let mut held = Vec::new();
    for _ in 0..PER_CLIENT_BULK_LIMIT {
        let stream = open_read(&stalled, ENDLESS_FILE)
            .await
            .expect("read stream within the limit was refused");
        held.push(stream);
    }
    // Wait long enough for every unread stream to fill its flow-control window.
    sleep(Duration::from_secs(5)).await;

    let reader = connect(name).await;
    let copy = timeout(STEP_TIMEOUT, read_file(&reader, KNOWN_FILE))
        .await
        .expect("a full read stalled behind another client's unconsumed streams");
    assert!(
        copy == expected,
        "file read next to unconsumed streams does not match"
    );
    assert_serving(&sandbox).await;
    sleep(Duration::from_secs(5)).await;

    // Held streams were paused, not dropped: they resume once read.
    for stream in &mut held {
        let chunk = timeout(STEP_TIMEOUT, stream.recv())
            .await
            .expect("held stream did not resume")
            .expect("held stream failed");
        assert!(chunk.is_some_and(|chunk| !chunk.is_empty()));
    }

    drop((held, stalled));
    assert_serving(&sandbox).await;
    sandbox.stop().await.unwrap();
    Sandbox::remove(name).await.unwrap();
}

#[msb_test]
async fn concurrent_bulk_writes_land_intact_beside_an_abandoned_write() {
    const WRITERS: usize = 4;
    const PAYLOAD: usize = 8 * 1024 * 1024;

    let name = "bulk-limits-writes";
    let sandbox = create_sandbox(name, 1024).await;

    let abandoned_client = connect(name).await;
    let abandoned = open_write(&abandoned_client, "/tmp/abandoned")
        .await
        .unwrap();
    abandoned.write(vec![0xab; 1024 * 1024]).await.unwrap();

    let mut writers = Vec::new();
    for index in 0..WRITERS {
        let client = connect(name).await;
        writers.push(tokio::spawn(async move {
            let payload = known_bytes(PAYLOAD, index as u8 + 3);
            let sink = open_write(&client, &written_path(index)).await?;
            for chunk in payload.chunks(WRITE_CHUNK) {
                sink.write(chunk).await?;
            }
            sink.close().await?;
            Ok::<_, MicrosandboxError>(payload)
        }));
    }
    // Abandon one write mid-transfer without closing it.
    drop((abandoned, abandoned_client));

    let mut payloads = Vec::new();
    for writer in writers {
        let payload = timeout(Duration::from_secs(60), writer)
            .await
            .expect("a write stalled beside the abandoned write")
            .unwrap()
            .expect("a write failed beside the abandoned write");
        payloads.push(payload);
    }

    let reader = connect(name).await;
    for (index, payload) in payloads.iter().enumerate() {
        let copy = read_file(&reader, &written_path(index)).await;
        assert!(copy == payload[..], "written file {index} does not match");
    }
    assert_serving(&sandbox).await;
    sandbox.stop().await.unwrap();
    Sandbox::remove(name).await.unwrap();
}
